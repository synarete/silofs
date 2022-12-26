/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <limits.h>

#define ITROOT_DEPTH            (1)
#define ITNODE_DEPTH_MAX        (16)

struct silofs_ino_set {
	size_t cnt;
	ino_t ino[SILOFS_ITNODE_NENTS];
};

struct silofs_it_ctx {
	const struct silofs_task       *task;
	struct silofs_sb_info          *sbi;
	struct silofs_itable_info      *itbi;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void iaddr_reset(struct silofs_iaddr *iaddr)
{
	vaddr_reset(&iaddr->vaddr);
	iaddr->ino = SILOFS_INO_NULL;
}

static void iaddr_setup(struct silofs_iaddr *iaddr, ino_t ino,
                        const struct silofs_vaddr *vaddr)
{
	vaddr_assign(&iaddr->vaddr, vaddr);
	iaddr->ino = ino;
}

static void iaddr_setup2(struct silofs_iaddr *iaddr, ino_t ino, loff_t voff)
{
	iaddr->ino = ino;
	vaddr_setup(&iaddr->vaddr, SILOFS_STYPE_INODE, voff);
}

static void iaddr_assign(struct silofs_iaddr *iaddr,
                         const struct silofs_iaddr *other)
{
	vaddr_assign(&iaddr->vaddr, &other->vaddr);
	iaddr->ino = other->ino;
}

static ino_t iaddr_ino(const struct silofs_iaddr *iaddr)
{
	return iaddr->ino;
}

static loff_t iaddr_voff(const struct silofs_iaddr *iaddr)
{
	return iaddr->vaddr.off;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ino_set *ino_set_new(struct silofs_alloc *alloc)
{
	struct silofs_ino_set *ino_set;
	const size_t size = sizeof(*ino_set);

	ino_set = silofs_allocate(alloc, size);
	if (ino_set != NULL) {
		silofs_memzero(ino_set, size);
	}
	return ino_set;
}

static void ino_set_del(struct silofs_ino_set *ino_set,
                        struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, ino_set, sizeof(*ino_set));
}

static bool ino_set_isfull(const struct silofs_ino_set *ino_set)
{
	return (ino_set->cnt >= ARRAY_SIZE(ino_set->ino));
}

static void ino_set_append(struct silofs_ino_set *ino_set, ino_t ino)
{
	ino_set->ino[ino_set->cnt++] = ino;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t ite_ino(const struct silofs_itable_entry *ite)
{
	return silofs_ino_to_cpu(ite->ite_ino);
}

static void ite_set_ino(struct silofs_itable_entry *ite, ino_t ino)
{
	ite->ite_ino = silofs_cpu_to_ino(ino);
}

static void ite_vaddr(const struct silofs_itable_entry *ite,
                      struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_parse(&ite->ite_vaddr, out_vaddr);
}

static void ite_set_vaddr(struct silofs_itable_entry *ite,
                          const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&ite->ite_vaddr, vaddr);
}

static bool ite_isfree(const struct silofs_itable_entry *ite)
{
	return ino_isnull(ite_ino(ite));
}

static bool ite_has_ino(const struct silofs_itable_entry *ite, ino_t ino)
{
	return (ite_ino(ite) == ino);
}

static void ite_setup(struct silofs_itable_entry *ite, ino_t ino,
                      const struct silofs_vaddr *vaddr)
{
	ite_set_ino(ite, ino);
	ite_set_vaddr(ite, vaddr);
}

static void ite_reset(struct silofs_itable_entry *ite)
{
	ite_set_ino(ite, SILOFS_INO_NULL);
	ite_set_vaddr(ite, vaddr_none());
}

static void ite_make_iaddr(const struct silofs_itable_entry *ite,
                           struct silofs_iaddr *iaddr)
{
	struct silofs_vaddr vaddr;

	ite_vaddr(ite, &vaddr);
	iaddr_setup(iaddr, ite_ino(ite), &vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void itn_parent(const struct silofs_itable_node *itn,
                       struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_parse(&itn->it_parent, out_vaddr);
}

static void itn_set_parent(struct silofs_itable_node *itn,
                           const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&itn->it_parent, vaddr);
}

static void itn_reset_parent(struct silofs_itable_node *itn)
{
	itn_set_parent(itn, vaddr_none());
}

static size_t itn_depth(const struct silofs_itable_node *itn)
{
	return silofs_le16_to_cpu(itn->it_depth);
}

static void itn_set_depth(struct silofs_itable_node *itn, size_t depth)
{
	itn->it_depth = silofs_cpu_to_le16((uint16_t)depth);
}

static size_t itn_nents(const struct silofs_itable_node *itn)
{
	return silofs_le16_to_cpu(itn->it_nents);
}

static void itn_set_nents(struct silofs_itable_node *itn, size_t nents)
{
	itn->it_nents = silofs_cpu_to_le16((uint16_t)nents);
}

static void itn_inc_nents(struct silofs_itable_node *itn)
{
	itn_set_nents(itn, itn_nents(itn) + 1);
}

static void itn_dec_nents(struct silofs_itable_node *itn)
{
	itn_set_nents(itn, itn_nents(itn) - 1);
}

static size_t itn_nchilds(const struct silofs_itable_node *itn)
{
	return silofs_le16_to_cpu(itn->it_nchilds);
}

static size_t itn_nchilds_max(const struct silofs_itable_node *itn)
{
	return ARRAY_SIZE(itn->it_child);
}

static void itn_set_nchilds(struct silofs_itable_node *itn, size_t nchilds)
{
	itn->it_nchilds = silofs_cpu_to_le16((uint16_t)nchilds);
}

static void itn_inc_nchilds(struct silofs_itable_node *itn)
{
	itn_set_nchilds(itn, itn_nchilds(itn) + 1);
}

static void itn_dec_nchilds(struct silofs_itable_node *itn)
{
	itn_set_nchilds(itn, itn_nchilds(itn) - 1);
}

static void itn_child_at(const struct silofs_itable_node *itn,
                         size_t slot, struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_parse(&itn->it_child[slot], out_vaddr);
}

static void itn_set_child_at(struct silofs_itable_node *itn,
                             size_t slot, const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&itn->it_child[slot], vaddr);
}

static void itn_clear_child_at(struct silofs_itable_node *itn, size_t slot)
{
	itn_set_child_at(itn, slot, vaddr_none());
}

static size_t itn_child_slot(const struct silofs_itable_node *itn, ino_t ino)
{
	size_t slot;
	const size_t depth = itn_depth(itn);
	const size_t shift = depth * SILOFS_ITNODE_SHIFT;

	slot = (ino >> shift) % itn_nchilds_max(itn);
	return slot;
}

static size_t itn_nents_max(const struct silofs_itable_node *itn)
{
	return ARRAY_SIZE(itn->ite);
}

static struct silofs_itable_entry *
itn_entry_at(const struct silofs_itable_node *itn, size_t slot)
{
	const struct silofs_itable_entry *ite = &itn->ite[slot];

	return unconst(ite);
}

static void itn_init(struct silofs_itable_node *itn, size_t depth)
{
	const size_t nents_max = itn_nents_max(itn);
	const size_t nchilds_max = itn_nchilds_max(itn);

	itn_reset_parent(itn);
	itn_set_depth(itn, depth);
	itn_set_nents(itn, 0);
	itn_set_nchilds(itn, 0);

	for (size_t i = 0; i < nents_max; ++i) {
		ite_reset(itn_entry_at(itn, i));
	}
	for (size_t i = 0; i < nchilds_max; ++i) {
		itn_clear_child_at(itn, i);
	}
}

static bool itn_isfull(const struct silofs_itable_node *itn)
{
	return (itn_nents(itn) == itn_nents_max(itn));
}

static bool itn_isempty(const struct silofs_itable_node *itn)
{
	return (itn_nents(itn) == 0);
}

static const struct silofs_itable_entry *
itn_find_next(const struct silofs_itable_node *itn,
              const struct silofs_itable_entry *from)
{
	size_t slot_beg;
	const struct silofs_itable_entry *ite;
	const size_t nents_max = itn_nents_max(itn);

	if (itn_isempty(itn)) {
		return NULL;
	}
	slot_beg = (from != NULL) ? (size_t)(from - itn->ite) : 0;
	for (size_t i = slot_beg; i < nents_max; ++i) {
		ite = itn_entry_at(itn, i);
		if (!ite_isfree(ite)) {
			return ite;
		}
	}
	return NULL;
}

static size_t itn_slot_by_ino(const struct silofs_itable_node *itn, ino_t ino)
{
	return ino % itn_nents_max(itn);
}

static struct silofs_itable_entry *
itn_lookup(const struct silofs_itable_node *itn, ino_t ino)
{
	size_t slot;
	const struct silofs_itable_entry *ite;

	if (itn_isempty(itn)) {
		return NULL;
	}
	slot = itn_slot_by_ino(itn, ino);
	ite = itn_entry_at(itn, slot);
	if (!ite_has_ino(ite, ino)) {
		return NULL;
	}
	return unconst(ite);
}

static struct silofs_itable_entry *
itn_insert(struct silofs_itable_node *itn, ino_t ino,
           const struct silofs_vaddr *vaddr)
{
	size_t slot;
	struct silofs_itable_entry *ite;

	if (itn_isfull(itn)) {
		return NULL;
	}
	slot = itn_slot_by_ino(itn, ino);
	ite = itn_entry_at(itn, slot);
	if (!ite_isfree(ite)) {
		return NULL;
	}
	ite_setup(ite, ino, vaddr);
	itn_inc_nents(itn);
	return ite;
}

static struct silofs_itable_entry *
itn_remove(struct silofs_itable_node *itn, ino_t ino)
{
	struct silofs_itable_entry *ite;

	ite = itn_lookup(itn, ino);
	if (ite == NULL) {
		return ite;
	}
	ite_reset(ite);
	itn_dec_nents(itn);
	return ite;
}

static void itn_set_child(struct silofs_itable_node *itn, ino_t ino,
                          const struct silofs_vaddr *vaddr)
{
	const size_t slot = itn_child_slot(itn, ino);

	itn_set_child_at(itn, slot, vaddr);
	itn_inc_nchilds(itn);
}

static void itn_clear_child(struct silofs_itable_node *itn, ino_t ino)
{
	const size_t slot = itn_child_slot(itn, ino);

	itn_clear_child_at(itn, slot);
	itn_dec_nchilds(itn);
}

static bool itn_isleaf(const struct silofs_itable_node *itn)
{
	return (itn_nchilds(itn) == 0);
}

static bool itn_isroot(const struct silofs_itable_node *itn)
{
	return (itn_depth(itn) == ITROOT_DEPTH);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void itni_incref(struct silofs_itnode_info *itni)
{
	if (itni != NULL) {
		vi_incref(&itni->itn_vi);
	}
}

static void itni_decref(struct silofs_itnode_info *itni)
{
	if (itni != NULL) {
		vi_decref(&itni->itn_vi);
	}
}

static const struct silofs_vaddr *
itni_vaddr(const struct silofs_itnode_info *itni)
{
	return vi_vaddr(&itni->itn_vi);
}

static void itni_dirtify(struct silofs_itnode_info *itni)
{
	vi_dirtify(&itni->itn_vi);
}

static size_t itni_depth(const struct silofs_itnode_info *itni)
{
	return itn_depth(itni->itn);
}

static void itni_setup_parent(struct silofs_itnode_info *child_itni,
                              const struct silofs_itnode_info *parent_itni)
{
	if (parent_itni != NULL) {
		itn_set_parent(child_itni->itn, itni_vaddr(parent_itni));
	} else {
		itn_reset_parent(child_itni->itn);
	}
	itni_dirtify(child_itni);
}

static void itni_setup(struct silofs_itnode_info *itni,
                       const struct silofs_itnode_info *parent_itni)
{
	const size_t depth = (parent_itni != NULL) ?
	                     itni_depth(parent_itni) + 1 : ITROOT_DEPTH;

	itn_init(itni->itn, depth);
	itni_setup_parent(itni, parent_itni);
}

static int itni_check_root(const struct silofs_itnode_info *itni)
{
	return itn_isroot(itni->itn) ? 0 : -SILOFS_EFSCORRUPTED;
}

static void itni_resolve_child_at(const struct silofs_itnode_info *itni,
                                  size_t slot, struct silofs_vaddr *out_vaddr)
{
	itn_child_at(itni->itn, slot, out_vaddr);
}

static void itni_resolve_child(const struct silofs_itnode_info *itni,
                               ino_t ino, struct silofs_vaddr *out_vaddr)
{
	const size_t slot = itn_child_slot(itni->itn, ino);

	itni_resolve_child_at(itni, slot, out_vaddr);
}

static bool itni_has_child(const struct silofs_itnode_info *itni, ino_t ino)
{
	struct silofs_vaddr vaddr;

	itni_resolve_child(itni, ino, &vaddr);
	return !vaddr_isnull(&vaddr);
}

static void itni_bind_child(struct silofs_itnode_info *itni, ino_t ino,
                            struct silofs_itnode_info *child_itni)
{
	itn_set_child(itni->itn, ino, itni_vaddr(child_itni));
	itni_dirtify(itni);
}

static void itni_unbind_child(struct silofs_itnode_info *itni, ino_t ino)
{
	itn_clear_child(itni->itn, ino);
	itni_dirtify(itni);
}

static void itni_fill_ino_set(const struct silofs_itnode_info *itni,
                              struct silofs_ino_set *ino_set)
{
	const struct silofs_itable_entry *ite;

	ino_set->cnt = 0;
	ite = itn_find_next(itni->itn, NULL);
	while (ite != NULL) {
		if (ino_set_isfull(ino_set)) {
			break;
		}
		ino_set_append(ino_set, ite_ino(ite));
		ite = itn_find_next(itni->itn, ite + 1);
	}
}

static int itni_lookup_at(const struct silofs_itnode_info *itni,
                          ino_t ino, struct silofs_iaddr *out_iaddr)
{
	const struct silofs_itable_entry *ite;

	ite = itn_lookup(itni->itn, ino);
	if (ite == NULL) {
		return -ENOENT;
	}
	ite_make_iaddr(ite, out_iaddr);
	return 0;
}

static bool itni_may_prune(const struct silofs_itnode_info *itni)
{
	const struct silofs_itable_node *itn = itni->itn;

	if (!itn_isempty(itn)) {
		return false;
	}
	if (!itn_isleaf(itn)) {
		return false;
	}
	if (itn_isroot(itn)) {
		return false;
	}
	return true;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_itable_info *itbi_of(const struct silofs_sb_info *sbi)
{
	const struct silofs_itable_info *itbi = &sbi->sb_itbi;

	return unconst(itbi);
}

static struct silofs_itable_info *itbi_of2(const struct silofs_task *task)
{
	return itbi_of(task_sbi(task));
}

static const struct silofs_vaddr *
itbi_root(const struct silofs_itable_info *itbi)
{
	return &itbi->it_root_itb;
}

static void itbi_set_root(struct silofs_itable_info *itbi,
                          const struct silofs_vaddr *vaddr)
{
	vaddr_assign(&itbi->it_root_itb, vaddr);
}

static void itbi_init_common(struct silofs_itable_info *itbi)
{
	itbi_set_root(itbi, vaddr_none());
	iaddr_reset(&itbi->it_root_dir);
	itbi->it_apex_ino = SILOFS_INO_ROOT + SILOFS_INO_PSEUDO_MAX;
	itbi->it_ninodes_max = ULONG_MAX / 2;
	itbi->it_ninodes = 0;
}

static void itbi_fini_common(struct silofs_itable_info *itbi)
{
	itbi_set_root(itbi, vaddr_none());
	iaddr_reset(&itbi->it_root_dir);
	itbi->it_apex_ino = 0;
	itbi->it_ninodes_max = 0;
	itbi->it_ninodes = 0;
}

int silofs_itbi_init(struct silofs_itable_info *itbi,
                     struct silofs_alloc *alloc)
{
	itbi_init_common(itbi);
	return silofs_inomap_init(&itbi->it_inomap, alloc);
}

void silofs_itbi_reinit(struct silofs_itable_info *itbi)
{
	itbi_init_common(itbi);
	silofs_inomap_clear(&itbi->it_inomap);
}

void silofs_itbi_fini(struct silofs_itable_info *itbi)
{
	silofs_inomap_fini(&itbi->it_inomap);
	itbi_fini_common(itbi);
}

void silofs_itbi_update_by(struct silofs_itable_info *itbi,
                           const struct silofs_itable_info *itbi_other)
{
	vaddr_assign(&itbi->it_root_itb, &itbi_other->it_root_itb);
	iaddr_assign(&itbi->it_root_dir, &itbi_other->it_root_dir);
	itbi->it_apex_ino = itbi_other->it_apex_ino;
	itbi->it_ninodes = itbi_other->it_ninodes;
	itbi->it_ninodes_max = itbi_other->it_ninodes_max;
}


static int itbi_set_rootdir(struct silofs_itable_info *itbi, ino_t ino,
                            const struct silofs_vaddr *vaddr)
{
	int err = 0;

	if (ino > SILOFS_INO_PSEUDO_MAX) {
		iaddr_setup(&itbi->it_root_dir, ino, vaddr);
	} else {
		log_err("illegal root-ino: ino=%ld off=%ld",
		        ino, vaddr->off);
		err = -EINVAL;
	}
	return err;
}

static int itbi_next_ino(struct silofs_itable_info *itbi, ino_t *out_ino)
{
	if (itbi->it_ninodes >= itbi->it_ninodes_max) {
		return -ENOSPC;
	}
	itbi->it_apex_ino += 1;
	*out_ino = itbi->it_apex_ino;
	return 0;
}

static void itbi_fixup_apex_ino(struct silofs_itable_info *itbi, ino_t ino)
{
	if (itbi->it_apex_ino < ino) {
		itbi->it_apex_ino = ino;
	}
}

static void itbi_inc_ninodes(struct silofs_itable_info *itbi)
{
	itbi->it_ninodes++;
}

static void itbi_dec_ninodes(struct silofs_itable_info *itbi)
{
	itbi->it_ninodes--;
}

static void itbi_parse_inos_of(struct silofs_itable_info *itbi,
                               const struct silofs_itable_node *itn)
{
	ino_t ino;
	const struct silofs_itable_entry *ite;

	ite = itn_find_next(itn, NULL);
	while (ite != NULL) {
		ino = ite_ino(ite);
		itbi_inc_ninodes(itbi);
		itbi_fixup_apex_ino(itbi, ino);
		ite = itn_find_next(itn, ite + 1);
	}
}

static int itbi_lookup_cached(struct silofs_itable_info *itbi, ino_t ino,
                              struct silofs_iaddr *out_iaddr)
{
	loff_t voff;
	int err;

	if (ino_isnull(ino)) {
		return -ENOENT;
	}
	if (ino == itbi->it_root_dir.ino) {
		iaddr_assign(out_iaddr, &itbi->it_root_dir);
		return 0;
	}
	err = silofs_inomap_lookup(&itbi->it_inomap, ino, &voff);
	if (err) {
		return err;
	}
	iaddr_setup2(out_iaddr, ino, voff);
	return 0;
}

static void itbi_update_cache(struct silofs_itable_info *itbi,
                              const struct silofs_iaddr *iaddr)
{
	const ino_t ino = iaddr_ino(iaddr);
	const loff_t voff = iaddr_voff(iaddr);

	silofs_inomap_update(&itbi->it_inomap, ino, voff);
}

static void itbi_remove_cached(struct silofs_itable_info *itbi, ino_t ino)
{
	silofs_inomap_remove(&itbi->it_inomap, ino);
}

static void itbi_drop_cache(struct silofs_itable_info *itbi)
{
	silofs_inomap_clear(&itbi->it_inomap);
}

static int itbi_resolve_real_ino(const struct silofs_itable_info *itbi,
                                 ino_t ino, ino_t *out_ino)
{
	int err = 0;
	const ino_t ino_max = SILOFS_INO_MAX;
	const ino_t ino_root = SILOFS_INO_ROOT;

	if ((ino < ino_root) || (ino > ino_max)) {
		ino = SILOFS_INO_NULL;
		err = -EINVAL;
	} else if (ino == ino_root) {
		ino = itbi->it_root_dir.ino;
		err = unlikely(ino_isnull(ino)) ? -ENOENT : 0;
	}
	*out_ino = ino;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void itc_setup(struct silofs_it_ctx *it_ctx,
                      const struct silofs_task *task)
{
	silofs_memzero(it_ctx, sizeof(*it_ctx));
	it_ctx->task = task;
	it_ctx->sbi = task_sbi(task);
	it_ctx->itbi = itbi_of(it_ctx->sbi);
}

static const struct silofs_vaddr *
itc_treeroot(const struct silofs_it_ctx *it_ctx)
{
	return itbi_root(it_ctx->itbi);
}

static void itc_set_root(struct silofs_it_ctx *it_ctx,
                         const struct silofs_vaddr *vaddr)
{
	itbi_set_root(it_ctx->itbi, vaddr);
}

static void itc_get_root(const struct silofs_it_ctx *it_ctx,
                         struct silofs_vaddr *out_vaddr)
{
	vaddr_assign(out_vaddr, itc_treeroot(it_ctx));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int itc_resolvs_real_ino(const struct silofs_it_ctx *it_ctx,
                                ino_t ino, ino_t *out_ino)
{
	return itbi_resolve_real_ino(it_ctx->itbi, ino, out_ino);
}

static void itc_update_cache(const struct silofs_it_ctx *it_ctx,
                             const struct silofs_iaddr *iaddr)
{
	itbi_update_cache(it_ctx->itbi, iaddr);
}

static void itc_remove_cached(const struct silofs_it_ctx *it_ctx, ino_t ino)
{
	itbi_remove_cached(it_ctx->itbi, ino);
}

static int itc_try_lookup_cached(const struct silofs_it_ctx *it_ctx,
                                 ino_t ino, struct silofs_iaddr *out_iaddr)
{
	return itbi_lookup_cached(it_ctx->itbi, ino, out_iaddr);
}

static void itc_drop_cache(const struct silofs_it_ctx *it_ctx)
{
	itbi_drop_cache(it_ctx->itbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int itc_spawn_itnode(const struct silofs_it_ctx *it_ctx,
                            struct silofs_itnode_info **out_itni)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_itnode_info *itni = NULL;
	int err;

	err = silofs_spawn_vnode(it_ctx->task, SILOFS_STYPE_ITNODE, 0, &vi);
	if (err) {
		return err;
	}
	itni = silofs_itni_from_vi(vi);
	silofs_itni_rebind_view(itni);
	*out_itni = itni;
	return 0;
}

static int itc_spawn_setup_itnode(const struct silofs_it_ctx *it_ctx,
                                  const struct silofs_itnode_info *parent_itni,
                                  struct silofs_itnode_info **out_itni)
{
	int err;

	err = itc_spawn_itnode(it_ctx, out_itni);
	if (err) {
		return err;
	}
	itni_setup(*out_itni, parent_itni);
	return 0;
}

static int itc_remove_itnode(const struct silofs_it_ctx *it_ctx,
                             struct silofs_itnode_info *itni)
{
	return silofs_remove_vnode(it_ctx->task, &itni->itn_vi);
}

static int recheck_itnode(struct silofs_itnode_info *itni)
{
	if (itni->itn_vi.v_recheck) {
		return 0;
	}
	/* TODO: recheck */
	itni->itn_vi.v_recheck = true;
	return 0;
}

static int itc_stage_itnode(const struct silofs_it_ctx *it_ctx,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stage_mode stg_mode,
                            struct silofs_itnode_info **out_itni)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_itnode_info *itni = NULL;
	int err;

	err = silofs_stage_vnode(it_ctx->task, vaddr, stg_mode, 0, &vi);
	if (err) {
		return err;
	}
	itni = silofs_itni_from_vi(vi);

	silofs_itni_rebind_view(itni);
	err = recheck_itnode(itni);
	if (err) {
		return err;
	}
	*out_itni = itni;
	return 0;
}

static int itc_stage_rdonly_itnode(const struct silofs_it_ctx *it_ctx,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_itnode_info **out_itni)
{
	return itc_stage_itnode(it_ctx, vaddr, SILOFS_STAGE_RO, out_itni);
}

static int
itc_stage_child_itnode(const struct silofs_it_ctx *it_ctx,
                       struct silofs_itnode_info *parent_itni,
                       ino_t ino, enum silofs_stage_mode stg_mode,
                       struct silofs_itnode_info **out_itni)
{
	struct silofs_vaddr vaddr;
	int err;

	itni_resolve_child(parent_itni, ino, &vaddr);
	itni_incref(parent_itni);
	err = itc_stage_itnode(it_ctx, &vaddr, stg_mode, out_itni);
	itni_decref(parent_itni);
	return err;
}

static int
itc_stage_mutable_child(const struct silofs_it_ctx *it_ctx,
                        struct silofs_itnode_info *parent_itni,
                        ino_t ino, struct silofs_itnode_info **out_itni)
{
	return itc_stage_child_itnode(it_ctx, parent_itni, ino,
	                              SILOFS_STAGE_RW, out_itni);
}

static int
itc_stage_rdonly_child(const struct silofs_it_ctx *it_ctx,
                       struct silofs_itnode_info *parent_itni,
                       ino_t ino, struct silofs_itnode_info **out_itni)
{
	return itc_stage_child_itnode(it_ctx, parent_itni, ino,
	                              SILOFS_STAGE_RO, out_itni);
}

static int itc_stage_itroot(const struct silofs_it_ctx *it_ctx,
                            enum silofs_stage_mode stg_mode,
                            struct silofs_itnode_info **out_itni)
{
	const struct silofs_vaddr *it_root = itc_treeroot(it_ctx);
	int err;

	err = itc_stage_itnode(it_ctx, it_root, stg_mode, out_itni);
	if (err) {
		return err;
	}
	err = itni_check_root(*out_itni);
	if (err) {
		return err;
	}
	return 0;
}

static int itc_stage_mutable_itroot(const struct silofs_it_ctx *it_ctx,
                                    struct silofs_itnode_info **out_itni)
{
	return itc_stage_itroot(it_ctx, SILOFS_STAGE_RW, out_itni);
}

static int itc_stage_rdonly_itroot(const struct silofs_it_ctx *it_ctx,
                                   struct silofs_itnode_info **out_itni)
{
	return itc_stage_itroot(it_ctx, SILOFS_STAGE_RO, out_itni);
}

static int itc_lookup_iaddr_of(const struct silofs_it_ctx *it_ctx, ino_t ino,
                               struct silofs_iaddr *out_iaddr)
{
	struct silofs_itnode_info *itni = NULL;
	const size_t depth_max = ITNODE_DEPTH_MAX;
	size_t depth = ITROOT_DEPTH;
	int err;

	err = itc_stage_rdonly_itroot(it_ctx, &itni);
	if (err) {
		return err;
	}
	while (depth < depth_max) {
		err = itni_lookup_at(itni, ino, out_iaddr);
		if (!err) {
			return 0;
		}
		err = itc_stage_rdonly_child(it_ctx, itni, ino, &itni);
		if (err) {
			return err;
		}
		depth++;
	}
	return -ENOENT;
}

static int itc_create_child(const struct silofs_it_ctx *it_ctx,
                            struct silofs_itnode_info *parent_itni, ino_t ino,
                            struct silofs_itnode_info **out_child_itni)
{
	const size_t depth_max = ITNODE_DEPTH_MAX;
	size_t depth;
	int err;

	depth = itni_depth(parent_itni);
	if (depth >= depth_max) {
		return -ENOSPC;
	}
	err = itc_spawn_setup_itnode(it_ctx, parent_itni, out_child_itni);
	if (err) {
		return err;
	}
	itni_bind_child(parent_itni, ino, *out_child_itni);
	return 0;
}

static int itc_require_child(const struct silofs_it_ctx *it_ctx,
                             struct silofs_itnode_info *itni, ino_t ino,
                             struct silofs_itnode_info **out_itni)
{
	int err;

	itni_incref(itni);
	if (itni_has_child(itni, ino)) {
		err = itc_stage_mutable_child(it_ctx, itni, ino, out_itni);
	} else {
		err = itc_create_child(it_ctx, itni, ino, out_itni);
	}
	itni_decref(itni);
	return err;
}

static int itc_try_insert_at(const struct silofs_it_ctx *it_ctx,
                             struct silofs_itnode_info *itni,
                             const struct silofs_iaddr *iaddr)
{
	struct silofs_itable_info *itbi = it_ctx->itbi;
	struct silofs_itable_entry *ite = NULL;
	const ino_t ino = iaddr->ino;

	ite = itn_insert(itni->itn, iaddr->ino, &iaddr->vaddr);
	if (ite == NULL) {
		return -ENOSPC;
	}
	itbi_inc_ninodes(itbi);
	itbi_fixup_apex_ino(itbi, ino);
	itni_dirtify(itni);
	return 0;
}

static int itc_insert_iref(const struct silofs_it_ctx *it_ctx,
                           const struct silofs_iaddr *iaddr)
{
	struct silofs_itnode_info *itni = NULL;
	const size_t depth_max = ITNODE_DEPTH_MAX;
	size_t depth = ITROOT_DEPTH;
	int err;

	err = itc_stage_mutable_itroot(it_ctx, &itni);
	if (err) {
		return err;
	}
	while (depth < depth_max) {
		err = itc_try_insert_at(it_ctx, itni, iaddr);
		if (!err) {
			return 0;
		}
		err = itc_require_child(it_ctx, itni, iaddr->ino, &itni);
		if (err) {
			return err;
		}
		depth++;
	}
	return -ENOSPC;
}

static int itc_try_remove_at(const struct silofs_it_ctx *it_ctx,
                             struct silofs_itnode_info *itni, ino_t ino)
{
	struct silofs_itable_entry *ite;

	ite = itn_remove(itni->itn, ino);
	if (ite == NULL) {
		return -ENOENT;
	}
	itbi_dec_ninodes(it_ctx->itbi);
	itni_dirtify(itni);
	return 0;
}

static int itc_prune_leaf(const struct silofs_it_ctx *it_ctx,
                          struct silofs_itnode_info *parent_itni,
                          struct silofs_itnode_info *child_itni, ino_t ino)
{
	int err;

	err = itc_remove_itnode(it_ctx, child_itni);
	if (err) {
		return err;
	}
	itni_unbind_child(parent_itni, ino);
	return 0;
}

static int itc_remove_itentry2(const struct silofs_it_ctx *it_ctx, ino_t ino)
{
	struct silofs_itnode_info *tpath[ITNODE_DEPTH_MAX + 1];
	struct silofs_itnode_info *itni = NULL;
	const size_t depth_min = ITROOT_DEPTH;
	const size_t depth_max = ITNODE_DEPTH_MAX;
	size_t depth = ITROOT_DEPTH;
	int err;

	silofs_memzero(tpath, sizeof(tpath));
	err = itc_stage_mutable_itroot(it_ctx, &itni);
	if (err) {
		return err;
	}
	while (depth < depth_max) {
		tpath[depth++] = itni;
		err = itc_try_remove_at(it_ctx, itni, ino);
		if (!err) {
			break;
		}
		err = itc_stage_mutable_child(it_ctx, itni, ino, &itni);
		if (err) {
			break;
		}
		err = -ENOENT;
	}
	if (err) {
		return err;
	}
	while (depth > depth_min) {
		itni = tpath[--depth];
		if (!itni_may_prune(itni)) {
			break;
		}
		err = itc_prune_leaf(it_ctx, tpath[depth - 1], itni, ino);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int itc_next_iaddr_for(const struct silofs_it_ctx *it_ctx,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_iaddr *out_iaddr)
{
	ino_t ino;
	int err;

	iaddr_reset(out_iaddr);
	err = itbi_next_ino(it_ctx->itbi, &ino);
	if (err) {
		return err;
	}
	iaddr_setup(out_iaddr, ino, vaddr);
	return 0;
}

int silofs_acquire_ino(const struct silofs_task *task,
                       const struct silofs_vaddr *vaddr,
                       struct silofs_iaddr *out_iaddr)
{
	struct silofs_it_ctx it_ctx;
	struct silofs_iaddr iaddr;
	int err;

	itc_setup(&it_ctx, task);
	err = itc_next_iaddr_for(&it_ctx, vaddr, &iaddr);
	if (err) {
		return err;
	}
	err = itc_insert_iref(&it_ctx, &iaddr);
	if (err) {
		return err;
	}
	itc_update_cache(&it_ctx, &iaddr);
	iaddr_assign(out_iaddr, &iaddr);
	return 0;
}

int silofs_discard_ino(const struct silofs_task *task, ino_t xino)
{
	struct silofs_it_ctx it_ctx;
	ino_t ino;
	int err;

	itc_setup(&it_ctx, task);
	err = itc_resolvs_real_ino(&it_ctx, xino, &ino);
	if (err) {
		return err;
	}
	err = itc_remove_itentry2(&it_ctx, ino);
	if (err) {
		return err;
	}
	itc_remove_cached(&it_ctx, ino);
	return 0;
}

int silofs_resolve_iaddr(const struct silofs_task *task, ino_t xino,
                         struct silofs_iaddr *out_iaddr)
{
	struct silofs_it_ctx it_ctx;
	ino_t ino;
	int err;

	itc_setup(&it_ctx, task);
	err = itc_resolvs_real_ino(&it_ctx, xino, &ino);
	if (err) {
		return err;
	}
	err = itc_try_lookup_cached(&it_ctx, ino, out_iaddr);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = itc_lookup_iaddr_of(&it_ctx, ino, out_iaddr);
	if (err) {
		return err;
	}
	itc_update_cache(&it_ctx, out_iaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int itc_scan_subtree(const struct silofs_it_ctx *it_ctx,
                            struct silofs_itnode_info *itni);

int silofs_format_itable_root(const struct silofs_task *task,
                              struct silofs_vaddr *out_vaddr)
{
	struct silofs_it_ctx it_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.itbi = itbi_of2(task),
	};
	struct silofs_itnode_info *itni = NULL;
	int err;

	err = itc_spawn_setup_itnode(&it_ctx, NULL, &itni);
	if (err) {
		return err;
	}
	itc_set_root(&it_ctx, itni_vaddr(itni));
	itc_get_root(&it_ctx, out_vaddr);
	return 0;
}

static int itc_reload_itable_root(const struct silofs_it_ctx *it_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_itnode_info *root_itni = NULL;
	int err;

	err = itc_stage_rdonly_itnode(it_ctx, vaddr, &root_itni);
	if (err) {
		return err;
	}
	if (!itn_isroot(root_itni->itn)) {
		return -ENOENT;
	}
	vaddr_assign(&it_ctx->itbi->it_root_itb, vaddr);
	return 0;
}

static void itc_scan_entries_of(const struct silofs_it_ctx *it_ctx,
                                const struct silofs_itnode_info *itni)
{
	itbi_parse_inos_of(it_ctx->itbi, itni->itn);
}

static int itc_scan_subtree_at(const struct silofs_it_ctx *it_ctx,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_itnode_info *itni = NULL;
	int err;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = itc_stage_rdonly_itnode(it_ctx, vaddr, &itni);
	if (err) {
		return err;
	}
	err = itc_scan_subtree(it_ctx, itni);
	if (err) {
		return err;
	}
	return 0;
}

static int itc_scan_subtree(const struct silofs_it_ctx *it_ctx,
                            struct silofs_itnode_info *itni)
{
	struct silofs_vaddr vaddr;
	const size_t nchilds = itn_nchilds(itni->itn);
	const size_t nchilds_max = itn_nchilds_max(itni->itn);
	int ret = 0;

	itc_scan_entries_of(it_ctx, itni);
	if (!nchilds) {
		return 0;
	}
	itni_incref(itni);
	for (size_t i = 0; i < nchilds_max; ++i) {
		itni_resolve_child_at(itni, i, &vaddr);
		ret = itc_scan_subtree_at(it_ctx, &vaddr);
		if (ret) {
			break;
		}
	}
	itni_decref(itni);
	return ret;
}

static int itc_parse_itable_top(const struct silofs_it_ctx *it_ctx,
                                struct silofs_ino_set *ino_set)
{
	struct silofs_itnode_info *itni = NULL;
	int err;

	err = itc_stage_rdonly_itnode(it_ctx, itc_treeroot(it_ctx), &itni);
	if (err) {
		return err;
	}
	itni_fill_ino_set(itni, ino_set);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int itc_stage_rdonly_inode(const struct silofs_it_ctx *it_ctx,
                                  ino_t ino, struct silofs_inode_info **out_ii)
{
	return silofs_stage_inode(it_ctx->task, ino, SILOFS_STAGE_RO, out_ii);
}

static int itc_scan_stage_root_inode_by(const struct silofs_it_ctx *it_ctx,
                                        const struct silofs_ino_set *ino_set,
                                        struct silofs_inode_info **out_root_ii)
{
	struct silofs_inode_info *ii = NULL;
	ino_t ino;
	int err;

	for (size_t i = 0; i < ino_set->cnt; ++i) {
		ino = ino_set->ino[i];
		err = itc_stage_rdonly_inode(it_ctx, ino, &ii);
		if (err) {
			return err;
		}
		if (silofs_is_rootdir(ii)) {
			*out_root_ii = ii;
			return 0;
		}
	}
	return -ENOENT;
}

static int itc_scan_stage_root_inode(const struct silofs_it_ctx *it_ctx,
                                     struct silofs_inode_info **out_root_ii)
{
	struct silofs_alloc *alloc = sbi_alloc(it_ctx->sbi);
	struct silofs_ino_set *ino_set;
	int ret = 0;

	ino_set = ino_set_new(alloc);
	if (ino_set == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	ret = itc_parse_itable_top(it_ctx, ino_set);
	if (ret) {
		goto out;
	}
	ret = itc_scan_stage_root_inode_by(it_ctx, ino_set, out_root_ii);
	if (ret) {
		goto out;
	}
out:
	ino_set_del(ino_set, alloc);
	return ret;
}

static int itc_reload_scan_itable(const struct silofs_it_ctx *it_ctx,
                                  const struct silofs_vaddr *vaddr)
{
	struct silofs_itnode_info *itni = NULL;
	int err;

	err = itc_reload_itable_root(it_ctx, vaddr);
	if (err) {
		return err;
	}
	err = itc_stage_rdonly_itroot(it_ctx, &itni);
	if (err) {
		return err;
	}
	err = itc_scan_subtree(it_ctx, itni);
	if (err) {
		return err;
	}
	return 0;
}

static int itc_bind_rootdir(const struct silofs_it_ctx *it_ctx,
                            const struct silofs_inode_info *ii)
{
	struct silofs_itable_info *itbi = it_ctx->itbi;
	const ino_t ino = ii_ino(ii);
	int err;

	err = itbi_set_rootdir(itbi, ino, ii_vaddr(ii));
	if (!err) {
		itbi_fixup_apex_ino(itbi, ino);
	}
	return err;
}

int silofs_bind_rootdir_to(const struct silofs_task *task,
                           const struct silofs_inode_info *ii)
{
	struct silofs_it_ctx it_ctx;

	itc_setup(&it_ctx, task);
	return itc_bind_rootdir(&it_ctx, ii);
}

int silofs_reload_itable_at(const struct silofs_task *task,
                            const struct silofs_vaddr *vaddr)
{
	struct silofs_it_ctx it_ctx;
	struct silofs_inode_info *root_ii = NULL;
	int err;

	itc_setup(&it_ctx, task);
	err = itc_reload_scan_itable(&it_ctx, vaddr);
	if (err) {
		return err;
	}
	err = itc_scan_stage_root_inode(&it_ctx, &root_ii);
	if (err) {
		return err;
	}
	err = itc_bind_rootdir(&it_ctx, root_ii);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_drop_itable_cache(const struct silofs_task *task)
{
	struct silofs_it_ctx it_ctx;

	itc_setup(&it_ctx, task);
	itc_drop_cache(&it_ctx);
}

void silofs_relax_inomap_of(struct silofs_sb_info *sbi, int flags)
{
	silofs_inomap_relax(&sbi->sb_itbi.it_inomap, flags);
}

void silofs_relax_inomap(const struct silofs_task *task, int flags)
{
	struct silofs_it_ctx it_ctx;

	itc_setup(&it_ctx, task);
	silofs_inomap_relax(&it_ctx.itbi->it_inomap, flags);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_itable_entry(const struct silofs_itable_entry *ite)
{
	struct silofs_vaddr vaddr;
	ino_t ino;
	int err;

	ite_vaddr(ite, &vaddr);
	err = silofs_verify_off(vaddr.off);
	if (err) {
		return err;
	}
	if (stype_isnone(vaddr.stype)) {
		ino = ite_ino(ite);
		if (!ino_isnull(ino)) {
			return -SILOFS_EFSCORRUPTED;
		}
	} else {
		if (!stype_isinode(vaddr.stype)) {
			return -SILOFS_EFSCORRUPTED;
		}
	}
	return 0;
}

static int verify_count(size_t count, size_t expected)
{
	return (count == expected) ? 0 : -SILOFS_EFSCORRUPTED;
}

static int verify_itnode_entries(const struct silofs_itable_node *itn)
{
	int err;
	ino_t ino;
	size_t count = 0;
	const struct silofs_itable_entry *ite;
	const size_t nents_max = itn_nents_max(itn);

	for (size_t i = 0; (i < nents_max); ++i) {
		ite = itn_entry_at(itn, i);
		err = verify_itable_entry(ite);
		if (err) {
			return err;
		}
		ino = ite_ino(ite);
		if (!ino_isnull(ino)) {
			count++;
		}
	}
	return verify_count(count, itn_nents(itn));
}

static int verify_itnode_childs(const struct silofs_itable_node *itn)
{
	struct silofs_vaddr vaddr;
	const size_t nchilds_max = itn_nchilds_max(itn);
	size_t nchilds = 0;
	int err;

	for (size_t slot = 0; slot < nchilds_max; ++slot) {
		itn_child_at(itn, slot, &vaddr);
		if (vaddr_isnull(&vaddr)) {
			continue;
		}
		err = silofs_verify_off(vaddr.off);
		if (err) {
			return err;
		}
		if (!stype_isequal(vaddr.stype, SILOFS_STYPE_ITNODE)) {
			return -SILOFS_EFSCORRUPTED;
		}
		nchilds++;
	}
	return verify_count(nchilds, itn_nchilds(itn));
}

static int verify_itnode_parent(const struct silofs_itable_node *itn)
{
	struct silofs_vaddr vaddr;
	int err;

	itn_parent(itn, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return 0;
	}
	err = silofs_verify_off(vaddr.off);
	if (err) {
		return err;
	}
	if (!stype_isequal(vaddr.stype, SILOFS_STYPE_ITNODE)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_itable_node(const struct silofs_itable_node *itn)
{
	int err;

	err = verify_itnode_parent(itn);
	if (err) {
		return err;
	}
	err = verify_itnode_entries(itn);
	if (err) {
		return err;
	}
	err = verify_itnode_childs(itn);
	if (err) {
		return err;
	}
	return 0;
}
