/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/infra.h>
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/private.h>



/* single entry of free vspace */
struct silofs_spa_entry {
	struct silofs_avl_node  spe_an;
	loff_t                  spe_voff;
	size_t                  spe_len;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long voff_compare(const void *x, const void *y)
{
	const loff_t *voff_x = x;
	const loff_t *voff_y = y;

	return *voff_y - *voff_x;
}

static struct silofs_spa_entry *
avl_node_to_spe(const struct silofs_avl_node *an)
{
	const struct silofs_spa_entry *spe = NULL;

	if (an != NULL) {
		spe = container_of2(an, struct silofs_spa_entry, spe_an);
	}
	return unconst(spe);
}

static const void *spe_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_spa_entry *spe = avl_node_to_spe(an);

	return &spe->spe_voff;
}

static void spe_init(struct silofs_spa_entry *spe, loff_t voff, size_t len)
{
	silofs_avl_node_init(&spe->spe_an);
	spe->spe_voff = voff;
	spe->spe_len = len;
}

static void spe_fini(struct silofs_spa_entry *spe)
{
	silofs_avl_node_fini(&spe->spe_an);
	spe->spe_voff = SILOFS_OFF_NULL;
	spe->spe_len = 0;
}

static loff_t spe_end(const struct silofs_spa_entry *spe)
{
	return off_end(spe->spe_voff, spe->spe_len);
}

static void spe_chop_head(struct silofs_spa_entry *spe, size_t len)
{
	silofs_assert_lt(len, spe->spe_len);

	spe->spe_voff = off_end(spe->spe_voff, len);
	spe->spe_len -= len;
}

static struct silofs_spa_entry *
spe_new(loff_t voff, size_t len, struct silofs_alloc_if *alif)
{
	struct silofs_spa_entry *spe;

	spe = silofs_allocate(alif, sizeof(*spe));
	if (spe != NULL) {
		spe_init(spe, voff, len);
	}
	return spe;
}

static void spe_del(struct silofs_spa_entry *spe,
                    struct silofs_alloc_if *alif)
{
	spe_fini(spe);
	silofs_deallocate(alif, spe, sizeof(*spe));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static unsigned int spamap_capacity(enum silofs_stype stype)
{
	const uint32_t mega = SILOFS_MEGA;
	const uint32_t nmul = stype_isdata(stype) ? 8 : 2;

	return (nmul * mega) / sizeof(struct silofs_spa_entry);
}

static struct silofs_spa_entry *
spamap_new_spe(struct silofs_spamap *spm, loff_t voff, size_t len)
{
	struct silofs_spa_entry *spe;

	spe = spe_new(voff, len, spm->spm_alif);
	return spe;
}

static void spamap_delete_spe(struct silofs_spamap *spm,
                              struct silofs_spa_entry *spe)
{
	spe_del(spe, spm->spm_alif);
}

static struct silofs_spa_entry *
spamap_minimal_spe(const struct silofs_spamap *spm)
{
	struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spm->spm_avl;

	if (avl->size > 0) {
		an = silofs_avl_begin(avl);
	}
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spamap_maximal_spe(const struct silofs_spamap *spm)
{
	struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spm->spm_avl;

	if (avl->size > 0) {
		an = silofs_avl_rbegin(avl);
	}
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spmap_lower_bound_spe(const struct silofs_spamap *spm, loff_t off)
{
	const struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spm->spm_avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spmap_prev_of(const struct silofs_spamap *spm,
              const struct silofs_spa_entry *spe)
{
	struct silofs_spa_entry *spe_prev = NULL;
	const struct silofs_avl_node *an_prev = NULL;
	const struct silofs_avl *avl = &spm->spm_avl;

	an_prev = silofs_avl_prev(avl, &spe->spe_an);
	if (an_prev != silofs_avl_end(avl)) {
		spe_prev = avl_node_to_spe(an_prev);
	}
	return spe_prev;
}

static void
spmap_find_next_prev(const struct silofs_spamap *spm, loff_t off,
                     struct silofs_spa_entry **out_spe_prev,
                     struct silofs_spa_entry **out_spe_next)
{
	struct silofs_spa_entry *spe_next = NULL;
	struct silofs_spa_entry *spe_prev = NULL;

	spe_next = spmap_lower_bound_spe(spm, off);
	if (spe_next != NULL) {
		silofs_assert_gt(spe_next->spe_voff, off);
		spe_prev = spmap_prev_of(spm, spe_next);
	} else {
		spe_prev = spamap_maximal_spe(spm);
	}
	if (spe_prev != NULL) {
		silofs_assert_lt(spe_prev->spe_voff, off);
	}
	*out_spe_prev = spe_prev;
	*out_spe_next = spe_next;
}

static void spamap_insert_spe(struct silofs_spamap *spm,
                              struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spm->spm_avl;

	silofs_avl_insert(avl, an);
}

static void spamap_remove_spe(struct silofs_spamap *spm,
                              struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spm->spm_avl;

	silofs_avl_remove(avl, an);
}

static void spamap_evict_spe(struct silofs_spamap *spm,
                             struct silofs_spa_entry *spe)
{
	spamap_remove_spe(spm, spe);
	spamap_delete_spe(spm, spe);
}

static int spamap_check_cap_add(const struct silofs_spamap *spm)
{
	return (spm->spm_avl.size < spm->spm_cap) ? 0 : -ENOMEM;
}

static int spamap_pop_vspace(struct silofs_spamap *spm,
                             struct silofs_vaddr *out_vaddr)
{
	struct silofs_spa_entry *spe;

	spe = spamap_minimal_spe(spm);
	if (spe == NULL) {
		return -ENOSPC;
	}
	vaddr_setup(out_vaddr, spm->spm_stype, spe->spe_voff);
	if (out_vaddr->len < spe->spe_len) {
		/* its ok to modify in-place and avoid the costly remove-insert
		 * into the tree, as this is already the minimal element */
		spe_chop_head(spe, out_vaddr->len);
	} else {
		spamap_evict_spe(spm, spe);
	}
	return 0;
}

static int spamap_merge_vspace(struct silofs_spamap *spm,
                               const struct silofs_vaddr *vaddr)
{
	int ret;
	loff_t off;
	loff_t end;
	struct silofs_spa_entry *spe = NULL;
	struct silofs_spa_entry *spe_prev = NULL;
	struct silofs_spa_entry *spe_next = NULL;

	ret = -ENOENT;
	off = vaddr_off(vaddr);
	end = off_end(off, vaddr->len);
	spmap_find_next_prev(spm, off, &spe_prev, &spe_next);

	if (spe_prev && (spe_end(spe_prev) == off)) {
		/* merge range into prev */
		spe = spe_prev;
		spe->spe_len += vaddr->len;
		off = spe->spe_voff;
		end = spe_end(spe);
		ret = 0;
	}
	if (spe_next == NULL) {
		/* no next to append with */
		return ret;
	}
	if (end != spe_next->spe_voff) {
		/* can not merge with next */
		return ret;
	}
	end = spe_end(spe_next);
	if (spe == NULL) {
		/* merge with next only */
		spamap_evict_spe(spm, spe_next);
		spe = spamap_new_spe(spm, off, off_ulen(off, end));
		if (spe == NULL) {
			return -ENOMEM;
		}
		spamap_insert_spe(spm, spe);
	} else {
		/* full merge (prev + next ) */
		spe->spe_len += spe_next->spe_len;
		spamap_evict_spe(spm, spe_next);
	}
	return 0;
}

static int spamap_insert_vspace(struct silofs_spamap *spm,
                                const struct silofs_vaddr *vaddr)
{
	loff_t voff;
	struct silofs_spa_entry *spe;
	struct silofs_spa_entry *spe_max = NULL;

	voff = vaddr_off(vaddr);
	spe = spamap_new_spe(spm, voff, vaddr->len);
	if (spe != NULL) {
		goto out_ok; /* trivial case */
	}
	spe_max = spamap_maximal_spe(spm);
	if (spe_max == NULL) {
		return -ENOMEM;
	}
	if (voff > spe_max->spe_voff) {
		return -ENOMEM;
	}
	spamap_delete_spe(spm, spe_max);
	spe = spamap_new_spe(spm, voff, vaddr->len);
	if (spe == NULL) {
		return -ENOMEM;
	}
out_ok:
	spamap_insert_spe(spm, spe);
	return 0;
}

static int spamap_add_vspace(struct silofs_spamap *spm,
                             const struct silofs_vaddr *vaddr)
{
	int err;

	err = spamap_merge_vspace(spm, vaddr);
	if (err != -ENOENT) {
		return err;
	}
	err = spamap_check_cap_add(spm);
	if (err) {
		return err;
	}
	err = spamap_insert_vspace(spm, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static void spamap_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_spamap *spm = p;
	struct silofs_spa_entry *spe = avl_node_to_spe(an);

	spamap_delete_spe(spm, spe);
}

static void spamap_clear(struct silofs_spamap *spm)
{
	const struct silofs_avl_node_functor fn = {
		.fn = spamap_avl_node_delete_cb,
		.ctx = spm
	};

	silofs_avl_clear(&spm->spm_avl, &fn);
}

static void spamap_init(struct silofs_spamap *spm, enum silofs_stype stype,
                        struct silofs_alloc_if *alif)
{
	silofs_avl_init(&spm->spm_avl, spe_getkey, voff_compare, spm);
	spm->spm_alif = alif;
	spm->spm_cap = spamap_capacity(stype);
	spm->spm_stype = stype;
}

static void spamap_fini(struct silofs_spamap *spm)
{
	silofs_avl_fini(&spm->spm_avl);
	spm->spm_alif = NULL;
	spm->spm_cap = 0;
	spm->spm_stype = SILOFS_STYPE_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spamap *
spvmap_sub_map(struct silofs_spvmap *spvm, enum silofs_stype stype)
{
	struct silofs_spamap *spm;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		spm = &spvm->spv_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		spm = &spvm->spv_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		spm = &spvm->spv_databk;
		break;
	case SILOFS_STYPE_ITNODE:
		spm = &spvm->spv_itnode;
		break;
	case SILOFS_STYPE_INODE:
		spm = &spvm->spv_inode;
		break;
	case SILOFS_STYPE_XANODE:
		spm = &spvm->spv_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		spm = &spvm->spv_dtnode;
		break;
	case SILOFS_STYPE_FTNODE:
		spm = &spvm->spv_ftnode;
		break;
	case SILOFS_STYPE_SYMVAL:
		spm = &spvm->spv_symval;
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		spm = NULL;
		break;
	}
	return spm;
}

int silofs_spvmap_store(struct silofs_spvmap *spvm,
                        const struct silofs_vaddr *vaddr)
{
	int err = -EINVAL;
	struct silofs_spamap *spm;

	spm = spvmap_sub_map(spvm, vaddr_stype(vaddr));
	if (spm != NULL) {
		err = spamap_add_vspace(spm, vaddr);
	}
	return err;
}

int silofs_spvmap_trypop(struct silofs_spvmap *spvm, enum silofs_stype stype,
                         struct silofs_vaddr *out_vaddr)
{
	int err = -EINVAL;
	struct silofs_spamap *spm;

	spm = spvmap_sub_map(spvm, stype);
	if (spm != NULL) {
		err = spamap_pop_vspace(spm, out_vaddr);
	}
	return err;
}

void silofs_spvmap_drop(struct silofs_spvmap *spvm)
{
	struct silofs_spamap *spm = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		spm = spvmap_sub_map(spvm, stype);
		if (spm != NULL) {
			spamap_clear(spm);
		}
	}
}

int silofs_spvmap_init(struct silofs_spvmap *spvm,
                       struct silofs_alloc_if *alif)
{
	struct silofs_spamap *spm = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		spm = spvmap_sub_map(spvm, stype);
		if (spm != NULL) {
			spamap_init(spm, stype, alif);
		}
	}
	return 0;
}

void silofs_spvmap_fini(struct silofs_spvmap *spvm)
{
	struct silofs_spamap *spm = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		spm = spvmap_sub_map(spvm, stype);
		if (spm != NULL) {
			spamap_clear(spm);
			spamap_fini(spm);
		}
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint32_t jenkins_hash(uint32_t a)
{
	a = (a + 0x7ed55d16) + (a << 12);
	a = (a ^ 0xc761c23c) ^ (a >> 19);
	a = (a + 0x165667b1) + (a << 5);
	a = (a + 0xd3a2646c) ^ (a << 9);
	a = (a + 0xfd7046c5) + (a << 3);
	a = (a ^ 0xb55a4f09) ^ (a >> 16);
	return a;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *
ui_from_vom_lh(const struct silofs_list_head *lh)
{
	const struct silofs_unode_info *ui = NULL;

	ui = container_of2(lh, struct silofs_unode_info, u_sptm_lh);
	return unconst(ui);
}

int silofs_sptmap_init(struct silofs_sptmap *sptm,
                       struct silofs_alloc_if *alif)
{
	const unsigned int cap = 1021;

	sptm->spt_htbl_sz = 0;
	sptm->spt_htbl_cap = 0;
	sptm->spt_htbl = silofs_lista_new(alif, cap);
	if (sptm->spt_htbl == NULL) {
		return -ENOMEM;
	}
	sptm->spt_htbl_cap = cap;
	return 0;
}

void silofs_sptmap_fini(struct silofs_sptmap *sptm,
                        struct silofs_alloc_if *alif)
{
	if (sptm->spt_htbl != NULL) {
		silofs_lista_del(sptm->spt_htbl, sptm->spt_htbl_cap, alif);
		sptm->spt_htbl_cap = 0;
		sptm->spt_htbl_sz = 0;
	}
}

static size_t sptmap_slot_of(const struct silofs_sptmap *sptm,
                             const struct silofs_taddr *taddr)
{
	uint64_t key;
	const uint64_t uoff = (uint64_t)taddr->voff;
	const uint64_t hash = uoff ^ silofs_metaid_hkey(&taddr->tree_id);

	key = (uint64_t)taddr->height;
	key |= jenkins_hash((uint32_t)hash);
	key ^= ~jenkins_hash((uint32_t)(hash >> 32));

	return key % sptm->spt_htbl_cap;
}

static struct silofs_list_head *
sptmap_lst_by(const struct silofs_sptmap *sptm,
              const struct silofs_taddr *taddr)
{
	const size_t slot = sptmap_slot_of(sptm, taddr);
	const struct silofs_list_head *lh = NULL;

	lh = &sptm->spt_htbl[slot];
	return silofs_unconst(lh);
}

void silofs_sptmap_insert(struct silofs_sptmap *sptm,
                          struct silofs_unode_info *ui)
{
	struct silofs_list_head *lst;

	silofs_assert(!off_isnull(ui->u_taddr.voff));
	if (!ui->u_tmapped) {
		lst = sptmap_lst_by(sptm, &ui->u_taddr);
		list_push_front(lst, &ui->u_sptm_lh);
		ui->u_tmapped = true;
		sptm->spt_htbl_sz++;
	}
}

void silofs_sptmap_remove(struct silofs_sptmap *sptm,
                          struct silofs_unode_info *ui)
{
	if (ui->u_tmapped) {
		silofs_assert_gt(sptm->spt_htbl_sz, 0);
		list_head_remove(&ui->u_sptm_lh);
		ui->u_tmapped = false;
		sptm->spt_htbl_sz--;
	}
}

static bool ui_has_taddr(const struct silofs_unode_info *ui,
                         const struct silofs_taddr *taddr)
{
	return silofs_taddr_isequal(&ui->u_taddr, taddr);
}

struct silofs_unode_info *
silofs_sptmap_lookup(const struct silofs_sptmap *sptm,
                     const struct silofs_taddr *taddr)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_unode_info *ui;

	lst = sptmap_lst_by(sptm, taddr);
	itr = lst->next;
	while (itr != lst) {
		ui = ui_from_vom_lh(itr);
		if (ui_has_taddr(ui, taddr)) {
			return unconst(ui);
		}
		itr = itr->next;
	}
	return NULL;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc_if *alif, size_t nelems)
{
	struct silofs_list_head *lista;

	lista = silofs_allocate(alif, sizeof(*lista) * nelems);
	if (lista != NULL) {
		list_head_initn(lista, nelems);
	}
	return lista;
}

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc_if *alif)
{
	list_head_finin(lista, nelems);
	silofs_deallocate(alif, lista, sizeof(*lista) * nelems);
}



