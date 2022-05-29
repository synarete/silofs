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
spe_new(loff_t voff, size_t len, struct silofs_alloc *alloc)
{
	struct silofs_spa_entry *spe;

	spe = silofs_allocate(alloc, sizeof(*spe));
	if (spe != NULL) {
		spe_init(spe, voff, len);
	}
	return spe;
}

static void spe_del(struct silofs_spa_entry *spe,
                    struct silofs_alloc *alloc)
{
	spe_fini(spe);
	silofs_deallocate(alloc, spe, sizeof(*spe));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static unsigned int spamap_capacity(enum silofs_stype stype)
{
	const uint32_t mega = SILOFS_MEGA;
	const uint32_t nmul = stype_isdata(stype) ? 16 : 4;

	return (nmul * mega);
}

static struct silofs_spa_entry *
spamap_new_spe(struct silofs_spamap *spa, loff_t voff, size_t len)
{
	struct silofs_spa_entry *spe;

	spe = spe_new(voff, len, spa->spa_alloc);
	return spe;
}

static void spamap_delete_spe(struct silofs_spamap *spa,
                              struct silofs_spa_entry *spe)
{
	spe_del(spe, spa->spa_alloc);
}

static struct silofs_spa_entry *
spamap_minimal_spe(const struct silofs_spamap *spa)
{
	struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	if (avl->size > 0) {
		an = silofs_avl_begin(avl);
	}
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spamap_maximal_spe(const struct silofs_spamap *spa)
{
	struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	if (avl->size > 0) {
		an = silofs_avl_rbegin(avl);
	}
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spmap_lower_bound_spe(const struct silofs_spamap *spa, loff_t off)
{
	const struct silofs_avl_node *an = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_spe(an);
}

static struct silofs_spa_entry *
spmap_prev_of(const struct silofs_spamap *spa,
              const struct silofs_spa_entry *spe)
{
	struct silofs_spa_entry *spe_prev = NULL;
	const struct silofs_avl_node *an_prev = NULL;
	const struct silofs_avl *avl = &spa->spa_avl;

	an_prev = silofs_avl_prev(avl, &spe->spe_an);
	if (an_prev != silofs_avl_end(avl)) {
		spe_prev = avl_node_to_spe(an_prev);
	}
	return spe_prev;
}

static void
spmap_find_next_prev(const struct silofs_spamap *spa, loff_t off,
                     struct silofs_spa_entry **out_spe_prev,
                     struct silofs_spa_entry **out_spe_next)
{
	struct silofs_spa_entry *spe_next = NULL;
	struct silofs_spa_entry *spe_prev = NULL;

	spe_next = spmap_lower_bound_spe(spa, off);
	if (spe_next != NULL) {
		silofs_assert_gt(spe_next->spe_voff, off);
		spe_prev = spmap_prev_of(spa, spe_next);
	} else {
		spe_prev = spamap_maximal_spe(spa);
	}
	if (spe_prev != NULL) {
		silofs_assert_lt(spe_prev->spe_voff, off);
	}
	*out_spe_prev = spe_prev;
	*out_spe_next = spe_next;
}

static void spamap_insert_spe(struct silofs_spamap *spa,
                              struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spa->spa_avl;

	silofs_avl_insert(avl, an);
}

static void spamap_remove_spe(struct silofs_spamap *spa,
                              struct silofs_spa_entry *spe)
{
	struct silofs_avl_node *an = &spe->spe_an;
	struct silofs_avl *avl = &spa->spa_avl;

	silofs_avl_remove(avl, an);
}

static void spamap_evict_spe(struct silofs_spamap *spa,
                             struct silofs_spa_entry *spe)
{
	spamap_remove_spe(spa, spe);
	spamap_delete_spe(spa, spe);
}

static int spamap_check_cap_add(const struct silofs_spamap *spa)
{
	const size_t spe_size = sizeof(struct silofs_spa_entry);
	const size_t cap_cur = spa->spa_avl.size * spe_size;
	const size_t cap_max = spa->spa_cap_max;

	return (cap_cur < cap_max) ? 0 : -ENOMEM;
}

static int spamap_pop_vspace(struct silofs_spamap *spa,
                             size_t len, loff_t *out_off)
{
	struct silofs_spa_entry *spe;

	spe = spamap_minimal_spe(spa);
	if (spe == NULL) {
		return -ENOSPC;
	}
	if (len > spe->spe_len) {
		return -ENOSPC;
	}
	*out_off = spe->spe_voff;
	if (len < spe->spe_len) {
		/* its ok to modify in-place and avoid the costly remove-insert
		 * into the tree, as this is already the minimal element */
		spe_chop_head(spe, len);
	} else {
		spamap_evict_spe(spa, spe);
	}
	return 0;
}

static int spamap_merge_vspace(struct silofs_spamap *spa,
                               loff_t off, size_t len)
{
	struct silofs_spa_entry *spe = NULL;
	struct silofs_spa_entry *spe_prev = NULL;
	struct silofs_spa_entry *spe_next = NULL;
	loff_t end;
	int ret = -ENOENT;

	end = off_end(off, len);
	spmap_find_next_prev(spa, off, &spe_prev, &spe_next);

	if (spe_prev && (spe_end(spe_prev) == off)) {
		/* merge range into prev */
		spe = spe_prev;
		spe->spe_len += len;
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
		spamap_evict_spe(spa, spe_next);
		spe = spamap_new_spe(spa, off, off_ulen(off, end));
		if (spe == NULL) {
			return -ENOMEM;
		}
		spamap_insert_spe(spa, spe);
	} else {
		/* full merge (prev + next ) */
		spe->spe_len += spe_next->spe_len;
		spamap_evict_spe(spa, spe_next);
	}
	return 0;
}

static int spamap_insert_vspace(struct silofs_spamap *spa,
                                loff_t off, size_t len)

{
	struct silofs_spa_entry *spe;
	struct silofs_spa_entry *spe_max = NULL;

	spe = spamap_new_spe(spa, off, len);
	if (spe != NULL) {
		goto out_ok; /* trivial case */
	}
	spe_max = spamap_maximal_spe(spa);
	if (spe_max == NULL) {
		return -ENOMEM;
	}
	if (off > spe_max->spe_voff) {
		return -ENOMEM;
	}
	spamap_delete_spe(spa, spe_max);
	spe = spamap_new_spe(spa, off, len);
	if (spe == NULL) {
		return -ENOMEM;
	}
out_ok:
	spamap_insert_spe(spa, spe);
	return 0;
}

static int spamap_add_vspace(struct silofs_spamap *spa, loff_t off, size_t len)
{
	int err;

	err = spamap_merge_vspace(spa, off, len);
	if (err != -ENOENT) {
		return err;
	}
	err = spamap_check_cap_add(spa);
	if (err) {
		return err;
	}
	err = spamap_insert_vspace(spa, off, len);
	if (err) {
		return err;
	}
	return 0;
}

static void spamap_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_spamap *spa = p;
	struct silofs_spa_entry *spe = avl_node_to_spe(an);

	spamap_delete_spe(spa, spe);
}

static void spamap_clear(struct silofs_spamap *spa)
{
	const struct silofs_avl_node_functor fn = {
		.fn = spamap_avl_node_delete_cb,
		.ctx = spa
	};

	silofs_avl_clear(&spa->spa_avl, &fn);
}

static void spamap_init(struct silofs_spamap *spa, enum silofs_stype stype,
                        struct silofs_alloc *alloc)
{
	silofs_avl_init(&spa->spa_avl, spe_getkey, voff_compare, spa);
	spa->spa_alloc = alloc;
	spa->spa_cap_max = spamap_capacity(stype);
	spa->spa_stype = stype;
}

static void spamap_fini(struct silofs_spamap *spa)
{
	silofs_avl_fini(&spa->spa_avl);
	spa->spa_alloc = NULL;
	spa->spa_cap_max = 0;
	spa->spa_stype = SILOFS_STYPE_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spamap *
spamaps_sub_map(struct silofs_spamaps *spam, enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		return &spam->spa_data1k;
	case SILOFS_STYPE_DATA4K:
		return &spam->spa_data4k;
	case SILOFS_STYPE_DATABK:
		return &spam->spa_databk;
	case SILOFS_STYPE_ITNODE:
		return &spam->spa_itnode;
	case SILOFS_STYPE_INODE:
		return &spam->spa_inode;
	case SILOFS_STYPE_XANODE:
		return &spam->spa_xanode;
	case SILOFS_STYPE_DTNODE:
		return &spam->spa_dtnode;
	case SILOFS_STYPE_FTNODE:
		return &spam->spa_ftnode;
	case SILOFS_STYPE_SYMVAL:
		return &spam->spa_symval;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPSTAT:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		break;
	}
	return NULL;
}

int silofs_spamaps_store(struct silofs_spamaps *spam,
                         enum silofs_stype stype, loff_t voff, size_t len)
{
	struct silofs_spamap *spa;
	int err = -EINVAL;

	spa = spamaps_sub_map(spam, stype);
	if (spa != NULL) {
		err = spamap_add_vspace(spa, voff, len);
	}
	return err;
}

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_stype stype,
                          size_t len, loff_t *out_voff)
{
	struct silofs_spamap *spa;
	int err = -EINVAL;

	spa = spamaps_sub_map(spam, stype);
	if (spa != NULL) {
		err = spamap_pop_vspace(spa, len, out_voff);
	}
	return err;
}

void silofs_spamaps_drop(struct silofs_spamaps *spam)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		spa = spamaps_sub_map(spam, stype);
		if (spa != NULL) {
			spamap_clear(spa);
		}
	}
}

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc *alloc)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		spa = spamaps_sub_map(spam, stype);
		if (spa != NULL) {
			spamap_init(spa, stype, alloc);
		}
	}
	return 0;
}

void silofs_spamaps_fini(struct silofs_spamaps *spam)
{
	struct silofs_spamap *spa = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		spa = spamaps_sub_map(spam, stype);
		if (spa != NULL) {
			spamap_clear(spa);
			spamap_fini(spa);
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
ui_from_unom_lh(const struct silofs_list_head *lh)
{
	const struct silofs_unode_info *ui = NULL;

	ui = container_of2(lh, struct silofs_unode_info, u_unom_lh);
	return unconst(ui);
}

int silofs_unomap_init(struct silofs_unomap *unom,
                       struct silofs_alloc *alloc)
{
	const unsigned int cap = 4093;

	unom->uno_htbl_sz = 0;
	unom->uno_htbl_cap = 0;
	unom->uno_htbl = silofs_lista_new(alloc, cap);
	if (unom->uno_htbl == NULL) {
		return -ENOMEM;
	}
	unom->uno_htbl_cap = cap;
	return 0;
}

void silofs_unomap_fini(struct silofs_unomap *unom,
                        struct silofs_alloc *alloc)
{
	if (unom->uno_htbl != NULL) {
		silofs_lista_del(unom->uno_htbl, unom->uno_htbl_cap, alloc);
		unom->uno_htbl_cap = 0;
		unom->uno_htbl_sz = 0;
	}
}

static size_t unomap_slot_of(const struct silofs_unomap *unom,
                             const struct silofs_taddr *taddr)
{
	uint64_t key;
	const uint64_t hash = silofs_xid_as_u64(&taddr->tree_id);

	key = (uint64_t)taddr->voff;
	key |= jenkins_hash((uint32_t)hash);
	key ^= (~hash >> 32);
	key = silofs_rotate64(key, taddr->height & 0xF);

	return key % unom->uno_htbl_cap;
}

static struct silofs_list_head *
unomap_lst_by(const struct silofs_unomap *unom,
              const struct silofs_taddr *taddr)
{
	const size_t slot = unomap_slot_of(unom, taddr);
	const struct silofs_list_head *lh = NULL;

	lh = &unom->uno_htbl[slot];
	return silofs_unconst(lh);
}

void silofs_unomap_insert(struct silofs_unomap *unom,
                          struct silofs_unode_info *ui)
{
	struct silofs_taddr taddr;
	struct silofs_list_head *lst;

	if (!ui->u_tmapped) {
		silofs_taddr_by_uaddr(&taddr, ui_uaddr(ui));

		lst = unomap_lst_by(unom, &taddr);
		list_push_front(lst, &ui->u_unom_lh);
		ui->u_tmapped = true;
		unom->uno_htbl_sz++;
	}
}

void silofs_unomap_remove(struct silofs_unomap *unom,
                          struct silofs_unode_info *ui)
{
	if (ui->u_tmapped) {
		silofs_assert_gt(unom->uno_htbl_sz, 0);
		list_head_remove(&ui->u_unom_lh);
		ui->u_tmapped = false;
		unom->uno_htbl_sz--;
	}
}

static bool ui_has_taddr(const struct silofs_unode_info *ui,
                         const struct silofs_taddr *taddr)
{
	struct silofs_taddr ui_taddr;

	silofs_taddr_by_uaddr(&ui_taddr, ui_uaddr(ui));
	return silofs_taddr_isequal(&ui_taddr, taddr);
}

struct silofs_unode_info *
silofs_unomap_lookup(const struct silofs_unomap *unom,
                     const struct silofs_taddr *taddr)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_unode_info *ui;

	lst = unomap_lst_by(unom, taddr);
	itr = lst->next;
	while (itr != lst) {
		ui = ui_from_unom_lh(itr);
		if (ui_has_taddr(ui, taddr)) {
			return unconst(ui);
		}
		itr = itr->next;
	}
	return NULL;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc *alloc, size_t nelems)
{
	struct silofs_list_head *lista;

	lista = silofs_allocate(alloc, sizeof(*lista) * nelems);
	if (lista != NULL) {
		list_head_initn(lista, nelems);
	}
	return lista;
}

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc *alloc)
{
	list_head_finin(lista, nelems);
	silofs_deallocate(alloc, lista, sizeof(*lista) * nelems);
}



