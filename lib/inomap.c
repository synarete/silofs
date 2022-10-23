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
#include <silofs/types.h>
#include <silofs/address.h>
#include <silofs/itable.h>
#include <silofs/spxmap.h>
#include <silofs/fs-private.h>


static void inoent_init(struct silofs_inoent *ient, ino_t ino, loff_t voff)
{
	list_head_init(&ient->htb_lh);
	list_head_init(&ient->lru_lh);
	ient->ino = ino;
	ient->voff = voff;
}

static void inoent_fini(struct silofs_inoent *ient)
{
	list_head_fini(&ient->htb_lh);
	list_head_fini(&ient->lru_lh);
	ient->ino = SILOFS_INO_NULL;
	ient->voff = SILOFS_OFF_NULL;
}

static struct silofs_inoent *
inoent_new(struct silofs_alloc *alloc, ino_t ino, loff_t voff)
{
	struct silofs_inoent *ient;

	ient = silofs_allocate(alloc, sizeof(*ient));
	if (ient != NULL) {
		inoent_init(ient, ino, voff);
	}
	return ient;
}

static void inoent_del(struct silofs_inoent *ient,
                       struct silofs_alloc *alloc)
{
	inoent_fini(ient);
	silofs_deallocate(alloc, ient, sizeof(*ient));
}

static struct silofs_inoent *
inoent_from_htb_lh(const struct silofs_list_head *lh)
{
	const struct silofs_inoent *ient;

	ient = container_of2(lh, struct silofs_inoent, htb_lh);
	return unconst(ient);
}

static struct silofs_inoent *
inoent_from_lru_lh(const struct silofs_list_head *lh)
{
	const struct silofs_inoent *ient;

	ient = container_of2(lh, struct silofs_inoent, lru_lh);
	return unconst(ient);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_inomap_init(struct silofs_inomap *imap,
                       struct silofs_alloc *alloc)
{
	const size_t htbl_nelems = 65479;

	listq_init(&imap->im_lru);
	imap->im_alloc = alloc;
	imap->im_htbl_nelems = 0;
	imap->im_htbl = silofs_lista_new(alloc, htbl_nelems);
	if (imap->im_htbl == NULL) {
		return -ENOMEM;
	}
	imap->im_htbl_nelems = htbl_nelems;
	return 0;
}

void silofs_inomap_fini(struct silofs_inomap *imap)
{
	silofs_inomap_clear(imap);
	silofs_lista_del(imap->im_htbl, imap->im_htbl_nelems, imap->im_alloc);
	listq_fini(&imap->im_lru);
	imap->im_htbl_nelems = 0;
	imap->im_htbl = NULL;
	imap->im_alloc = NULL;
}

static size_t inomap_ino_to_slot(const struct silofs_inomap *imap, ino_t ino)
{
	return ino % imap->im_htbl_nelems;
}

static struct silofs_list_head *
inomap_list_at(const struct silofs_inomap *imap, size_t slot)
{
	const struct silofs_list_head *lst = &imap->im_htbl[slot];

	return unconst(lst);
}

static struct silofs_list_head *
inomap_list_of(const struct silofs_inomap *imap, ino_t ino)
{
	return inomap_list_at(imap, inomap_ino_to_slot(imap, ino));
}

static struct silofs_inoent *
inomap_search_htbl(const struct silofs_inomap *imap, ino_t ino)
{
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_inoent *ient;

	lst = inomap_list_of(imap, ino);
	itr = lst->next;
	while (itr != lst) {
		ient = inoent_from_htb_lh(itr);
		if (ient->ino == ino) {
			return unconst(ient);
		}
		itr = itr->next;
	}
	return NULL;
}

static void inomap_promote_lru(struct silofs_inomap *imap,
                               struct silofs_inoent *ient)
{
	struct silofs_listq *lru = &imap->im_lru;

	listq_remove(lru, &ient->lru_lh);
	listq_push_front(lru, &ient->lru_lh);
}

int silofs_inomap_lookup(struct silofs_inomap *imap,
                         ino_t ino, loff_t *out_voff)
{
	struct silofs_inoent *ient;

	ient = inomap_search_htbl(imap, ino);
	if (ient == NULL) {
		return -ENOENT;
	}
	inomap_promote_lru(imap, ient);
	*out_voff = ient->voff;
	return 0;
}

static struct silofs_inoent *
inomap_new_ient(const struct silofs_inomap *imap, ino_t ino, loff_t voff)
{
	return inoent_new(imap->im_alloc, ino, voff);
}

static void inomap_del_ient(const struct silofs_inomap *imap,
                            struct silofs_inoent *ient)
{
	inoent_del(ient, imap->im_alloc);
}

static void inomap_insert_htbl(struct silofs_inomap *imap,
                               struct silofs_inoent *ient)
{
	struct silofs_list_head *lst;

	lst = inomap_list_of(imap, ient->ino);
	list_push_front(lst, &ient->htb_lh);
}

static void inomap_remove_htbl(struct silofs_inomap *imap,
                               struct silofs_inoent *ient)
{
	list_head_remove(&ient->htb_lh);
	silofs_unused(imap);
}

static void inomap_insert_lru(struct silofs_inomap *imap,
                              struct silofs_inoent *ient)
{
	listq_push_front(&imap->im_lru, &ient->lru_lh);
}

static void inomap_remove_lru(struct silofs_inomap *imap,
                              struct silofs_inoent *ient)
{
	listq_remove(&imap->im_lru, &ient->lru_lh);
}

static struct silofs_inoent *inomap_get_lru(struct silofs_inomap *imap)
{
	struct silofs_list_head *lh;
	struct silofs_inoent *ient = NULL;

	lh = listq_back(&imap->im_lru);
	if (lh != NULL) {
		ient = inoent_from_lru_lh(lh);
	}
	return ient;
}

static void inomap_remove_del(struct silofs_inomap *imap,
                              struct silofs_inoent *ient)
{
	if (likely(ient != NULL)) {
		inomap_remove_htbl(imap, ient);
		inomap_remove_lru(imap, ient);
		inomap_del_ient(imap, ient);
	}
}

static bool inomap_relax_once(struct silofs_inomap *imap)
{
	struct silofs_inoent *ient;
	bool removed = false;

	ient = inomap_get_lru(imap);
	if (ient != NULL) {
		inomap_remove_del(imap, ient);
		removed = true;
	}
	return removed;
}

static size_t inomap_relax_count(const struct silofs_inomap *imap, int flags)
{
	const size_t sz = imap->im_lru.sz;
	const size_t ne = imap->im_htbl_nelems;

	if (sz > (2 * ne)) {
		return 2;
	}
	if (sz > ne) {
		return 1;
	}
	if ((sz > (ne / 4)) && (flags & SILOFS_F_TIMEOUT)) {
		return 4;
	}
	if (flags & SILOFS_F_WALKFS) {
		return 8;
	}
	return 0;
}

void silofs_inomap_relax(struct silofs_inomap *imap, int flags)
{
	const size_t cnt = inomap_relax_count(imap, flags);

	for (size_t i = 0; i < cnt; ++i) {
		if (!inomap_relax_once(imap)) {
			break;
		}
	}
}

int silofs_inomap_insert(struct silofs_inomap *imap, ino_t ino, loff_t voff)
{
	struct silofs_inoent *ient;

	ient = inomap_new_ient(imap, ino, voff);
	if (ient == NULL) {
		return -ENOMEM;
	}
	inomap_insert_htbl(imap, ient);
	inomap_insert_lru(imap, ient);
	return 0;
}

int silofs_inomap_remove(struct silofs_inomap *imap, ino_t ino)
{
	struct silofs_inoent *ient;

	ient = inomap_search_htbl(imap, ino);
	if (ient == NULL) {
		return -ENOENT;
	}
	inomap_remove_del(imap, ient);
	return 0;
}

int silofs_inomap_update(struct silofs_inomap *imap, ino_t ino, loff_t voff)
{
	struct silofs_inoent *ient;
	int ret = 0;

	ient = inomap_search_htbl(imap, ino);
	if (ient == NULL) {
		silofs_inomap_relax(imap, 0);
		ret = silofs_inomap_insert(imap, ino, voff);
	} else {
		ient->voff = voff;
	}
	return ret;
}

void silofs_inomap_clear(struct silofs_inomap *imap)
{
	struct silofs_inoent *ient;

	ient = inomap_get_lru(imap);
	while (ient != NULL) {
		inomap_remove_del(imap, ient);
		ient = inomap_get_lru(imap);
	}
}

