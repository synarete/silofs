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
#include <silofs/list.h>


static void list_head_set(struct silofs_list_head *lnk,
                          struct silofs_list_head *prv,
                          struct silofs_list_head *nxt)
{
	lnk->next = nxt;
	lnk->prev = prv;
}

static void list_head_insert(struct silofs_list_head *lnk,
                             struct silofs_list_head *prv,
                             struct silofs_list_head *nxt)
{
	list_head_set(lnk, prv, nxt);

	nxt->prev = lnk;
	prv->next = lnk;
}

void silofs_list_head_insert_after(struct silofs_list_head *prev_lnk,
                                   struct silofs_list_head *lnk)
{
	list_head_insert(lnk, prev_lnk, prev_lnk->next);
}

void silofs_list_head_insert_before(struct silofs_list_head *lnk,
                                    struct silofs_list_head *next_lnk)
{
	list_head_insert(lnk, next_lnk->prev, next_lnk);
}

void silofs_list_head_remove(struct silofs_list_head *lnk)
{
	struct silofs_list_head *next = lnk->next;
	struct silofs_list_head *prev = lnk->prev;

	next->prev = prev;
	prev->next = next;
	list_head_set(lnk, lnk, lnk);
}

void silofs_list_head_init(struct silofs_list_head *lnk)
{
	list_head_set(lnk, lnk, lnk);
}

void silofs_list_head_initn(struct silofs_list_head *lnk_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		silofs_list_head_init(&lnk_arr[i]);
	}
}

void silofs_list_head_fini(struct silofs_list_head *lnk)
{
	list_head_set(lnk, NULL, NULL);
}

void silofs_list_head_finin(struct silofs_list_head *lnk_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		silofs_list_head_fini(&lnk_arr[i]);
	}
}

void silofs_list_init(struct silofs_list_head *lst)
{
	silofs_list_head_init(lst);
}

void silofs_list_fini(struct silofs_list_head *lst)
{
	silofs_list_head_fini(lst);
}

void silofs_list_push_front(struct silofs_list_head *lst,
                            struct silofs_list_head *lnk)
{
	silofs_list_head_insert_after(lst, lnk);
}

void silofs_list_push_back(struct silofs_list_head *lst,
                           struct silofs_list_head *lnk)
{
	silofs_list_head_insert_before(lnk, lst);
}

struct silofs_list_head *silofs_list_front(const struct silofs_list_head *lst)
{
	return lst->next;
}

struct silofs_list_head *silofs_list_back(const struct silofs_list_head *lst)
{
	return lst->prev;
}

struct silofs_list_head *silofs_list_pop_front(struct silofs_list_head *lst)
{
	struct silofs_list_head *lnk;

	lnk = silofs_list_front(lst);
	if (lnk != lst) {
		silofs_list_head_remove(lnk);
	} else {
		lnk = NULL;
	}
	return lnk;
}

struct silofs_list_head *silofs_list_pop_back(struct silofs_list_head *lst)
{
	struct silofs_list_head *lnk;

	lnk = silofs_list_back(lst);
	if (lnk != lst) {
		silofs_list_head_remove(lnk);
	} else {
		lnk = NULL;
	}
	return lnk;
}

bool silofs_list_isempty(const struct silofs_list_head *lst)
{
	return (lst->next == lst);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_listq_init(struct silofs_listq *lsq)
{
	silofs_list_init(&lsq->ls);
	lsq->sz = 0;
}

void silofs_listq_initn(struct silofs_listq *lsq, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		silofs_listq_init(&lsq[i]);
	}
}

void silofs_listq_fini(struct silofs_listq *lsq)
{
	silofs_list_fini(&lsq->ls);
	lsq->sz = 0;
}

void silofs_listq_finin(struct silofs_listq *lsq, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		silofs_listq_fini(&lsq[i]);
	}
}

size_t silofs_listq_size(const struct silofs_listq *lsq)
{
	return lsq->sz;
}

bool silofs_listq_isempty(const struct silofs_listq *lsq)
{
	return (lsq->sz == 0);
}

void silofs_listq_remove(struct silofs_listq *lsq,
                         struct silofs_list_head *lnk)
{
	silofs_list_head_remove(lnk);
	lsq->sz--;
}

void silofs_listq_push_front(struct silofs_listq *lsq,
                             struct silofs_list_head *lnk)
{
	silofs_list_push_front(&lsq->ls, lnk);
	lsq->sz++;
}

void silofs_listq_push_back(struct silofs_listq *lsq,
                            struct silofs_list_head *lnk)
{
	silofs_list_push_back(&lsq->ls, lnk);
	lsq->sz++;
}

struct silofs_list_head *silofs_listq_pop_front(struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = silofs_list_pop_front(&lsq->ls);
		lsq->sz--;
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_pop_back(struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = silofs_list_pop_back(&lsq->ls);
		lsq->sz--;
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_front(const struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = silofs_list_front(&lsq->ls);
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_back(const struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = silofs_list_back(&lsq->ls);
	}
	return lnk;
}

struct silofs_list_head *
silofs_listq_next(const struct silofs_listq *lsq,
                  const struct silofs_list_head *lnk)
{
	struct silofs_list_head *nxt = NULL;

	if ((lsq->sz > 0) && (lnk->next != &lsq->ls)) {
		nxt = lnk->next;
	}
	return nxt;
}

struct silofs_list_head *
silofs_listq_prev(const struct silofs_listq *lsq,
                  const struct silofs_list_head *lnk)
{
	struct silofs_list_head *prv = NULL;

	if ((lsq->sz > 0) && (lnk->prev != &lsq->ls)) {
		prv = lnk->prev;
	}
	return prv;
}


