/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

void silofs_list_head_initn(struct silofs_list_head *lh_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		silofs_list_head_init(&lh_arr[i]);
	}
}

void silofs_list_head_finin(struct silofs_list_head *lh_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		silofs_list_head_fini(&lh_arr[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

struct silofs_list_head *silofs_listq_next(const struct silofs_listq *lsq,
                                           const struct silofs_list_head *lnk)
{
	struct silofs_list_head *nxt = NULL;

	if ((lsq->sz > 0) && (lnk->next != &lsq->ls)) {
		nxt = lnk->next;
	}
	return nxt;
}

struct silofs_list_head *silofs_listq_prev(const struct silofs_listq *lsq,
                                           const struct silofs_list_head *lnk)
{
	struct silofs_list_head *prv = NULL;

	if ((lsq->sz > 0) && (lnk->prev != &lsq->ls)) {
		prv = lnk->prev;
	}
	return prv;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc *alloc, size_t nelems)
{
	struct silofs_list_head *lista;

	lista = silofs_memalloc(alloc, sizeof(*lista) * nelems, 0);
	if (lista != NULL) {
		silofs_list_head_initn(lista, nelems);
	}
	return lista;
}

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc *alloc)
{
	silofs_list_head_finin(lista, nelems);
	silofs_memfree(alloc, lista, sizeof(*lista) * nelems, 0);
}
