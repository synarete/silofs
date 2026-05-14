/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/ccattr.h>
#include <silofs/memalloc.h>
#include <silofs/base/list.h>

void silofs_list_head_set(struct silofs_list_head *lh,
                          struct silofs_list_head *prv,
                          struct silofs_list_head *nxt)
{
	lh->next = nxt;
	lh->prev = prv;
}

void silofs_list_head_insert(struct silofs_list_head *lh,
                             struct silofs_list_head *prv,
                             struct silofs_list_head *nxt)
{
	silofs_list_head_set(lh, prv, nxt);
	nxt->prev = lh;
	prv->next = lh;
}

void silofs_list_head_insert_after(struct silofs_list_head *prev_lh,
                                   struct silofs_list_head *lh)
{
	silofs_list_head_insert(lh, prev_lh, prev_lh->next);
}

void silofs_list_head_insert_before(struct silofs_list_head *lh,
                                    struct silofs_list_head *next_lh)
{
	silofs_list_head_insert(lh, next_lh->prev, next_lh);
}

void silofs_list_head_remove(struct silofs_list_head *lh)
{
	struct silofs_list_head *nxt = lh->next;
	struct silofs_list_head *prv = lh->prev;

	nxt->prev = prv;
	prv->next = nxt;
	silofs_list_head_set(lh, lh, lh);
}

void silofs_list_head_init(struct silofs_list_head *lh)
{
	silofs_list_head_set(lh, lh, lh);
}

void silofs_list_head_fini(struct silofs_list_head *lh)
{
	silofs_list_head_set(lh, nullptr, nullptr);
}

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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
		lnk = nullptr;
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
		lnk = nullptr;
	}
	return lnk;
}

bool silofs_list_isempty(const struct silofs_list_head *lst)
{
	return (lst->next == lst);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * 3-way compare of two list elements, via their list_head ref.
 */
static int
compare(const struct silofs_list_functor *fn,
        const struct silofs_list_head *lh1, const struct silofs_list_head *lh2)
{
	return fn->compare_fn(fn, lh1, lh2);
}

/*
 * Merge two NULL-terminated singly-linked sublists (linked via ->next
 * only).
 */
static struct silofs_list_head *
list_merge(struct silofs_list_head *lst_a, struct silofs_list_head *lst_b,
           const struct silofs_list_functor *cmp)
{
	struct silofs_list_head result = {};
	struct silofs_list_head *tail  = &result;

	while ((lst_a != nullptr) && (lst_b != nullptr)) {
		if (compare(cmp, lst_a, lst_b) <= 0) {
			tail->next = lst_a;
			lst_a      = lst_a->next;
		} else {
			tail->next = lst_b;
			lst_b      = lst_b->next;
		}
		tail = tail->next;
	}
	if (lst_a != nullptr) {
		tail->next = lst_a;
	} else {
		tail->next = lst_b;
	}
	return result.next;
}

static struct silofs_list_head *
list_merge_pending(struct silofs_list_head **pending, size_t top,
                   const struct silofs_list_functor *cmp)
{
	struct silofs_list_head *result = nullptr;

	for (size_t i = 0; i < top; ++i) {
		if (pending[i]) {
			result = list_merge(pending[i], result, cmp);
		}
	}
	return result;
}

static void list_rebuild_prev_links(struct silofs_list_head *lh)
{
	struct silofs_list_head *cur = lh;

	while (cur->next != nullptr) {
		struct silofs_list_head *nxt = cur->next;

		nxt->prev = cur;
		cur       = cur->next;
	}
}

static void list_reattach_to_sentinel(struct silofs_list_head *lst,
                                      struct silofs_list_head *lh)
{
	struct silofs_list_head *itr;

	lst->next = lh;
	lh->prev  = lst;
	list_rebuild_prev_links(lh);

	itr = lh;
	while (itr->next != nullptr) {
		itr = itr->next;
	}
	itr->next = lst;
	lst->prev = itr;
}

/*
 * Iterative bottom-up merge sort. Uses a pending[32] array where pending[i]
 * holds a sorted sublist of length 2^i (or NULL). Each new node is merged
 * upward until it lands in an empty slot, doubling sorted run lengths each
 * pass. O(n log n), no recursion, no heap allocation.
 */
static struct silofs_list_head *
list_build_pending(struct silofs_list_head *lst,
                   struct silofs_list_head **pending,
                   const struct silofs_list_functor *fn)
{
	struct silofs_list_head *lh;
	size_t top = 0;

	while (!silofs_list_isempty(lst)) {
		struct silofs_list_head *nxt;
		size_t i = 0;

		lh  = lst->next;
		nxt = lh->next;

		nxt->prev = lst;
		lst->next = nxt;
		lh->next  = nullptr;
		lh->prev  = nullptr;

		while (pending[i]) {
			lh = list_merge(pending[i], lh, fn);

			pending[i++] = nullptr;
		}
		pending[i] = lh;
		if (i == top) {
			top++;
		}
	}
	return list_merge_pending(pending, top, fn);
}

static void
list_sort(struct silofs_list_head *lst, const struct silofs_list_functor *fn)
{
	struct silofs_list_head *pending[32] = { nullptr };
	struct silofs_list_head *sorted;

	sorted = list_build_pending(lst, pending, fn);
	if (sorted != nullptr) {
		list_reattach_to_sentinel(lst, sorted);
	}
}

void silofs_list_sort(struct silofs_list_head *lst,
                      const struct silofs_list_functor *fn)
{
	if (!silofs_list_isempty(lst)) {
		list_sort(lst, fn);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
	struct silofs_list_head *lnk = nullptr;

	if (lsq->sz > 0) {
		lnk = silofs_list_pop_front(&lsq->ls);
		lsq->sz--;
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_pop_back(struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = nullptr;

	if (lsq->sz > 0) {
		lnk = silofs_list_pop_back(&lsq->ls);
		lsq->sz--;
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_front(const struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = nullptr;

	if (lsq->sz > 0) {
		lnk = silofs_list_front(&lsq->ls);
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_back(const struct silofs_listq *lsq)
{
	struct silofs_list_head *lnk = nullptr;

	if (lsq->sz > 0) {
		lnk = silofs_list_back(&lsq->ls);
	}
	return lnk;
}

struct silofs_list_head *silofs_listq_next(const struct silofs_listq *lsq,
                                           const struct silofs_list_head *lnk)
{
	struct silofs_list_head *nxt = nullptr;

	if (lsq->sz > 0) {
		if (lnk == nullptr) {
			nxt = lsq->ls.next;
		} else if (lnk->next != &lsq->ls) {
			nxt = lnk->next;
		}
	}
	return nxt;
}

struct silofs_list_head *silofs_listq_prev(const struct silofs_listq *lsq,
                                           const struct silofs_list_head *lnk)
{
	struct silofs_list_head *prv = nullptr;

	if (lsq->sz > 0) {
		if (lnk == nullptr) {
			prv = lsq->ls.prev;
		} else if (lnk->prev != &lsq->ls) {
			prv = lnk->prev;
		}
	}
	return prv;
}
