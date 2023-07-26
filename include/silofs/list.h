/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_LIST_H_
#define SILOFS_LIST_H_

#include <stdlib.h>
#include <stdbool.h>

/* linked-list */
struct silofs_list_head {
	struct silofs_list_head *prev;
	struct silofs_list_head *next;
};


/* sized linked-list queue */
struct silofs_listq {
	struct silofs_list_head ls;
	size_t sz;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_list_init(struct silofs_list_head *lst);

void silofs_list_fini(struct silofs_list_head *lst);

void silofs_list_push_front(struct silofs_list_head *lst,
                            struct silofs_list_head *lnk);

void silofs_list_push_back(struct silofs_list_head *lst,
                           struct silofs_list_head *lnk);

struct silofs_list_head *
silofs_list_front(const struct silofs_list_head *lst);

struct silofs_list_head *
silofs_list_back(const struct silofs_list_head *lst);

struct silofs_list_head *
silofs_list_pop_front(struct silofs_list_head *lst);

struct silofs_list_head *
silofs_list_pop_back(struct silofs_list_head *lst);

bool silofs_list_isempty(const struct silofs_list_head *lst);


void silofs_listq_init(struct silofs_listq *lsq);

void silofs_listq_initn(struct silofs_listq *lsq, size_t cnt);

void silofs_listq_fini(struct silofs_listq *lsq);

void silofs_listq_finin(struct silofs_listq *lsq, size_t cnt);

size_t silofs_listq_size(const struct silofs_listq *lsq);

bool silofs_listq_isempty(const struct silofs_listq *lsq);

void silofs_listq_remove(struct silofs_listq *lsq,
                         struct silofs_list_head *lnk);

void silofs_listq_push_front(struct silofs_listq *lsq,
                             struct silofs_list_head *lnk);

void silofs_listq_push_back(struct silofs_listq *lsq,
                            struct silofs_list_head *lnk);

struct silofs_list_head *
silofs_listq_pop_front(struct silofs_listq *lsq);

struct silofs_list_head *
silofs_listq_pop_back(struct silofs_listq *lsq);

struct silofs_list_head *
silofs_listq_front(const struct silofs_listq *lsq);

struct silofs_list_head *
silofs_listq_back(const struct silofs_listq *lsq);

struct silofs_list_head *
silofs_listq_next(const struct silofs_listq *lsq,
                  const struct silofs_list_head *lnk);

struct silofs_list_head *
silofs_listq_prev(const struct silofs_listq *lsq,
                  const struct silofs_list_head *lnk);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_list_head_initn(struct silofs_list_head *lh_arr, size_t cnt);

void silofs_list_head_finin(struct silofs_list_head *lh_arr, size_t cnt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline void
silofs_list_head_set(struct silofs_list_head *lh,
                     struct silofs_list_head *prv,
                     struct silofs_list_head *nxt)
{
	lh->next = nxt;
	lh->prev = prv;
}

static inline void
silofs_list_head_insert(struct silofs_list_head *lh,
                        struct silofs_list_head *prv,
                        struct silofs_list_head *nxt)
{
	silofs_list_head_set(lh, prv, nxt);
	nxt->prev = lh;
	prv->next = lh;
}

static inline void
silofs_list_head_insert_after(struct silofs_list_head *prev_lh,
                              struct silofs_list_head *lh)
{
	silofs_list_head_insert(lh, prev_lh, prev_lh->next);
}

static inline void
silofs_list_head_insert_before(struct silofs_list_head *lh,
                               struct silofs_list_head *next_lh)
{
	silofs_list_head_insert(lh, next_lh->prev, next_lh);
}

static inline void silofs_list_head_remove(struct silofs_list_head *lh)
{
	struct silofs_list_head *nxt = lh->next;
	struct silofs_list_head *prv = lh->prev;

	nxt->prev = prv;
	prv->next = nxt;
	silofs_list_head_set(lh, lh, lh);
}

static inline void silofs_list_head_init(struct silofs_list_head *lh)
{
	silofs_list_head_set(lh, lh, lh);
}

static inline void silofs_list_head_fini(struct silofs_list_head *lh)
{
	silofs_list_head_set(lh, NULL, NULL);
}

#endif /* SILOFS_LIST_H_ */




