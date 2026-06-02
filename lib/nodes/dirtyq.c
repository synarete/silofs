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
#include <silofs/nodes.h>

static void
dirtyq_append(struct silofs_dirtyq *drq, struct silofs_dq_elem *dqe);

static void
dirtyq_remove(struct silofs_dirtyq *drq, struct silofs_dq_elem *dqe);

void silofs_dqe_init(struct silofs_dq_elem *dqe, size_t sz)
{
	silofs_assert_gt(sz, 0);
	silofs_assert_le(sz, 65536);

	silofs_list_head_init(&dqe->drq_lh);
	silofs_list_head_init(&dqe->dsq_lh);
	dqe->drq    = nullptr;
	dqe->sz     = (uint32_t)sz;
	dqe->in_drq = false;
	dqe->in_dsq = false;
}

void silofs_dqe_fini(struct silofs_dq_elem *dqe)
{
	silofs_assert_gt(dqe->sz, 0);
	silofs_assert(!dqe->in_drq);

	silofs_list_head_fini(&dqe->dsq_lh);
	silofs_list_head_fini(&dqe->drq_lh);
	dqe->drq = nullptr;
	dqe->sz  = 0;
}

bool silofs_dqe_isinq(const struct silofs_dq_elem *dqe)
{
	return dqe->in_drq || dqe->in_dsq;
}

void silofs_dqe_set_dirtyq(struct silofs_dq_elem *dqe,
                           struct silofs_dirtyq *drq)
{
	silofs_assert(!dqe->in_drq);
	dqe->drq = drq;
}

void silofs_dqe_markdirty(struct silofs_dq_elem *dqe)
{
	if (!dqe->in_drq) {
		silofs_assert_not_null(dqe->drq);

		dirtyq_append(dqe->drq, dqe);
		dqe->in_drq = true;
	}
}

void silofs_dqe_cleardirty(struct silofs_dq_elem *dqe)
{
	if (dqe->in_drq) {
		silofs_assert_not_null(dqe->drq);

		dirtyq_remove(dqe->drq, dqe);
		dqe->in_drq = false;
	}
}

bool silofs_dqe_isdirty(const struct silofs_dq_elem *dqe)
{
	return dqe->in_drq;
}

static struct silofs_dq_elem *dqe_from_drq_lh(struct silofs_list_head *lh)
{
	struct silofs_dq_elem *dqe = nullptr;

	if (lh != nullptr) {
		dqe = mut_container_of(lh, struct silofs_dq_elem, drq_lh);
	}
	return dqe;
}

static struct silofs_dq_elem *dqe_from_mut_dsq_lh(struct silofs_list_head *lh)
{
	struct silofs_dq_elem *dqe = nullptr;

	if (lh != nullptr) {
		dqe = mut_container_of(lh, struct silofs_dq_elem, dsq_lh);
	}
	return dqe;
}

static const struct silofs_dq_elem *
dqe_from_dsq_lh(const struct silofs_list_head *lh)
{
	const struct silofs_dq_elem *dqe = nullptr;

	if (lh != nullptr) {
		dqe = container_of(lh, struct silofs_dq_elem, dsq_lh);
	}
	return dqe;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *drq)
{
	silofs_listq_init(&drq->drq);
	drq->drq_accum = 0;
}

void silofs_dirtyq_fini(struct silofs_dirtyq *drq)
{
	silofs_listq_fini(&drq->drq);
	drq->drq_accum = 0;
}

static void
dirtyq_append(struct silofs_dirtyq *drq, struct silofs_dq_elem *dqe)
{
	silofs_listq_push_back(&drq->drq, &dqe->drq_lh);
	drq->drq_accum += dqe->sz;
}

static void
dirtyq_remove(struct silofs_dirtyq *drq, struct silofs_dq_elem *dqe)
{
	silofs_assert(dqe->in_drq);
	silofs_listq_remove(&drq->drq, &dqe->drq_lh);
	drq->drq_accum -= dqe->sz;
}

struct silofs_dq_elem *silofs_dirtyq_front(const struct silofs_dirtyq *drq)
{
	struct silofs_list_head *lh;

	lh = silofs_listq_front(&drq->drq);
	return dqe_from_drq_lh(lh);
}

struct silofs_dq_elem *silofs_dirtyq_nextof(const struct silofs_dirtyq *drq,
                                            const struct silofs_dq_elem *dqe)
{
	struct silofs_list_head *lh = nullptr;

	if (dqe != nullptr) {
		lh = listq_next(&drq->drq, &dqe->drq_lh);
	}
	return dqe_from_drq_lh(lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_destageq_init(struct silofs_destageq *dsq)
{
	silofs_listq_init(&dsq->dsq);
}

void silofs_destageq_fini(struct silofs_destageq *dsq)
{
	silofs_listq_fini(&dsq->dsq);
}

static struct silofs_dq_elem *destageq_front(const struct silofs_destageq *dsq)
{
	struct silofs_list_head *lh;

	lh = silofs_listq_front(&dsq->dsq);
	return dqe_from_mut_dsq_lh(lh);
}

static struct silofs_dq_elem *
destageq_nextof(const struct silofs_destageq *dsq,
                const struct silofs_dq_elem *dqe)
{
	struct silofs_list_head *lh = nullptr;

	if (dqe != nullptr) {
		lh = listq_next(&dsq->dsq, &dqe->dsq_lh);
	}
	return dqe_from_mut_dsq_lh(lh);
}

static void
destageq_push_back(struct silofs_destageq *dsq, struct silofs_dq_elem *dqe)
{
	if (!dqe->in_dsq) {
		silofs_listq_push_back(&dsq->dsq, &dqe->dsq_lh);
		dqe->in_dsq = true;
	}
}

static struct silofs_dq_elem *destageq_pop_front(struct silofs_destageq *dsq)
{
	struct silofs_list_head *lh;
	struct silofs_dq_elem *dqe = nullptr;

	lh = silofs_listq_pop_front(&dsq->dsq);
	if (lh != nullptr) {
		dqe         = dqe_from_mut_dsq_lh(lh);
		dqe->in_dsq = false;
	}
	return dqe;
}

void silofs_destageq_populate(struct silofs_destageq *dsq,
                              const struct silofs_dirtyq *drq)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(drq);
	while (dqe != nullptr) {
		destageq_push_back(dsq, dqe);
		dqe = silofs_dirtyq_nextof(drq, dqe);
	}
}

void silofs_destageq_depopulate(struct silofs_destageq *dsq)
{
	struct silofs_dq_elem *dqe;

	dqe = destageq_pop_front(dsq);
	while (dqe != nullptr) {
		dqe = destageq_pop_front(dsq);
	}
}

struct silofs_dqe_functor {
	struct silofs_list_functor lsfn;
	silofs_dqe_compare_fn dqe_cmp_fn;
};

static const struct silofs_dqe_functor *
dqfn_of(const struct silofs_list_functor *lsfn)
{
	return container_of(lsfn, struct silofs_dqe_functor, lsfn);
}

static int dqe_compare_by(const struct silofs_list_functor *lsfn,
                          const struct silofs_list_head *lh1,
                          const struct silofs_list_head *lh2)
{
	const struct silofs_dqe_functor *dqfn = dqfn_of(lsfn);
	const struct silofs_dq_elem *dqe1     = dqe_from_dsq_lh(lh1);
	const struct silofs_dq_elem *dqe2     = dqe_from_dsq_lh(lh2);

	return dqfn->dqe_cmp_fn(dqe1, dqe2);
}

void silofs_destageq_sort(struct silofs_destageq *dsq,
                          silofs_dqe_compare_fn dqe_comp_fn)
{
	struct silofs_dqe_functor dqfn = {
		.lsfn.compare_fn = dqe_compare_by,
		.dqe_cmp_fn      = dqe_comp_fn,
	};

	silofs_list_sort(&dsq->dsq.ls, &dqfn.lsfn);
}

int silofs_destageq_foreach(const struct silofs_destageq *dsq,
                            silofs_dqe_execute_fn dqe_exec_fn, void *userp)
{
	struct silofs_dq_elem *dqe;
	int err = 0;

	dqe = destageq_front(dsq);
	while ((dqe != nullptr) && !err) {
		err = dqe_exec_fn(dqe, userp);
		dqe = destageq_nextof(dsq, dqe);
	}
	return err;
}
