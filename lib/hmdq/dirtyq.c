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
#include <silofs/hmdq/dirtyq.h>


void silofs_dqe_init(struct silofs_dqe *dqe)
{
	silofs_list_head_init(&dqe->lh);
}

void silofs_dqe_fini(struct silofs_dqe *dqe)
{
	silofs_list_head_fini(&dqe->lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *dq)
{
	listq_init(&dq->dq);
	dq->dq_accum = 0;
}

void silofs_dirtyq_fini(struct silofs_dirtyq *dq)
{
	listq_fini(&dq->dq);
	dq->dq_accum = 0;
}

void silofs_dirtyq_append(struct silofs_dirtyq *dq,
                          struct silofs_dqe *dqe, size_t len)
{
	listq_push_back(&dq->dq, &dqe->lh);
	dq->dq_accum += len;
}

void silofs_dirtyq_remove(struct silofs_dirtyq *dq,
                          struct silofs_dqe *dqe, size_t len)
{
	silofs_assert_ge(dq->dq_accum, len);

	listq_remove(&dq->dq, &dqe->lh);
	dq->dq_accum -= len;
}

static struct silofs_dqe *dqe_from_lh(struct silofs_list_head *lh)
{
	struct silofs_dqe *dqe = NULL;

	if (lh != NULL) {
		dqe = silofs_container_of(lh, struct silofs_dqe, lh);
	}
	return dqe;
}

struct silofs_dqe *silofs_dirtyq_front(const struct silofs_dirtyq *dq)
{
	struct silofs_list_head *lh;

	lh = listq_front(&dq->dq);
	return dqe_from_lh(lh);
}

struct silofs_dqe *silofs_dirtyq_next_of(const struct silofs_dirtyq *dq,
                const struct silofs_dqe *dqe)
{
	struct silofs_list_head *lh = NULL;

	if (dqe != NULL) {
		lh = listq_next(&dq->dq, &dqe->lh);
	}
	return dqe_from_lh(lh);
}
