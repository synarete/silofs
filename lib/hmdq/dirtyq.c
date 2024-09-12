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
                          struct silofs_list_head *lh, size_t len)
{
	listq_push_back(&dq->dq, lh);
	dq->dq_accum += len;
}

void silofs_dirtyq_remove(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len)
{
	silofs_assert_ge(dq->dq_accum, len);

	listq_remove(&dq->dq, lh);
	dq->dq_accum -= len;
}

struct silofs_list_head *silofs_dirtyq_front(const struct silofs_dirtyq *dq)
{
	return listq_front(&dq->dq);
}

struct silofs_list_head *
silofs_dirtyq_next_of(const struct silofs_dirtyq *dq,
                      const struct silofs_list_head *lh)
{
	return listq_next(&dq->dq, lh);
}
