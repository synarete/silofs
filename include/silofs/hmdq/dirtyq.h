/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_DIRTYQ_H_
#define SILOFS_DIRTYQ_H_

#include <silofs/infra.h>
#include <silofs/addr.h>

/* dirty-queue of cached-elements */
struct silofs_dirtyq {
	struct silofs_listq dq;
	size_t              dq_accum;
};

/* dirty-queue element (type-safe) */
struct silofs_dq_elem {
	struct silofs_list_head lh;
	struct silofs_dirtyq   *dq;
	uint32_t                sz;
	bool                    inq;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dqe_init(struct silofs_dq_elem *dqe, size_t sz);

void silofs_dqe_fini(struct silofs_dq_elem *dqe);

void silofs_dqe_setq(struct silofs_dq_elem *dqe, struct silofs_dirtyq *dq);

void silofs_dqe_enqueue(struct silofs_dq_elem *dqe);

void silofs_dqe_dequeue(struct silofs_dq_elem *dqe);

bool silofs_dqe_is_dirty(const struct silofs_dq_elem *dqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *dq);

void silofs_dirtyq_fini(struct silofs_dirtyq *dq);

struct silofs_dq_elem *silofs_dirtyq_front(const struct silofs_dirtyq *dq);

struct silofs_dq_elem *silofs_dirtyq_next_of(const struct silofs_dirtyq  *dq,
                                             const struct silofs_dq_elem *dqe);

#endif /* SILOFS_DIRTYQ_H_ */
