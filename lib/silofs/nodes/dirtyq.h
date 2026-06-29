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
#ifndef SILOFS_DIRTYQ_H_
#define SILOFS_DIRTYQ_H_

#include <silofs/base.h>

/* dirty/destage queue element */
struct silofs_dq_elem {
	struct silofs_list_head drq_lh;
	struct silofs_list_head dsq_lh;
	struct silofs_dirtyq   *drq;
	uint32_t                sz;
	bool                    in_drq;
	bool                    in_dsq;
};

/* dirty elements' queue */
struct silofs_dirtyq {
	struct silofs_listq drq;
	size_t              drq_accum;
};

/* de-stage elements' queue */
struct silofs_destageq {
	struct silofs_listq dsq;
};

typedef int (*silofs_dqe_compare_fn)(const struct silofs_dq_elem *dqe1,
                                     const struct silofs_dq_elem *dqe2);

typedef int (*silofs_dqe_execute_fn)(struct silofs_dq_elem *dqe, void *userp);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dqe_init(struct silofs_dq_elem *dqe, size_t sz);

void silofs_dqe_fini(struct silofs_dq_elem *dqe);

bool silofs_dqe_isinq(const struct silofs_dq_elem *dqe);

void silofs_dqe_set_dirtyq(struct silofs_dq_elem *dqe,
                           struct silofs_dirtyq  *drq);

void silofs_dqe_setdirty(struct silofs_dq_elem *dqe);

void silofs_dqe_cleardirty(struct silofs_dq_elem *dqe);

bool silofs_dqe_isdirty(const struct silofs_dq_elem *dqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *drq);

void silofs_dirtyq_fini(struct silofs_dirtyq *drq);

struct silofs_dq_elem * //
silofs_dirtyq_front(const struct silofs_dirtyq *drq);

struct silofs_dq_elem * //
silofs_dirtyq_nextof(const struct silofs_dirtyq  *drq,
                     const struct silofs_dq_elem *dqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_destageq_init(struct silofs_destageq *dsq);

void silofs_destageq_fini(struct silofs_destageq *dsq);

void silofs_destageq_populate(struct silofs_destageq     *dsq,
                              const struct silofs_dirtyq *drq);

void silofs_destageq_depopulate(struct silofs_destageq *dsq);

void silofs_destageq_sort(struct silofs_destageq *dsq,
                          silofs_dqe_compare_fn   dqe_cmp_fn);

int silofs_destageq_foreach(const struct silofs_destageq *dsq,
                            silofs_dqe_execute_fn dqe_exec_fn, void *usep);

#endif /* SILOFS_DIRTYQ_H_ */
