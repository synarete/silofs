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
#ifndef SILOFS_NODE_H_
#define SILOFS_NODE_H_

/* de-stage queue */
struct silofs_dstgq {
	struct silofs_listq dq;
};

/* union of all sub view */
union silofs_view {
	struct silofs_pview *pview;
	struct silofs_lview *lview;
	void                *opaque_view;
};

/* nodes' control state-flags */
enum silofs_ni_flags {
	SILOFS_NIF_RECHECKED = SILOFS_BIT(0),
	SILOFS_NIF_PINNED    = SILOFS_BIT(1),
	SILOFS_NIF_LOOSE     = SILOFS_BIT(2),
};

/* base of all in-memory node representations */
struct silofs_node_info {
	struct silofs_hmapq_elem hmqe;
	struct silofs_dq_elem    dqe;
	int                      flags;
	union silofs_view        view;
	union silofs_view        viewx;

	bool (*isevictable_fn)(const struct silofs_node_info *ni);
};

void silofs_ni_init(struct silofs_node_info *ni, size_t view_size);

void silofs_ni_fini(struct silofs_node_info *ni);

void silofs_ni_incref(struct silofs_node_info *ni);

void silofs_ni_decref(struct silofs_node_info *ni);

size_t silofs_ni_refcnt(const struct silofs_node_info *ni);

void silofs_ni_setf(struct silofs_node_info *ni, enum silofs_ni_flags f);

void silofs_ni_clearf(struct silofs_node_info *ni, enum silofs_ni_flags f);

bool silofs_ni_testf(const struct silofs_node_info *ni,
                     enum silofs_ni_flags           f);

bool silofs_ni_isevictable(const struct silofs_node_info *ni);

size_t silofs_ni_view_size(const struct silofs_node_info *ni);

int silofs_ni_attach_view(struct silofs_node_info *ni,  //
                          struct silofs_alloc *alloc, bool bzero);

void silofs_ni_detach_view(struct silofs_node_info *ni, //
                           struct silofs_alloc *alloc, bool bzero);

int silofs_ni_attach_viewx(struct silofs_node_info *ni,
                           struct silofs_alloc     *alloc);

void silofs_ni_detach_viewx(struct silofs_node_info *ni,
                            struct silofs_alloc     *alloc);

const struct silofs_node_info * //
silofs_ni_from_hmqe(const struct silofs_hmapq_elem *hmqe);

struct silofs_node_info *       //
silofs_ni_from_mut_hmqe(struct silofs_hmapq_elem *hmqe);

const struct silofs_node_info * //
silofs_ni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_node_info *       //
silofs_ni_from_mut_dqe(struct silofs_dq_elem *dqe);

#endif                          /* SILOFS_NODE_H_ */
