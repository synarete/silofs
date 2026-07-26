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
#include <silofs/ondisk.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool ni_isevictable(const struct silofs_node_info *ni)
{
	if (silofs_ni_testf(ni, SILOFS_NIF_PINNED)) {
		return false;
	}
	if (silofs_dqe_isinq(&ni->dqe)) {
		return false;
	}
	if (silofs_ni_refcnt(ni) > 0) {
		return false;
	}
	return true;
}

void silofs_ni_init(struct silofs_node_info *ni,
                    const struct silofs_stype *stype)
{
	const size_t sz = silofs_stype_size(stype);

	silofs_hmqe_init(&ni->hmqe);
	silofs_dqe_init(&ni->dqe, sz);
	silofs_stype_assign(&ni->stype, stype);
	ni->view.opaque_view  = nullptr;
	ni->viewx.opaque_view = nullptr;
	ni->flags             = 0;
	ni->isevictable_fn    = ni_isevictable;
}

void silofs_ni_fini(struct silofs_node_info *ni)
{
	silofs_hmqe_fini(&ni->hmqe);
	silofs_dqe_fini(&ni->dqe);
}

void silofs_ni_setf(struct silofs_node_info *ni, enum silofs_ni_flags f)
{
	ni->flags |= (unsigned)f;
}

void silofs_ni_clearf(struct silofs_node_info *ni, enum silofs_ni_flags f)
{
	ni->flags &= ~((unsigned)f);
}

bool silofs_ni_testf(const struct silofs_node_info *ni, enum silofs_ni_flags f)
{
	const unsigned v = (unsigned)f;

	return ((ni->flags & v) == v);
}

void silofs_ni_incref(struct silofs_node_info *ni)
{
	silofs_hmqe_incref(&ni->hmqe);
}

void silofs_ni_decref(struct silofs_node_info *ni)
{
	silofs_hmqe_decref(&ni->hmqe);
}

size_t silofs_ni_refcnt(const struct silofs_node_info *ni)
{
	const int refcnt = silofs_hmqe_refcnt(&ni->hmqe);

	silofs_assert_ge(refcnt, 0);
	silofs_assert_lt(refcnt, INT32_MAX);

	return (size_t)refcnt;
}

bool silofs_ni_isevictable(const struct silofs_node_info *ni)
{
	return ni_isevictable(ni);
}

const struct silofs_node_info *
silofs_ni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_node_info *ni = nullptr;

	if (hmqe != nullptr) {
		ni = container_of(hmqe, struct silofs_node_info, hmqe);
	}
	return ni;
}

struct silofs_node_info *
silofs_ni_from_mut_hmqe(struct silofs_hmapq_elem *hmqe)
{
	struct silofs_node_info *ni = nullptr;

	if (hmqe != nullptr) {
		ni = mut_container_of(hmqe, struct silofs_node_info, hmqe);
	}
	return ni;
}

const struct silofs_node_info *
silofs_ni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_node_info *ni = nullptr;

	if (dqe != nullptr) {
		ni = container_of(dqe, struct silofs_node_info, dqe);
	}
	return ni;
}

struct silofs_node_info * //
silofs_ni_from_mut_dqe(struct silofs_dq_elem *dqe)
{
	struct silofs_node_info *ni = nullptr;

	if (dqe != nullptr) {
		ni = mut_container_of(dqe, struct silofs_node_info, dqe);
	}
	return ni;
}

void silofs_ni_set_dq(struct silofs_node_info *ni, struct silofs_dirtyq *dq)
{
	silofs_dqe_set_dirtyq(&ni->dqe, dq);
}

bool silofs_ni_isdirty(const struct silofs_node_info *ni)
{
	return silofs_dqe_isdirty(&ni->dqe);
}

void silofs_ni_setdirty(struct silofs_node_info *ni)
{
	if (!silofs_ni_isdirty(ni)) {
		silofs_dqe_setdirty(&ni->dqe);
	}
}

void silofs_ni_cleardirty(struct silofs_node_info *ni)
{
	if (silofs_ni_isdirty(ni)) {
		silofs_dqe_cleardirty(&ni->dqe);
	}
}

size_t silofs_ni_view_size(const struct silofs_node_info *ni)
{
	const size_t view_size = ni->dqe.sz;

	silofs_assert_gt(view_size, 0);
	silofs_assert_le(view_size, 65536);

	return view_size;
}

static enum silofs_allocf allocf_of(size_t vsize, bool bzero, bool trypunch)
{
	enum silofs_allocf allocf = SILOFS_ALLOCF_NONE;

	if (trypunch && (vsize >= 8192)) {
		allocf |= SILOFS_ALLOCF_TRYPUNCH;
	}
	if (bzero) {
		allocf |= SILOFS_ALLOCF_BZERO;
	}
	return allocf;
}

static int ni_attach_view_at(struct silofs_node_info *ni, void **view,
                             struct silofs_alloc *alloc, bool bzero)
{
	const size_t vsize        = silofs_ni_view_size(ni);
	enum silofs_allocf allocf = allocf_of(vsize, bzero, false);

	*view = silofs_memalloc(alloc, vsize, (int)allocf);
	return (*view == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void ni_detach_view_at(struct silofs_node_info *ni, void **view,
                              struct silofs_alloc *alloc, bool bzero)
{
	const size_t vsize        = silofs_ni_view_size(ni);
	enum silofs_allocf allocf = allocf_of(vsize, bzero, true);

	silofs_memfree(alloc, *view, vsize, (int)allocf);
	*view = nullptr;
}

int silofs_ni_attach_view(struct silofs_node_info *ni, //
                          struct silofs_alloc *alloc, bool bzero)
{
	void **view = &ni->view.opaque_view;
	int ret;

	if (*view == nullptr) {
		ret = ni_attach_view_at(ni, view, alloc, bzero);
	} else {
		ret = 0;
	}
	return ret;
}

void silofs_ni_detach_view(struct silofs_node_info *ni,
                           struct silofs_alloc *alloc, bool bzero)
{
	void **view = &ni->view.opaque_view;

	if (*view != nullptr) {
		ni_detach_view_at(ni, view, alloc, bzero);
	}
}

int silofs_ni_attach_viewx(struct silofs_node_info *ni,
                           struct silofs_alloc *alloc)
{
	void **view = &ni->viewx.opaque_view;
	int ret     = 0;

	if (*view == nullptr) {
		ret = ni_attach_view_at(ni, view, alloc, false);
	}
	return ret;
}

void silofs_ni_detach_viewx(struct silofs_node_info *ni,
                            struct silofs_alloc *alloc)
{
	void **view = &ni->viewx.opaque_view;

	if (*view != nullptr) {
		ni_detach_view_at(ni, view, alloc, false);
	}
}
