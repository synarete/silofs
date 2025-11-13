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
#include "configs.h"
#include <stdlib.h>
#include <silofs/ondisk.h>
#include "addr.h"
#include "crypt.h"
#include "view.h"

static bool view_isdata(enum silofs_mtype mtype)
{
	return silofs_mtype_isdata(mtype);
}

static size_t view_len(enum silofs_mtype mtype)
{
	return silofs_mtype_size(mtype);
}

static struct silofs_view *
view_malloc(struct silofs_alloc *alloc, enum silofs_mtype mtype, int flags)
{
	return silofs_memalloc(alloc, view_len(mtype), flags);
}

static void view_free(struct silofs_view *view, struct silofs_alloc *alloc,
                      enum silofs_mtype mtype, int flags)
{
	silofs_memfree(alloc, view, view_len(mtype), flags);
}

static void view_init_meta(struct silofs_view *view, enum silofs_mtype mtype)
{
	const size_t size = view_len(mtype);

	memset(view, 0, size);
	silofs_hdr_setup(&view->u.hdr[0], (uint16_t)mtype, size);
}

static void view_init(struct silofs_view *view, enum silofs_mtype mtype)
{
	if (!view_isdata(mtype)) {
		view_init_meta(view, mtype);
	}
}

static void view_fini_meta(struct silofs_view *view, enum silofs_mtype mtype)
{
	const size_t nz = silofs_min(view_len(mtype), sizeof(view->u.hdr[0]));

	memset(view, 0, nz);
}

static void view_fini(struct silofs_view *view, enum silofs_mtype mtype)
{
	if (!view_isdata(mtype)) {
		view_fini_meta(view, mtype);
	}
}

struct silofs_view *
silofs_view_new(struct silofs_alloc *alloc, enum silofs_mtype mtype, int flags)
{
	struct silofs_view *view = nullptr;

	view = view_malloc(alloc, mtype, flags);
	if (view != nullptr) {
		view_init(view, mtype);
	}
	return view;
}

void silofs_view_del(struct silofs_view *view, struct silofs_alloc *alloc,
                     enum silofs_mtype mtype, int flags)
{
	if (likely(view != nullptr)) {
		view_fini(view, mtype);
		view_free(view, alloc, mtype, flags);
	}
}

void silofs_view_seal(struct silofs_view *view)
{
	silofs_hdr_seal(&view->u.hdr[0]);
}

int silofs_view_verify(const struct silofs_view *view, enum silofs_mtype mtype)
{
	return silofs_hdr_verify2(&view->u.hdr[0], mtype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_ivkey *ivkey,
                        const struct silofs_view *view,
                        enum silofs_mtype mtype, void *ptr)
{
	return silofs_encrypt_buf(cipher, ivkey, view, ptr, view_len(mtype));
}

int silofs_decrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_ivkey *ivkey,
                        const struct silofs_view *view,
                        enum silofs_mtype mtype, void *ptr)
{
	return silofs_decrypt_buf(cipher, ivkey, view, ptr, view_len(mtype));
}

int silofs_decrypt_view_inplace(const struct silofs_cipher *cipher,
                                const struct silofs_ivkey *ivkey,
                                struct silofs_view *view,
                                enum silofs_mtype mtype)
{
	return silofs_decrypt_buf(cipher, ivkey, view, view, view_len(mtype));
}
