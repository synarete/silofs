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

static uint32_t hdr_magic(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_magic);
}

static void hdr_set_magic(struct silofs_header *hdr, uint32_t magic)
{
	hdr->h_magic = silofs_cpu_to_le32(magic);
}

static size_t hdr_size(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_size);
}

static void hdr_set_size(struct silofs_header *hdr, size_t size)
{
	silofs_assert_gt(size, sizeof(*hdr));
	silofs_assert_le(size, SILOFS_LBK_SIZE);

	hdr->h_size = silofs_cpu_to_le32((uint32_t)size);
}

static size_t hdr_payload_size(const struct silofs_header *hdr)
{
	const size_t size = hdr_size(hdr);

	silofs_assert_gt(size, sizeof(*hdr));
	silofs_assert_le(size, SILOFS_LBK_SIZE);

	return size - sizeof(*hdr);
}

static enum silofs_mtype hdr_mtype(const struct silofs_header *hdr)
{
	const uint8_t mtype = hdr->h_mtype;

	return (enum silofs_mtype)mtype;
}

static void hdr_set_mtype(struct silofs_header *hdr, enum silofs_mtype mtype)
{
	hdr->h_mtype = (uint8_t)mtype;
}

static enum silofs_hdrf hdr_flags(const struct silofs_header *hdr)
{
	const int flags = (int)silofs_le16_to_cpu(hdr->h_flags);

	return (enum silofs_hdrf)flags;
}

static void hdr_set_flags(struct silofs_header *hdr, enum silofs_hdrf flags)
{
	silofs_assert_le(hdr->h_size, SILOFS_LBK_SIZE);

	hdr->h_flags = silofs_cpu_to_le16((uint16_t)flags);
}

static void hdr_add_flags(struct silofs_header *hdr, enum silofs_hdrf flags)
{
	hdr_set_flags(hdr, flags | hdr_flags(hdr));
}

static bool
hdr_has_flags(const struct silofs_header *hdr, enum silofs_hdrf flags)
{
	return (hdr_flags(hdr) & flags) > 0;
}

static uint32_t hdr_csum(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct silofs_header *hdr, uint32_t csum)
{
	hdr->h_csum = silofs_cpu_to_le32(csum);
	hdr_add_flags(hdr, SILOFS_HDRF_CSUM);
}

static bool hdr_has_csum(const struct silofs_header *hdr)
{
	return hdr_has_flags(hdr, SILOFS_HDRF_CSUM);
}

static const void *hdr_payload(const struct silofs_header *hdr)
{
	return hdr + 1;
}

void silofs_hdr_setup(struct silofs_header *hdr, enum silofs_mtype mtype)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr_set_magic(hdr, SILOFS_META_MAGIC);
	hdr_set_size(hdr, silofs_mtype_size(mtype));
	hdr_set_mtype(hdr, mtype);
	hdr_set_flags(hdr, SILOFS_HDRF_NONE);
}

static int
hdr_verify_base(const struct silofs_header *hdr, enum silofs_mtype mtype,
                size_t size, enum silofs_hdrf flags)
{
	if (hdr_magic(hdr) != SILOFS_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_mtype(hdr) != mtype) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_size(hdr) != size) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (!hdr_has_flags(hdr, flags)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static uint32_t hdr_calc_chekcsum(const struct silofs_header *hdr)
{
	const void  *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	return silofs_xxh32(payload, pl_size, SILOFS_META_MAGIC);
}

void silofs_hdr_seal(struct silofs_header *hdr)
{
	const uint32_t csum = hdr_calc_chekcsum(hdr);

	hdr_set_csum(hdr, csum);
}

static int hdr_verify_checksum(const struct silofs_header *hdr)
{
	uint32_t csum;

	if (!hdr_has_csum(hdr)) {
		return 0;
	}
	csum = hdr_calc_chekcsum(hdr);
	if (csum != hdr_csum(hdr)) {
		return -SILOFS_EFSBADCRC;
	}
	return 0;
}

static int
hdr_verify_by(const struct silofs_header *hdr, enum silofs_mtype mtype,
              size_t size, enum silofs_hdrf flags)
{
	int err;

	err = hdr_verify_base(hdr, mtype, size, flags);
	if (!err && (flags & SILOFS_HDRF_CSUM)) {
		err = hdr_verify_checksum(hdr);
	}
	return err;
}

int silofs_hdr_verify(const struct silofs_header *hdr, enum silofs_mtype mtype)
{
	const size_t     size  = silofs_mtype_size(mtype);
	enum silofs_hdrf flags = SILOFS_HDRF_CSUM;

	return hdr_verify_by(hdr, (uint16_t)mtype, size, flags);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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
	memset(view, 0, view_len(mtype));
	silofs_hdr_setup(&view->u.hdr[0], mtype);
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
	int ret = 0;

	if (!silofs_mtype_isdata(mtype)) {
		ret = silofs_hdr_verify(&view->u.hdr[0], mtype);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_civkey *civkey,
                        const struct silofs_view   *view,
                        enum silofs_mtype mtype, void *ptr)
{
	return silofs_encrypt_buf(cipher, civkey, view, ptr, view_len(mtype));
}

int silofs_decrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_civkey *civkey,
                        const struct silofs_view   *view,
                        enum silofs_mtype mtype, void *ptr)
{
	return silofs_decrypt_buf(cipher, civkey, view, ptr, view_len(mtype));
}

int silofs_decrypt_view_inplace(const struct silofs_cipher *cipher,
                                const struct silofs_civkey *civkey,
                                struct silofs_view         *view,
                                enum silofs_mtype           mtype)
{
	return silofs_decrypt_buf(cipher, civkey, view, view, view_len(mtype));
}
