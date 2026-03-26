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

static size_t hdr_size_by(uint8_t stype, enum silofs_hdrf flags)
{
	size_t sz;

	silofs_assert_gt(flags & (SILOFS_HDRF_PNODE | SILOFS_HDRF_VNODE), 0);

	if (flags & SILOFS_HDRF_PNODE) {
		sz = silofs_ptype_size(stype);
	} else if (flags & SILOFS_HDRF_VNODE) {
		sz = silofs_vtype_size(stype);
	} else {
		sz = sizeof(struct silofs_header);
	}
	return sz;
}

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

static uint8_t hdr_stype(const struct silofs_header *hdr)
{
	return hdr->h_stype;
}

static void hdr_set_stype(struct silofs_header *hdr, uint8_t stype)
{
	hdr->h_stype = stype;
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

void silofs_hdr_setup(struct silofs_header *hdr, uint8_t stype,
                      enum silofs_hdrf flags)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr_set_magic(hdr, SILOFS_META_MAGIC);
	hdr_set_size(hdr, hdr_size_by(stype, flags));
	hdr_set_stype(hdr, stype);
	hdr_set_flags(hdr, flags);
}

static int hdr_verify_base(const struct silofs_header *hdr, uint8_t stype,
                           enum silofs_hdrf flags)
{
	if (hdr_magic(hdr) != SILOFS_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_stype(hdr) != stype) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (!hdr_has_flags(hdr, flags)) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_size(hdr) != hdr_size_by(stype, flags)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static uint32_t hdr_calc_chekcsum(const struct silofs_header *hdr)
{
	const void *payload  = hdr_payload(hdr);
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

int silofs_hdr_verify(const struct silofs_header *hdr, uint8_t stype,
                      enum silofs_hdrf flags)
{
	int err;

	err = hdr_verify_base(hdr, stype, flags);
	if (err) {
		return err;
	}
	err = hdr_verify_checksum(hdr);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool view_isdata(enum silofs_vtype vtype)
{
	return silofs_vtype_isdata(vtype);
}

static size_t view_len(enum silofs_vtype vtype)
{
	return silofs_vtype_size(vtype);
}

static struct silofs_lview *
view_malloc(struct silofs_alloc *alloc, enum silofs_vtype vtype, int flags)
{
	return silofs_memalloc(alloc, view_len(vtype), flags);
}

static void view_free(struct silofs_lview *view, struct silofs_alloc *alloc,
                      enum silofs_vtype vtype, int flags)
{
	silofs_memfree(alloc, view, view_len(vtype), flags);
}

static void view_init_meta(struct silofs_lview *view, enum silofs_vtype vtype)
{
	memset(view, 0, view_len(vtype));
	silofs_hdr_setup(&view->u.hdr[0], (uint8_t)vtype, SILOFS_HDRF_VNODE);
}

static void view_init(struct silofs_lview *view, enum silofs_vtype vtype)
{
	if (!view_isdata(vtype)) {
		view_init_meta(view, vtype);
	}
}

static void view_fini_meta(struct silofs_lview *view, enum silofs_vtype vtype)
{
	const size_t nz = silofs_min(view_len(vtype), sizeof(view->u.hdr[0]));

	memset(view, 0, nz);
}

static void view_fini(struct silofs_lview *view, enum silofs_vtype vtype)
{
	if (!view_isdata(vtype)) {
		view_fini_meta(view, vtype);
	}
}

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_vtype vtype, int flags)
{
	struct silofs_lview *view = nullptr;

	view = view_malloc(alloc, vtype, flags);
	if (view != nullptr) {
		view_init(view, vtype);
	}
	return view;
}

void silofs_lview_del(struct silofs_lview *view, struct silofs_alloc *alloc,
                      enum silofs_vtype vtype, int flags)
{
	if (likely(view != nullptr)) {
		view_fini(view, vtype);
		view_free(view, alloc, vtype, flags);
	}
}

void silofs_seal_lview(struct silofs_lview *view)
{
	silofs_hdr_seal(&view->u.hdr[0]);
}

int silofs_verify_lview(const struct silofs_lview *view,
                        enum silofs_vtype vtype)
{
	int ret = 0;

	if (!silofs_vtype_isdata(vtype)) {
		ret = silofs_hdr_verify(&view->u.hdr[0], (uint8_t)vtype,
		                        SILOFS_HDRF_VNODE);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_lview *view,
                         enum silofs_vtype vtype, void *ptr)
{
	return silofs_encrypt_buf(ci_hd, civkey, view, ptr, view_len(vtype));
}

int silofs_decrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_lview *view,
                         enum silofs_vtype vtype, void *ptr)
{
	return silofs_decrypt_buf(ci_hd, civkey, view, ptr, view_len(vtype));
}

int silofs_encrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey *civkey,
                          const struct silofs_lview *lview,
                          struct silofs_lview *lview_enc, size_t len)
{
	return silofs_encrypt_buf(ci_hd, civkey, lview, lview_enc, len);
}

int silofs_decrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey *civkey,
                          const struct silofs_lview *lview_enc,
                          struct silofs_lview *lview, size_t len)
{
	return silofs_decrypt_buf(ci_hd, civkey, lview_enc, lview, len);
}

int silofs_decrypt_view_inplace(const struct silofs_cipher_hd *ci_hd,
                                const struct silofs_civkey *civkey,
                                struct silofs_lview *view,
                                enum silofs_vtype vtype)
{
	return silofs_decrypt_buf(ci_hd, civkey, view, view, view_len(vtype));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t pview_len(enum silofs_ptype ptype)
{
	return silofs_ptype_size(ptype);
}

static struct silofs_pview *
pview_malloc(struct silofs_alloc *alloc, enum silofs_ptype ptype, int flags)
{
	return silofs_memalloc(alloc, pview_len(ptype), flags);
}

static void pview_free(struct silofs_pview *pview, struct silofs_alloc *alloc,
                       enum silofs_ptype ptype, int flags)
{
	silofs_memfree(alloc, pview, pview_len(ptype), flags);
}

static void pview_bzero(struct silofs_pview *pview, enum silofs_ptype ptype)
{
	memset(pview, 0, pview_len(ptype));
}

static void pview_init(struct silofs_pview *pview, enum silofs_ptype ptype)
{
	pview_bzero(pview, ptype);
	silofs_hdr_setup(&pview->pv.hdr[0], (uint8_t)ptype, SILOFS_HDRF_PNODE);
}

static void pview_fini(struct silofs_pview *pview, enum silofs_ptype ptype)
{
	pview_bzero(pview, ptype);
}

struct silofs_pview *
silofs_pview_new(struct silofs_alloc *alloc, enum silofs_ptype ptype)
{
	struct silofs_pview *pview = nullptr;

	pview = pview_malloc(alloc, ptype, 0);
	if (pview != nullptr) {
		pview_init(pview, ptype);
	}
	return pview;
}

void silofs_pview_del(struct silofs_pview *pview, struct silofs_alloc *alloc,
                      enum silofs_ptype ptype)
{
	if (likely(pview != nullptr)) {
		pview_fini(pview, ptype);
		pview_free(pview, alloc, ptype, 0);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_seal_pview(struct silofs_pview *pview)
{
	silofs_hdr_seal(&pview->pv.hdr[0]);
}

int silofs_verify_pview(const struct silofs_pview *pview,
                        enum silofs_ptype ptype)
{
	return silofs_hdr_verify(&pview->pv.hdr[0], (uint8_t)ptype,
	                         SILOFS_HDRF_PNODE);
}

int silofs_encrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_pview *pview,
                         struct silofs_pview *pview_enc, size_t len)
{
	return silofs_encrypt_buf(ci_hd, civkey, pview, pview_enc, len);
}

int silofs_decrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_pview *pview_enc,
                         struct silofs_pview *pview, size_t len)
{
	return silofs_decrypt_buf(ci_hd, civkey, pview_enc, pview, len);
}
