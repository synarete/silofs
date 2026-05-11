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

	return (uint32_t)silofs_xxh3(payload, pl_size);
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
		return -SILOFS_EBADMSG;
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

static bool lview_isdata(enum silofs_vtype vtype)
{
	return silofs_vtype_isdata(vtype);
}

static size_t lview_len(enum silofs_vtype vtype)
{
	return silofs_vtype_size(vtype);
}

static struct silofs_lview *
lview_malloc(struct silofs_alloc *alloc, enum silofs_vtype vtype, int flags)
{
	return silofs_memalloc(alloc, lview_len(vtype), flags);
}

static void lview_free(struct silofs_lview *lview, struct silofs_alloc *alloc,
                       enum silofs_vtype vtype, int flags)
{
	silofs_memfree(alloc, lview, lview_len(vtype), flags);
}

static void
lview_init_meta(struct silofs_lview *lview, enum silofs_vtype vtype)
{
	memset(lview, 0, lview_len(vtype));
	silofs_hdr_setup(&lview->u.hdr[0], (uint8_t)vtype, SILOFS_HDRF_VNODE);
}

static void lview_init(struct silofs_lview *lview, enum silofs_vtype vtype)
{
	if (!lview_isdata(vtype)) {
		lview_init_meta(lview, vtype);
	}
}

static void
lview_fini_meta(struct silofs_lview *lview, enum silofs_vtype vtype)
{
	const size_t nz =
		silofs_min(lview_len(vtype), sizeof(lview->u.hdr[0]));

	memset(lview, 0, nz);
}

static void lview_fini(struct silofs_lview *lview, enum silofs_vtype vtype)
{
	if (!lview_isdata(vtype)) {
		lview_fini_meta(lview, vtype);
	}
}

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_vtype vtype, int flags)
{
	struct silofs_lview *lview = nullptr;

	lview = lview_malloc(alloc, vtype, flags);
	if (lview != nullptr) {
		lview_init(lview, vtype);
	}
	return lview;
}

void silofs_lview_del(struct silofs_lview *lview, struct silofs_alloc *alloc,
                      enum silofs_vtype vtype, int flags)
{
	if (likely(lview != nullptr)) {
		lview_fini(lview, vtype);
		lview_free(lview, alloc, vtype, flags);
	}
}

void silofs_seal_lview(struct silofs_lview *lview)
{
	silofs_hdr_seal(&lview->u.hdr[0]);
}

int silofs_verify_lview(const struct silofs_lview *lview,
                        enum silofs_vtype vtype)
{
	int ret = 0;

	if (!silofs_vtype_isdata(vtype)) {
		ret = silofs_hdr_verify(&lview->u.hdr[0], (uint8_t)vtype,
		                        SILOFS_HDRF_VNODE);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_lview *lview,
                         enum silofs_vtype vtype, void *ptr)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = lview,
		.data_out = ptr,
		.data_len = lview_len(vtype),
	};

	return silofs_encrypt(&ed_ctx);
}

int silofs_decrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_lview *lview,
                         enum silofs_vtype vtype, void *ptr)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = lview,
		.data_out = ptr,
		.data_len = lview_len(vtype),
	};

	return silofs_decrypt(&ed_ctx);
}

int silofs_decrypt_view_inplace(const struct silofs_cipher_hd *ci_hd,
                                const struct silofs_civkey *civkey,
                                struct silofs_lview *lview,
                                enum silofs_vtype vtype)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = lview,
		.data_out = lview,
		.data_len = lview_len(vtype),
	};

	return silofs_decrypt(&ed_ctx);
}

int silofs_encrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey *civkey,
                          const struct silofs_lview *lview,
                          struct silofs_lview *lview_enc, size_t len)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = lview,
		.data_out = lview_enc,
		.data_len = len,
	};

	return silofs_encrypt(&ed_ctx);
}

int silofs_decrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey *civkey,
                          const struct silofs_lview *lview_enc,
                          struct silofs_lview *lview, size_t len)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = lview_enc,
		.data_out = lview,
		.data_len = len,
	};

	return silofs_decrypt(&ed_ctx);
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
                         const struct silofs_caad *caad,
                         const struct silofs_pview *pview_in,
                         struct silofs_pview *pview_out,
                         struct silofs_ctag *ctag_out, size_t pview_len)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = caad,
		.ctag_in  = nullptr,
		.ctag_out = ctag_out,
		.data_in  = pview_in,
		.data_out = pview_out,
		.data_len = pview_len,
	};

	return silofs_encrypt(&ed_ctx);
}

int silofs_decrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         const struct silofs_caad *caad,
                         const struct silofs_ctag *ctag_in,
                         const struct silofs_pview *pview_in,
                         struct silofs_pview *pview_out, size_t pview_len)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = caad,
		.ctag_in  = nullptr, /* FIXME pview_out, */
		.ctag_out = nullptr,
		.data_in  = pview_in,
		.data_out = pview_out,
		.data_len = pview_len,
	};

	/* TODO: rm */
	silofs_unused(ctag_in);

	return silofs_decrypt(&ed_ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void dsqe_init(struct silofs_dsq_elem *dsqe)
{
	silofs_list_head_init(&dsqe->lh);
	dsqe->inq = false;
}

static void dsqe_fini(struct silofs_dsq_elem *dsqe)
{
	silofs_assert_eq(dsqe->inq, false);
	silofs_list_head_fini(&dsqe->lh);
}

static void
dsqe_push_to(struct silofs_dsq_elem *dsqe, struct silofs_listq *dsq)
{
	silofs_assert_eq(dsqe->inq, false);
	silofs_listq_push_back(dsq, &dsqe->lh);
	dsqe->inq = true;
}

static void
dsqe_pop_from(struct silofs_dsq_elem *dsqe, struct silofs_listq *dsq)
{
	silofs_assert_eq(dsqe->inq, true);
	silofs_listq_remove(dsq, &dsqe->lh);
	dsqe->inq = false;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ni_init(struct silofs_node_info *ni, size_t view_size)
{
	silofs_assert_gt(view_size, 0);
	silofs_assert_le(view_size, 65536);

	silofs_hmqe_init(&ni->hmqe, view_size);
	dsqe_init(&ni->dsqe);
	ni->view.opaque_view     = nullptr;
	ni->view_enc.opaque_view = nullptr;
}

void silofs_ni_fini(struct silofs_node_info *ni)
{
	silofs_hmqe_fini(&ni->hmqe);
	dsqe_fini(&ni->dsqe);
}

void silofs_ni_incref(struct silofs_node_info *ni)
{
	silofs_hmqe_incref(&ni->hmqe);
}

void silofs_ni_decref(struct silofs_node_info *ni)
{
	silofs_hmqe_decref(&ni->hmqe);
}

void silofs_ni_push_dsq(struct silofs_node_info *ni, struct silofs_listq *dsq)
{
	dsqe_push_to(&ni->dsqe, dsq);
}

void silofs_ni_pop_dsq(struct silofs_node_info *ni, struct silofs_listq *dsq)
{
	dsqe_pop_from(&ni->dsqe, dsq);
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
silofs_ni_from_dsqe(const struct silofs_dsq_elem *dsqe)
{
	const struct silofs_node_info *ni = nullptr;

	if (dsqe != nullptr) {
		ni = container_of(dsqe, struct silofs_node_info, dsqe);
	}
	return ni;
}

struct silofs_node_info *silofs_ni_from_mut_dsqe(struct silofs_dsq_elem *dsqe)
{
	struct silofs_node_info *ni = nullptr;

	if (dsqe != nullptr) {
		ni = mut_container_of(dsqe, struct silofs_node_info, dsqe);
	}
	return ni;
}
