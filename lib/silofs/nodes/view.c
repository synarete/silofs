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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

static size_t
hdr_size_by(const struct silofs_stype *stype, enum silofs_hdrf flags)
{
	size_t sz;

	silofs_assert_gt(flags & (SILOFS_HDRF_PNODE | SILOFS_HDRF_LNODE), 0);

	if (flags & SILOFS_HDRF_PNODE) {
		sz = silofs_ptype_size(stype->ptype);
	} else if (flags & SILOFS_HDRF_LNODE) {
		sz = silofs_ltype_size(stype->ltype);
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

static void
hdr_stype(const struct silofs_header *hdr, struct silofs_stype *out_stype)
{
	out_stype->ptype = (enum silofs_ptype)hdr->h_ptype;
	out_stype->ltype = (enum silofs_ltype)hdr->h_ltype;
}

static void
hdr_set_stype(struct silofs_header *hdr, const struct silofs_stype *stype)
{
	hdr->h_ptype = (uint8_t)(stype->ptype);
	hdr->h_ltype = (uint8_t)(stype->ltype);
}

static bool hdr_has_stype(const struct silofs_header *hdr,
                          const struct silofs_stype *stype)
{
	struct silofs_stype h_stype;

	hdr_stype(hdr, &h_stype);
	return ((h_stype.ptype == stype->ptype) &&
	        (h_stype.ltype == stype->ltype));
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

void silofs_hdr_setup(struct silofs_header *hdr,
                      const struct silofs_stype *stype, enum silofs_hdrf flags)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr_set_magic(hdr, SILOFS_META_MAGIC);
	hdr_set_size(hdr, hdr_size_by(stype, flags));
	hdr_set_stype(hdr, stype);
	hdr_set_flags(hdr, flags);
}

static int
hdr_verify_base(const struct silofs_header *hdr,
                const struct silofs_stype *stype, enum silofs_hdrf flags)
{
	if (hdr_magic(hdr) != SILOFS_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (!hdr_has_stype(hdr, stype)) {
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

int silofs_hdr_verify(const struct silofs_header *hdr,
                      const struct silofs_stype *stype, enum silofs_hdrf flags)
{
	int err;

	err = hdr_verify_base(hdr, stype, flags);
	return_if_err(err);

	err = hdr_verify_checksum(hdr);
	return_if_err(err);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool lview_isdata(enum silofs_ltype ltype)
{
	return silofs_ltype_isdata(ltype);
}

static size_t lview_len(enum silofs_ltype ltype)
{
	return silofs_ltype_size(ltype);
}

static struct silofs_lview *
lview_malloc(struct silofs_alloc *alloc, enum silofs_ltype ltype, int flags)
{
	return silofs_memalloc(alloc, lview_len(ltype), flags);
}

static void lview_free(struct silofs_lview *lview, struct silofs_alloc *alloc,
                       enum silofs_ltype ltype, int flags)
{
	silofs_memfree(alloc, lview, lview_len(ltype), flags);
}

static void
lview_init_meta(struct silofs_lview *lview, enum silofs_ltype ltype)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_LNODE,
		.ltype = ltype,
	};

	memset(lview, 0, lview_len(ltype));
	silofs_hdr_setup(&lview->u.hdr[0], &stype, SILOFS_HDRF_LNODE);
}

void silofs_lview_setup(struct silofs_lview *lview, enum silofs_ltype ltype)
{
	if (!lview_isdata(ltype)) {
		lview_init_meta(lview, ltype);
	}
}

static void
lview_fini_meta(struct silofs_lview *lview, enum silofs_ltype ltype)
{
	const size_t nz =
		silofs_min(lview_len(ltype), sizeof(lview->u.hdr[0]));

	memset(lview, 0, nz);
}

static void lview_fini(struct silofs_lview *lview, enum silofs_ltype ltype)
{
	if (!lview_isdata(ltype)) {
		lview_fini_meta(lview, ltype);
	}
}

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_ltype ltype, int flags)
{
	struct silofs_lview *lview = nullptr;

	lview = lview_malloc(alloc, ltype, flags);
	if (lview != nullptr) {
		silofs_lview_setup(lview, ltype);
	}
	return lview;
}

void silofs_lview_del(struct silofs_lview *lview, struct silofs_alloc *alloc,
                      enum silofs_ltype ltype, int flags)
{
	if (likely(lview != nullptr)) {
		lview_fini(lview, ltype);
		lview_free(lview, alloc, ltype, flags);
	}
}

void silofs_lview_seal(struct silofs_lview *lview)
{
	silofs_hdr_seal(&lview->u.hdr[0]);
}

int silofs_lview_verify(const struct silofs_lview *lview,
                        enum silofs_ltype ltype)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_LNODE,
		.ltype = ltype,
	};

	if (silofs_ltype_isdata(ltype)) {
		return 0;
	}

	return silofs_hdr_verify(&lview->u.hdr[0], &stype, SILOFS_HDRF_LNODE);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t pview_len(enum silofs_ptype ptype)
{
	return silofs_ptype_size(ptype);
}

static void pview_bzero(struct silofs_pview *pview, enum silofs_ptype ptype)
{
	memset(pview, 0, pview_len(ptype));
}

void silofs_pview_setup(struct silofs_pview *pview,
                        const struct silofs_stype *stype)
{
	pview_bzero(pview, stype->ptype);
	silofs_hdr_setup(&pview->pv.hdr[0], stype, SILOFS_HDRF_PNODE);
}

void silofs_pview_seal(struct silofs_pview *pview)
{
	silofs_hdr_seal(&pview->pv.hdr[0]);
}

int silofs_pview_verify(const struct silofs_pview *pview,
                        const struct silofs_stype *stype)
{
	return silofs_hdr_verify(&pview->pv.hdr[0], stype, SILOFS_HDRF_PNODE);
}
