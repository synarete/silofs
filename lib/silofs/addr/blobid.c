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
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>

static const struct silofs_blobid s_blobid_none = {
	.stype.ptype = SILOFS_PTYPE_NONE,
	.stype.ltype = SILOFS_LTYPE_NONE,
	.vers        = SILOFS_FMT_VERSION,
};

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_blobid_none;
}

static void blobid_clear(struct silofs_blobid *blobid)
{
	silofs_layerid_reset(&blobid->layerid);
	silofs_uniqid_reset(&blobid->uniqid);
	silofs_stype_clear(&blobid->stype);
	blobid->vers = 0;
}

void silofs_blobid_init(struct silofs_blobid *blobid,
                        const struct silofs_stype *stype,
                        const struct silofs_layerid *layerid,
                        const struct silofs_uniqid *uniqid)
{
	silofs_layerid_assignx(&blobid->layerid, layerid);
	silofs_uniqid_assignx(&blobid->uniqid, uniqid);
	silofs_stype_assign(&blobid->stype, stype);
	blobid->vers = SILOFS_FMT_VERSION;
}

void silofs_blobid_fini(struct silofs_blobid *blobid)
{
	blobid_clear(blobid);
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	blobid_clear(blobid);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	silofs_layerid_assign(&blobid->layerid, &other->layerid);
	silofs_uniqid_assign(&blobid->uniqid, &other->uniqid);
	silofs_stype_assign(&blobid->stype, &other->stype);
	blobid->stype.ptype = other->stype.ptype;
	blobid->stype.ltype = other->stype.ltype;
	blobid->vers        = other->vers;
}

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	long cmp;

	cmp = silofs_stype_compare(&blobid->stype, &other->stype);
	if (cmp != 0) {
		goto out;
	}
	cmp = silofs_layerid_compare(&blobid->layerid, &other->layerid);
	if (cmp != 0) {
		goto out;
	}
	cmp = silofs_uniqid_compare(&blobid->uniqid, &other->uniqid);
	if (cmp != 0) {
		goto out;
	}
	cmp = (long)blobid->vers - (long)other->vers;
out:
	return cmp;
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return (silofs_blobid_compare(blobid, other) == 0);
}

bool silofs_blobid_has_stype(const struct silofs_blobid *blobid,
                             const struct silofs_stype *stype)
{
	return silofs_stype_isequal(&blobid->stype, stype);
}

size_t silofs_blobid_slotsize(const struct silofs_blobid *blobid)
{
	return silofs_stype_size(&blobid->stype);
}

void silofs_blobid48b_htox(struct silofs_blobid48b *blobid48,
                           const struct silofs_blobid *blobid)
{
	memset(blobid48, 0, sizeof(*blobid48));
	silofs_layerid_assign(&blobid48->layerid, &blobid->layerid);
	silofs_uniqid_assign(&blobid48->uniqid, &blobid->uniqid);
	blobid48->ptype = (uint8_t)blobid->stype.ptype;
	blobid48->ltype = (uint8_t)blobid->stype.ltype;
	blobid48->vers  = silofs_cpu_to_le16(blobid->vers);
}

void silofs_blobid48b_xtoh(const struct silofs_blobid48b *blobid48,
                           struct silofs_blobid *blobid)
{
	silofs_layerid_assign(&blobid->layerid, &blobid48->layerid);
	silofs_uniqid_assign(&blobid->uniqid, &blobid48->uniqid);
	blobid->stype.ptype = (enum silofs_ptype)blobid48->ptype;
	blobid->stype.ltype = (enum silofs_ltype)blobid48->ltype;
	blobid->vers        = silofs_le16_to_cpu(blobid48->vers);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobidx_setup(struct silofs_blobidx *blobidx,
                          const struct silofs_hash256 *h)
{
	silofs_hash256_assign(&blobidx->idx, h);
}

void silofs_blobidx_assign(struct silofs_blobidx *blobidx,
                           const struct silofs_blobidx *other)
{
	silofs_blobidx_setup(blobidx, &other->idx);
}

void silofs_blobidx_derive(struct silofs_blobidx *blobidx,
                           const struct silofs_mdigest_hd *md_hd,
                           const struct silofs_blobid *blobid)
{
	struct silofs_blobid48b blobid48b;
	struct silofs_hash256 hash;

	silofs_blobid48b_htox(&blobid48b, blobid);
	silofs_sha3_256_of(md_hd, &blobid48b, sizeof(blobid48b), &hash);
	silofs_blobidx_setup(blobidx, &hash);
}

bool silofs_blobidx_isequal(const struct silofs_blobidx *blobidx,
                            const struct silofs_blobidx *other)
{
	return silofs_hash256_isequal(&blobidx->idx, &other->idx);
}

int silofs_blobidx_to_str(const struct silofs_blobidx *blobidx, char *str,
                          size_t len)
{
	return silofs_hash256_to_str(&blobidx->idx, str, len);
}

int silofs_blobidx_from_str(struct silofs_blobidx *blobidx, const char *str,
                            size_t len)
{
	return silofs_hash256_from_str(&blobidx->idx, str, len);
}
