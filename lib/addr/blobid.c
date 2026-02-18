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
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "hash.h"
#include "blobid.h"

static const struct silofs_blobid s_blobid_none = {
	.flags  = SILOFS_BIDF_NONE,
	.vspace = SILOFS_MTYPE_NONE,
	.vers   = SILOFS_FMT_VERSION,
};

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_blobid_none;
}

static void blobid_clear(struct silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

static void blobid_init_common(struct silofs_blobid *blobid)
{
	blobid_clear(blobid);
	blobid->vers = SILOFS_FMT_VERSION;
}

void silofs_blobid_initp(struct silofs_blobid *blobid, enum silofs_ptype ptype)
{
	blobid_init_common(blobid);
	blobid->stype.ptype = ptype;
	blobid->flags       = SILOFS_BIDF_PNODE;
}

void silofs_blobid_initv(struct silofs_blobid *blobid, enum silofs_mtype mtype)
{
	blobid_init_common(blobid);
	blobid->stype.mtype = mtype;
	blobid->flags       = SILOFS_BIDF_VNODE;
	blobid->vspace      = mtype;
}

void silofs_blobid_fini(struct silofs_blobid *blobid)
{
	blobid_clear(blobid);
}

static uint8_t blobid_stype(const struct silofs_blobid *blobid)
{
	uint8_t stype;

	if (blobid->flags & SILOFS_BIDF_PNODE) {
		stype = (uint8_t)blobid->stype.ptype;
	} else if (blobid->flags & SILOFS_BIDF_VNODE) {
		stype = (uint8_t)blobid->stype.mtype;
	} else {
		stype = 0;
	}
	return stype;
}

static void blobid_set_stype(struct silofs_blobid *blobid, unsigned stype,
                             enum silofs_bidf bidf)
{
	blobid->stype.xtype = 0;
	if (bidf & SILOFS_BIDF_PNODE) {
		blobid->stype.ptype = (enum silofs_ptype)stype;
	} else if (bidf & SILOFS_BIDF_VNODE) {
		blobid->stype.mtype = (enum silofs_mtype)stype;
	}
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	blobid_init_common(blobid);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	silofs_layerid_assign(&blobid->layerid, &other->layerid);
	silofs_uniqid_assign(&blobid->uniqid, &other->uniqid);
	blobid->flags = other->flags;
	blobid_set_stype(blobid, other->stype.xtype, other->flags);
	blobid->vspace = other->vspace;
	blobid->height = other->height;
	blobid->vers   = other->vers;
}

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	long cmp;

	cmp = silofs_layerid_compare(&blobid->layerid, &other->layerid);
	if (cmp != 0) {
		return cmp;
	}
	cmp = silofs_uniqid_compare(&blobid->uniqid, &other->uniqid);
	if (cmp != 0) {
		return cmp;
	}
	cmp = (long)blobid->stype.xtype - (long)other->stype.xtype;
	if (cmp != 0) {
		return cmp;
	}
	cmp = (long)blobid->flags - (long)other->flags;
	if (cmp != 0) {
		return cmp;
	}
	cmp = (long)blobid->vspace - (long)other->vspace;
	if (cmp != 0) {
		return cmp;
	}
	cmp = (long)blobid->height - (long)other->height;
	if (cmp != 0) {
		return cmp;
	}
	cmp = (long)blobid->vers - (long)other->vers;
	if (cmp != 0) {
		return cmp;
	}
	return 0;
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return (silofs_blobid_compare(blobid, other) == 0);
}

uint64_t silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t s)
{
	struct silofs_blobid56b blobid56;

	silofs_blobid56b_htox(&blobid56, blobid);
	return silofs_xxh64(&blobid56, sizeof(blobid56), s);
}

void silofs_blobid56b_htox(struct silofs_blobid56b *blobid56,
                           const struct silofs_blobid *blobid)
{
	memset(blobid56, 0, sizeof(*blobid56));
	silofs_layerid_assign(&blobid56->layerid, &blobid->layerid);
	silofs_uniqid_assign(&blobid56->uniqid, &blobid->uniqid);
	blobid56->flags  = silofs_cpu_to_le16(blobid->flags);
	blobid56->stype  = blobid_stype(blobid);
	blobid56->vspace = (uint8_t)blobid->vspace;
	blobid56->height = (uint8_t)blobid->height;
	blobid56->vers   = silofs_cpu_to_le16(blobid->vers);
}

void silofs_blobid56b_xtoh(const struct silofs_blobid56b *blobid56,
                           struct silofs_blobid *blobid)
{
	silofs_layerid_assign(&blobid->layerid, &blobid56->layerid);
	silofs_uniqid_assign(&blobid->uniqid, &blobid56->uniqid);
	blobid->flags = silofs_le16_to_cpu(blobid56->flags);
	blobid_set_stype(blobid, blobid56->stype, blobid->flags);
	blobid->vspace = (enum silofs_mtype)blobid56->vspace;
	blobid->height = (enum silofs_height)blobid56->height;
	blobid->vers   = silofs_le16_to_cpu(blobid56->vers);
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
	struct silofs_blobid56b blobid56b;
	struct silofs_hash256 hash;

	silofs_blobid56b_htox(&blobid56b, blobid);
	silofs_sha3_256_of(md_hd, &blobid56b, sizeof(blobid56b), &hash);
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
