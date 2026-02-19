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
#include "stype.h"
#include "blobid.h"

static const struct silofs_blobid s_blobid_none = {
	.ptype = SILOFS_PTYPE_NONE,
	.vtype = SILOFS_VTYPE_NONE,
	.vers  = SILOFS_FMT_VERSION,
};

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_blobid_none;
}

static void blobid_clear(struct silofs_blobid *blobid)
{
	silofs_layerid_reset(&blobid->layerid);
	silofs_uniqid_reset(&blobid->uniqid);
	blobid->ptype  = SILOFS_PTYPE_NONE;
	blobid->vtype  = SILOFS_VTYPE_NONE;
	blobid->height = SILOFS_HEIGHT_NONE;
	blobid->vers   = 0;
}

void silofs_blobid_init(struct silofs_blobid *blobid, enum silofs_ptype ptype,
                        enum silofs_vtype vtype)
{
	blobid_clear(blobid);
	blobid->ptype = ptype;
	blobid->vtype = vtype;
	blobid->vers  = SILOFS_FMT_VERSION;
}

void silofs_blobid_fini(struct silofs_blobid *blobid)
{
	blobid_clear(blobid);
}

void silofs_blobid_update(struct silofs_blobid *blobid,
                          const struct silofs_layerid *layerid,
                          const struct silofs_uniqid *uniqid)
{
	if (layerid != nullptr) {
		silofs_layerid_assign(&blobid->layerid, layerid);
	}
	if (uniqid != nullptr) {
		silofs_uniqid_assign(&blobid->uniqid, uniqid);
	}
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
	blobid->ptype  = other->ptype;
	blobid->vtype  = other->vtype;
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
	cmp = (long)blobid->ptype - (long)other->ptype;
	if (cmp != 0) {
		return cmp;
	}
	cmp = (long)blobid->vtype - (long)other->vtype;
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

size_t silofs_blobid_slotsize(const struct silofs_blobid *blobid)
{
	size_t sz;

	if (blobid->ptype == SILOFS_PTYPE_VNODE) {
		sz = silofs_vtype_size(blobid->vtype);
	} else {
		sz = silofs_ptype_size(blobid->ptype);
	}
	return sz;
}

void silofs_blobid56b_htox(struct silofs_blobid56b *blobid56,
                           const struct silofs_blobid *blobid)
{
	memset(blobid56, 0, sizeof(*blobid56));
	silofs_layerid_assign(&blobid56->layerid, &blobid->layerid);
	silofs_uniqid_assign(&blobid56->uniqid, &blobid->uniqid);
	blobid56->ptype  = (uint8_t)blobid->ptype;
	blobid56->vtype  = (uint8_t)blobid->vtype;
	blobid56->height = (uint8_t)blobid->height;
	blobid56->vers   = silofs_cpu_to_le16(blobid->vers);
}

void silofs_blobid56b_xtoh(const struct silofs_blobid56b *blobid56,
                           struct silofs_blobid *blobid)
{
	silofs_layerid_assign(&blobid->layerid, &blobid56->layerid);
	silofs_uniqid_assign(&blobid->uniqid, &blobid56->uniqid);
	blobid->ptype  = (enum silofs_ptype)blobid56->ptype;
	blobid->vtype  = (enum silofs_vtype)blobid56->vtype;
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
