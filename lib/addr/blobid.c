/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/addr.h>


void silofs_blobid_setup(struct silofs_blobid *blobid,
                         enum silofs_btype btype, size_t len, const void *val)
{
	silofs_memzero(blobid, sizeof(*blobid));
	blobid->btype = btype;
	blobid->len = (uint32_t)silofs_min(len, sizeof(blobid->val));
	memcpy(blobid->val, val, blobid->len);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	blobid->btype = other->btype;
	blobid->len = other->len;
	memcpy(blobid->val, other->val, sizeof(blobid->val));
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	silofs_memzero(blobid, sizeof(*blobid));
	blobid->btype = SILOFS_BTYPE_NONE;
}

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	int cmp;

	cmp = (int)blobid1->btype - (int)blobid2->btype;
	if (cmp) {
		return cmp;
	}
	cmp = (int)blobid1->len - (int)blobid2->len;
	if (cmp) {
		return cmp;
	}
	return memcmp(blobid1->val, blobid2->val, blobid1->len);
}


uint64_t silofs_blobid_hash64(const struct silofs_blobid *blobid)
{
	uint64_t v = (uint64_t)(blobid->btype);

	for (size_t i = 0; i < blobid->len; ++i) {
		v = silofs_lrotate64(v, 8);
		v ^= (uint64_t)blobid->val[i];
	}
	return v;
}
