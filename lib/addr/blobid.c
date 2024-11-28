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

void silofs_blobid_setup(struct silofs_blobid *blobid, const void *id,
                         size_t id_len)
{
	silofs_memzero(blobid, sizeof(*blobid));
	blobid->id_len = (uint32_t)silofs_min(id_len, sizeof(blobid->id));
	memcpy(blobid->id, id, blobid->id_len);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	blobid->id_len = other->id_len;
	memcpy(blobid->id, other->id, sizeof(blobid->id));
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	blobid->id_len = 0;
}

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	int cmp;

	cmp = (int)blobid1->id_len - (int)blobid2->id_len;
	if (cmp == 0) {
		cmp = memcmp(blobid1->id, blobid2->id, blobid1->id_len);
	}
	return cmp;
}

uint64_t silofs_blobid_hash64(const struct silofs_blobid *blobid)
{
	uint64_t v = blobid->id_len;

	for (size_t i = 0; i < blobid->id_len; ++i) {
		v = silofs_lrotate64(v, 8);
		v ^= (uint64_t)blobid->id[i];
	}
	return v;
}
