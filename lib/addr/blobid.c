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
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "meta.h"
#include "blobid.h"

void silofs_blobid_generate(struct silofs_blobid *blobid)
{
	silofs_uuid_generate(&blobid->uuid);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	silofs_uuid_assign(&blobid->uuid, &other->uuid);
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

long silofs_blobid_compare(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	return silofs_uuid_compare(&blobid1->uuid, &blobid2->uuid);
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	return (silofs_blobid_compare(blobid1, blobid2) == 0);
}

void silofs_blobid_to_str(const struct silofs_blobid *blobid,
                          struct silofs_strbuf *sbuf)
{
	silofs_uuid_unparse(&blobid->uuid, sbuf);
}

int silofs_blobid_from_str(struct silofs_blobid *blobid,
                           const struct silofs_strview *sv)
{
	return silofs_uuid_parse(&blobid->uuid, sv);
}

void silofs_blobid_by_uuid(struct silofs_blobid *blobid,
                           const struct silofs_uuid *uuid)
{
	SILOFS_STATICASSERT_EQ(sizeof(blobid->uuid.uu), 16);

	silofs_uuid_assign(&blobid->uuid, uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobidx s_blobidx_none = {
	.index = 0,
};

const struct silofs_blobidx *silofs_blobidx_none(void)
{
	return &s_blobidx_none;
}

void silofs_blobidx_init(struct silofs_blobidx *blobidx,
                         const struct silofs_blobid *blobid, uint32_t idx)
{
	silofs_blobid_assign(&blobidx->blobid, blobid);
	blobidx->index = idx;
}

void silofs_blobidx_fini(struct silofs_blobidx *blobidx)
{
	silofs_blobid_reset(&blobidx->blobid);
	blobidx->index = 0;
}

bool silofs_blobidx_isnull(const struct silofs_blobidx *blobidx)
{
	return (blobidx->index == 0);
}

bool silofs_blobidx_has_blobid(const struct silofs_blobidx *blobidx,
                               const struct silofs_blobid *blobid)
{
	return silofs_blobid_isequal(&blobidx->blobid, blobid);
}

void silofs_blobidx_generate(struct silofs_blobidx *blobidx)
{
	silofs_blobid_generate(&blobidx->blobid);
	blobidx->index = 1;
}

void silofs_blobidx_reset(struct silofs_blobidx *blobidx)
{
	silofs_blobid_reset(&blobidx->blobid);
	blobidx->index = 0;
}

void silofs_blobidx_assign(struct silofs_blobidx *blobidx,
                           const struct silofs_blobidx *other)
{
	silofs_blobid_assign(&blobidx->blobid, &other->blobid);
	blobidx->index = other->index;
}

long silofs_blobidx_compare(const struct silofs_blobidx *blobidx1,
                            const struct silofs_blobidx *blobidx2)
{
	long cmp;

	cmp = silofs_blobid_compare(&blobidx1->blobid, &blobidx2->blobid);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(blobidx2->index) - (long)(blobidx1->index);
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_blobidx_isequal(const struct silofs_blobidx *blobidx,
                            const struct silofs_blobidx *other)
{
	return silofs_blobidx_compare(blobidx, other) == 0;
}

uint64_t silofs_blobidx_hash64(const struct silofs_blobidx *blobidx)
{
	struct silofs_blobidx48b blobidx32b;

	silofs_blobidx32b_htox(&blobidx32b, blobidx);
	return silofs_hash_xxh64(&blobidx32b, sizeof(blobidx32b),
	                         blobidx->index);
}

void silofs_blobidx_to_str(const struct silofs_blobidx *blobidx,
                           struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf sbuf;

	silofs_blobid_to_str(&blobidx->blobid, &sbuf);
	silofs_strbuf_sprintf(out_sbuf, "%s:%u", sbuf.str, blobidx->index);
}

void silofs_blobidx32b_htox(struct silofs_blobidx48b *blobidx32,
                            const struct silofs_blobidx *blobidx)
{
	memset(blobidx32, 0, sizeof(*blobidx32));
	silofs_blobid_assign(&blobidx32->blobid, &blobidx->blobid);
	blobidx32->index = silofs_cpu_to_le32(blobidx->index);
}

void silofs_blobidx32b_xtoh(const struct silofs_blobidx48b *blobidx32,
                            struct silofs_blobidx *blobidx)
{
	silofs_blobid_assign(&blobidx->blobid, &blobidx32->blobid);
	blobidx->index = silofs_le32_to_cpu(blobidx32->index);
}
