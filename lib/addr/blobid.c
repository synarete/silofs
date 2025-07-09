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

void silofs_blobid_generate(union silofs_blobid *blobid)
{
	struct silofs_uuid *uu = &blobid->uuid[0];

	silofs_uuid_generate(uu);
	blobid->d[2] = silofs_hash_xxh64(uu->uu, sizeof(uu->uu), uu->uu[0]);
	blobid->d[3] = silofs_twang_mix64(blobid->d[2]);
}

void silofs_blobid_assign(union silofs_blobid *blobid,
                          const union silofs_blobid *other)
{
	memcpy(blobid, other, sizeof(*blobid));
}

void silofs_blobid_assign_hash(union silofs_blobid *blobid,
                               const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&blobid->hash, hash);
}

void silofs_blobid_reset(union silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

long silofs_blobid_compare(const union silofs_blobid *blobid,
                           const union silofs_blobid *other)
{
	return memcmp(blobid, other, sizeof(*blobid));
}

bool silofs_blobid_isequal(const union silofs_blobid *blobid1,
                           const union silofs_blobid *blobid2)
{
	return (silofs_blobid_compare(blobid1, blobid2) == 0);
}

void silofs_blobid_to_sbuf(const union silofs_blobid *blobid,
                           struct silofs_strbuf *sbuf)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid->bid, sizeof(blobid->bid), sbuf->str,
	                    sizeof(sbuf->str) - 1, &cnt);
	if (silofs_likely(cnt < sizeof(sbuf->str))) {
		sbuf->str[cnt] = '\0';
	}
}

void silofs_blobid_to_str(const union silofs_blobid *blobid,
                          struct silofs_strspan *ss)
{
	struct silofs_strbuf sbuf;

	silofs_strbuf_reset(&sbuf);
	silofs_blobid_to_sbuf(blobid, &sbuf);
	silofs_strspan_assign(ss, sbuf.str);
}

int silofs_blobid_from_str(union silofs_blobid *blobid,
                           const struct silofs_strview *sv)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->bid, sizeof(blobid->bid), sv->str,
	                          sv->len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != 2 * sizeof(blobid->bid)) {
		return -1;
	}
	return 0;
}

uint64_t silofs_blobid_hash64(const union silofs_blobid *blobid, uint64_t seed)
{
	return silofs_hash_xxh64(blobid->bid, sizeof(blobid->bid), seed);
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
                         const union silofs_blobid *blobid, uint32_t idx)
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
                               const union silofs_blobid *blobid)
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
	struct silofs_blobidx48b blobidx48b;

	silofs_blobidx48b_htox(&blobidx48b, blobidx);
	return silofs_hash_xxh64(&blobidx48b, sizeof(blobidx48b),
	                         blobidx->index);
}

void silofs_blobidx_to_str(const struct silofs_blobidx *blobidx,
                           struct silofs_strbuf *out_sbuf)
{
	struct silofs_strbuf sbuf;

	silofs_blobid_to_sbuf(&blobidx->blobid, &sbuf);
	silofs_strbuf_sprintf(out_sbuf, "%s:%u", sbuf.str, blobidx->index);
}

void silofs_blobidx48b_htox(struct silofs_blobidx48b *blobidx48,
                            const struct silofs_blobidx *blobidx)
{
	memset(blobidx48, 0, sizeof(*blobidx48));
	silofs_blobid_assign(&blobidx48->blobid, &blobidx->blobid);
	blobidx48->index = silofs_cpu_to_le32(blobidx->index);
}

void silofs_blobidx48b_xtoh(const struct silofs_blobidx48b *blobidx48,
                            struct silofs_blobidx *blobidx)
{
	silofs_blobid_assign(&blobidx->blobid, &blobidx48->blobid);
	blobidx->index = silofs_le32_to_cpu(blobidx48->index);
}
