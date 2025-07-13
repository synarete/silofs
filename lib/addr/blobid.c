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

static const struct silofs_blobid s_silofs_blobid_none = {};

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_silofs_blobid_none;
}

void silofs_blobid_generate(struct silofs_blobid *blobid)
{
	struct silofs_uuid *uu = &blobid->u.uuid[0];

	silofs_uuid_generate(uu);
	blobid->u.d[2] = silofs_hash_xxh64(uu->uu, sizeof(uu->uu), uu->uu[0]);
	blobid->u.d[3] = silofs_twang_mix64(blobid->u.d[2]);
}

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	memcpy(blobid, other, sizeof(*blobid));
}

void silofs_blobid_assign_hash(struct silofs_blobid *blobid,
                               const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&blobid->u.hash, hash);
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return memcmp(blobid, other, sizeof(*blobid));
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	return (silofs_blobid_compare(blobid1, blobid2) == 0);
}

void silofs_blobid_to_sbuf(const struct silofs_blobid *blobid,
                           struct silofs_strbuf *sbuf)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid->u.bid, sizeof(blobid->u.bid), sbuf->str,
	                    sizeof(sbuf->str) - 1, &cnt);
	if (silofs_likely(cnt < sizeof(sbuf->str))) {
		sbuf->str[cnt] = '\0';
	}
}

void silofs_blobid_to_str(const struct silofs_blobid *blobid,
                          struct silofs_strspan *ss)
{
	struct silofs_strbuf sbuf;

	silofs_strbuf_reset(&sbuf);
	silofs_blobid_to_sbuf(blobid, &sbuf);
	silofs_strspan_assign(ss, sbuf.str);
}

int silofs_blobid_from_str(struct silofs_blobid *blobid,
                           const struct silofs_strview *sv)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->u.bid, sizeof(blobid->u.bid),
	                          sv->str, sv->len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != 2 * sizeof(blobid->u.bid)) {
		return -1;
	}
	return 0;
}

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed)
{
	return silofs_hash_xxh64(blobid->u.bid, sizeof(blobid->u.bid), seed);
}
