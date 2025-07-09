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
