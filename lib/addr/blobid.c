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
#include "uuid.h"
#include "meta.h"
#include "blobid.h"

static const struct silofs_blobid s_silofs_blobid_none;

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_silofs_blobid_none;
}

void silofs_blobid_generate(struct silofs_blobid *blobid)
{
	struct silofs_uuid *uu = &blobid->u.uuid[0];
	const uint64_t now = (uint64_t)silofs_time_mono_now();
	uint64_t u;

	silofs_uuid_generate(uu);
	u = silofs_hash_xxh64(uu->uu, sizeof(uu->uu), uu->uu[0]);
	silofs_u8b_from_u64(&blobid->u.bid[16], u);
	u = silofs_twang_mix64(u ^ now);
	silofs_u8b_from_u64(&blobid->u.bid[24], u);
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

bool silofs_blobid_isnone(const struct silofs_blobid *blobid)
{
	return silofs_blobid_isequal(blobid, &s_silofs_blobid_none);
}

int silofs_blobid_to_ascii(const struct silofs_blobid *blobid, char *s,
                           size_t n)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid->u.bid, sizeof(blobid->u.bid), s, n, &cnt);

	if (cnt >= n) {
		return -1;
	}
	s[cnt] = '\0';
	return 0;
}

int silofs_blobid_from_ascii(struct silofs_blobid *blobid, const char *s,
                             size_t n)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->u.bid, sizeof(blobid->u.bid), s, n,
	                          &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->u.bid)) {
		return -1;
	}
	return 0;
}

void silofs_blobid_to_sbuf(const struct silofs_blobid *blobid,
                           struct silofs_strbuf *sbuf)
{
	silofs_strbuf_reset(sbuf);
	silofs_blobid_to_ascii(blobid, sbuf->str, sizeof(sbuf->str) - 1);
}

int silofs_blobid_to_str(const struct silofs_blobid *blobid,
                         struct silofs_strspan *ss)
{
	struct silofs_strbuf sbuf;
	size_t n;

	silofs_strbuf_reset(&sbuf);
	silofs_blobid_to_sbuf(blobid, &sbuf);
	n = silofs_strspan_assign(ss, sbuf.str);
	return (n < ss->n) ? 0 : -SILOFS_EINVAL;
}

int silofs_blobid_to_str2(const struct silofs_blobid *blobid, char *s,
                          size_t n)
{
	struct silofs_strspan ss;

	silofs_strspan_initk(&ss, s, 0, n);
	return silofs_blobid_to_str(blobid, &ss);
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
	if (cnt != sizeof(blobid->u.bid)) {
		return -1;
	}
	return 0;
}

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed)
{
	return silofs_hash_xxh64(blobid->u.bid, sizeof(blobid->u.bid), seed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobref_reset(struct silofs_blobref *blobref)
{
	silofs_memzero(blobref, sizeof(*blobref));
}

bool silofs_blobref_isnull(const struct silofs_blobref *blobref)
{
	return (blobref->bid[0] == '\0');
}

int silofs_blobref_verify(const struct silofs_blobref *blobref)
{
	struct silofs_blobid blobid;

	return silofs_blobref_to_blobid(blobref, &blobid);
}

int silofs_blobref_from_blobid(struct silofs_blobref *blobref,
                               const struct silofs_blobid *blobid)
{
	struct silofs_strspan ss;

	silofs_blobref_reset(blobref);
	silofs_strspan_initk(&ss, blobref->bid, 0, sizeof(blobref->bid));
	return silofs_blobid_to_str(blobid, &ss);
}

int silofs_blobref_to_blobid(const struct silofs_blobref *blobref,
                             struct silofs_blobid *out_blobid)
{
	struct silofs_strview sv;
	int err = -SILOFS_EBLOBREF;

	silofs_strview_init(&sv, blobref->bid);
	if (sv.len && (sv.len < sizeof(blobref->bid))) {
		err = silofs_blobid_from_str(out_blobid, &sv);
	}
	return err;
}
