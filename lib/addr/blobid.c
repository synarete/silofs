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
#include "crypt.h"
#include "htox.h"
#include "uuid.h"
#include "meta.h"
#include "blobid.h"

static const union silofs_blobidu s_silofs_blobid_none;

const union silofs_blobidu *silofs_blobid_none(void)
{
	return &s_silofs_blobid_none;
}

static uint64_t blobid_seed(void)
{
	static uint64_t s_blobid_seed;

	if (s_blobid_seed == 0) {
		s_blobid_seed = (uint64_t)getpid();
	}
	return ++s_blobid_seed;
}

void silofs_blobid_generate(union silofs_blobidu *blobid)
{
	silofs_gcrypt_random(blobid->ui, sizeof(blobid->ui));
	silofs_xrand_by_hash(blobid->ui, sizeof(blobid->ui), blobid_seed());
}

void silofs_blobid_assign(union silofs_blobidu *blobid,
                          const union silofs_blobidu *other)
{
	memcpy(blobid, other, sizeof(*blobid));
}

void silofs_blobid_assign_hash(union silofs_blobidu *blobid,
                               const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&blobid->hash, hash);
}

void silofs_blobid_reset(union silofs_blobidu *blobid)
{
	memset(blobid, 0, sizeof(*blobid));
}

long silofs_blobid_compare(const union silofs_blobidu *blobid,
                           const union silofs_blobidu *other)
{
	return memcmp(blobid, other, sizeof(*blobid));
}

bool silofs_blobid_isequal(const union silofs_blobidu *blobid1,
                           const union silofs_blobidu *blobid2)
{
	return (silofs_blobid_compare(blobid1, blobid2) == 0);
}

bool silofs_blobid_isnone(const union silofs_blobidu *blobid)
{
	return silofs_blobid_isequal(blobid, &s_silofs_blobid_none);
}

int silofs_blobid_to_ascii(const union silofs_blobidu *blobid, char *s,
                           size_t n)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid->bid.b, sizeof(blobid->bid.b), s, n, &cnt);

	if (cnt >= n) {
		return -1;
	}
	s[cnt] = '\0';
	return 0;
}

int silofs_blobid_from_ascii(union silofs_blobidu *blobid, const char *s,
                             size_t n)
{
	const size_t bsz = sizeof(blobid->bid.b);
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->bid.b, bsz, s, n, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->bid)) {
		return -1;
	}
	return 0;
}

void silofs_blobid_to_sbuf(const union silofs_blobidu *blobid,
                           struct silofs_strbuf *sbuf)
{
	silofs_strbuf_reset(sbuf);
	silofs_blobid_to_ascii(blobid, sbuf->str, sizeof(sbuf->str) - 1);
}

int silofs_blobid_to_str(const union silofs_blobidu *blobid,
                         struct silofs_strspan *ss)
{
	struct silofs_strbuf sbuf;
	size_t n;

	silofs_strbuf_reset(&sbuf);
	silofs_blobid_to_sbuf(blobid, &sbuf);
	n = silofs_strspan_assign(ss, sbuf.str);
	return (n < ss->n) ? 0 : -SILOFS_EINVAL;
}

int silofs_blobid_to_str2(const union silofs_blobidu *blobid, char *s,
                          size_t n)
{
	struct silofs_strspan ss;

	silofs_strspan_initk(&ss, s, 0, n);
	return silofs_blobid_to_str(blobid, &ss);
}

int silofs_blobid_from_str(union silofs_blobidu *blobid,
                           const struct silofs_strview *sv)
{
	const size_t bsz = sizeof(blobid->bid.b);
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->bid.b, bsz, sv->str, sv->len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->bid)) {
		return -1;
	}
	return 0;
}

uint64_t
silofs_blobid_hash64(const union silofs_blobidu *blobid, uint64_t seed)
{
	return silofs_hash_xxh64(blobid->bid.b, sizeof(blobid->bid.b), seed);
}

void silofs_blobid_import(union silofs_blobidu *blobid,
                          const struct silofs_blobid *other)
{
	memcpy(&blobid->bid, other, sizeof(blobid->bid));
}

void silofs_blobid_export(const union silofs_blobidu *blobid,
                          struct silofs_blobid *other)
{
	memcpy(other, &blobid->bid, sizeof(*other));
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
	union silofs_blobidu blobid;

	return silofs_blobref_to_blobid(blobref, &blobid);
}

int silofs_blobref_from_blobid(struct silofs_blobref *blobref,
                               const union silofs_blobidu *blobid)
{
	struct silofs_strspan ss;

	silofs_blobref_reset(blobref);
	silofs_strspan_initk(&ss, blobref->bid, 0, sizeof(blobref->bid));
	return silofs_blobid_to_str(blobid, &ss);
}

int silofs_blobref_to_blobid(const struct silofs_blobref *blobref,
                             union silofs_blobidu *out_blobid)
{
	struct silofs_strview sv;
	int err = -SILOFS_EBLOBREF;

	silofs_strview_init(&sv, blobref->bid);
	if (sv.len && (sv.len < sizeof(blobref->bid))) {
		err = silofs_blobid_from_str(out_blobid, &sv);
	}
	return err;
}
