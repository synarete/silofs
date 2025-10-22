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

static const struct silofs_blobid s_silofs_blobid_none;

const struct silofs_blobid *silofs_blobid_none(void)
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

void silofs_blobid_generate(struct silofs_blobid *blobid)
{
	silofs_gcrypt_random(blobid->b, sizeof(blobid->b));
	silofs_xrand_by_hash(blobid->b, sizeof(blobid->b), blobid_seed());
}

void silofs_blobid_copyto(const struct silofs_blobid *blobid,
                          struct silofs_blobid *other)
{
	memcpy(other->b, blobid->b, sizeof(other->b));
}

void silofs_blobid_from_hash(struct silofs_blobid *blobid,
                             const struct silofs_hash256 *hash)
{
	STATICASSERT_EQ(sizeof(blobid->b), sizeof(hash->hash));

	memcpy(blobid->b, hash->hash, sizeof(blobid->b));
}

void silofs_blobid_to_hash(const struct silofs_blobid *blobid,
                           struct silofs_hash256 *out_hash)
{
	STATICASSERT_EQ(sizeof(blobid->b), sizeof(out_hash->hash));

	memcpy(out_hash->hash, blobid->b, sizeof(out_hash->hash));
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid->b, 0, sizeof(blobid->b));
}

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return memcmp(blobid->b, other->b, sizeof(blobid->b));
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

	silofs_mem_to_ascii(blobid->b, sizeof(blobid->b), s, n, &cnt);

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

	err = silofs_ascii_to_mem(blobid->b, sizeof(blobid->b), s, n, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->b)) {
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

int silofs_blobid_from_str(struct silofs_blobid *blobid,
                           const struct silofs_strview *sv)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->b, sizeof(blobid->b), sv->str,
	                          sv->len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->b)) {
		return -1;
	}
	return 0;
}

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed)
{
	return silofs_hash_xxh64(blobid->b, sizeof(blobid->b), seed);
}
