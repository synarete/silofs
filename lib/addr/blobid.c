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

static void generate_random(uint8_t *p, size_t n, uint64_t seed)
{
	silofs_gcrypt_random(p, n);
	silofs_xrand_by_hash(p, n, seed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobid s_silofs_blobid_none;

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_silofs_blobid_none;
}

static uint64_t blobid_base_seed(void)
{
	struct timespec ts;
	const pid_t pid = getpid();

	silofs_clock_real_now(&ts);

	return ((uint64_t)pid * (uint64_t)ts.tv_nsec) ^ (uint64_t)ts.tv_sec;
}

static uint64_t blobid_seed(void)
{
	static uint64_t s_blobid_seed;

	if (s_blobid_seed == 0) {
		s_blobid_seed = blobid_base_seed();
	}
	return ++s_blobid_seed;
}

void silofs_blobid_generate(struct silofs_blobid *blobid)
{
	generate_random(blobid->id, sizeof(blobid->id), blobid_seed());
}

void silofs_blobid_generate2(struct silofs_blobid *blobid,
			     const struct silofs_svolid *svolid)
{
	const size_t svid_size = sizeof(svolid->id);
	const size_t rand_size = sizeof(blobid->id) - svid_size;

	STATICASSERT_EQ(sizeof(blobid->id) / 2, sizeof(svolid->id));

	generate_random(&blobid->id[0], rand_size, blobid_seed());
	memcpy(&blobid->id[rand_size], svolid->id, svid_size);
}

void silofs_blobid_copyto(const struct silofs_blobid *blobid,
			  struct silofs_blobid *other)
{
	memcpy(other->id, blobid->id, sizeof(other->id));
}

void silofs_blobid_from_hash(struct silofs_blobid *blobid,
			     const struct silofs_hash256 *hash)
{
	STATICASSERT_EQ(sizeof(blobid->id), sizeof(hash->hash));

	memcpy(blobid->id, hash->hash, sizeof(blobid->id));
}

void silofs_blobid_to_hash(const struct silofs_blobid *blobid,
			   struct silofs_hash256 *out_hash)
{
	STATICASSERT_EQ(sizeof(blobid->id), sizeof(out_hash->hash));

	memcpy(out_hash->hash, blobid->id, sizeof(out_hash->hash));
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid->id, 0, sizeof(blobid->id));
}

long silofs_blobid_compare(const struct silofs_blobid *blobid,
			   const struct silofs_blobid *other)
{
	return memcmp(blobid->id, other->id, sizeof(blobid->id));
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

	silofs_mem_to_ascii(blobid->id, sizeof(blobid->id), s, n, &cnt);

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

	err = silofs_ascii_to_mem(blobid->id, sizeof(blobid->id), s, n, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->id)) {
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

	err = silofs_ascii_to_mem(blobid->id, sizeof(blobid->id), sv->str,
				  sv->len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->id)) {
		return -1;
	}
	return 0;
}

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed)
{
	return silofs_hash_xxh64(blobid->id, sizeof(blobid->id), seed);
}
