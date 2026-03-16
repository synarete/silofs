/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <silofs/ondisk.h>
#include <silofs/infra.h>
#include "gcry.h"
#include "prand.h"

static size_t do_gcry_random(void *buf, size_t len)
{
	silofs_gcrypt_random(buf, len);
	return len;
}

static size_t do_getentropy(void *buf, size_t len)
{
	const size_t nr = silofs_min(len, 256);
	int ret;

	ret = getentropy(buf, nr);
	return (ret == 0) ? nr : 0;
}

static void fill_random(void *buf, size_t len)
{
	uint8_t *ptr = buf;
	size_t cnt   = 0;
	int itr      = 0;

	while (cnt < len) {
		if (itr & 1) {
			cnt += do_gcry_random(ptr + cnt, len - cnt);
		} else {
			cnt += do_getentropy(ptr + cnt, len - cnt);
		}
		itr += 1;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_prand_in {
	uint8_t key[32];
	uint64_t count;
	uint64_t extra[3];
};

static void prandgen_fill_in(const struct silofs_prandgen *prng,
                             uint64_t count, struct silofs_prand_in *prin)
{
	struct timespec ts[2];

	STATICASSERT_EQ(sizeof(prin->key), sizeof(prng->key));

	silofs_clock_gettime_boot(&ts[0]);
	silofs_clock_gettime_real(&ts[1]);

	memcpy(prin->key, prng->key, sizeof(prin->key));
	prin->count    = count;
	prin->extra[0] = (uint64_t)ts[0].tv_sec * (uint64_t)ts[1].tv_nsec;
	prin->extra[1] = (uint64_t)ts[0].tv_nsec * (uint64_t)gettid();
	prin->extra[2] = (prng->cycle + 1) * (uint64_t)ts[1].tv_sec;
}

static void prandgen_mkhash(const struct silofs_prandgen *prng, uint64_t count,
                            struct silofs_hash256 *out_hash)
{
	struct silofs_prand_in prin = {};

	prandgen_fill_in(prng, count, &prin);
	silofs_sha3_256_of(&prng->md_hd, &prin, sizeof(prin), out_hash);
}

static void prandgen_regen_key(struct silofs_prandgen *prng)
{
	struct silofs_hash256 hash;
	uint64_t count;

	STATICASSERT_EQ(sizeof(prng->key), sizeof(hash));

	memset(prng->key, 0, sizeof(prng->key));
	fill_random(&count, sizeof(count));
	prandgen_mkhash(prng, count, &hash);
	memcpy(prng->key, &hash, sizeof(prng->key));
	memset(&hash, 0, sizeof(hash));
}

static void prandgen_seed_key(struct silofs_prandgen *prng)
{
	fill_random(prng->key, sizeof(prng->key));
}

static void *prandgen_prandom_buf(struct silofs_prandgen *prng)
{
	return prng->prandom;
}

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	struct silofs_hash256 hash;
	size_t psz = sizeof(prng->prandom);
	uint8_t *p = prandgen_prandom_buf(prng);
	size_t n   = 0;

	while (n < psz) {
		const size_t k = silofs_min(sizeof(hash.hash), psz - n);

		prandgen_mkhash(prng, prng->count, &hash);
		memcpy(p + n, hash.hash, k);
		n += k;

		prng->count++;
	}
}

static void prandom_reset_prandom(struct silofs_prandgen *prng)
{
	memset(prng->prandom, 0, sizeof(prng->prandom));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_prandgen_init(struct silofs_prandgen *prng)
{
	memset(prng, 0, sizeof(*prng));
	prng->cycle = 0;
	prng->slot  = 0;
	prng->count = 0;
	prandgen_seed_key(prng);

	return silofs_mdigest_init(&prng->md_hd);
}

void silofs_prandgen_fini(struct silofs_prandgen *prng)
{
	silofs_mdigest_fini(&prng->md_hd);
	memset(prng, 0, sizeof(*prng));
}

static uint64_t prandgen_consume_slot(struct silofs_prandgen *prng)
{
	uint64_t pr;

	/* take full u64 */
	pr = prng->prandom[prng->slot];
	/* clear used slot */
	prng->prandom[prng->slot] = 0;
	/* move to next */
	prng->slot++;

	return pr;
}

static bool prandgen_has_more(const struct silofs_prandgen *prng)
{
	return (prng->slot < ARRAY_SIZE(prng->prandom));
}

static void prandgen_prepare(struct silofs_prandgen *prng)
{
	if ((!prng->slot && !prng->cycle) || !prandgen_has_more(prng)) {
		if ((prng->cycle % 31) == 0) {
			prandgen_regen_key(prng);
		}
		prandom_reset_prandom(prng);
		prandgen_refill_prandom(prng);
		prng->cycle++;
		prng->slot = 0;
	}
}

void silofs_prandgen_take(struct silofs_prandgen *prng, void *p, size_t n)
{
	uint8_t *q = p;
	size_t k   = 0;

	while (k < n) {
		uint64_t u;
		const size_t nb = silofs_min(n - k, sizeof(u));

		prandgen_prepare(prng);
		u = prandgen_consume_slot(prng);

		memcpy(&q[k], &u, nb);
		k += nb;
	}
}

uint64_t silofs_prandgen_take64(struct silofs_prandgen *prng)
{
	uint64_t u;

	silofs_prandgen_take(prng, &u, sizeof(u));
	return u;
}
