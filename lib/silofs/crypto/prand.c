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
#include <silofs/crypto/gcry.h>
#include <silofs/crypto/prand.h>

static void do_gcry_random(void *buf, size_t len)
{
	silofs_gcrypt_random(buf, len);
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
	size_t cnt;

	cnt = do_getentropy(buf, len);
	if (cnt < len) {
		do_gcry_random(silofs_nextof(buf, cnt), len - cnt);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_prand_in {
	uint8_t key[32];
	uint64_t extra[4];
};

static void prandgen_fill_in(const struct silofs_prandgen *prng,
                             struct silofs_prand_in *prin)
{
	const uintptr_t aslr = (uintptr_t)prin;

	STATICASSERT_EQ(sizeof(prin->key), sizeof(prng->key));

	memcpy(prin->key, prng->key, sizeof(prin->key));
	prin->extra[0] = prng->count;
	prin->extra[1] = prng->xbits;
	prin->extra[2] = (uint64_t)aslr;
	prin->extra[3] = prng->slot;
}

static void prandgen_mkhash(const struct silofs_prandgen *prng,
                            struct silofs_hash256 *out_hash)
{
	struct silofs_prand_in prin = {};

	prandgen_fill_in(prng, &prin);
	silofs_sha3_256_of(&prng->md_hd, &prin, sizeof(prin), out_hash);
}

static void prandgen_renew_key(struct silofs_prandgen *prng,
                               const struct silofs_hash256 *hash)
{
	struct silofs_hash256 xh;

	STATICASSERT_EQ(sizeof(xh.hash), sizeof(prng->key));

	silofs_sha256_of(&prng->md_hd, hash->hash, sizeof(hash->hash), &xh);
	memcpy(prng->key, xh.hash, sizeof(prng->key));
}

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	size_t psz = sizeof(prng->prandom);
	void *p    = prng->prandom;
	size_t n   = 0;

	while (n < psz) {
		struct silofs_hash256 hash;
		size_t k;

		prandgen_mkhash(prng, &hash);
		prng->count++;

		k = silofs_min(sizeof(hash.hash), psz - n);
		memcpy(p, hash.hash, k);
		p = silofs_nextof(p, k);
		n += k;

		prandgen_renew_key(prng, &hash);
	}
}

static void prandgen_reset_prandom(struct silofs_prandgen *prng)
{
	memset(prng->prandom, 0, sizeof(prng->prandom));
}

static void prandgen_renew_prandom(struct silofs_prandgen *prng)
{
	prandgen_reset_prandom(prng);
	prandgen_refill_prandom(prng);
}

static void prandgen_refresh_state(struct silofs_prandgen *prng)
{
	struct timespec ts;
	const pid_t tid = gettid();

	silofs_clock_gettime_mono(&ts);
	prng->xbits = silofs_twang64((uint64_t)ts.tv_nsec ^ (uint64_t)tid);

	if (!prng->key_ts || ((prng->key_ts + 10) < ts.tv_sec)) {
		fill_random(prng->key, sizeof(prng->key));
		prng->key_ts = ts.tv_sec;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_prandgen_init(struct silofs_prandgen *prng)
{
	memset(prng, 0, sizeof(*prng));
	prng->count = 0;
	prng->slot  = 0;
	prandgen_refresh_state(prng);

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
	prandgen_refresh_state(prng);
	if (!prandgen_has_more(prng)) {
		prandgen_renew_prandom(prng);
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

/*
 * TODO-0063: Extend with APIs to ingect external entropy
 *
 * Use the actual file-system activity as a source of entropy and inject it
 * into PRNG state.
 */
