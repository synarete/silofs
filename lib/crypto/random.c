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
#include <silofs/configs.h>
#include <silofs/ondisk.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "infra.h"
#include "gcry.h"
#include "random.h"

static size_t do_getentropy(void *buf, size_t len)
{
	const size_t nr = silofs_min(len, 256);

	if (getentropy(buf, nr) != 0) {
		silofs_gcrypt_random(buf, nr);
	}
	return nr;
}

static void silofs_getentropy(void *buf, size_t len)
{
	uint8_t *ptr = buf;
	size_t   cnt = 0;

	while (cnt < len) {
		cnt += do_getentropy(ptr + cnt, len - cnt);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
prandgen_mkhash(struct silofs_prandgen *prng, struct silofs_hash256 *out_hash)
{
	uint32_t        d[8];
	const size_t    nd = ARRAY_SIZE(d);
	const size_t    ne = ARRAY_SIZE(prng->entropy);
	size_t          di = prng->xseed + prng->slot;
	uint64_t        u  = prng->entropy[di % ne];
	struct timespec t;

	d[di++ % nd] = (uint32_t)u;
	silofs_clock_mono_now(&t);
	d[di++ % nd] = (uint32_t)t.tv_sec * 0xc2b2ae35;
	d[di++ % nd] = prng->xseed;
	d[di++ % nd] = (uint32_t)t.tv_nsec;
	u            = (uint64_t)t.tv_nsec ^ 0xc6a4a7935bd1e995UL;
	silofs_uptime(&t);
	u ^= silofs_twang64((uint64_t)t.tv_nsec) ^ 0x9ae16a3b2f90404fULL;
	d[di++ % nd] = (uint32_t)t.tv_sec * 0x85ebca6b;
	d[di++ % nd] = (uint32_t)u;
	d[di++ % nd] = (uint32_t)t.tv_nsec * 0x5bd1e995;
	d[di++ % nd] = (uint32_t)(u >> 32);

	silofs_sha3_256_of(&prng->mdigest, d, sizeof(d), out_hash);
	prng->xseed = silofs_xxh32(d, sizeof(d), (uint32_t)di);
}

static void *prandgen_prandom_buf(struct silofs_prandgen *prng)
{
	return prng->prandom;
}

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	struct silofs_hash256 hash;
	const size_t          psz = sizeof(prng->prandom);
	uint8_t              *p   = prandgen_prandom_buf(prng);
	size_t                k, cnt = 0;

	while (cnt < psz) {
		prandgen_mkhash(prng, &hash);
		k = silofs_min(sizeof(hash.hash), psz - cnt);
		memcpy(p + cnt, hash.hash, k);
		cnt += k;
	}
}

static void prandgen_refill_entropy(struct silofs_prandgen *prng)
{
	silofs_getentropy(prng->entropy, sizeof(prng->entropy));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_prandgen_init(struct silofs_prandgen *prng)
{
	int err;

	STATICASSERT_EQ(sizeof(*prng), 1024);

	memset(prng, 0, sizeof(*prng));
	prng->cycle = 0;
	prng->slot  = 0;
	prng->count = 0;
	err         = silofs_mdigest_init(&prng->mdigest);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_prandgen_fini(struct silofs_prandgen *prng)
{
	silofs_mdigest_fini(&prng->mdigest);
	memset(prng, 0, sizeof(*prng));
}

static uint64_t prandgen_consume_slot(struct silofs_prandgen *prng)
{
	const size_t i = prng->slot++ % ARRAY_SIZE(prng->prandom);

	return prng->prandom[i];
}

static void prandgen_prepare(struct silofs_prandgen *prng)
{
	const size_t np_max = SILOFS_ARRAY_SIZE(prng->prandom);

	if (!prng->slot && !prng->cycle) {
		/* init case: start fresh */
		prandgen_refill_prandom(prng);
		prandgen_refill_entropy(prng);
		prng->cycle = 1;
	} else if (prng->slot == np_max) {
		/* normal case: refill as needed */
		prandgen_refill_prandom(prng);
		prng->slot = 0;
		prng->cycle++;
		if ((prng->cycle % 31 == 0)) {
			prandgen_refill_entropy(prng);
		}
	}
}

static void prandgen_remix_xseed(struct silofs_prandgen *prng, uint64_t u)
{
	const uint64_t c = (uint64_t)(prng->count++) ^ 0xc3a5c85c97cb3127ULL;
	const uint64_t t = silofs_twang64(u ^ c);

	prng->xseed ^= (uint32_t)t;
	prng->xseed ^= (uint32_t)(t >> 32);
}

void silofs_prandgen_take(struct silofs_prandgen *prng, void *p, size_t n)
{
	uint64_t u;
	uint8_t *q = p;
	size_t   nb, k = 0;

	while (k < n) {
		nb = silofs_min(n - k, sizeof(u));

		prandgen_prepare(prng);
		u = prandgen_consume_slot(prng);
		prandgen_remix_xseed(prng, u);

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
