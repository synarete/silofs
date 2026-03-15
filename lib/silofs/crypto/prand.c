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
	size_t cnt   = 0;

	while (cnt < len) {
		cnt += do_getentropy(ptr + cnt, len - cnt);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_prand_in {
	uint32_t d[8];
};

static void prandgen_fill_in(struct silofs_prandgen *prng, uint32_t s,
                             struct silofs_prand_in *prin)
{
	struct timespec ts[2];
	const size_t nd = ARRAY_SIZE(prin->d);
	const size_t ne = ARRAY_SIZE(prng->entropy);
	size_t di;
	uint64_t ev;
	const uint32_t xseed[2] = {
		(uint32_t)(prng->xseed),
		(uint32_t)(prng->xseed >> 32),
	};

	silofs_clock_gettime_boot(&ts[0]);
	silofs_clock_gettime_real(&ts[1]);

	di = xseed[0] + s;
	ev = prng->entropy[di % ne];

	prin->d[di++ % nd] = (uint32_t)ev;
	prin->d[di++ % nd] = (uint32_t)ts[0].tv_sec * (0xc2b2ae35 + s);
	prin->d[di++ % nd] = xseed[1] + prng->slot;
	prin->d[di++ % nd] = (uint32_t)ts[1].tv_nsec;

	ev ^= silofs_twang64((uint64_t)ts[0].tv_nsec ^ 0x9ae16a3b2f90404fUL);
	prin->d[di++ % nd] = (uint32_t)ts[1].tv_sec * 0x85ebca6b;
	prin->d[di++ % nd] = (uint32_t)ev;
	prin->d[di++ % nd] = (uint32_t)(ts[0].tv_nsec ^ ts[1].tv_nsec);
	prin->d[di++ % nd] = (uint32_t)(ev >> 32);
}

static void prandgen_mkhash(struct silofs_prandgen *prng, uint32_t s,
                            struct silofs_hash256 *out_hash)
{
	struct silofs_prand_in prin = {};

	prandgen_fill_in(prng, s, &prin);
	silofs_sha3_256_of(&prng->md_hd, &prin, sizeof(prin), out_hash);
	prng->xseed ^= silofs_xxh64(&prin, sizeof(prin), prin.d[0] + s);
}

static void *prandgen_prandom_buf(struct silofs_prandgen *prng)
{
	return prng->prandom;
}

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	struct silofs_hash256 hash;
	const size_t psz = sizeof(prng->prandom);
	uint32_t s;
	uint8_t *p;

	s = 0;
	p = prandgen_prandom_buf(prng);
	for (size_t n = 0, k = 0; n < psz; n += k) {
		k = silofs_min(sizeof(hash.hash), psz - n);

		prandgen_mkhash(prng, ++s, &hash);
		memcpy(p + n, hash.hash, k);
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

	memset(prng, 0, sizeof(*prng));
	prng->cycle = 0;
	prng->slot  = 0;
	prng->count = 0;

	err = silofs_mdigest_init(&prng->md_hd);
	if (err) {
		return err;
	}
	return 0;
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
	pr = silofs_twang64(prng->prandom[prng->slot] ^ prng->count);
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
		prandgen_refill_entropy(prng);
		prandgen_refill_prandom(prng);
		prng->cycle++;
		prng->slot = 0;
	}
}

static void prandgen_remix_xseed(struct silofs_prandgen *prng, uint64_t u)
{
	prng->count++;
	prng->xseed ^= (u * prng->count);
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
