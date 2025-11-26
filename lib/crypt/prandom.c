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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <silofs/ondisk.h>
#include "infra.h"
#include "prandom.h"

static void do_getentropy(void *buf, size_t len)
{
	int err;

	err = getentropy(buf, len);
	if (err) {
		silofs_panic("getentropy: err=%d", errno);
	}
}

void silofs_getentropy(void *p, size_t n)
{
	uint8_t *ptr = p;
	const uint8_t *end = ptr + n;
	const size_t getentropy_max = 256;

	while (ptr < end) {
		size_t cnt;

		cnt = (size_t)(end - ptr);
		if (cnt > getentropy_max) {
			cnt = getentropy_max;
		}
		do_getentropy(ptr, cnt);
		ptr += cnt;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* Blum-Blum-Shub pseudo-random number generator, using p=383 q=503 */
static uint64_t blum_blum_shub(uint64_t n)
{
	return (n * n) % 192649UL;
}

static uint64_t twang_mix64(uint64_t n)
{
	n = ~n + (n << 21);
	n = n ^ (n >> 24);
	n = n + (n << 3) + (n << 8);
	n = n ^ (n >> 14);
	n = n + (n << 2) + (n << 4);
	n = n ^ (n >> 28);
	n = n + (n << 31);

	return n;
}

static void setup_udata(uint64_t u[4])
{
	struct timespec t;

	silofs_clock_mono_now(&t);
	u[0] = (uint64_t)t.tv_sec % 2654435761;
	u[1] = (uint64_t)t.tv_nsec ^ 0xc6a4a7935bd1e995UL;
	silofs_uptime(&t);
	u[2] = (uint64_t)t.tv_sec;
	u[3] = (uint64_t)t.tv_nsec ^ 0x5bd1e995UL;
}

static uint64_t prandom_seed(void)
{
	uint64_t u[4] = {};

	setup_udata(u);
	return silofs_xxh64(u, sizeof(u), (uint64_t)gettid());
}

void silofs_prandom(void *p, size_t n)
{
	uint16_t *d = p;
	uint8_t *q = p;
	uint64_t xx, bbs;

	xx = prandom_seed();
	for (size_t i = 0; i < (n / sizeof(*d)); ++i) {
		bbs = blum_blum_shub(xx);
		d[i] = (uint16_t)bbs;
		xx = twang_mix64(xx + bbs);
	}
	if (n & 1) {
		q[n - 1] = (uint8_t)xx;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
prandgen_mkhash(struct silofs_prandgen *prng, struct silofs_hash256 *out_hash)
{
	uint32_t d[8];
	uint64_t u;
	struct timespec t;

	silofs_clock_mono_now(&t);
	d[0] = (uint32_t)t.tv_sec * 0xc2b2ae35;
	d[1] = (uint32_t)t.tv_nsec;
	d[2] = (uint32_t)prng->cycle;
	silofs_uptime(&t);
	d[3] = (uint32_t)t.tv_sec * 0x85ebca6b;
	d[4] = (uint32_t)t.tv_nsec * 0x5bd1e995;
	u = (uint64_t)t.tv_nsec ^ 0xc6a4a7935bd1e995UL;
	u = twang_mix64(u);
	d[5] = (uint32_t)u;
	d[6] = (uint32_t)gettid() ^ prng->xxprev;
	d[7] = (uint32_t)(u >> 32);

	silofs_sha3_256_of(&prng->mdigest, d, sizeof(d), out_hash);
	prng->xxprev = silofs_xxh32(d, sizeof(d), prng->xxprev);
}

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	struct silofs_hash256 hash;
	const size_t len = sizeof(prng->prandom);
	size_t k, cnt = 0;

	while (cnt < len) {
		prandgen_mkhash(prng, &hash);
		k = silofs_min(sizeof(hash.hash), len - cnt);
		memcpy(&prng->prandom[cnt], hash.hash, k);
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

	memset(prng, 0, sizeof(*prng));
	err = silofs_mdigest_init(&prng->mdigest);
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

static size_t
prandgen_take_some(struct silofs_prandgen *prng, void *buf, size_t len)
{
	const size_t np_max = SILOFS_ARRAY_SIZE(prng->prandom);
	const size_t ne_max = SILOFS_ARRAY_SIZE(prng->entropy);
	uint8_t *p = buf;
	size_t cnt = 0;

	while ((cnt < len) && (prng->slot < np_max)) {
		p[cnt++] = prng->prandom[prng->slot] ^
		           prng->entropy[prng->slot % ne_max];
		prng->slot++;
	}
	return cnt;
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

void silofs_prandgen_take(struct silofs_prandgen *prng, void *buf, size_t bsz)
{
	uint8_t *m = buf;
	size_t k, cnt = 0;

	while (cnt < bsz) {
		prandgen_prepare(prng);
		k = prandgen_take_some(prng, &m[cnt], bsz - cnt);
		silofs_expect_gt(k, 0);
		cnt += k;
	}
}
