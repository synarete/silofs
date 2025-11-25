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
#include <silofs/macros.h>
#include <silofs/panic.h>
#include <silofs/random.h>
#include "utility.h"
#include "hashfn.h"
#include "times.h"

static void do_getentropy(void *buf, size_t len)
{
	int err;

	err = getentropy(buf, len);
	if (err) {
		silofs_panic("getentropy: err=%d", errno);
	}
}

static void silofs_getentropy(void *p, size_t n)
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

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	silofs_prandom(prng->prandom, sizeof(prng->prandom));
}

static void prandgen_refill_entropy(struct silofs_prandgen *prng)
{
	silofs_getentropy(prng->entropy, sizeof(prng->entropy));
}

void silofs_prandgen_init(struct silofs_prandgen *prng)
{
	prng->slot = 0;
	prng->cycle = 0;
	prandgen_refill_prandom(prng);
	prandgen_refill_entropy(prng);
}

void silofs_prandgen_fini(struct silofs_prandgen *prng)
{
	memset(prng->prandom, 0, sizeof(prng->prandom));
	memset(prng->entropy, 0, sizeof(prng->entropy));
	prng->cycle = 0;
	prng->slot = 0;
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
	const size_t nslots_max = SILOFS_ARRAY_SIZE(prng->prandom);

	if (prng->slot < nslots_max) {
		return;
	}
	prandgen_refill_prandom(prng);

	prng->slot = 0;
	prng->cycle++;

	if (prng->cycle < (31 * nslots_max)) {
		return;
	}
	prandgen_refill_entropy(prng);
}

void silofs_prandgen_take(struct silofs_prandgen *prng, void *buf, size_t bsz)
{
	uint8_t *cur = buf;
	const uint8_t *end = cur + bsz;
	size_t cnt = 0;

	while (cur < end) {
		prandgen_prepare(prng);
		cnt = prandgen_take_some(prng, cur, (size_t)(end - cur));
		silofs_expect_gt(cnt, 0);
		cur += cnt;
	}
}

void silofs_prandgen_take_u64(struct silofs_prandgen *prng, uint64_t *out_u64)
{
	silofs_prandgen_take(prng, out_u64, sizeof(*out_u64));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_prandgen_ascii(struct silofs_prandgen *prng, char *str, size_t n)
{
	uint64_t rnd = 0;
	const int base = 33;
	const int last = 126;
	int print_ch;

	silofs_prandgen_take_u64(prng, &rnd);
	for (size_t i = 0; i < n; ++i) {
		if (i % 53) {
			rnd = rnd >> 1;
		} else {
			silofs_prandgen_take_u64(prng, &rnd);
		}
		print_ch = abs((int)(rnd % (uint64_t)(last - base)) + base);
		str[i] = (char)print_ch;
	}
}
