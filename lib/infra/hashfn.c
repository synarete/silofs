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
#include <xxhash.h>
#include <silofs/macros.h>
#include "utility.h"
#include "times.h"
#include "hashfn.h"

uint64_t silofs_fnv1a(const void *buf, size_t len, uint64_t seed)
{
	const uint8_t *itr = (const uint8_t *)buf;
	const uint8_t *end = itr + len;
	const uint64_t fnv_prime = 0x100000001B3UL;
	uint64_t hval = seed;

	while (itr < end) {
		hval *= fnv_prime;
		hval ^= (uint64_t)(*itr++);
	}
	return hval;
}

uint32_t silofs_xxh32(const void *buf, size_t len, uint32_t seed)
{
	return XXH32(buf, len, seed);
}

uint64_t silofs_xxh64(const void *buf, size_t len, uint64_t seed)
{
	return XXH64(buf, len, seed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	u[0] = (uint64_t)t.tv_sec ^ 0xc6a4a7935bd1e995UL;
	u[1] = (uint64_t)t.tv_nsec;
	silofs_uptime(&t);
	u[2] = (uint64_t)t.tv_sec + (uint64_t)gettid();
	u[3] = (uint64_t)t.tv_nsec ^ 0x5bd1e995UL;
}

static void prand_head(uint64_t *d, const uint64_t *s, size_t n)
{
	uint64_t u[4] = {};
	const size_t nu = SILOFS_ARRAY_SIZE(u);
	const size_t nd = n / sizeof(*d);

	setup_udata(u);
	for (size_t i = 0; i < nd; ++i) {
		const uint64_t xx = s[i];

		u[(i + 1) % nu] ^= twang_mix64(xx + i);
		u[(i + 2) % nu] ^= xx / (i | 1);
		u[(i + 3) % nu] ^= ~xx + i;

		d[i] = silofs_xxh64(u, sizeof(u), xx);
	}
}

static void prand_tail(uint8_t *d, const uint8_t *s, size_t n)
{
	union {
		struct timespec t;
		uint8_t b[16];
	} u = {};

	silofs_clock_mono_now(&u.t);
	for (size_t i = 0; i < n; ++i) {
		d[i] = s[i] ^ u.b[i % SILOFS_ARRAY_SIZE(u.b)];
	}
}

static void *skip(const void *p, size_t n)
{
	const uint8_t *q = p;

	q += n;
	return silofs_unconst(q);
}

void silofs_prand_by_hash(void *dst, const void *src, size_t n)
{
	const size_t nh = (n / sizeof(uint64_t)) * sizeof(uint64_t);
	const size_t nt = n - nh;

	prand_head(dst, src, nh);
	prand_tail(skip(dst, nh), skip(src, nh), nt);
}
