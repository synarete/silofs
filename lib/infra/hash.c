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
#include <xxhash.h>
#include <silofs/macros.h>
#include "times.h"
#include "hash.h"

uint64_t silofs_hash_fnv1a(const void *buf, size_t len, uint64_t seed)
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

uint32_t silofs_hash_xxh32(const void *buf, size_t len, uint32_t seed)
{
	return XXH32(buf, len, seed);
}

uint64_t silofs_hash_xxh64(const void *buf, size_t len, uint64_t seed)
{
	return XXH64(buf, len, seed);
}

uint64_t silofs_twang_mix64(uint64_t n)
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

void silofs_xrand_by_hash(void *ptr, size_t len, uint64_t seed)
{
	uint64_t u[5] = { seed, seed, seed, seed, seed };
	uint64_t *itr = ptr;
	uint64_t xx = *itr;
	const size_t ns = len / sizeof(*itr);
	const size_t nu = SILOFS_ARRAY_SIZE(u);
	struct timespec t;

	silofs_mclock_now(&t);
	u[0] ^= (uint64_t)t.tv_sec;
	u[1] ^= (uint64_t)t.tv_nsec;
	u[2] ^= (uint64_t)gettid();
	silofs_rclock_now(&t);
	u[3] ^= (uint64_t)t.tv_sec;
	u[4] ^= (uint64_t)t.tv_nsec;

	for (uint32_t i = 0; i < ns; ++i) {
		u[(i + 1) % nu] ^= silofs_twang_mix64(xx);
		u[(i + 2) % nu] ^= xx / (i | 1);
		u[(i + 3) % nu] ^= ~xx + i;
		u[(i + 4) % nu] ^= xx * (i + 11);

		xx = silofs_hash_xxh64(u, sizeof(u), xx);
		*itr++ ^= xx;
	}
}
