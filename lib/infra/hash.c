/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/hash.h>
#include <xxhash.h>

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
