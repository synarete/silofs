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
#include <xxhash.h>

#include <silofs/macros.h>
#include <silofs/infra/hashfn.h>

uint64_t silofs_twang64(uint64_t n)
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

uint64_t silofs_xxh3(const void *buf, size_t len)
{
	return XXH3_64bits(buf, len);
}

uint64_t silofs_xxh3_seed(const void *buf, size_t len, uint64_t seed)
{
	return XXH3_64bits_withSeed(buf, len, seed);
}
