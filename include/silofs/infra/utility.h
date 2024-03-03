/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_UTILITY_H_
#define SILOFS_UTILITY_H_

#include <stdlib.h>
#include <stdint.h>

struct silofs_substr;

/* fixed-size string-buffer (typically, for names) */
struct silofs_strbuf {
	char str[256];
};

void silofs_strbuf_reset(struct silofs_strbuf *sbuf);

void silofs_strbuf_assign(struct silofs_strbuf *sbuf,
                          const struct silofs_strbuf *other);

void silofs_strbuf_setup(struct silofs_strbuf *sbuf,
                         const struct silofs_substr *str);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

char silofs_nibble_to_ascii(int n);

int silofs_ascii_to_nibble(char a);


void silofs_uint64_to_ascii(uint64_t u, char *a);

uint64_t silofs_ascii_to_uint64(const char *a);

void silofs_byte_to_ascii(uint8_t b, char *a);

void silofs_ascii_to_byte(const char *a, uint8_t *b);

size_t silofs_mem_to_ascii(const void *ptr, size_t len, char *buf, size_t bsz);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_burnstackn(int n);

void silofs_burnstack(void);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline int32_t silofs_min32(int32_t x, int32_t y)
{
	return x < y ? x : y;
}

static inline int64_t silofs_min64(int64_t x, int64_t y)
{
	return x < y ? x : y;
}

static inline uint64_t silofs_min(uint64_t x, uint64_t y)
{
	return x < y ? x : y;
}

static inline uint64_t silofs_min3(uint64_t x, uint64_t y, uint64_t z)
{
	return silofs_min(silofs_min(x, y), z);
}

static inline int32_t silofs_max32(int32_t x, int32_t y)
{
	return x > y ? x : y;
}

static inline int32_t silofs_clamp32(int32_t x, int32_t x_min, int32_t x_max)
{
	return silofs_max32(silofs_min32(x, x_max), x_min);
}

static inline int64_t silofs_max64(int64_t x, int64_t y)
{
	return x > y ? x : y;
}

static inline uint64_t silofs_max(uint64_t x, uint64_t y)
{
	return x > y ? x : y;
}

static inline uint64_t silofs_clamp(uint64_t v, uint64_t lo, uint64_t hi)
{
	return silofs_min(silofs_max(v, lo), hi);
}

static inline uint32_t silofs_clz32(uint32_t n)
{
	return n ? (uint32_t)__builtin_clz(n) : 32;
}

static inline uint32_t silofs_clz64(uint64_t n)
{
	return n ? (uint32_t)__builtin_clzl(n) : 64;
}

static inline uint32_t silofs_popcount32(uint32_t n)
{
	return n ? (uint32_t)__builtin_popcount(n) : 0;
}

static inline uint32_t silofs_popcount64(uint64_t n)
{
	return n ? (uint32_t)__builtin_popcountl(n) : 0;
}

static inline uint64_t silofs_div_round_up(uint64_t n, uint64_t d)
{
	return (n + d - 1) / d;
}

static inline uint64_t silofs_lrotate64(uint64_t x, unsigned int n)
{
	return (x << n) | (x >> (64 - n));
}

static inline uint64_t silofs_rrotate64(uint64_t x, unsigned int n)
{
	return (x >> n) | (x << (64 - n));
}

static inline void *silofs_unconst(const void *p)
{
	union {
		const void *p;
		void *q;
	} u = {
		.p = p
	};
	return u.q;
}

#endif /* SILOFS_UTILITY_H_ */
