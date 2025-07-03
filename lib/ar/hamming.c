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
#include <stdint.h>
#include "infra.h"
#include "hamming.h"

/*
 * Hamming12 code: transforms 8-bits data message into 12-bits code-word
 * (data + parity) which enable us to detect and correct single bit flip.
 * In case of 2 or more bit flips returns false-corrected data (no error
 * detection).
 *
 *
 * Bits:         1  2  3  4  5  6  7  8  9 10 11 12
 *             +--+--+--+--+--+--+--+--+--+--+--+--+
 * Code word:   p1 p2 d1 p4 d2 d3 d4 p8 d5 d6 d7 d8
 *
 *
 * Control table:
 *
 *             +-----+-----+--------------+
 *             | Pos | Bit | Parity       |
 *             +-----+-----+--------------+
 *             |  1  | p1  | p1           |
 *             |  2  | p2  | p2           |
 *             |  3  | d1  | p1 ^ p2      |
 *             |  4  | p4  | p4           |
 *             |  5  | d2  | p1 ^ p4      |
 *             |  6  | d3  | p2 ^ p4      |
 *             |  7  | d4  | p1 ^ p2 ^ p4 |
 *             |  8  | p8  | p8           |
 *             |  9  | d5  | p1 ^ p8      |
 *             | 10  | d6  | p2 ^ p8      |
 *             | 11  | d7  | p1 ^ p2 ^ p8 |
 *             | 12  | d8  | p4 ^ p8      |
 *             +-----+-----+--------------+
 *
 * Encode (send):
 *   p1 = d1 ^ d2 ^ d4 ^ d5 ^ d7
 *   p2 = d1 ^ d3 ^ d4 ^ d6 ^ d7
 *   p4 = d2 ^ d3 ^ d4 ^ d8
 *   p8 = d5 ^ d6 ^ d7 ^ d8
 *
 * Decode (recv):
 *   p1r = p1 ^ d1 ^ d2 ^ d4 ^ d5 ^ d7
 *   p2r = p2 ^ d1 ^ d3 ^ d4 ^ d6 ^ d7
 *   p4r = p4 ^ d2 ^ d3 ^ d4 ^ d8
 *   p8r = p8 ^ d5 ^ d6 ^ d7 ^ d8
 */
static uint16_t ham12_getbit(uint16_t w, unsigned n)
{
	return (w >> (n - 1)) & 1;
}

static void ham12_setbit(uint16_t *w, unsigned n, uint16_t v)
{
	*w |= (v << (n - 1));
}

static void ham12_flipbit(uint16_t *w, unsigned n)
{
	*w ^= (1 << (n - 1));
}

static uint16_t ham12_encode(uint8_t n)
{
	const uint16_t d1 = ham12_getbit(n, 1);
	const uint16_t d2 = ham12_getbit(n, 2);
	const uint16_t d3 = ham12_getbit(n, 3);
	const uint16_t d4 = ham12_getbit(n, 4);
	const uint16_t d5 = ham12_getbit(n, 5);
	const uint16_t d6 = ham12_getbit(n, 6);
	const uint16_t d7 = ham12_getbit(n, 7);
	const uint16_t d8 = ham12_getbit(n, 8);
	const uint16_t p1 = d1 ^ d2 ^ d4 ^ d5 ^ d7;
	const uint16_t p2 = d1 ^ d3 ^ d4 ^ d6 ^ d7;
	const uint16_t p4 = d2 ^ d3 ^ d4 ^ d8;
	const uint16_t p8 = d5 ^ d6 ^ d7 ^ d8;
	uint16_t cw = 0;

	ham12_setbit(&cw, 1, p1);
	ham12_setbit(&cw, 2, p2);
	ham12_setbit(&cw, 3, d1);
	ham12_setbit(&cw, 4, p4);
	ham12_setbit(&cw, 5, d2);
	ham12_setbit(&cw, 6, d3);
	ham12_setbit(&cw, 7, d4);
	ham12_setbit(&cw, 8, p8);
	ham12_setbit(&cw, 9, d5);
	ham12_setbit(&cw, 10, d6);
	ham12_setbit(&cw, 11, d7);
	ham12_setbit(&cw, 12, d8);

	return cw;
}

static uint16_t ham12_calc_syndrome(uint16_t cw)
{
	const uint16_t d1 = ham12_getbit(cw, 3);
	const uint16_t d2 = ham12_getbit(cw, 5);
	const uint16_t d3 = ham12_getbit(cw, 6);
	const uint16_t d4 = ham12_getbit(cw, 7);
	const uint16_t d5 = ham12_getbit(cw, 9);
	const uint16_t d6 = ham12_getbit(cw, 10);
	const uint16_t d7 = ham12_getbit(cw, 11);
	const uint16_t d8 = ham12_getbit(cw, 12);
	const uint16_t p1 = ham12_getbit(cw, 1);
	const uint16_t p2 = ham12_getbit(cw, 2);
	const uint16_t p4 = ham12_getbit(cw, 4);
	const uint16_t p8 = ham12_getbit(cw, 8);
	const uint16_t p1r = p1 ^ d1 ^ d2 ^ d4 ^ d5 ^ d7;
	const uint16_t p2r = p2 ^ d1 ^ d3 ^ d4 ^ d6 ^ d7;
	const uint16_t p4r = p4 ^ d2 ^ d3 ^ d4 ^ d8;
	const uint16_t p8r = p8 ^ d5 ^ d6 ^ d7 ^ d8;

	return (p8r << 3) | (p4r << 2) | (p2r << 1) | p1r;
}

static uint8_t ham12_extract_data(uint16_t cw)
{
	const uint16_t d1 = ham12_getbit(cw, 3);
	const uint16_t d2 = ham12_getbit(cw, 5);
	const uint16_t d3 = ham12_getbit(cw, 6);
	const uint16_t d4 = ham12_getbit(cw, 7);
	const uint16_t d5 = ham12_getbit(cw, 9);
	const uint16_t d6 = ham12_getbit(cw, 10);
	const uint16_t d7 = ham12_getbit(cw, 11);
	const uint16_t d8 = ham12_getbit(cw, 12);
	uint16_t n = 0;

	ham12_setbit(&n, 1, d1);
	ham12_setbit(&n, 2, d2);
	ham12_setbit(&n, 3, d3);
	ham12_setbit(&n, 4, d4);
	ham12_setbit(&n, 5, d5);
	ham12_setbit(&n, 6, d6);
	ham12_setbit(&n, 7, d7);
	ham12_setbit(&n, 8, d8);

	return (uint8_t)n;
}

static int ham12_decode(uint16_t cw, uint8_t *out_dat)
{
	uint16_t syn;

	syn = ham12_calc_syndrome(cw);
	if (syn > 12) {
		/* un-correctable data */
		return -1;
	}
	if (syn != 0) {
		/* one (or more) bit flips */
		ham12_flipbit(&cw, syn);
	}
	*out_dat = ham12_extract_data(cw);
	return 0;
}

int silofs_hamming12_encode(uint8_t octet, uint16_t *out_codeword)
{
	*out_codeword = (ham12_encode(octet) & 0xFFF);
	return 0;
}

int silofs_hamming12_decode(uint16_t codeword, uint8_t *out_octet)
{
	return ham12_decode(codeword & 0xFFF, out_octet);
}
