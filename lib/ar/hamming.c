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
	*w |= (uint16_t)(v << (n - 1));
}

static void ham12_flipbit(uint16_t *w, unsigned n)
{
	*w ^= (uint16_t)(1 << (n - 1));
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
	uint16_t       cw = 0;

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

static void ham12_extract(uint16_t cw, uint16_t *out_dat, uint16_t *out_syn)
{
	const uint16_t d1  = ham12_getbit(cw, 3);
	const uint16_t d2  = ham12_getbit(cw, 5);
	const uint16_t d3  = ham12_getbit(cw, 6);
	const uint16_t d4  = ham12_getbit(cw, 7);
	const uint16_t d5  = ham12_getbit(cw, 9);
	const uint16_t d6  = ham12_getbit(cw, 10);
	const uint16_t d7  = ham12_getbit(cw, 11);
	const uint16_t d8  = ham12_getbit(cw, 12);
	const uint16_t p1  = ham12_getbit(cw, 1);
	const uint16_t p2  = ham12_getbit(cw, 2);
	const uint16_t p4  = ham12_getbit(cw, 4);
	const uint16_t p8  = ham12_getbit(cw, 8);
	const uint16_t p1r = p1 ^ d1 ^ d2 ^ d4 ^ d5 ^ d7;
	const uint16_t p2r = p2 ^ d1 ^ d3 ^ d4 ^ d6 ^ d7;
	const uint16_t p4r = p4 ^ d2 ^ d3 ^ d4 ^ d8;
	const uint16_t p8r = p8 ^ d5 ^ d6 ^ d7 ^ d8;

	*out_dat = 0;
	ham12_setbit(out_dat, 1, d1);
	ham12_setbit(out_dat, 2, d2);
	ham12_setbit(out_dat, 3, d3);
	ham12_setbit(out_dat, 4, d4);
	ham12_setbit(out_dat, 5, d5);
	ham12_setbit(out_dat, 6, d6);
	ham12_setbit(out_dat, 7, d7);
	ham12_setbit(out_dat, 8, d8);
	*out_syn = (uint16_t)((p8r << 3) | (p4r << 2) | (p2r << 1) | p1r);
}

static int ham12_decode(uint16_t cw, uint8_t *out_dat)
{
	uint16_t syn, dat;

	ham12_extract(cw, &dat, &syn);
	if (syn > 12) {
		/* un-correctable data */
		return -1;
	}
	if (syn == 0) {
		goto out_ok;
	}
	/* one (or more) bit flips */
	ham12_flipbit(&cw, syn);
	ham12_extract(cw, &dat, &syn);
	if (syn > 12) {
		/* un-correctable data */
		return -1;
	}
out_ok:
	*out_dat = (uint8_t)dat;
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ham12_encode8(const uint8_t dat[8], uint8_t out[12])
{
	unsigned cw, i, j = 0;

	memset(out, 0, 12);
	for (i = 0; i < 8; ++i) {
		cw = ham12_encode(dat[i]);
		if (i & 1) {
			out[j] = (uint8_t)(cw & 0xFF);
			out[j - 1] |= (uint8_t)((cw >> 8) & 0xF);
			j += 1;
		} else {
			out[j] = (uint8_t)(cw >> 4);
			out[j + 1] |= (uint8_t)((cw & 0xF) << 4);
			j += 2;
		}
	}
}

static int ham12_decode8(const uint8_t in[12], uint8_t out[8])
{
	unsigned cw, i, j = 0;
	int      nerr = 0;

	memset(out, 0, 8);
	for (i = 0; i < 8; ++i) {
		if (i & 1) {
			cw = ((unsigned)in[j - 1] & 0xF) << 8;
			cw |= in[j];
			j += 1;
		} else {
			cw = in[j];
			cw <<= 4;
			cw |= (unsigned)in[j + 1] >> 4;
			j += 2;
		}
		if (ham12_decode((uint16_t)cw, &out[i])) {
			nerr++;
		}
	}
	return nerr;
}

int silofs_hamming12_encode_buf(const void *inb, size_t inlen, void *outb,
                                size_t outlen)
{
	const uint8_t *in  = inb;
	uint8_t       *out = outb;

	if ((inlen % 8) || (outlen % 12)) {
		return -1;
	}
	if ((12 * inlen) != (8 * outlen)) {
		return -1;
	}
	for (size_t i = 0, j = 0; i < inlen; i += 8, j += 12) {
		ham12_encode8(in + i, out + j);
	}
	return 0;
}

int silofs_hamming12_decode_buf(const void *inb, size_t inlen, void *outb,
                                size_t outlen)
{
	const uint8_t *in   = inb;
	uint8_t       *out  = outb;
	int            nerr = 0;

	if ((inlen % 12) || (outlen % 8)) {
		return -1;
	}
	if ((8 * inlen) != (12 * outlen)) {
		return -1;
	}
	for (size_t i = 0, j = 0; i < inlen; i += 12, j += 8) {
		nerr += ham12_decode8(in + i, out + j);
	}
	return !nerr ? 0 : -1;
}

/*
 * TODO-0060: Add Golay(24,12)
 *
 * Need a better error-correction code. See reference implementation in
 * Wireshark's code base.
 */
