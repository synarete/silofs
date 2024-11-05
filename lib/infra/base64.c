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
#include <silofs/configs.h>
#include <silofs/macros.h>
#include <silofs/infra/base64.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#define BASE64_ENCODE_LEN(inlen)        ((((inlen) + 2) / 3) * 4)
#define BASE64_DECODE_ADD               64
#define BASE64_DECODE_ENT(ch, v) \
        [(ch)] = ((short)(v) + BASE64_DECODE_ADD)

static const char base64_encode_tbl[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int8_t base64_decode_tbl[] = {
	BASE64_DECODE_ENT('A', 0x0),
	BASE64_DECODE_ENT('B', 0x1),
	BASE64_DECODE_ENT('C', 0x2),
	BASE64_DECODE_ENT('D', 0x3),
	BASE64_DECODE_ENT('E', 0x4),
	BASE64_DECODE_ENT('F', 0x5),
	BASE64_DECODE_ENT('G', 0x6),
	BASE64_DECODE_ENT('H', 0x7),
	BASE64_DECODE_ENT('I', 0x8),
	BASE64_DECODE_ENT('J', 0x9),
	BASE64_DECODE_ENT('K', 0xA),
	BASE64_DECODE_ENT('L', 0xB),
	BASE64_DECODE_ENT('M', 0xC),
	BASE64_DECODE_ENT('N', 0xD),
	BASE64_DECODE_ENT('O', 0xE),
	BASE64_DECODE_ENT('P', 0xF),
	BASE64_DECODE_ENT('Q', 0x10),
	BASE64_DECODE_ENT('R', 0x11),
	BASE64_DECODE_ENT('S', 0x12),
	BASE64_DECODE_ENT('T', 0x13),
	BASE64_DECODE_ENT('U', 0x14),
	BASE64_DECODE_ENT('V', 0x15),
	BASE64_DECODE_ENT('W', 0x16),
	BASE64_DECODE_ENT('X', 0x17),
	BASE64_DECODE_ENT('Y', 0x18),
	BASE64_DECODE_ENT('Z', 0x19),
	BASE64_DECODE_ENT('a', 0x1A),
	BASE64_DECODE_ENT('b', 0x1B),
	BASE64_DECODE_ENT('c', 0x1C),
	BASE64_DECODE_ENT('d', 0x1D),
	BASE64_DECODE_ENT('e', 0x1E),
	BASE64_DECODE_ENT('f', 0x1F),
	BASE64_DECODE_ENT('g', 0x20),
	BASE64_DECODE_ENT('h', 0x21),
	BASE64_DECODE_ENT('i', 0x22),
	BASE64_DECODE_ENT('j', 0x23),
	BASE64_DECODE_ENT('k', 0x24),
	BASE64_DECODE_ENT('l', 0x25),
	BASE64_DECODE_ENT('m', 0x26),
	BASE64_DECODE_ENT('n', 0x27),
	BASE64_DECODE_ENT('o', 0x28),
	BASE64_DECODE_ENT('p', 0x29),
	BASE64_DECODE_ENT('q', 0x2A),
	BASE64_DECODE_ENT('r', 0x2B),
	BASE64_DECODE_ENT('s', 0x2C),
	BASE64_DECODE_ENT('t', 0x2D),
	BASE64_DECODE_ENT('u', 0x2E),
	BASE64_DECODE_ENT('v', 0x2F),
	BASE64_DECODE_ENT('w', 0x30),
	BASE64_DECODE_ENT('x', 0x31),
	BASE64_DECODE_ENT('y', 0x32),
	BASE64_DECODE_ENT('z', 0x33),
	BASE64_DECODE_ENT('0', 0x34),
	BASE64_DECODE_ENT('1', 0x35),
	BASE64_DECODE_ENT('2', 0x36),
	BASE64_DECODE_ENT('3', 0x37),
	BASE64_DECODE_ENT('4', 0x38),
	BASE64_DECODE_ENT('5', 0x39),
	BASE64_DECODE_ENT('6', 0x3A),
	BASE64_DECODE_ENT('7', 0x3B),
	BASE64_DECODE_ENT('8', 0x3C),
	BASE64_DECODE_ENT('9', 0x3D),
	BASE64_DECODE_ENT('+', 0x3E),
	BASE64_DECODE_ENT('/', 0x3F),
};

static char base64_encode_sext(int sext)
{
	return base64_encode_tbl[(uint8_t)sext  & 0x3F];
}

static bool base64_ispad(int chr)
{
	return (chr == '=');
}

static int base64_decode_sext(int chr, uint8_t *out_sext)
{
	int sext;
	const size_t decode_tbl_nelems =
	        SILOFS_ARRAY_SIZE(base64_decode_tbl);

	if (chr >= (int)decode_tbl_nelems) {
		return -EINVAL;
	}
	sext = base64_decode_tbl[chr] - BASE64_DECODE_ADD;
	if ((sext < 0) || (sext > 0x3F)) {
		return -EINVAL;
	}
	*out_sext = (uint8_t)sext;
	return 0;
}

static void
base64_encode_head(const void *in, char *out, size_t len)
{
	int sext;
	const uint8_t *inb = in;

	while (len) {
		sext = inb[0] >> 2;
		out[0] = base64_encode_sext(sext);
		sext = (inb[0] << 4) + (inb[1] >> 4);
		out[1] = base64_encode_sext(sext);
		sext = (inb[1] << 2) + (inb[2] >> 6);
		out[2] = base64_encode_sext(sext);
		sext = inb[2];
		out[3] = base64_encode_sext(sext);

		out += 4;
		len -= 3;
		inb += 3;
	}
}

static void
base64_encode_tail(const void *in, size_t inlen, char *out, size_t outlen)
{
	int sext;
	const uint8_t *inb = in;

	if (!outlen) {
		return;
	}
	sext = inb[0] >> 2;
	out[0] = base64_encode_sext(sext);
	if (!--outlen) {
		return;
	}
	sext = (inb[0] << 4) + (--inlen ? (inb[1] >> 4) : 0);
	out[1] = base64_encode_sext(sext);
	if (!--outlen) {
		return;
	}
	if (inlen) {
		sext = (inb[1] << 2) + (--inlen ? (inb[2] >> 6) : 0);
		out[2] = base64_encode_sext(sext);
	} else {
		out[2] = '=';
	}
	if (!--outlen) {
		return;
	}
	if (inlen) {
		sext = inb[2];
		out[3] = base64_encode_sext(sext);
	} else {
		out[3] = '=';
	}
}

int silofs_base64_encode(const void *in, size_t inlen,
                         char *out, size_t outlen_max, size_t *out_len)
{
	size_t outlen;
	size_t head_len_in = 0;
	size_t tail_len_in = 0;
	size_t head_len_out = 0;
	size_t tail_len_out = 0;
	const uint8_t *inb = in;

	outlen = BASE64_ENCODE_LEN(inlen);
	if (outlen > outlen_max) {
		return -EINVAL;
	}
	if (inlen >= 3) {
		head_len_in = (inlen / 3) * 3;
		head_len_out = (inlen / 3) * 4;
		base64_encode_head(inb, out, head_len_in);
	}
	tail_len_in = inlen - head_len_in;
	tail_len_out = outlen - head_len_out;
	base64_encode_tail(inb + head_len_in, tail_len_in,
	                   out + head_len_out, tail_len_out);

	if (outlen < outlen_max) {
		out[outlen] = '\0';
	}
	*out_len = outlen;
	return 0;
}

static void
base64_decode_sextets(const uint8_t *inb, uint8_t *outb, size_t cnt)
{
	if (cnt > 0) {
		outb[0] = (uint8_t)((inb[0] << 2) | (inb[1] >> 4));
	}
	if (cnt > 1) {
		outb[1] = (uint8_t)((inb[1] << 4) | (inb[2] >> 2));
	}
	if (cnt > 2) {
		outb[2] = (uint8_t)((inb[2] << 6) | inb[3]);
	}
}

int silofs_base64_decode(const char *in, size_t inlen,
                         void *out, size_t outlen_max,
                         size_t *out_len, size_t *out_inrd)
{
	uint8_t sext[4];
	size_t incnt = 0;
	size_t nsexts = 0;
	size_t npads = 0;
	size_t outlen = 0;
	uint8_t *outb = out;
	int chr = 0;
	int err = -1;

	while ((incnt < inlen) && (outlen < outlen_max) && (npads < 2)) {
		chr = in[incnt];
		if (base64_ispad(chr)) {
			npads++;
		} else {
			if (npads) {
				break;
			}
			err = base64_decode_sext(chr, &sext[nsexts++]);
			if (err) {
				goto out_err;
			}
			if ((outlen + nsexts - 1) > outlen_max) {
				goto out_err;
			}
			if (nsexts == 4) {
				base64_decode_sextets(sext, outb, 3);
				outlen += 3;
				outb += 3;
				nsexts = 0;
			}
		}
		incnt++;
	}
	if (nsexts) {
		if ((outlen + nsexts - 1) > outlen_max) {
			goto out_err;
		}
		base64_decode_sextets(sext, outb, nsexts - 1);
		outlen += nsexts - 1;
	}
	*out_len = outlen;
	*out_inrd = incnt;
	return 0;
out_err:
	*out_len = outlen;
	*out_inrd = incnt;
	return -EINVAL;
}

size_t silofs_base64_encode_len(size_t inlen)
{
	return BASE64_ENCODE_LEN(inlen);
}

