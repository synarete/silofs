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
#include <silofs/str/ascii.h>
#include <ctype.h>

char silofs_nibble_to_ascii(int n)
{
	const int a = n & 0xF;

	switch (a) {
	case 0x0:
		return '0';
	case 0x1:
		return '1';
	case 0x2:
		return '2';
	case 0x3:
		return '3';
	case 0x4:
		return '4';
	case 0x5:
		return '5';
	case 0x6:
		return '6';
	case 0x7:
		return '7';
	case 0x8:
		return '8';
	case 0x9:
		return '9';
	case 0xa:
		return 'a';
	case 0xb:
		return 'b';
	case 0xc:
		return 'c';
	case 0xd:
		return 'd';
	case 0xe:
		return 'e';
	case 0xf:
		return 'f';
	default:
		break;
	}
	return (char)-1;
}

int silofs_ascii_to_nibble(char a)
{
	const int c = tolower((int)a);

	switch (c) {
	case '0':
		return 0x0;
	case '1':
		return 0x1;
	case '2':
		return 0x2;
	case '3':
		return 0x3;
	case '4':
		return 0x4;
	case '5':
		return 0x5;
	case '6':
		return 0x6;
	case '7':
		return 0x7;
	case '8':
		return 0x8;
	case '9':
		return 0x9;
	case 'a':
		return 0xa;
	case 'b':
		return 0xb;
	case 'c':
		return 0xc;
	case 'd':
		return 0xd;
	case 'e':
		return 0xe;
	case 'f':
		return 0xf;
	default:
		break;
	}
	return -1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_byte_to_ascii(uint8_t b, char *a)
{
	a[0] = silofs_nibble_to_ascii((int)(b >> 4));
	a[1] = silofs_nibble_to_ascii((int)b);
}

int silofs_ascii_to_byte(const char *a, uint8_t *b)
{
	uint32_t nib[2];
	int ret;

	ret = silofs_ascii_to_nibble(a[0]);
	if (ret == -1) {
		return -1;
	}
	nib[0] = (uint32_t)ret;

	ret = silofs_ascii_to_nibble(a[1]);
	if (ret == -1) {
		return -1;
	}
	nib[1] = (uint32_t)ret;

	*b = (uint8_t)(nib[0] << 4 | nib[1]);
	return 0;
}

void silofs_uint64_to_ascii(uint64_t u, char *a)
{
	int shift;
	uint8_t b;

	shift = 64;
	while (shift > 0) {
		shift -= 8;
		b = (uint8_t)((u >> shift) & 0xFF);
		silofs_byte_to_ascii(b, a);
		a += 2;
	}
}

int silofs_ascii_to_uint64(const char *a, uint64_t *out_u)
{
	uint64_t u = 0;
	uint8_t b = 0;
	int err;

	for (size_t i = 0; i < 8; ++i) {
		err = silofs_ascii_to_byte(a, &b);
		if (err) {
			return err;
		}
		u = (u << 8) | (uint64_t)b;
		a += 2;
	}
	*out_u = u;
	return 0;
}

void silofs_mem_to_ascii(const void *mem, size_t msz, char *asb, size_t asz,
                         size_t *out_cnt)
{
	const uint8_t *b = mem;
	size_t cnt = 0;

	for (size_t i = 0; i < msz; ++i) {
		if ((cnt + 2) > asz) {
			break;
		}
		silofs_byte_to_ascii(b[i], asb + cnt);
		cnt += 2;
	}
	*out_cnt = cnt;
}

int silofs_ascii_to_mem(void *mem, size_t msz, const char *asb, size_t asz,
                        size_t *out_cnt)
{
	uint8_t *b = mem;
	size_t cnt = 0;
	int err = 0;

	for (size_t i = 0; (i + 1) < asz; i += 2) {
		if (cnt >= msz) {
			break;
		}
		err = silofs_ascii_to_byte(&asb[i], b + cnt);
		if (err) {
			break;
		}
		cnt += 1;
	}
	*out_cnt = cnt;
	return err;
}
