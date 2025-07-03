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
#include "utests.h"

static void flipbit8(uint8_t *v, unsigned n)
{
	*v ^= (1 << n);
}

static void flipbit16(uint16_t *v, unsigned n)
{
	*v ^= (1 << n);
}

static void ut_hamming12_simple(struct ut_env *ute)
{
	uint8_t octet, data;
	uint16_t codeword = 0;
	int err;

	for (unsigned i = 0; i < 0xFF; ++i) {
		octet = (uint8_t)i;
		err = silofs_hamming12_encode(octet, &codeword);
		ut_expect_ok(err);
		err = silofs_hamming12_decode(codeword, &data);
		ut_expect_ok(err);
		ut_expect_eq(octet, data);
	}

	ut_unused(ute);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_hamming12_error1(struct ut_env *ute)
{
	uint8_t octet, data;
	uint16_t codeword = 0;
	int err;

	for (unsigned i = 0; i < 0xFF; ++i) {
		for (unsigned j = 0; j < 12; ++j) {
			octet = (uint8_t)i;
			err = silofs_hamming12_encode(octet, &codeword);
			ut_expect_ok(err);
			flipbit16(&codeword, j);
			err = silofs_hamming12_decode(codeword, &data);
			ut_expect_ok(err);
			ut_expect_eq(octet, data);
		}
	}
	ut_unused(ute);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_hamming12_buf_simple_(struct ut_env *ute, size_t len)
{
	const size_t enclen = (len * 12) / 8;
	void *dat = ut_randbuf(ute, len);
	void *res = ut_zerobuf(ute, len);
	void *enc = ut_zerobuf(ute, enclen);
	int err;

	err = silofs_hamming12_encode_buf(dat, len, enc, enclen);
	ut_expect_ok(err);
	err = silofs_hamming12_decode_buf(enc, enclen, res, len);
	ut_expect_ok(err);
	ut_expect_eqm(dat, res, len);
}

static void ut_hamming12_buf_simple(struct ut_env *ute)
{
	const size_t len[] = { 8, 64, 1024, 4096 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(len); ++i) {
		ut_hamming12_buf_simple_(ute, len[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_hamming12_buf_error1_(struct ut_env *ute, size_t len)
{
	const size_t enclen = (len * 12) / 8;
	void *dat = ut_randbuf(ute, len);
	void *res = ut_zerobuf(ute, len);
	uint8_t *enc = ut_zerobuf(ute, enclen);
	int err;

	err = silofs_hamming12_encode_buf(dat, len, enc, enclen);
	ut_expect_ok(err);
	for (size_t i = 0; i < enclen; i += 2) {
		flipbit8(&enc[i], ((i / 2) % 8));
	}
	err = silofs_hamming12_decode_buf(enc, enclen, res, len);
	ut_expect_ok(err);
	ut_expect_eqm(dat, res, len);
}

static void ut_hamming12_buf_error1(struct ut_env *ute)
{
	const size_t len[] = { 8, 64, 1024, 4096 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(len); ++i) {
		ut_hamming12_buf_error1_(ute, len[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_hamming12_simple),
	UT_DEFTEST(ut_hamming12_error1),
	UT_DEFTEST(ut_hamming12_buf_simple),
	UT_DEFTEST(ut_hamming12_buf_error1),
};

const struct ut_testdefs ut_tdefs_hamming = UT_MKTESTS(ut_local_tests);
