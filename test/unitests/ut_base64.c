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
#include "unitests.h"

#define MKVEC(d_, e_)        \
	{                    \
		.dat = (d_), \
		.exp = (e_), \
	}

struct ut_base64_vector {
	const char *dat;
	const char *exp;
};

static const struct ut_base64_vector ut_base64_rfc4648_vecs[] = {
	MKVEC("", ""),
	MKVEC("f", "Zg=="),
	MKVEC("fo", "Zm8="),
	MKVEC("foo", "Zm9v"),
	MKVEC("foob", "Zm9vYg=="),
	MKVEC("fooba", "Zm9vYmE="),
	MKVEC("foobar", "Zm9vYmFy"),
};

static const struct ut_base64_vector ut_base64_ascii_vecs[] = {
	MKVEC("abcdef-abcdef-abcdef-abcdef-abcdef",
	      "YWJjZGVmLWFiY2RlZi1hYmNkZWYtYWJjZGVmLWFiY2RlZg=="),
	MKVEC("abcdefghijblmnopq", "YWJjZGVmZ2hpamJsbW5vcHE="),
	MKVEC("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="),
	MKVEC("0123456789 abcdefghijklmnop _-+%* ",
	      "MDEyMzQ1Njc4OSBhYmNkZWZnaGlqa2xtbm9wIF8tKyUqIA=="),
};

static const struct ut_base64_vector ut_base64_common_vecs[] = {

	MKVEC("The quick brown fox jumped over the lazy dogs.",
	      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1w"
	      "ZWQgb3ZlciB0aGUgbGF6eSBkb2dzLg=="),
	MKVEC("It was the best of times, it was the worst of times.",
	      "SXQgd2FzIHRoZSBiZXN0IG9mIHRpbWVzLC"
	      "BpdCB3YXMgdGhlIHdvcnN0IG9mIHRpbWVzLg=="),

};

static void
ut_base64_encdec(struct ut_env *ute, const char *dat, const char *exp)
{
	int err;
	size_t len;
	size_t nrd = 0;
	size_t enc_len = 0;
	size_t dec_len = 0;
	const size_t dat_len = strlen(dat);
	const size_t exp_len = strlen(exp);
	char enc[128] = "";
	char dec[256] = "";

	len = sizeof(enc);
	err = silofs_base64_encode(dat, dat_len, enc, len, &enc_len);
	ut_expect_ok(err);
	ut_expect_lt(enc_len, len);
	ut_expect_eq(enc_len, exp_len);
	ut_expect_eqm(enc, exp, exp_len);

	len = sizeof(dec);
	err = silofs_base64_decode(enc, enc_len, dec, len, &dec_len, &nrd);
	ut_expect_ok(err);
	ut_expect_lt(dec_len, len);
	ut_expect_eq(dec_len, dat_len);
	ut_expect_eq(enc_len, nrd);
	ut_expect_eqm(dat, dec, dat_len);

	ut_unused(ute);
}

static void ut_base64_with(struct ut_env *ute,
                           const struct ut_base64_vector *vec, size_t nvecs)
{
	for (size_t i = 0; i < nvecs; ++i) {
		ut_base64_encdec(ute, vec[i].dat, vec[i].exp);
	}
}

static void ut_base64_rfc4648(struct ut_env *ute)
{
	ut_base64_with(ute, ut_base64_rfc4648_vecs,
	               UT_ARRAY_SIZE(ut_base64_rfc4648_vecs));
}

static void ut_base64_ascii(struct ut_env *ute)
{
	ut_base64_with(ute, ut_base64_ascii_vecs,
	               UT_ARRAY_SIZE(ut_base64_ascii_vecs));
}

static void ut_base64_common(struct ut_env *ute)
{
	ut_base64_with(ute, ut_base64_common_vecs,
	               UT_ARRAY_SIZE(ut_base64_common_vecs));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_base64_random_(struct ut_env *ute, size_t bsz)
{
	int err;
	size_t nrd = 0;
	size_t enc_len = 0;
	size_t dec_len = 0;
	const size_t slen = silofs_base64_encode_len(bsz);
	char *str = ut_zerobuf(ute, slen + 1);
	void *buf1 = ut_randbuf(ute, bsz);
	void *buf2 = ut_randbuf(ute, bsz);

	err = silofs_base64_encode(buf1, bsz, str, slen, &enc_len);
	ut_expect_ok(err);
	ut_expect_eq(enc_len, slen);
	ut_expect_eq(strlen(str), slen);

	err = silofs_base64_decode(str, enc_len, buf2, bsz, &dec_len, &nrd);
	ut_expect_ok(err);
	ut_expect_eq(dec_len, bsz);
	ut_expect_eq(enc_len, nrd);
	ut_expect_eqm(buf1, buf2, bsz);
}

static void ut_base64_random(struct ut_env *ute)
{
	ut_base64_random_(ute, 1);
	ut_base64_random_(ute, 111);
	ut_base64_random_(ute, 111111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_base64_rfc4648),
	UT_DEFTEST(ut_base64_ascii),
	UT_DEFTEST(ut_base64_common),
	UT_DEFTEST(ut_base64_random),
};

const struct ut_testdefs ut_tdefs_base64 = UT_MKTESTS(ut_local_tests);
