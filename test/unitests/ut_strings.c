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


static struct silofs_strview *ut_new_strview(struct ut_env *ute)
{
	struct silofs_strview *sv = NULL;

	sv = ut_zalloc(ute, sizeof(*sv));
	sv->len = 0;
	sv->str = NULL;
	return sv;
}

static void ut_strview_compare(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t sz;
	int eq;
	int cmp;
	bool emp;

	silofs_strview_init(sv, "123456789");
	sz = silofs_strview_size(sv);
	ut_expect_eq(sz, 9);
	emp = silofs_strview_isempty(sv);
	ut_expect(!emp);
	cmp = silofs_strview_compare(sv, "123");
	ut_expect_gt(cmp, 0);
	cmp = silofs_strview_compare(sv, "9");
	ut_expect_lt(cmp, 0);
	cmp = silofs_strview_compare(sv, "123456789");
	ut_expect_eq(cmp, 0);
	eq = silofs_strview_isequal(sv, "123456789");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_find(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t pos;

	silofs_strview_init(sv, "ABCDEF abcdef ABCDEF");
	pos = silofs_strview_find(sv, "A");
	ut_expect_eq(pos, 0);
	pos = silofs_strview_find(sv, "EF");
	ut_expect_eq(pos, 4);
	pos = silofs_strview_nfind(sv, 10, "EF", 2);
	ut_expect_eq(pos, 18);
	pos = silofs_strview_find_chr(sv, 1, 'A');
	ut_expect_eq(pos, 14);
	pos = silofs_strview_find(sv, "UUU");
	ut_expect_gt(pos, silofs_strview_size(sv));
	silofs_strview_fini(sv);
}

static void ut_strview_rfind(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t pos;

	silofs_strview_init(sv, "ABRACADABRA");
	pos = silofs_strview_rfind(sv, "A");
	ut_expect_eq(pos, 10);
	pos = silofs_strview_rfind(sv, "BR");
	ut_expect_eq(pos, 8);
	pos = silofs_strview_size(sv) / 2;
	pos = silofs_strview_nrfind(sv, pos, "BR", 2);
	ut_expect_eq(pos, 1);
	pos = silofs_strview_rfind_chr(sv, 1, 'B');
	ut_expect_eq(pos, 1);
	silofs_strview_fini(sv);
}

static void ut_strview_find_first_of(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t pos;

	silofs_strview_init(sv, "012x456x89z");
	pos = silofs_strview_find_first_of(sv, "xyz");
	ut_expect_eq(pos, 3);
	pos = silofs_strview_nfind_first_of(sv, 5, "x..z", 4);
	ut_expect_eq(pos, 7);
	pos = silofs_strview_find_first_of(sv, "XYZ");
	ut_expect_gt(pos, silofs_strview_size(sv));
	silofs_strview_fini(sv);
}

static void ut_strview_find_last_of(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t pos;

	silofs_strview_init(sv, "AAAAA-BBBBB");
	pos = silofs_strview_find_last_of(sv, "xyzAzyx");
	ut_expect_eq(pos, 4);
	pos = silofs_strview_nfind_last_of(sv, 9, "X-Y", 3);
	ut_expect_eq(pos, 5);
	pos = silofs_strview_find_last_of(sv, "BBBBBBBBBBBBBBBBBBBBB");
	ut_expect_eq(pos, silofs_strview_size(sv) - 1);
	pos = silofs_strview_find_last_of(sv, "...");
	ut_expect_gt(pos, silofs_strview_size(sv));
	silofs_strview_fini(sv);
}

static void ut_strview_find_first_not_of(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t pos;

	silofs_strview_init(sv, "aaa bbb ccc * ddd + eee");
	pos = silofs_strview_find_first_not_of(sv, "a b c d e");
	ut_expect_eq(pos, 12);
	pos = silofs_strview_nfind_first_not_of(sv, 14, "d e", 3);
	ut_expect_eq(pos, 18);
	silofs_strview_fini(sv);
}

static void ut_strview_find_last_not_of(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t pos;

	silofs_strview_init(sv, "-..3456.--");
	pos = silofs_strview_find_last_not_of(sv, ".-");
	ut_expect_eq(pos, 6);
	pos = silofs_strview_nfind_last_not_of(sv, 1, "*", 1);
	ut_expect_eq(pos, 1);
	silofs_strview_fini(sv);
}

static void ut_strview_sub(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview sub = { .str = NULL };
	const char *abc = "abcdefghijklmnopqrstuvwxyz";
	bool eq;

	silofs_strview_initn(sv, abc, 10); /* "abcdefghij" */
	silofs_strview_sub(sv, 2, 4, &sub);
	eq  = silofs_strview_isequal(&sub, "cdef");
	ut_expect(eq);
	silofs_strview_rsub(sv, 3, &sub);
	eq  = silofs_strview_isequal(&sub, "hij");
	ut_expect(eq);
	silofs_strview_chop(sv, 8, &sub);
	eq  = silofs_strview_isequal(&sub, "ab");
	ut_expect(eq);
	silofs_strview_init_by(&sub, sv);
	eq  = silofs_strview_nisequal(&sub, sv->str, sv->len);
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_count(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	size_t n;

	silofs_strview_init(sv, "xxx-xxx-xxx-xxx");
	n = silofs_strview_count(sv, "xxx");
	ut_expect_eq(n, 4);
	n = silofs_strview_count_chr(sv, '-');
	ut_expect_eq(n, 3);
	silofs_strview_fini(sv);
}

static void ut_strview_split(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview_pair split;
	bool eq;

	silofs_strview_init(sv, "ABC-DEF+123");
	silofs_strview_split(sv, "-", &split);
	eq = silofs_strview_isequal(&split.first, "ABC");
	ut_expect(eq);
	eq = silofs_strview_isequal(&split.second, "DEF+123");
	ut_expect(eq);
	silofs_strview_split(sv, " + * ", &split);
	eq = silofs_strview_isequal(&split.first, "ABC-DEF");
	ut_expect(eq);
	eq = silofs_strview_isequal(&split.second, "123");
	ut_expect(eq);
	silofs_strview_split_chr(sv, 'B', &split);
	eq = silofs_strview_isequal(&split.first, "A");
	ut_expect(eq);
	eq = silofs_strview_isequal(&split.second, "C-DEF+123");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_rsplit(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview_pair split;
	bool eq;

	silofs_strview_init(sv, "UUU--YYY--ZZZ");
	silofs_strview_rsplit(sv, "-.", &split);
	eq = silofs_strview_isequal(&split.first, "UUU--YYY");
	ut_expect(eq);
	eq = silofs_strview_isequal(&split.second, "ZZZ");
	ut_expect(eq);
	silofs_strview_rsplit(sv, "+", &split);
	eq = silofs_strview_nisequal(&split.first, sv->str, sv->len);
	ut_expect(eq);
	eq = silofs_strview_isequal(&split.second, "ZZZ");
	ut_expect(!eq);
	silofs_strview_init(sv, "1.2.3.4.5");
	silofs_strview_rsplit_chr(sv, '.', &split);
	eq = silofs_strview_isequal(&split.first, "1.2.3.4");
	ut_expect(eq);
	eq = silofs_strview_isequal(&split.second, "5");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_trim(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview sub = { .str = NULL };
	size_t sz = 0;
	bool eq;

	silofs_strview_init(sv, ".:ABCD");
	silofs_strview_trim_any_of(sv, ":,.%^", &sub);
	eq = silofs_strview_isequal(&sub, "ABCD");
	ut_expect(eq);
	sz = silofs_strview_size(sv);
	silofs_strview_ntrim_any_of(sv, silofs_strview_data(sv), sz, &sub);
	eq = silofs_strview_size(&sub) == 0;
	ut_expect(eq);
	silofs_strview_trim_chr(sv, '.', &sub);
	eq = silofs_strview_isequal(&sub, ":ABCD");
	ut_expect(eq);
	silofs_strview_trim(sv, 4, &sub);
	eq = silofs_strview_isequal(&sub, "CD");
	ut_expect(eq);
	silofs_strview_trim_if(sv, silofs_chr_ispunct, &sub);
	eq = silofs_strview_isequal(&sub, "ABCD");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_chop(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview sub = { .str = NULL };
	size_t sz = 0;
	bool eq;

	silofs_strview_init(sv, "123....");
	silofs_strview_chop_any_of(sv, "+*&^%$.", &sub);
	eq = silofs_strview_isequal(&sub, "123");
	ut_expect(eq);
	sz = silofs_strview_size(sv);
	silofs_strview_nchop_any_of(sv, silofs_strview_data(sv), sz, &sub);
	eq = silofs_strview_isequal(&sub, "");
	ut_expect(eq);
	silofs_strview_chop(sv, 6, &sub);
	eq = silofs_strview_isequal(&sub, "1");
	ut_expect(eq);
	silofs_strview_chop_chr(sv, '.', &sub);
	eq  = silofs_strview_isequal(&sub, "123");
	ut_expect(eq);
	silofs_strview_chop_if(sv, silofs_chr_ispunct, &sub);
	eq  = silofs_strview_isequal(&sub, "123");
	ut_expect(eq);
	silofs_strview_chop_if(sv, silofs_chr_isprint, &sub);
	eq  = silofs_strview_size(&sub) == 0;
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_strip(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview sub = { .str = NULL };
	const char *s = NULL;
	const char *s2 = "s ";
	size_t sz = 0;
	bool eq;

	silofs_strview_init(sv, ".....#XYZ#.........");
	silofs_strview_strip_any_of(sv, "-._#", &sub);
	eq  = silofs_strview_isequal(&sub, "XYZ");
	ut_expect(eq);
	silofs_strview_strip_chr(sv, '.', &sub);
	eq = silofs_strview_isequal(&sub, "#XYZ#");
	ut_expect(eq);
	silofs_strview_strip_if(sv, silofs_chr_ispunct, &sub);
	eq = silofs_strview_isequal(&sub, "XYZ");
	ut_expect(eq);
	s = silofs_strview_data(sv);
	sz = silofs_strview_size(sv);
	silofs_strview_nstrip_any_of(sv, s, sz, &sub);
	eq = silofs_strview_isequal(&sub, "");
	ut_expect(eq);
	silofs_strview_init(sv, " \t ABC\n\r\v");
	silofs_strview_strip_ws(sv, &sub);
	eq = silofs_strview_isequal(&sub, "ABC");
	ut_expect(eq);
	silofs_strview_init(sv, s2);
	silofs_strview_strip_if(sv, silofs_chr_isspace, &sub);
	eq = silofs_strview_isequal(&sub, "s");
	ut_expect(eq);
	silofs_strview_init(sv, s2 + 1);
	silofs_strview_strip_if(sv, silofs_chr_isspace, &sub);
	eq = silofs_strview_isequal(&sub, "");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_find_token(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview tok = { .str = NULL };
	const char *seps = " \t\n\v\r";
	bool eq;

	silofs_strview_init(sv, " A BB \t  CCC    DDDD  \n");
	silofs_strview_find_token(sv, seps, &tok);
	eq  = silofs_strview_isequal(&tok, "A");
	ut_expect(eq);
	silofs_strview_find_next_token(sv, &tok, seps, &tok);
	eq  = silofs_strview_isequal(&tok, "BB");
	ut_expect(eq);
	silofs_strview_find_next_token(sv, &tok, seps, &tok);
	eq  = silofs_strview_isequal(&tok, "CCC");
	ut_expect(eq);
	silofs_strview_find_next_token(sv, &tok, seps, &tok);
	eq  = silofs_strview_isequal(&tok, "DDDD");
	ut_expect(eq);
	silofs_strview_find_next_token(sv, &tok, seps, &tok);
	eq  = silofs_strview_isequal(&tok, "");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_tokenize(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	struct silofs_strview toks_list[7];
	const char *seps = " /:;.| " ;
	const char *line =
	        "    /Ant:::Bee;:Cat:Dog;...Elephant.../Frog:/Giraffe///    ";
	size_t n_toks = 0;
	int err = 0;
	bool eq;

	silofs_strview_init(sv, line);
	err = silofs_strview_tokenize(sv, seps, toks_list, 7, &n_toks);
	ut_expect_eq(err, 0);
	ut_expect_eq(n_toks, 7);
	eq  = silofs_strview_isequal(&toks_list[0], "Ant");
	ut_expect(eq);
	eq  = silofs_strview_isequal(&toks_list[4], "Elephant");
	ut_expect(eq);
	eq  = silofs_strview_isequal(&toks_list[6], "Giraffe");
	ut_expect(eq);
	silofs_strview_fini(sv);
}

static void ut_strview_common_prefix(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	const char *dat = "0123456789abcdef";
	size_t sz = 0;

	silofs_strview_init(sv, dat);
	sz = silofs_strview_common_prefix(sv, "0123456789ABCDEF");
	ut_expect_eq(sz, 10);
	sz = silofs_strview_common_prefix(sv, dat);
	ut_expect_eq(sz, 16);
	sz = silofs_strview_common_prefix(sv, "XYZ");
	ut_expect_eq(sz, 0);
	silofs_strview_fini(sv);
}

static void ut_strview_common_suffix(struct ut_env *ute)
{
	struct silofs_strview *sv = ut_new_strview(ute);
	char dat[] = "abcdef0123456789";
	size_t sz = 0;

	silofs_strview_init(sv, dat);
	sz = silofs_strview_common_suffix(sv, "ABCDEF0123456789");
	ut_expect_eq(sz, 10);
	sz = silofs_strview_common_suffix(sv, dat);
	ut_expect_eq(sz, 16);
	sz = silofs_strview_common_suffix(sv, "XYZ");
	ut_expect_eq(sz, 0);
	silofs_strview_fini(sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_strmref *ut_new_strmref(struct ut_env *ute)
{
	struct silofs_strmref *smr = NULL;

	smr = ut_zalloc(ute, sizeof(*smr));
	silofs_strmref_initz(smr);
	return smr;
}

static void ut_strmref_assign(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	struct silofs_strmref sub;
	char dat[] = "0123456789......";
	const char *s = NULL;
	size_t sz = 0;
	bool eq;

	silofs_strmref_initk(smr, dat, 10, 16);
	silofs_strmref_sub(smr, 10, 6, &sub);
	sz = silofs_strmref_size(&sub);
	ut_expect_eq(sz, 0);
	sz = silofs_strmref_wrsize(&sub);
	ut_expect_eq(sz, 6);

	s = "ABC";
	silofs_strmref_assign(smr, s);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 3);
	sz = silofs_strmref_wrsize(smr);
	ut_expect_eq(sz, 16);
	eq = silofs_strview_isequal(&smr->v, s);
	ut_expect(eq);
	s = "ABCDEF";
	silofs_strmref_assign(&sub, s);
	eq = silofs_strview_isequal(&sub.v, s);
	ut_expect(eq);
	s = "ABCDEF$$$";
	silofs_strmref_assign(&sub, s);
	sz = silofs_strmref_size(&sub);
	ut_expect_eq(sz, 6);
	sz = silofs_strmref_wrsize(&sub);
	ut_expect_eq(sz, 6);
	eq = silofs_strview_isequal(&sub.v, s);
	ut_expect(!eq);
	silofs_strmref_sub(&sub, 5, 100, &sub);
	s = "XYZ";
	silofs_strmref_assign(&sub, s);
	sz = silofs_strmref_size(&sub);
	ut_expect_eq(sz, 1);
	sz = silofs_strmref_wrsize(&sub);
	ut_expect_eq(sz, 1);
	silofs_strmref_fini(smr);
}

static void ut_strmref_append(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char buf[20] = "";
	const char *s = "0123456789abcdef";
	size_t sz = 0;
	bool eq;

	silofs_strmref_initk(smr, buf, 0, UT_ARRAY_SIZE(buf));
	silofs_strmref_append(smr, s);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 16);
	sz = silofs_strmref_wrsize(smr);
	ut_expect_eq(sz, UT_ARRAY_SIZE(buf));
	eq = silofs_strview_isequal(&smr->v, s);
	ut_expect(eq);
	silofs_strmref_append(smr, s);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, UT_ARRAY_SIZE(buf));
	sz = silofs_strmref_wrsize(smr);
	ut_expect_eq(sz, UT_ARRAY_SIZE(buf));
	silofs_strmref_initk(smr, buf, 0, UT_ARRAY_SIZE(buf));
	silofs_strmref_nappend(smr, s, 1);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 1);
	silofs_strmref_nappend(smr, s + 1, 1);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 2);
	eq = silofs_strview_nisequal(&smr->v, s, 2);
	ut_expect(eq);
	silofs_strmref_fini(smr);
}

static void ut_strmref_insert(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char buf[20] = "";
	const char *s = "0123456789";
	size_t sz = 0;
	bool eq;

	silofs_strmref_initk(smr, buf, 0, UT_ARRAY_SIZE(buf));
	silofs_strmref_insert(smr, 0, s);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 10);
	eq = silofs_strview_isequal(&smr->v, s);
	ut_expect(eq);
	silofs_strmref_insert(smr, 10, s);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 20);
	eq = silofs_strview_isequal(&smr->v, "01234567890123456789");
	ut_expect(eq);
	silofs_strmref_insert(smr, 1, "....");
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 20);
	eq = silofs_strview_isequal(&smr->v, "0....123456789012345");
	ut_expect(eq);
	silofs_strmref_insert(smr, 16, "%%%");
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 20);
	eq = silofs_strview_isequal(&smr->v, "0....12345678901%%%2");
	ut_expect(eq);
	silofs_strmref_insert_chr(smr, 1, 20, '$');
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 20);
	eq = silofs_strview_isequal(&smr->v, "0$$$$$$$$$$$$$$$$$$$");
	ut_expect(eq);
	silofs_strmref_fini(smr);
}

static void ut_strmref_replace(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char buf[10] = "";
	const char *s = "ABCDEF";
	size_t wsz = 0;
	size_t sz = 0;
	bool eq;

	silofs_strmref_initk(smr, buf, 0, UT_ARRAY_SIZE(buf));
	silofs_strmref_replace(smr, 0, 2, s);
	wsz = silofs_strmref_size(smr);
	ut_expect_eq(wsz, 6);
	eq = silofs_strview_isequal(&smr->v, s);
	ut_expect(eq);
	silofs_strmref_replace(smr, 1, 2, s);
	eq = silofs_strview_isequal(&smr->v, "AABCDEFDEF");
	ut_expect(eq);
	silofs_strmref_replace(smr, 6, 3, s);
	eq = silofs_strview_isequal(&smr->v, "AABCDEABCD");
	ut_expect(eq);
	silofs_strmref_replace_chr(smr, 0, 10, 30, '.');
	eq = silofs_strview_isequal(&smr->v, "..........");
	ut_expect(eq);
	silofs_strmref_replace_chr(smr, 1, 8, 4, 'A');
	eq = silofs_strview_isequal(&smr->v, ".AAAA.");
	ut_expect(eq);
	sz = silofs_strmref_size(smr);
	silofs_strmref_nreplace(smr, 2, 80, silofs_strmref_data(smr), sz);
	eq = silofs_strview_isequal(&smr->v, ".A.AAAA.");
	ut_expect(eq);
	sz = silofs_strmref_size(smr);
	silofs_strmref_nreplace(smr, 4, 80, silofs_strmref_data(smr), sz);
	eq = silofs_strview_isequal(&smr->v, ".A.A.A.AAA");  /* Truncated */
	ut_expect(eq);
	silofs_strmref_fini(smr);
}

static void ut_strmref_erase(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char buf[5] = "";
	size_t wsz = 0;
	bool eq;

	silofs_strmref_initk(smr, buf, 0, UT_ARRAY_SIZE(buf));
	silofs_strmref_assign(smr, "ABCDEF");
	eq = silofs_strview_isequal(&smr->v, "ABCDE");
	ut_expect(eq);
	silofs_strmref_erase(smr, 1, 2);
	eq = silofs_strview_isequal(&smr->v, "ADE");
	ut_expect(eq);
	silofs_strmref_erase(smr, 0, 100);
	eq = silofs_strview_isequal(&smr->v, "");
	ut_expect(eq);
	wsz = silofs_strmref_wrsize(smr);
	ut_expect_eq(wsz, UT_ARRAY_SIZE(buf));
	silofs_strmref_fini(smr);
}

static void ut_strmref_reverse(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char buf[40] = "";
	bool eq;

	silofs_strmref_initk(smr, buf, 0, UT_ARRAY_SIZE(buf));
	silofs_strmref_assign(smr, "abracadabra");
	silofs_strmref_reverse(smr);
	eq = silofs_strview_isequal(&smr->v, "arbadacarba");
	ut_expect(eq);
	silofs_strmref_assign(smr, "0123456789");
	silofs_strmref_reverse(smr);
	eq = silofs_strview_isequal(&smr->v, "9876543210");
	ut_expect(eq);
	silofs_strmref_fini(smr);
}

static void ut_strmref_copyto(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char dat[] = "123456789";
	char buf[10] = "";
	size_t sz = 0;
	char pad = '@';
	bool eq;

	silofs_strmref_init(smr, dat);
	sz = silofs_strmref_size(smr);
	ut_expect_eq(sz, 9);
	sz = silofs_strview_copyto(&smr->v, buf, sizeof(buf));
	ut_expect_eq(sz, 9);
	eq = !strcmp(buf, "123456789");
	ut_expect(eq);
	ut_expect_eq(pad, '@');
	silofs_strmref_fini(smr);
}

static void ut_strmref_case(struct ut_env *ute)
{
	struct silofs_strmref *smr = ut_new_strmref(ute);
	char buf[20] = "0123456789abcdef";
	bool eq;

	silofs_strmref_init(smr, buf);
	silofs_strmref_toupper(smr);
	eq = silofs_strview_isequal(&smr->v, "0123456789ABCDEF");
	ut_expect(eq);
	silofs_strmref_tolower(smr);
	eq = silofs_strview_isequal(&smr->v, "0123456789abcdef");
	ut_expect(eq);
	silofs_strmref_fini(smr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_strbuf *ut_new_strbuf(struct ut_env *ute)
{
	struct silofs_strbuf *sbuf = NULL;

	sbuf = ut_zalloc(ute, sizeof(*sbuf));
	silofs_strbuf_init(sbuf);
	return sbuf;
}

static void ut_strbuf_simple(struct ut_env *ute)
{
	struct silofs_strbuf *sbuf1 = ut_new_strbuf(ute);
	struct silofs_strbuf *sbuf2 = ut_new_strbuf(ute);
	struct silofs_strview sv = { .str = NULL };
	const char *abc = "abcdefghijklmnopqrstuvwxyz";
	const char *xdig = "0123456789abcdef";
	bool eq;

	silofs_strbuf_setup_by(sbuf1, abc);
	silofs_strbuf_assign(sbuf2, sbuf1);
	silofs_strbuf_as_sv(sbuf2, &sv);
	eq = silofs_strview_isequal(&sv, abc);
	ut_expect(eq);
	silofs_strview_init(&sv, xdig);
	silofs_strbuf_setup(sbuf1, &sv);
	silofs_strbuf_assign(sbuf2, sbuf1);
	silofs_strbuf_as_sv(sbuf2, &sv);
	eq = silofs_strview_isequal(&sv, xdig);
	ut_expect(eq);
	silofs_strbuf_fini(sbuf1);
	silofs_strbuf_fini(sbuf2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_strview_compare),
	UT_DEFTEST(ut_strview_find),
	UT_DEFTEST(ut_strview_rfind),
	UT_DEFTEST(ut_strview_find_first_of),
	UT_DEFTEST(ut_strview_find_last_of),
	UT_DEFTEST(ut_strview_find_first_not_of),
	UT_DEFTEST(ut_strview_find_last_not_of),
	UT_DEFTEST(ut_strview_sub),
	UT_DEFTEST(ut_strview_count),
	UT_DEFTEST(ut_strview_split),
	UT_DEFTEST(ut_strview_rsplit),
	UT_DEFTEST(ut_strview_trim),
	UT_DEFTEST(ut_strview_chop),
	UT_DEFTEST(ut_strview_strip),
	UT_DEFTEST(ut_strview_find_token),
	UT_DEFTEST(ut_strview_tokenize),
	UT_DEFTEST(ut_strview_common_prefix),
	UT_DEFTEST(ut_strview_common_suffix),
	UT_DEFTEST(ut_strmref_assign),
	UT_DEFTEST(ut_strmref_append),
	UT_DEFTEST(ut_strmref_insert),
	UT_DEFTEST(ut_strmref_replace),
	UT_DEFTEST(ut_strmref_erase),
	UT_DEFTEST(ut_strmref_reverse),
	UT_DEFTEST(ut_strmref_copyto),
	UT_DEFTEST(ut_strmref_case),
	UT_DEFTEST(ut_strbuf_simple),
};

const struct ut_testdefs ut_tdefs_strings = UT_MKTESTS(ut_local_tests);
