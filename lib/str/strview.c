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
#include <silofs/infra.h>
#include <silofs/str/strchr.h>
#include <silofs/str/strview.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#define strview_out_of_range(sv_, pos_) \
	silofs_panic("strview out-of-range: pos=%ld len=%ld sv=%p", \
	             (long)(pos_), (long)((sv_)->len), (sv_))

#define strview_check_range(sv_, pos_) \
	do { \
		if ((pos_) >= (sv_)->len) { \
			strview_out_of_range(sv_, pos_); \
		} \
	} while (0)


static bool chr_eq(char c1, char c2)
{
	return c1 == c2;
}

size_t silofs_strview_max_size(void)
{
	return SIZE_MAX >> 2;
}

size_t silofs_strview_npos(void)
{
	return silofs_strview_max_size();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_init(struct silofs_strview *sv, const char *s)
{
	silofs_strview_initn(sv, s, silofs_str_length(s));
}

void silofs_strview_initn(struct silofs_strview *sv, const char *s, size_t n)
{
	sv->str = s;
	sv->len = n;
}

void silofs_strview_initz(struct silofs_strview *sv)
{
	static const char z[1] = "";

	silofs_strview_initn(sv, z, 0);
}

void silofs_strview_initv(struct silofs_strview *sv,
                          const struct silofs_strview *other)
{
	silofs_strview_initn(sv, other->str, other->len);
}


void silofs_strview_init_by(struct silofs_strview *sv,
                            const struct silofs_strview *other)
{
	sv->str = other->str;
	sv->len = other->len;
}

void silofs_strview_fini(struct silofs_strview *sv)
{
	sv->str = NULL;
	sv->len = 0;
}

size_t silofs_strview_size(const struct silofs_strview *sv)
{
	return sv->len;
}

const char *silofs_strview_data(const struct silofs_strview *sv)
{
	return sv->str;
}

bool silofs_strview_isempty(const struct silofs_strview *sv)
{
	return (sv->len == 0);
}

const char *silofs_strview_begin(const struct silofs_strview *sv)
{
	return sv->str;
}

const char *silofs_strview_end(const struct silofs_strview *sv)
{
	return sv->str + sv->len;
}

size_t silofs_strview_offset(const struct silofs_strview *sv, const char *p)
{
	const size_t npos = silofs_strview_npos();
	ptrdiff_t dif;

	if (p == NULL) {
		return npos;
	}
	if (p < sv->str) {
		return npos;
	}
	if (p >= (sv->str + sv->len)) {
		return npos;
	}
	dif = (p - sv->str);
	return (size_t)dif;
}

const char *silofs_strview_at(const struct silofs_strview *sv, size_t n)
{
	strview_check_range(sv, n);

	return sv->str + n;
}

bool silofs_strview_haspos(const struct silofs_strview *sv, size_t pos)
{
	return (pos < sv->len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_copyto(const struct silofs_strview *sv,
                             void *buf, size_t n)
{
	const size_t len = silofs_min(n, sv->len);
	char *str = buf;

	silofs_str_copy(str, sv->str, len);
	if (len < n) {
		silofs_str_terminate(buf, len);
	}
	return len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_strview_compare(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_ncompare(sv, s, silofs_str_length(s));
}

int silofs_strview_ncompare(const struct silofs_strview *sv,
                            const char *s, size_t n)
{
	int res = 0;

	if ((sv->str != s) || (sv->len != n)) {
		res = silofs_str_ncompare(sv->str, sv->len, s, n);
	}
	return res;
}

bool silofs_strview_isequal(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_nisequal(sv, s, silofs_str_length(s));
}

bool silofs_strview_nisequal(const struct silofs_strview *sv,
                             const char *s, size_t n)
{
	if (sv->len != n) {
		return false;
	}
	if (sv->str == s) {
		return true;
	}
	return (silofs_str_compare(sv->str, s, n) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_count(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_ncount(sv, s, silofs_str_length(s));
}

size_t silofs_strview_ncount(const struct silofs_strview *sv,
                             const char *s, size_t n)
{
	size_t cnt = 0;
	size_t pos = 0;
	size_t i;

	i = silofs_strview_nfind(sv, pos, s, n);
	while (i < sv->len) {
		++cnt;
		pos = i + n;
		i = silofs_strview_nfind(sv, pos, s, n);
	}
	return cnt;
}

size_t silofs_strview_count_chr(const struct silofs_strview *sv, char c)
{
	size_t cnt = 0;
	size_t pos = 0;
	size_t i;


	i = silofs_strview_find_chr(sv, pos, c);
	while (i < sv->len) {
		++cnt;
		pos = i + 1;
		i = silofs_strview_find_chr(sv, pos, c);
	}
	return cnt;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_find(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_nfind(sv, 0UL, s, silofs_str_length(s));
}

size_t silofs_strview_nfind(const struct silofs_strview *sv,
                            size_t pos, const char *s, size_t n)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const char *p = NULL;

	if (pos < sz) {
		if (n > 1) {
			p = silofs_str_find(dat + pos, sz - pos, s, n);
		} else if (n == 1) {
			p = silofs_str_find_chr(dat + pos, sz - pos, s[0]);
		} else {
			/* Compatible with STL: empty string always matches */
			p = dat + pos;
		}
	}
	return silofs_strview_offset(sv, p);
}

size_t silofs_strview_find_chr(const struct silofs_strview *sv,
                               size_t pos, char c)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const char *p = NULL;

	if (pos < sz) {
		p = silofs_str_find_chr(dat + pos, sz - pos, c);
	}
	return silofs_strview_offset(sv, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_rfind(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_nrfind(sv, sv->len, s, silofs_str_length(s));
}

size_t silofs_strview_nrfind(const struct silofs_strview *sv,
                             size_t pos, const char *s, size_t n)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const size_t k = (pos < sz) ? pos + 1 : sz;
	const char *p = NULL;
	const char *q = s;

	if (n == 0) {
		/* STL compatible: empty string always matches */
		p = dat + k;
	} else if (n == 1) {
		p = silofs_str_rfind_chr(dat, k, *q);
	} else {
		p = silofs_str_rfind(dat, k, q, n);
	}
	return silofs_strview_offset(sv, p);
}

size_t silofs_strview_rfind_chr(const struct silofs_strview *sv,
                                size_t pos, char c)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const size_t k = (pos < sz) ? pos + 1 : sz;
	const char *p;

	p = silofs_str_rfind_chr(dat, k, c);
	return silofs_strview_offset(sv, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_find_first_of(const struct silofs_strview *ss,
                                    const char *s)
{
	return silofs_strview_nfind_first_of(ss, 0UL, s, silofs_str_length(s));
}

size_t silofs_strview_nfind_first_of(const struct silofs_strview *sv,
                                     size_t pos, const char *s, size_t n)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const char *p = NULL;
	const char *q = s;

	if ((n != 0) && (pos < sz)) {
		if (n == 1) {
			p = silofs_str_find_chr(dat + pos, sz - pos, *q);
		} else {
			p = silofs_str_find_first_of(dat + pos,
			                             sz - pos, q, n);
		}
	}
	return silofs_strview_offset(sv, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_find_last_of(const struct silofs_strview *sv,
                                   const char *s)
{
	const size_t len = silofs_str_length(s);

	return silofs_strview_nfind_last_of(sv, sv->len, s, len);
}

size_t silofs_strview_nfind_last_of(const struct silofs_strview *sv,
                                    size_t pos, const char *s, size_t n)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const char *p = NULL;
	const char *q = s;

	if (n != 0) {
		const size_t k = (pos < sz) ? pos + 1 : sz;

		if (n == 1) {
			p = silofs_str_rfind_chr(dat, k, *q);
		} else {
			p = silofs_str_find_last_of(dat, k, q, n);
		}
	}
	return silofs_strview_offset(sv, p);
}

size_t silofs_strview_find_first_not_of(const struct silofs_strview *sv,
                                        const char *s)
{
	const size_t len = silofs_str_length(s);

	return silofs_strview_nfind_first_not_of(sv, 0UL, s, len);
}

size_t silofs_strview_nfind_first_not_of(const struct silofs_strview *sv,
                size_t pos, const char *s, size_t n)
{
	const size_t sz = sv->len;
	const char *dat = sv->str;
	const char *p = NULL;
	const char *q = s;

	if (pos < sz) {
		if (n == 0) {
			p = dat + pos;
		} else if (n == 1) {
			p = silofs_str_find_first_not_eq(dat + pos,
			                                 sz - pos, *q);
		} else {
			p = silofs_str_find_first_not_of(dat + pos,
			                                 sz - pos, q, n);
		}
	}

	return silofs_strview_offset(sv, p);
}

size_t silofs_strview_find_first_not(const struct silofs_strview *sv,
                                     size_t pos, char c)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	const char *p = NULL;

	if (pos < sz) {
		p = silofs_str_find_first_not_eq(dat + pos, sz - pos, c);
	}
	return silofs_strview_offset(sv, p);
}

size_t silofs_strview_find_last_not_of(const struct silofs_strview *sv,
                                       const char *s)
{
	const size_t len = silofs_str_length(s);

	return silofs_strview_nfind_last_not_of(sv, sv->len, s, len);
}

size_t silofs_strview_nfind_last_not_of(const struct silofs_strview *sv,
                                        size_t pos, const char *s, size_t n)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	const char *p = NULL;
	const char *q = s;

	if (sz != 0) {
		const size_t k = (pos < sz) ? pos + 1 : sz;

		if (n == 0) {
			p = dat + k - 1; /* compatible with STL */
		} else if (n == 1) {
			p = silofs_str_find_last_not_eq(dat, k, *q);
		} else {
			p = silofs_str_find_last_not_of(dat, k, q, n);
		}
	}
	return silofs_strview_offset(sv, p);
}

size_t silofs_strview_find_last_not(const struct silofs_strview *sv,
                                    size_t pos, char c)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	const size_t k = (pos < sz) ? pos + 1 : sz;
	const char *p = NULL;

	p = silofs_str_find_last_not_eq(dat, k, c);
	return silofs_strview_offset(sv, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_sub(const struct silofs_strview *sv,
                        size_t i, size_t n, struct silofs_strview *out_sv)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	const size_t j = silofs_min(i, sz);
	const size_t k = silofs_min(n, sz - j);

	silofs_strview_initn(out_sv, dat + j, k);
}

void silofs_strview_rsub(const struct silofs_strview *sv,
                         size_t n, struct silofs_strview *out_sv)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	const size_t k = silofs_min(n, sz);
	const size_t j = sz - n;

	silofs_strview_initn(out_sv, dat + j, k);
}

void silofs_strview_intersection(const struct silofs_strview *sv1,
                                 const struct silofs_strview *sv2,
                                 struct silofs_strview *out_sv)
{
	const char *sv1_beg = silofs_strview_begin(sv1);
	const char *sv1_end = silofs_strview_end(sv1);
	const char *sv2_beg = silofs_strview_begin(sv2);
	const char *sv2_end  = silofs_strview_end(sv2);
	size_t i = 0;
	size_t n = 0;

	if (sv1_beg <= sv2_beg) {
		/* Case 1:  [.s1...)  [..s2.....) -- Return empty strviewing */
		if (sv1_end <= sv2_beg) {
			i = sv2->len;
		}
		/* Case 2: [.s1........)
		                [.s2..) */
		else if (sv2_end <= sv1_end) {
			n = sv2->len;
		}
		/* Case 3: [.s1.....)
		               [.s2......) */
		else {
			n = (size_t)(sv1_end - sv2_beg);
		}
		silofs_strview_sub(sv2, i, n, out_sv);
	} else {
		/* One step recursion -- its ok */
		silofs_strview_intersection(sv2, sv1, out_sv);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Helper function to create split-of-strviewings */
static void strview_make_split_pair(const struct silofs_strview *sv,
                                    size_t i1, size_t n1,
                                    size_t i2, size_t n2,
                                    struct silofs_strview_pair *out_sv_pair)
{
	silofs_strview_sub(sv, i1, n1, &out_sv_pair->first);
	silofs_strview_sub(sv, i2, n2, &out_sv_pair->second);
}

void silofs_strview_split(const struct silofs_strview *sv, const char *seps,
                          struct silofs_strview_pair *out_sv_pair)
{

	silofs_strview_nsplit(sv, seps, silofs_str_length(seps), out_sv_pair);
}

void silofs_strview_nsplit(const struct silofs_strview *sv,
                           const char *seps, size_t n,
                           struct silofs_strview_pair *out_sv_pair)
{
	const size_t sz = sv->len;
	size_t i, j = sz;

	i = silofs_strview_nfind_first_of(sv, 0UL, seps, n);
	if (i < sz) {
		j = silofs_strview_nfind_first_not_of(sv, i, seps, n);
	}

	strview_make_split_pair(sv, 0UL, i, j, sz, out_sv_pair);
}

void silofs_strview_split_chr(const struct silofs_strview *sv, char sep,
                              struct silofs_strview_pair *out_sv_pair)
{
	const size_t sz = sv->len;
	const size_t i = silofs_strview_find_chr(sv, 0UL, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	strview_make_split_pair(sv, 0UL, i, j, sz, out_sv_pair);
}

void silofs_strview_split_str(const struct silofs_strview *sv, const char *str,
                              struct silofs_strview_pair *out_sv_pair)
{
	const size_t sz = sv->len;
	const size_t i = silofs_strview_find(sv, str);
	const size_t j = (i < sz) ? i + silofs_str_length(str) : sz;

	strview_make_split_pair(sv, 0UL, i, j, sz, out_sv_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_rsplit(const struct silofs_strview *ss, const char *seps,
                           struct silofs_strview_pair *out_ss_pair)
{
	silofs_strview_nrsplit(ss, seps, silofs_str_length(seps), out_ss_pair);
}

void silofs_strview_nrsplit(const struct silofs_strview *sv,
                            const char *seps, size_t n,
                            struct silofs_strview_pair *out_ss_pair)
{
	const size_t sz = sv->len;
	size_t i = 0;
	size_t j = sz;

	i = silofs_strview_nfind_last_of(sv, sz, seps, n);
	if (i < sz) {
		j = silofs_strview_nfind_last_not_of(sv, i, seps, n);

		if (j < sz) {
			++i;
			++j;
		} else {
			i = j = sz;
		}
	}
	strview_make_split_pair(sv, 0UL, j, i, sz, out_ss_pair);
}

void silofs_strview_rsplit_chr(const struct silofs_strview *sv, char sep,
                               struct silofs_strview_pair *out_ss_pair)
{
	const size_t sz = sv->len;
	const size_t i = silofs_strview_rfind_chr(sv, sz, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	strview_make_split_pair(sv, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_trim(const struct silofs_strview *sv, size_t n,
                         struct silofs_strview *out_sv)
{
	silofs_strview_sub(sv, n, sv->len, out_sv);
}

void silofs_strview_trim_any_of(const struct silofs_strview *sv,
                                const char *set, struct silofs_strview *out_sv)
{
	silofs_strview_ntrim_any_of(sv, set, silofs_str_length(set), out_sv);
}

void silofs_strview_ntrim_any_of(const struct silofs_strview *sv,
                                 const char *set, size_t n,
                                 struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	const size_t i = silofs_strview_nfind_first_not_of(sv, 0UL, set, n);

	silofs_strview_sub(sv, i, sz, out_sv);
}

void silofs_strview_trim_chr(const struct silofs_strview *sv, char c,
                             struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	const size_t i = silofs_strview_find_first_not(sv, 0UL, c);

	silofs_strview_sub(sv, i, sz, out_sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_chop(const struct silofs_strview *sv,
                         size_t n, struct silofs_strview *out_sv)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	const size_t k = silofs_min(sz, n);

	silofs_strview_initn(out_sv, dat, sz - k);
}

void silofs_strview_chop_any_of(const struct silofs_strview *sv,
                                const char *set, struct silofs_strview *out_sv)
{
	silofs_strview_nchop_any_of(sv, set, silofs_str_length(set), out_sv);
}

void silofs_strview_nchop_any_of(const struct silofs_strview *sv,
                                 const char *set, size_t n,
                                 struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	const size_t j = silofs_strview_nfind_last_not_of(sv, sz, set, n);

	silofs_strview_sub(sv, 0UL, ((j < sz) ? j + 1 : 0), out_sv);
}

void silofs_strview_chop_chr(const struct silofs_strview *sv, char c,
                             struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	const size_t j = silofs_strview_find_last_not(sv, sz, c);

	silofs_strview_sub(sv, 0UL, ((j < sz) ? j + 1 : 0), out_sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_strip_any_of(const struct silofs_strview *sv,
                                 const char *set,
                                 struct silofs_strview *out_sv)
{
	silofs_strview_nstrip_any_of(sv, set, silofs_str_length(set), out_sv);
}

void silofs_strview_nstrip_any_of(const struct silofs_strview *sv,
                                  const char *set, size_t n,
                                  struct silofs_strview *out_sv)
{
	struct silofs_strview sub = { .str = NULL };

	silofs_strview_ntrim_any_of(sv, set, n, &sub);
	silofs_strview_nchop_any_of(&sub, set, n, out_sv);
}

void silofs_strview_strip_chr(const struct silofs_strview *sv, char c,
                              struct silofs_strview *out_sv)
{
	struct silofs_strview sub = { .str = NULL };

	silofs_strview_trim_chr(sv, c, &sub);
	silofs_strview_chop_chr(&sub, c, out_sv);
}

void silofs_strview_strip_ws(const struct silofs_strview *sv,
                             struct silofs_strview *out_sv)
{
	const char *spaces = " \n\t\r\v\f";

	silofs_strview_strip_any_of(sv, spaces, out_sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_find_token(const struct silofs_strview *sv,
                               const char *seps, struct silofs_strview *out_sv)
{
	silofs_strview_nfind_token(sv, seps, silofs_str_length(seps), out_sv);
}

void silofs_strview_nfind_token(const struct silofs_strview *sv,
                                const char *seps, size_t n,
                                struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	const size_t ki = silofs_strview_nfind_first_not_of(sv, 0UL, seps, n);
	const size_t i = silofs_min(ki, sz);
	const size_t kj = silofs_strview_nfind_first_of(sv, i, seps, n);
	const size_t j = silofs_min(kj, sz);

	silofs_strview_sub(sv, i, j - i, out_sv);
}

void silofs_strview_find_token_chr(const struct silofs_strview *sv, char sep,
                                   struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	const size_t ki = silofs_strview_find_first_not(sv, 0UL, sep);
	const size_t i = silofs_min(ki, sz);
	const size_t kj = silofs_strview_find_chr(sv, i, sep);
	const size_t j  = silofs_min(kj, sz);

	silofs_strview_sub(sv, i, j - i, out_sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strview_find_next_token(const struct silofs_strview *sv,
                                    const struct silofs_strview *tok,
                                    const char *seps,
                                    struct silofs_strview *out_sv)
{
	const size_t len = silofs_str_length(seps);

	silofs_strview_nfind_next_token(sv, tok, seps, len, out_sv);
}

void silofs_strview_nfind_next_token(const struct silofs_strview *sv,
                                     const struct silofs_strview *tok,
                                     const char *seps, size_t n,
                                     struct silofs_strview *out_sv)
{
	struct silofs_strview sub = { .str = NULL };
	const size_t sz = sv->len;
	size_t i;

	i = silofs_strview_offset(sv, silofs_strview_end(tok));
	silofs_strview_sub(sv, i, sz, &sub);
	silofs_strview_nfind_token(&sub, seps, n, out_sv);
}

void silofs_strview_find_next_token_chr(const struct silofs_strview *sv,
                                        const struct silofs_strview *tok,
                                        char sep, struct silofs_strview *out)
{
	struct silofs_strview sub = { .str = NULL };
	const size_t sz = sv->len;
	size_t i;

	i = silofs_strview_offset(sv, silofs_strview_end(tok));
	silofs_strview_sub(sv, i, sz, &sub);
	silofs_strview_find_token_chr(&sub, sep, out);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_strview_tokenize(const struct silofs_strview *ss,
                            const char *seps,
                            struct silofs_strview tok_list[],
                            size_t list_size, size_t *out_ntok)
{
	return silofs_strview_ntokenize(ss, seps, silofs_str_length(seps),
	                                tok_list, list_size, out_ntok);
}

int silofs_strview_ntokenize(const struct silofs_strview *ss,
                             const char *seps, size_t n,
                             struct silofs_strview tok_list[],
                             size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct silofs_strview tok;
	struct silofs_strview *tgt = NULL;

	silofs_strview_nfind_token(ss, seps, n, &tok);
	while (!silofs_strview_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		silofs_strview_init_by(tgt, &tok);

		silofs_strview_nfind_next_token(ss, &tok, seps, n, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

int silofs_strview_tokenize_chr(const struct silofs_strview *ss, char sep,
                                struct silofs_strview tok_list[],
                                size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct silofs_strview tok;
	struct silofs_strview *tgt = NULL;

	silofs_strview_find_token_chr(ss, sep, &tok);
	while (!silofs_strview_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		silofs_strview_init_by(tgt, &tok);

		silofs_strview_find_next_token_chr(ss, &tok, sep, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_common_prefix(const struct silofs_strview *sv,
                                    const char *s)
{
	return silofs_strview_ncommon_prefix(sv, s, silofs_str_length(s));
}

size_t silofs_strview_ncommon_prefix(const struct silofs_strview *sv,
                                     const char *s, size_t n)
{
	const size_t sz = sv->len;
	const size_t nn = silofs_min(n, sz);

	return silofs_str_common_prefix(sv->str, s, nn);
}

bool silofs_strview_starts_with(const struct silofs_strview *sv, char c)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;

	return (sz > 0) && chr_eq(c, *dat);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_common_suffix(const struct silofs_strview *sv,
                                    const char *s)
{
	return silofs_strview_ncommon_suffix(sv, s, silofs_str_length(s));
}

size_t silofs_strview_ncommon_suffix(const struct silofs_strview *sv,
                                     const char *s, size_t n)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;
	size_t k = 0;

	if (n > sz) {
		k = silofs_str_common_suffix(dat, s + (n - sz), sz);
	} else {
		k = silofs_str_common_suffix(dat + (sz - n), s, n);
	}
	return k;
}

int silofs_strview_ends_with(const struct silofs_strview *sv, char c)
{
	const char *dat = sv->str;
	const size_t sz = sv->len;

	return (sz > 0) && chr_eq(c, dat[sz - 1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic Operations:
 */
static size_t strview_find_if(const struct silofs_strview *sv,
                              silofs_chr_testif_fn fn, bool cond)
{
	const char *p = silofs_strview_begin(sv);
	const char *q = silofs_strview_end(sv);
	size_t pos = silofs_strview_npos();

	while (p < q) {
		if (fn(*p) == cond) {
			pos = silofs_strview_offset(sv, p);
			break;
		}
		++p;
	}
	return pos;
}

size_t silofs_strview_find_if(const struct silofs_strview *sv,
                              silofs_chr_testif_fn fn)
{
	return strview_find_if(sv, fn, true);
}

size_t silofs_strview_find_if_not(const struct silofs_strview *sv,
                                  silofs_chr_testif_fn fn)
{
	return strview_find_if(sv, fn, false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t strview_rfind_if(const struct silofs_strview *sv,
                               silofs_chr_testif_fn fn, bool cond)
{
	const char *p = silofs_strview_end(sv);
	const char *q = silofs_strview_begin(sv);
	size_t pos = silofs_strview_npos();

	while (p-- > q) {
		if (fn(*p) == cond) {
			pos = silofs_strview_offset(sv, p);
			break;
		}
	}
	return pos;
}

size_t silofs_strview_rfind_if(const struct silofs_strview *sv,
                               silofs_chr_testif_fn fn)
{
	return strview_rfind_if(sv, fn, true);
}

size_t silofs_strview_rfind_if_not(const struct silofs_strview *sv,
                                   silofs_chr_testif_fn fn)
{
	return strview_rfind_if(sv, fn, false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strview_count_if(const struct silofs_strview *sv,
                               silofs_chr_testif_fn fn)
{
	const char *p = silofs_strview_begin(sv);
	const char *q = silofs_strview_end(sv);
	size_t cnt = 0;

	while (p < q) {
		if (fn(*p++)) {
			++cnt;
		}
	}
	return cnt;
}

bool silofs_strview_test_if(const struct silofs_strview *sv,
                            silofs_chr_testif_fn fn)
{
	const char *p = silofs_strview_begin(sv);
	const char *q = silofs_strview_end(sv);

	while (p < q) {
		if (!fn(*p++)) {
			return false;
		}
	}
	return true;
}

void silofs_strview_trim_if(const struct silofs_strview *sv,
                            silofs_chr_testif_fn fn,
                            struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	size_t pos;

	pos = silofs_strview_find_if_not(sv, fn);
	silofs_strview_sub(sv, pos, sz, out_sv);
}

void silofs_strview_chop_if(const struct silofs_strview *sv,
                            silofs_chr_testif_fn fn,
                            struct silofs_strview *out_sv)
{
	const size_t sz = sv->len;
	size_t pos;

	pos = silofs_strview_rfind_if_not(sv, fn);
	silofs_strview_sub(sv, 0UL, ((pos < sz) ? pos + 1 : 0), out_sv);
}

void silofs_strview_strip_if(const struct silofs_strview *sv,
                             silofs_chr_testif_fn fn,
                             struct silofs_strview *out_sv)
{
	struct silofs_strview sub = { .str = NULL };

	silofs_strview_trim_if(sv, fn, &sub);
	silofs_strview_chop_if(&sub, fn, out_sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_strview_isalnum(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isalnum);
}

bool silofs_strview_isalpha(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isalpha);
}

bool silofs_strview_isascii(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isascii);
}

bool silofs_strview_isblank(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isblank);
}

bool silofs_strview_iscntrl(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_iscntrl);
}

bool silofs_strview_isdigit(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isdigit);
}

bool silofs_strview_isgraph(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isgraph);
}

bool silofs_strview_islower(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_islower);
}

bool silofs_strview_isprint(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isprint);
}

bool silofs_strview_ispunct(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_ispunct);
}

bool silofs_strview_isspace(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isspace);
}

bool silofs_strview_isupper(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isupper);
}

bool silofs_strview_isxdigit(const struct silofs_strview *sv)
{
	return silofs_strview_test_if(sv, silofs_chr_isxdigit);
}
