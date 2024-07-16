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
#include <silofs/str/strref.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>


static char *unconst_str(const char *s)
{
	union {
		const char *p;
		char *q;
	} u = {
		.p = s
	};
	return u.q;
}

static bool chr_eq(char c1, char c2)
{
	return c1 == c2;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define strref_out_of_range(ss, pos, sz)                \
	silofs_panic("out-of-range pos=%ld sz=%ld ss=%s",      \
	             (long)(pos), (long)(sz), ((const char*)(ss)->str))


static size_t strref_max_size(void)
{
	return ULONG_MAX >> 2;
}
size_t silofs_strref_max_size(void)
{
	return strref_max_size();
}

static size_t strref_npos(void)
{
	return strref_max_size();
}
size_t silofs_strref_npos(void)
{
	return strref_npos();
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Immutable String Operations:
 */

/* Returns the offset of p within strref */
static size_t strref_offset(const struct silofs_strref *ss, const char *p)
{
	size_t off;

	off = strref_npos();
	if (p != NULL) {
		if ((p >= ss->str) && (p < (ss->str + ss->len))) {
			off = (size_t)(p - ss->str);
		}
	}
	return off;
}

void silofs_strref_init(struct silofs_strref *ss, const char *s)
{
	silofs_strref_init_rd(ss, s, silofs_str_length(s));
}

void silofs_strref_init_rd(struct silofs_strref *ss, const char *s, size_t n)
{
	silofs_strref_init_rw(ss, unconst_str(s), n, 0UL);
}

void silofs_strref_init_rwa(struct silofs_strref *ss, char *s)
{
	const size_t len = silofs_str_length(s);

	silofs_strref_init_rw(ss, s, len, len);
}

void silofs_strref_init_rw(struct silofs_strref *ss,
                           char *s, size_t nrd, size_t nwr)
{
	ss->str  = s;
	ss->len  = nrd;
	ss->nwr  = nwr;
}

void silofs_strref_inits(struct silofs_strref *ss)
{
	static const char *es = "";
	silofs_strref_init(ss, es);
}

void silofs_strref_clone(const struct silofs_strref *ss,
                         struct silofs_strref *other)
{
	other->str = ss->str;
	other->len = ss->len;
	other->nwr = ss->nwr;
}

void silofs_strref_destroy(struct silofs_strref *ss)
{
	ss->str  = NULL;
	ss->len  = 0;
	ss->nwr  = 0;
}


static const char *strref_data(const struct silofs_strref *ss)
{
	return ss->str;
}

static char *strref_mutable_data(const struct silofs_strref *ss)
{
	return unconst_str(ss->str);
}

static size_t strref_size(const struct silofs_strref *ss)
{
	return ss->len;
}

size_t silofs_strref_size(const struct silofs_strref *ss)
{
	return strref_size(ss);
}

static size_t strref_wrsize(const struct silofs_strref *ss)
{
	return ss->nwr;
}

size_t silofs_strref_wrsize(const struct silofs_strref *ss)
{
	return strref_wrsize(ss);
}

static bool strref_isempty(const struct silofs_strref *ss)
{
	return (strref_size(ss) == 0);
}

bool silofs_strref_isempty(const struct silofs_strref *ss)
{
	return strref_isempty(ss);
}

static const char *strref_begin(const struct silofs_strref *ss)
{
	return strref_data(ss);
}

const char *silofs_strref_begin(const struct silofs_strref *ss)
{
	return strref_begin(ss);
}

static const char *strref_end(const struct silofs_strref *ss)
{
	return (strref_data(ss) + strref_size(ss));
}

const char *silofs_strref_end(const struct silofs_strref *ss)
{
	return strref_end(ss);
}

size_t silofs_strref_offset(const struct silofs_strref *ss, const char *p)
{
	return strref_offset(ss, p);
}

const char *silofs_strref_at(const struct silofs_strref *ss, size_t n)
{
	const size_t sz = strref_size(ss);

	if (!(n < sz)) {
		strref_out_of_range(ss, n, sz);
	}
	return strref_data(ss) + n;
}

int silofs_strref_isvalid_index(const struct silofs_strref *ss, size_t i)
{
	return (i < strref_size(ss));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_copyto(const struct silofs_strref *ss,
                            char *buf, size_t n)
{
	const size_t len = silofs_min(n, ss->len);

	silofs_str_copy(buf, ss->str, len);
	if (len < n) { /* If possible, terminate with EOS. */
		silofs_str_terminate(buf, len);
	}
	return len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_strref_compare(const struct silofs_strref *ss, const char *s)
{
	return silofs_strref_ncompare(ss, s, silofs_str_length(s));
}

int silofs_strref_ncompare(const struct silofs_strref *ss,
                           const char *s, size_t n)
{
	int res = 0;

	if ((ss->str != s) || (ss->len != n)) {
		res = silofs_str_ncompare(ss->str, ss->len, s, n);
	}
	return res;
}

bool silofs_strref_isequal(const struct silofs_strref *ss, const char *s)
{
	return silofs_strref_nisequal(ss, s, silofs_str_length(s));
}

bool silofs_strref_nisequal(const struct silofs_strref *ss,
                            const char *s, size_t n)
{
	const char *str;

	if (strref_size(ss) != n) {
		return false;
	}
	str = strref_data(ss);
	if (str == s) {
		return true;
	}
	return (silofs_str_compare(str, s, n) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_count(const struct silofs_strref *ss, const char *s)
{
	return silofs_strref_ncount(ss, s, silofs_str_length(s));
}

size_t silofs_strref_ncount(const struct silofs_strref *ss,
                            const char *s, size_t n)
{
	size_t i;
	size_t pos = 0;
	size_t cnt = 0;
	const size_t sz = strref_size(ss);

	i = silofs_strref_nfind(ss, pos, s, n);
	while (i < sz) {
		++cnt;
		pos = i + n;
		i = silofs_strref_nfind(ss, pos, s, n);
	}
	return cnt;
}

size_t silofs_strref_count_chr(const struct silofs_strref *ss, char c)
{
	size_t i;
	size_t pos = 0;
	size_t cnt = 0;
	const size_t sz = strref_size(ss);

	i = silofs_strref_find_chr(ss, pos, c);
	while (i < sz) {
		++cnt;
		pos = i + 1;
		i = silofs_strref_find_chr(ss, pos, c);
	}
	return cnt;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_find(const struct silofs_strref *ss, const char *s)
{
	return silofs_strref_nfind(ss, 0UL, s, silofs_str_length(s));
}

size_t silofs_strref_nfind(const struct silofs_strref *ss,
                           size_t pos, const char *s, size_t n)
{
	size_t sz;
	const char *dat;
	const char *p = NULL;

	dat = strref_data(ss);
	sz  = strref_size(ss);

	if (pos < sz) {
		if (n > 1) {
			p = silofs_str_find(dat + pos, sz - pos, s, n);
		} else if (n == 1) {
			p = silofs_str_find_chr(dat + pos, sz - pos, s[0]);
		} else {
			/*
			 * Stay compatible with STL: empty string always
			 * matches (if inside string).
			 */
			p = dat + pos;
		}
	}
	return strref_offset(ss, p);
}

size_t silofs_strref_find_chr(const struct silofs_strref *ss, size_t pos,
                              char c)
{
	size_t sz;
	const char *dat;
	const char *p = NULL;

	dat = strref_data(ss);
	sz  = strref_size(ss);

	if (pos < sz) {
		p = silofs_str_find_chr(dat + pos, sz - pos, c);
	}
	return strref_offset(ss, p);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_rfind(const struct silofs_strref *ss, const char *s)
{
	const size_t pos = strref_size(ss);

	return silofs_strref_nrfind(ss, pos, s, silofs_str_length(s));
}

size_t silofs_strref_nrfind(const struct silofs_strref *ss,
                            size_t pos, const char *s, size_t n)
{
	size_t k;
	const char *p;
	const char *q;
	const char *dat = strref_data(ss);
	const size_t sz = strref_size(ss);

	p = NULL;
	q = s;
	k = (pos < sz) ? pos + 1 : sz;
	if (n == 0) {
		/* STL compatible: empty string always matches */
		p = dat + k;
	} else if (n == 1) {
		p = silofs_str_rfind_chr(dat, k, *q);
	} else {
		p = silofs_str_rfind(dat, k, q, n);
	}
	return strref_offset(ss, p);
}

size_t silofs_strref_rfind_chr(const struct silofs_strref *ss,
                               size_t pos, char c)
{
	size_t k;
	const char *p;
	const size_t sz = strref_size(ss);
	const char *dat = strref_data(ss);

	k = (pos < sz) ? pos + 1 : sz;
	p = silofs_str_rfind_chr(dat, k, c);
	return strref_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_find_first_of(const struct silofs_strref *ss,
                                   const char *s)
{
	return silofs_strref_nfind_first_of(ss, 0UL, s, silofs_str_length(s));
}

size_t silofs_strref_nfind_first_of(const struct silofs_strref *ss,
                                    size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = strref_data(ss);
	const size_t sz = strref_size(ss);

	if ((n != 0) && (pos < sz)) {
		if (n == 1) {
			p = silofs_str_find_chr(dat + pos, sz - pos, *q);
		} else {
			p = silofs_str_find_first_of(dat + pos,
			                             sz - pos, q, n);
		}
	}
	return strref_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_find_last_of(const struct silofs_strref *ss,
                                  const char *s)
{
	return silofs_strref_nfind_last_of(ss, strref_size(ss),
	                                   s, silofs_str_length(s));
}

size_t silofs_strref_nfind_last_of(const struct silofs_strref *ss, size_t pos,
                                   const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = strref_data(ss);
	const size_t sz = strref_size(ss);

	if (n != 0) {
		const size_t k = (pos < sz) ? pos + 1 : sz;

		if (n == 1) {
			p = silofs_str_rfind_chr(dat, k, *q);
		} else {
			p = silofs_str_find_last_of(dat, k, q, n);
		}
	}
	return strref_offset(ss, p);
}

size_t silofs_strref_find_first_not_of(const struct silofs_strref *ss,
                                       const char *s)
{
	const size_t len = silofs_str_length(s);

	return silofs_strref_nfind_first_not_of(ss, 0UL, s, len);
}

size_t silofs_strref_nfind_first_not_of(const struct silofs_strref *ss,
                                        size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = strref_data(ss);
	const size_t sz = strref_size(ss);

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

	return strref_offset(ss, p);
}

size_t silofs_strref_find_first_not(const struct silofs_strref *ss,
                                    size_t pos, char c)
{
	const char *p = NULL;
	const char *dat = strref_data(ss);
	const size_t sz = strref_size(ss);

	if (pos < sz) {
		p = silofs_str_find_first_not_eq(dat + pos, sz - pos, c);
	}
	return strref_offset(ss, p);
}

size_t silofs_strref_find_last_not_of(const struct silofs_strref *ss,
                                      const char *s)
{
	return silofs_strref_nfind_last_not_of(ss, strref_size(ss),
	                                       s, silofs_str_length(s));
}

size_t silofs_strref_nfind_last_not_of(const struct silofs_strref *ss,
                                       size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = strref_data(ss);
	const size_t sz = strref_size(ss);

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
	return strref_offset(ss, p);
}

size_t silofs_strref_find_last_not(const struct silofs_strref *ss,
                                   size_t pos, char c)
{
	const size_t sz = strref_size(ss);
	const size_t k = (pos < sz) ? pos + 1 : sz;
	const char *dat = strref_data(ss);
	const char *p  = silofs_str_find_last_not_eq(dat, k, c);

	return strref_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_sub(const struct silofs_strref *ss,
                       size_t i, size_t n, struct silofs_strref *out_ss)
{
	const size_t sz  = strref_size(ss);
	const size_t j   = silofs_min(i, sz);
	const size_t n1  = silofs_min(n, sz - j);
	const size_t wr  = strref_wrsize(ss);
	const size_t k   = silofs_min(i, wr);
	const size_t n2  = silofs_min(n, wr - k);

	silofs_strref_init_rw(out_ss, strref_mutable_data(ss) + j, n1, n2);
}

void silofs_strref_rsub(const struct silofs_strref *ss,
                        size_t n, struct silofs_strref *out_ss)
{
	const size_t sz  = strref_size(ss);
	const size_t n1  = silofs_min(n, sz);
	const size_t j   = sz - n1;
	const size_t wr  = strref_wrsize(ss);
	const size_t k   = silofs_min(j, wr);
	const size_t n2  = wr - k;

	silofs_strref_init_rw(out_ss, strref_mutable_data(ss) + j, n1, n2);
}

void silofs_strref_intersection(const struct silofs_strref *s1,
                                const struct silofs_strref *s2,
                                struct silofs_strref *out_ss)
{
	size_t i = 0;
	size_t n = 0;
	const char *s1_begin;
	const char *s1_end;
	const char *s2_begin;
	const char *s2_end;

	s1_begin = strref_begin(s1);
	s2_begin = strref_begin(s2);
	if (s1_begin <= s2_begin) {
		i = n = 0;

		s1_end = strref_end(s1);
		s2_end = strref_end(s2);

		/* Case 1:  [.s1...)  [..s2.....) -- Return empty strrefing */
		if (s1_end <= s2_begin) {
			i = strref_size(s2);
		}
		/* Case 2: [.s1........)
		                [.s2..) */
		else if (s2_end <= s1_end) {
			n = strref_size(s2);
		}
		/* Case 3: [.s1.....)
		               [.s2......) */
		else {
			n = (size_t)(s1_end - s2_begin);
		}
		silofs_strref_sub(s2, i, n, out_ss);
	} else {
		/* One step recursion -- its ok */
		silofs_strref_intersection(s2, s1, out_ss);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Helper function to create split-of-strrefings */
static void strref_make_split_pair(const struct silofs_strref *ss,
                                   size_t i1, size_t n1,
                                   size_t i2, size_t n2,
                                   struct silofs_strref_pair *out_ss_pair)
{
	silofs_strref_sub(ss, i1, n1, &out_ss_pair->first);
	silofs_strref_sub(ss, i2, n2, &out_ss_pair->second);
}

void silofs_strref_split(const struct silofs_strref *ss, const char *seps,
                         struct silofs_strref_pair *out_ss_pair)
{

	silofs_strref_nsplit(ss, seps, silofs_str_length(seps), out_ss_pair);
}

void silofs_strref_nsplit(const struct silofs_strref *ss,
                          const char *seps, size_t n,
                          struct silofs_strref_pair *out_ss_pair)
{
	const size_t sz = strref_size(ss);
	const size_t i = silofs_strref_nfind_first_of(ss, 0UL, seps, n);
	const size_t j = (i >= sz) ? sz :
	                 silofs_strref_nfind_first_not_of(ss, i, seps, n);

	strref_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

void silofs_strref_split_chr(const struct silofs_strref *ss, char sep,
                             struct silofs_strref_pair *out_ss_pair)
{
	const size_t sz = strref_size(ss);
	const size_t i = silofs_strref_find_chr(ss, 0UL, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	strref_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

void silofs_strref_split_str(const struct silofs_strref *ss, const char *str,
                             struct silofs_strref_pair *out_ss_pair)
{
	const size_t sz = strref_size(ss);
	const size_t i = silofs_strref_find(ss, str);
	const size_t j = (i < sz) ? i + silofs_str_length(str) : sz;

	strref_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_rsplit(const struct silofs_strref *ss, const char *seps,
                          struct silofs_strref_pair *out_ss_pair)
{
	silofs_strref_nrsplit(ss, seps, silofs_str_length(seps), out_ss_pair);
}

void silofs_strref_nrsplit(const struct silofs_strref *ss,
                           const char *seps, size_t n,
                           struct silofs_strref_pair *out_ss_pair)
{
	size_t i;
	size_t j;
	const size_t sz = strref_size(ss);

	i = silofs_strref_nfind_last_of(ss, sz, seps, n);
	if (i < sz) {
		j = silofs_strref_nfind_last_not_of(ss, i, seps, n);

		if (j < sz) {
			++i;
			++j;
		} else {
			i = j = sz;
		}
	} else {
		j = sz;
	}
	strref_make_split_pair(ss, 0UL, j, i, sz, out_ss_pair);
}

void silofs_strref_rsplit_chr(const struct silofs_strref *ss, char sep,
                              struct silofs_strref_pair *out_ss_pair)
{
	const size_t sz = strref_size(ss);
	const size_t i = silofs_strref_rfind_chr(ss, sz, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	strref_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_trim(const struct silofs_strref *ss, size_t n,
                        struct silofs_strref *out_ss)
{
	silofs_strref_sub(ss, n, strref_size(ss), out_ss);
}

void silofs_strref_trim_any_of(const struct silofs_strref *ss,
                               const char *set, struct silofs_strref *out_ss)
{
	silofs_strref_ntrim_any_of(ss, set, silofs_str_length(set), out_ss);
}

void silofs_strref_ntrim_any_of(const struct silofs_strref *ss,
                                const char *set, size_t n,
                                struct silofs_strref *out_ss)
{
	const size_t sz = strref_size(ss);
	const size_t i = silofs_strref_nfind_first_not_of(ss, 0UL, set, n);

	silofs_strref_sub(ss, i, sz, out_ss);
}

void silofs_strref_trim_chr(const struct silofs_strref *ss, char c,
                            struct silofs_strref *out_ss)
{
	const size_t sz = strref_size(ss);
	const size_t i = silofs_strref_find_first_not(ss, 0UL, c);

	silofs_strref_sub(ss, i, sz, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_chop(const struct silofs_strref *ss,
                        size_t n, struct silofs_strref *out_ss)
{
	char *dat = strref_mutable_data(ss);
	const size_t sz = strref_size(ss);
	const size_t wr = strref_wrsize(ss);
	const size_t k = silofs_min(sz, n);

	silofs_strref_init_rw(out_ss, dat, sz - k, wr);
}

void silofs_strref_chop_any_of(const struct silofs_strref *ss,
                               const char *set, struct silofs_strref *out_ss)
{
	silofs_strref_nchop_any_of(ss, set, silofs_str_length(set), out_ss);
}

void silofs_strref_nchop_any_of(const struct silofs_strref *ss,
                                const char *set, size_t n,
                                struct silofs_strref *out_ss)
{
	const size_t sz = strref_size(ss);
	const size_t j = silofs_strref_nfind_last_not_of(ss, sz, set, n);

	silofs_strref_sub(ss, 0UL, ((j < sz) ? j + 1 : 0), out_ss);
}

void silofs_strref_chop_chr(const struct silofs_strref *ss, char c,
                            struct silofs_strref *out_ss)
{
	const size_t sz = strref_size(ss);
	const size_t j = silofs_strref_find_last_not(ss, sz, c);

	silofs_strref_sub(ss, 0UL, ((j < sz) ? j + 1 : 0), out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_strip_any_of(const struct silofs_strref *ss,
                                const char *set, struct silofs_strref *result)
{
	silofs_strref_nstrip_any_of(ss, set, silofs_str_length(set), result);
}

void silofs_strref_nstrip_any_of(const struct silofs_strref *ss,
                                 const char *set, size_t n,
                                 struct silofs_strref *result)
{
	struct silofs_strref sub;

	silofs_strref_ntrim_any_of(ss, set, n, &sub);
	silofs_strref_nchop_any_of(&sub, set, n, result);
}

void silofs_strref_strip_chr(const struct silofs_strref *ss, char c,
                             struct silofs_strref *result)
{
	struct silofs_strref sub;

	silofs_strref_trim_chr(ss, c, &sub);
	silofs_strref_chop_chr(&sub, c, result);
}

void silofs_strref_strip_ws(const struct silofs_strref *ss,
                            struct silofs_strref *out_ss)
{
	const char *spaces = " \n\t\r\v\f";

	silofs_strref_strip_any_of(ss, spaces, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_find_token(const struct silofs_strref *ss,
                              const char *seps, struct silofs_strref *result)
{
	silofs_strref_nfind_token(ss, seps, silofs_str_length(seps), result);
}

void silofs_strref_nfind_token(const struct silofs_strref *ss,
                               const char *seps, size_t n,
                               struct silofs_strref *result)
{
	const size_t sz = strref_size(ss);
	const size_t ki = silofs_strref_nfind_first_not_of(ss, 0UL, seps, n);
	const size_t i = silofs_min(ki, sz);
	const size_t kj = silofs_strref_nfind_first_of(ss, i, seps, n);
	const size_t j = silofs_min(kj, sz);

	silofs_strref_sub(ss, i, j - i, result);
}

void silofs_strref_find_token_chr(const struct silofs_strref *ss, char sep,
                                  struct silofs_strref *result)
{
	const size_t sz = strref_size(ss);
	const size_t ki = silofs_strref_find_first_not(ss, 0UL, sep);
	const size_t i = silofs_min(ki, sz);
	const size_t kj = silofs_strref_find_chr(ss, i, sep);
	const size_t j  = silofs_min(kj, sz);

	silofs_strref_sub(ss, i, j - i, result);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_find_next_token(const struct silofs_strref *ss,
                                   const struct silofs_strref *tok,
                                   const char *seps,
                                   struct silofs_strref *out_ss)
{
	silofs_strref_nfind_next_token(ss, tok, seps,
	                               silofs_str_length(seps), out_ss);
}

void silofs_strref_nfind_next_token(const struct silofs_strref *ss,
                                    const struct silofs_strref *tok,
                                    const char *seps, size_t n,
                                    struct silofs_strref *result)
{
	struct silofs_strref sub;
	const size_t sz  = strref_size(ss);
	const char *p = strref_end(tok);
	const size_t i = strref_offset(ss, p);

	silofs_strref_sub(ss, i, sz, &sub);
	silofs_strref_nfind_token(&sub, seps, n, result);
}

void silofs_strref_find_next_token_chr(const struct silofs_strref *ss,
                                       const struct silofs_strref *tok,
                                       char sep, struct silofs_strref *out_ss)
{
	struct silofs_strref sub;
	const size_t sz = strref_size(ss);
	const size_t i = strref_offset(ss, strref_end(tok));

	silofs_strref_sub(ss, i, sz, &sub);
	silofs_strref_find_token_chr(&sub, sep, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_strref_tokenize(const struct silofs_strref *ss,
                           const char *seps,
                           struct silofs_strref tok_list[],
                           size_t list_size, size_t *out_ntok)
{
	return silofs_strref_ntokenize(ss, seps, silofs_str_length(seps),
	                               tok_list, list_size, out_ntok);
}

int silofs_strref_ntokenize(const struct silofs_strref *ss,
                            const char *seps, size_t n,
                            struct silofs_strref tok_list[],
                            size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct silofs_strref tok;
	struct silofs_strref *tgt = NULL;

	silofs_strref_nfind_token(ss, seps, n, &tok);
	while (!silofs_strref_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		silofs_strref_clone(&tok, tgt);

		silofs_strref_nfind_next_token(ss, &tok, seps, n, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

int silofs_strref_tokenize_chr(const struct silofs_strref *ss, char sep,
                               struct silofs_strref tok_list[],
                               size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct silofs_strref tok;
	struct silofs_strref *tgt = NULL;

	silofs_strref_find_token_chr(ss, sep, &tok);
	while (!silofs_strref_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		silofs_strref_clone(&tok, tgt);

		silofs_strref_find_next_token_chr(ss, &tok, sep, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_common_prefix(const struct silofs_strref *ss,
                                   const char *s)
{
	return silofs_strref_ncommon_prefix(ss, s, silofs_str_length(s));
}

size_t silofs_strref_ncommon_prefix(const struct silofs_strref *ss,
                                    const char *s, size_t n)
{
	const size_t sz = strref_size(ss);
	const size_t nn = silofs_min(n, sz);

	return silofs_str_common_prefix(strref_data(ss), s, nn);
}

bool silofs_strref_starts_with(const struct silofs_strref *ss, char c)
{
	return !strref_isempty(ss) && chr_eq(c, *strref_data(ss));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_common_suffix(const struct silofs_strref *ss,
                                   const char *s)
{
	return silofs_strref_ncommon_suffix(ss, s, silofs_str_length(s));
}

size_t silofs_strref_ncommon_suffix(const struct silofs_strref *ss,
                                    const char *s, size_t n)
{
	size_t k;
	const size_t sz = strref_size(ss);
	const char *dat = strref_data(ss);

	if (n > sz) {
		k = silofs_str_common_suffix(dat, s + (n - sz), sz);
	} else {
		k = silofs_str_common_suffix(dat + (sz - n), s, n);
	}
	return k;
}

int silofs_strref_ends_with(const struct silofs_strref *ss, char c)
{
	const size_t sz = strref_size(ss);

	return (sz > 0) && chr_eq(c, strref_data(ss)[sz - 1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Mutable String Operations:
 */
char *silofs_strref_data(const struct silofs_strref *ss)
{
	return strref_mutable_data(ss);
}

/* Set EOS characters at the end of characters array (if possible) */
static void strref_terminate(struct silofs_strref *ss)
{
	char *dat;
	const size_t sz = strref_size(ss);
	const size_t wr = strref_wrsize(ss);

	if (sz < wr) {
		dat = strref_mutable_data(ss);
		silofs_str_terminate(dat, sz);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Inserts a copy of s before position pos. */
static void strref_insert(struct silofs_strref *ss,
                          size_t pos, const char *s, size_t n)
{
	char *dat = silofs_strref_data(ss);

	/* Start insertion before position j. */
	const size_t sz = strref_size(ss);
	const size_t j = silofs_min(pos, sz);

	/* Number of writable elements after j. */
	const size_t wr = strref_wrsize(ss);
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* Number of elements of ss after j (to be moved fwd). */
	const size_t k = sz - j;

	/*
	 * Insert n elements of p: try as many as possible, truncate tail in
	 * case of insufficient buffer capacity.
	 */
	ss->len = j + silofs_str_insert(dat + j, rem, k, s, n);
	strref_terminate(ss);
}

/* Inserts n copies of c before position pos. */
static void strref_insert_fill(struct silofs_strref *ss,
                               size_t pos, size_t n, char c)
{
	char *dat = silofs_strref_data(ss);

	/* Start insertion before position j. */
	const size_t sz  = strref_size(ss);
	const size_t j = silofs_min(pos, sz);

	/* Number of writable elements after j. */
	const size_t wr = strref_wrsize(ss);
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* Number of elements of ss after j (to be moved fwd). */
	const size_t k = sz - j;

	/*
	 * Insert n copies of c: try as many as possible; truncate tail in
	 * case of insufficient buffer capacity.
	 */
	ss->len = j + silofs_str_insert_chr(dat + j, rem, k, n, c);
	strref_terminate(ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Replaces a strrefing of *this with a copy of s. */
static void strref_replace(struct silofs_strref *ss, size_t pos, size_t n1,
                           const char *s, size_t n)
{
	/* Number of elements to replace (assuming pos <= size). */
	const size_t sz = strref_size(ss);
	const size_t k = silofs_min(sz - pos, n1);

	/*
	 * Replace k elements after pos with s; truncate tail in case of
	 * insufficient buffer capacity.
	 */
	char *dat = strref_mutable_data(ss);
	const size_t wr = strref_wrsize(ss);

	ss->len = pos + silofs_str_replace(dat + pos, wr - pos,
	                                   sz - pos, k, s, n);
	strref_terminate(ss);
}

/* Replaces a strrefing of *this with n2 copies of c. */
static void strref_replace_fill(struct silofs_strref *ss,
                                size_t pos, size_t n1, size_t n2, char c)
{
	char *dat = strref_mutable_data(ss);

	/* Number of elements to replace (assuming pos <= size). */
	const size_t sz = strref_size(ss);
	const size_t k = silofs_min(sz - pos, n1);

	/*
	 * Replace k elements after pos with n2 copies of c; truncate tail in
	 * case of insufficient buffer capacity.
	 */
	const size_t wr = strref_wrsize(ss);

	ss->len = pos +  silofs_str_replace_chr(dat + pos, wr - pos,
	                                        sz - pos, k, n2, c);
	strref_terminate(ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_assign(struct silofs_strref *ss, const char *s)
{
	silofs_strref_nassign(ss, s, silofs_str_length(s));
}

void silofs_strref_nassign(struct silofs_strref *ss, const char *s, size_t len)
{
	silofs_strref_nreplace(ss, 0, strref_size(ss), s, len);
}

void silofs_strref_assign_chr(struct silofs_strref *ss, size_t n, char c)
{
	silofs_strref_replace_chr(ss, 0, strref_size(ss), n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_push_back(struct silofs_strref *ss, char c)
{
	silofs_strref_append_chr(ss, 1, c);
}

void silofs_strref_append(struct silofs_strref *ss, const char *s)
{
	silofs_strref_nappend(ss, s, silofs_str_length(s));
}

void silofs_strref_nappend(struct silofs_strref *ss, const char *s, size_t len)
{
	silofs_strref_ninsert(ss, strref_size(ss), s, len);
}

void silofs_strref_append_chr(struct silofs_strref *ss, size_t n, char c)
{
	silofs_strref_insert_chr(ss, strref_size(ss), n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_insert(struct silofs_strref *ss, size_t pos, const char *s)
{
	silofs_strref_ninsert(ss, pos, s, silofs_str_length(s));
}

void silofs_strref_ninsert(struct silofs_strref *ss, size_t pos,
                           const char *s, size_t len)
{
	const size_t sz = strref_size(ss);

	if (pos <= sz) {
		strref_insert(ss, pos, s, len);
	} else {
		strref_out_of_range(ss, pos, sz);
	}
}

void silofs_strref_insert_chr(struct silofs_strref *ss, size_t pos, size_t n,
                              char c)
{
	const size_t sz = strref_size(ss);

	if (pos <= sz) {
		strref_insert_fill(ss, pos, n, c);
	} else {
		strref_out_of_range(ss, pos, sz);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strref_replace(struct silofs_strref *ss,
                           size_t pos, size_t n, const char *s)
{
	silofs_strref_nreplace(ss, pos, n, s, silofs_str_length(s));
}

void silofs_strref_nreplace(struct silofs_strref *ss,
                            size_t pos, size_t n,  const char *s, size_t len)
{
	const size_t sz = strref_size(ss);

	if (pos < sz) {
		strref_replace(ss, pos, n, s, len);
	} else if (pos == sz) {
		strref_insert(ss, pos, s, len);
	} else {
		strref_out_of_range(ss, pos, sz);
	}
}

void silofs_strref_replace_chr(struct silofs_strref *ss,
                               size_t pos, size_t n1, size_t n2, char c)
{
	const size_t sz = strref_size(ss);

	if (pos < sz) {
		strref_replace_fill(ss, pos, n1, n2, c);
	} else if (pos == sz) {
		strref_insert_fill(ss, pos, n2, c);
	} else {
		strref_out_of_range(ss, pos, sz);
	}
}

void silofs_strref_erase(struct silofs_strref *ss, size_t pos, size_t n)
{
	silofs_strref_replace_chr(ss, pos, n, 0, '\0');
}

void silofs_strref_reverse(struct silofs_strref *ss)
{
	const size_t sz  = strref_size(ss);
	const size_t wr  = strref_wrsize(ss);
	const size_t len = silofs_min(sz, wr);

	silofs_str_reverse(silofs_strref_data(ss), len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic Operations:
 */
static size_t strref_find_if(const struct silofs_strref *ss,
                             silofs_chr_testif_fn fn, bool c)
{
	const char *p = strref_begin(ss);
	const char *q = strref_end(ss);

	while (p < q) {
		if (fn(*p) == c) {
			return strref_offset(ss, p);
		}
		++p;
	}
	return strref_npos();
}

size_t silofs_strref_find_if(const struct silofs_strref *ss,
                             silofs_chr_testif_fn fn)
{
	return strref_find_if(ss, fn, 1);
}

size_t silofs_strref_find_if_not(const struct silofs_strref *ss,
                                 silofs_chr_testif_fn fn)
{
	return strref_find_if(ss, fn, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t strref_rfind_if(const struct silofs_strref *ss,
                              silofs_chr_testif_fn fn, bool c)
{
	const char *p = strref_end(ss);
	const char *q = strref_begin(ss);

	while (p-- > q) {
		if (fn(*p) == c) {
			return strref_offset(ss, p);
		}
	}
	return strref_npos();
}

size_t silofs_strref_rfind_if(const struct silofs_strref *ss,
                              silofs_chr_testif_fn fn)
{
	return strref_rfind_if(ss, fn, true);
}

size_t silofs_strref_rfind_if_not(const struct silofs_strref *ss,
                                  silofs_chr_testif_fn fn)
{
	return strref_rfind_if(ss, fn, false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strref_count_if(const struct silofs_strref *ss,
                              silofs_chr_testif_fn fn)
{
	size_t cnt = 0;
	const char *p = strref_begin(ss);
	const char *q = strref_end(ss);

	while (p < q) {
		if (fn(*p++)) {
			++cnt;
		}
	}
	return cnt;
}

bool silofs_strref_test_if(const struct silofs_strref *ss,
                           silofs_chr_testif_fn fn)
{
	const char *p = strref_begin(ss);
	const char *q = strref_end(ss);

	while (p < q) {
		if (!fn(*p++)) {
			return false;
		}
	}
	return true;
}

void silofs_strref_trim_if(const struct silofs_strref *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_strref *out_ss)
{
	size_t pos;
	const size_t sz = strref_size(ss);

	pos  = silofs_strref_find_if_not(ss, fn);
	silofs_strref_sub(ss, pos, sz, out_ss);
}

void silofs_strref_chop_if(const struct silofs_strref *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_strref *out_ss)
{
	size_t pos;
	const size_t sz = strref_size(ss);

	pos = silofs_strref_rfind_if_not(ss, fn);
	silofs_strref_sub(ss, 0UL, ((pos < sz) ? pos + 1 : 0), out_ss);
}

void silofs_strref_strip_if(const struct silofs_strref *ss,
                            silofs_chr_testif_fn fn,
                            struct silofs_strref *out_ss)
{
	struct silofs_strref sub;

	silofs_strref_trim_if(ss, fn, &sub);
	silofs_strref_chop_if(&sub, fn, out_ss);
}

void silofs_strref_foreach(struct silofs_strref *ss, silofs_chr_modify_fn fn)
{
	char *p;
	const size_t sz = strref_wrsize(ss);

	p = strref_mutable_data(ss);
	for (size_t i = 0; i < sz; ++i) {
		fn(p++);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Ctype Operations:
 */
bool silofs_strref_isalnum(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isalnum);
}

bool silofs_strref_isalpha(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isalpha);
}

bool silofs_strref_isascii(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isascii);
}

bool silofs_strref_isblank(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isblank);
}

bool silofs_strref_iscntrl(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_iscntrl);
}

bool silofs_strref_isdigit(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isdigit);
}

bool silofs_strref_isgraph(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isgraph);
}

bool silofs_strref_islower(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_islower);
}

bool silofs_strref_isprint(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isprint);
}

bool silofs_strref_ispunct(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_ispunct);
}

bool silofs_strref_isspace(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isspace);
}

bool silofs_strref_isupper(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isupper);
}

bool silofs_strref_isxdigit(const struct silofs_strref *ss)
{
	return silofs_strref_test_if(ss, silofs_chr_isxdigit);
}

static void chr_toupper(char *c)
{
	*c = (char)silofs_chr_toupper(*c);
}

static void chr_tolower(char *c)
{
	*c = (char)silofs_chr_tolower(*c);
}

void silofs_strref_toupper(struct silofs_strref *ss)
{
	silofs_strref_foreach(ss, chr_toupper);
}

void silofs_strref_tolower(struct silofs_strref *ss)
{
	silofs_strref_foreach(ss, chr_tolower);
}

void silofs_strref_capitalize(struct silofs_strref *ss)
{
	if (ss->len) {
		chr_toupper(ss->str);
	}
}
