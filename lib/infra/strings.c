/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/infra/panic.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/strings.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void chr_assign(char *c1, char c2)
{
	*c1 = c2;
}

static int chr_eq(char c1, char c2)
{
	return c1 == c2;
}

static void chr_swap(char *p, char *q)
{
	const char c = *p;

	*p = *q;
	*q = c;
}

/*
static int chr_lt(char c1, char c2)
{
    return c1 < c2;
}
*/
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t str_length(const char *s)
{
	return strlen(s);
}

size_t silofs_str_length(const char *s)
{
	return (s != NULL) ? str_length(s) : 0;
}

int silofs_str_compare(const char *s1, const char *s2, size_t n)
{
	return (s1 == s2) ? 0 : memcmp(s1, s2, n);
}

int silofs_str_ncompare(const char *s1, size_t n1,
                        const char *s2, size_t n2)
{
	int res;
	size_t n;

	n   = silofs_min(n1, n2);
	res = silofs_str_compare(s1, s2, n);

	if (res == 0) {
		res = (n1 > n2) - (n1 < n2);
	}

	return res;
}

const char *silofs_str_find_chr(const char *s, size_t n, char a)
{
	return (const char *)(memchr(s, a, n));
}

const char *silofs_str_find(const char *s1, size_t n1,
                            const char *s2, size_t n2)
{
	const char *q;

	if (!n2 || (n1 < n2)) {
		return NULL;
	}
	q = s1 + (n1 - n2 + 1);
	for (const char *p = s1; p != q; ++p) {
		if (!silofs_str_compare(p, s2, n2)) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_rfind(const char *s1, size_t n1,
                             const char *s2, size_t n2)
{
	if (!n2 || (n1 < n2)) {
		return NULL;
	}
	for (const char *p = s1 + (n1 - n2); p >= s1; --p) {
		if (!silofs_str_compare(p, s2, n2)) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_rfind_chr(const char *s, size_t n, char c)
{
	for (const char *p = s + n; p != s;) {
		if (chr_eq(*--p, c)) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_find_first_of(const char *s1, size_t n1,
                                     const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = s1; p < q; ++p) {
		if (silofs_str_find_chr(s2, n2, *p) != NULL) {
			return p;
		}
	}
	return NULL;
}

const char *
silofs_str_find_first_not_of(const char *s1, size_t n1,
                             const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = s1; p < q; ++p) {
		if (silofs_str_find_chr(s2, n2, *p) == NULL) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_find_first_not_eq(const char *s, size_t n, char c)
{
	const char *q = s + n;

	for (const char *p = s; p < q; ++p) {
		if (!chr_eq(*p, c)) {
			return p;
		}
	}
	return NULL;
}

const char *
silofs_str_find_last_of(const char *s1, size_t n1,
                        const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = q; p > s1;) {
		if (silofs_str_find_chr(s2, n2, *--p) != NULL) {
			return p;
		}
	}
	return NULL;
}

const char *
silofs_str_find_last_not_of(const char *s1, size_t n1,
                            const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = q; p > s1;) {
		if (silofs_str_find_chr(s2, n2, *--p) == NULL) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_find_last_not_eq(const char *s, size_t n, char c)
{
	for (const char *p = s + n; p > s;) {
		if (!chr_eq(*--p, c)) {
			return p;
		}
	}
	return NULL;
}

size_t silofs_str_common_prefix(const char *s1, const char *s2, size_t n)
{
	size_t k = 0;
	const char *p = s1;
	const char *q = s2;

	while (k != n) {
		if (!chr_eq(*p, *q)) {
			break;
		}
		++k;
		++p;
		++q;
	}
	return k;
}

size_t silofs_str_common_suffix(const char *s1, const char *s2, size_t n)
{
	size_t k = 0;
	const char *p  = s1 + n;
	const char *q  = s2 + n;

	while (k != n) {
		--p;
		--q;
		if (!chr_eq(*p, *q)) {
			break;
		}
		++k;
	}
	return k;
}

size_t silofs_str_overlaps(const char *s1, size_t n1,
                           const char *s2, size_t n2)
{
	size_t d;
	size_t k;

	if (s1 < s2) {
		d = (size_t)(s2 - s1);
		k = (d < n1) ? (n1 - d) : 0;
	} else {
		d = (size_t)(s1 - s2);
		k = (d < n2) ? (n2 - d) : 0;
	}
	return k;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_str_terminate(char *s, size_t n)
{
	chr_assign(s + n, '\0');
}

void silofs_str_fill(char *s, size_t n, char c)
{
	memset(s, c, n);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void str_copy(char *s1, const char *s2, size_t n)
{
	memcpy(s1, s2, n);
}

static void str_move(char *s1, const char *s2, size_t n)
{
	memmove(s1, s2, n);
}

void silofs_str_copy(char *t, const char *s, size_t n)
{
	const size_t d = (size_t)((t > s) ? t - s : s - t);

	if (silofs_likely(n > 0) && silofs_likely(d > 0)) {
		if (silofs_likely(n < d)) {
			str_copy(t, s, n);
		} else {
			str_move(t, s, n); /* overlap */
		}
	}
}

void silofs_str_reverse(char *s, size_t n)
{
	char *p = s;
	char *q = s + n - 1;

	while (p < q) {
		chr_swap(p++, q--);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Insert where there is no overlap between source and destination. Tries to
 * insert as many characters as possible, but without overflow.
 *
 * Makes room at the beginning of the buffer: move the current string m steps
 * forward, and then inserts s to the beginning of buffer.
 */
static size_t
str_insert_no_overlap(char *p, size_t sz, size_t n1,
                      const char *s, size_t n2)
{
	const size_t k = silofs_min(n2, sz);
	const size_t m = silofs_min(n1, sz - k);

	silofs_str_copy(p + k, p, m);
	silofs_str_copy(p, s, k);

	return k + m;
}

/*
 * Insert where source and destination may overlap. Using local buffer for
 * safe copy -- avoid dynamic allocation, even at the price of performance
 */
static size_t
str_insert_with_overlap(char *p, size_t sz, size_t n1,
                        const char *s, size_t n2)
{
	size_t n;
	size_t k;
	size_t d;
	const char *q;
	char buf[512];

	n = n1;
	q = s + silofs_min(n2, sz);
	d = (size_t)(q - s);
	while (d > 0) {
		k = silofs_min(d, SILOFS_ARRAY_SIZE(buf));
		silofs_str_copy(buf, q - k, k);
		n = str_insert_no_overlap(p, sz, n, buf, k);
		d -= k;
	}
	return n;
}

size_t silofs_str_insert(char *p, size_t sz, size_t n1,
                         const char *s, size_t n2)
{
	size_t k;
	size_t n = 0;

	if (n2 >= sz) {
		n = sz;
		silofs_str_copy(p, s, n);
	} else {
		k = silofs_str_overlaps(p, sz, s, n2);
		if (k > 0) {
			n = str_insert_with_overlap(p, sz, n1, s, n2);
		} else {
			n = str_insert_no_overlap(p, sz, n1, s, n2);
		}
	}

	return n;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Inserts n2 copies of c to the front of p. Tries to insert as many characters
 * as possible, but does not insert more then available writable characters
 * in the buffer.
 *
 * Makes room at the beginning of the buffer: move the current string m steps
 * forward, then fill k c-characters into p.
 *
 * p   Target buffer
 * sz  Size of buffer: number of writable elements after p.
 * n1  Number of chars already in p (must be less or equal to sz)
 * n2  Number of copies of c to insert.
 * c   Fill character.
 *
 * Returns the number of characters in p after insertion (always less or equal
 * to sz).
 */
size_t silofs_str_insert_chr(char *p, size_t sz, size_t n1,
                             size_t n2, char c)
{
	size_t m;
	const size_t k = silofs_min(n2, sz);

	m = silofs_min(n1, sz - k);
	silofs_str_copy(p + k, p, m);
	silofs_str_fill(p, k, c);

	return k + m;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_str_replace(char *p, size_t sz, size_t len, size_t n1,
                          const char *s, size_t n2)
{
	size_t k;
	size_t m;

	if (n1 < n2) {
		/*
		 * Case 1: Need to extend existing string. We assume that s
		 * may overlap p and try to do our best...
		 */
		if (s < p) {
			k = n1;
			m = silofs_str_insert(p + k, sz - k,
			                      len - k, s + k, n2 - k);
			silofs_str_copy(p, s, k);
		} else {
			k = n1;
			silofs_str_copy(p, s, n1);
			m = silofs_str_insert(p + k, sz - k,
			                      len - k, s + k, n2 - k);
		}
	} else {
		/*
		 * Case 2: No need to worry about extra space; just copy s to
		 * the beginning of buffer and adjust size, then move the tail
		 * of the string backwards.
		 */
		k = n2;
		silofs_str_copy(p, s, k);

		m = len - n1;
		silofs_str_copy(p + k, p + n1, m);
	}

	return k + m;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_str_replace_chr(char *p, size_t sz, size_t len,
                              size_t n1, size_t n2, char c)
{
	size_t k;
	size_t m;

	if (n1 < n2) {
		/* Case 1: First fill n1 characters, then insert the rest */
		k = n1;
		silofs_str_fill(p, k, c);
		m = silofs_str_insert_chr(p + k, sz - k, len - k, n2 - k, c);
	} else {
		/*
		 * Case 2: No need to worry about extra space; just fill n2
		 * characters in the beginning of buffer.
		 */
		k = n2;
		silofs_str_fill(p, k, c);

		/* Move the tail of the string backwards. */
		m = len - n1;
		silofs_str_copy(p + k, p + n1, m);
	}
	return k + m;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/*
 * Wrappers over standard ctypes functions (macros?).
 */
static bool int_to_bool(int v)
{
	return (v != 0);
}

bool silofs_chr_isalnum(char c)
{
	return int_to_bool(isalnum(c));
}

bool silofs_chr_isalpha(char c)
{
	return int_to_bool(isalpha(c));
}

bool silofs_chr_isascii(char c)
{
	return int_to_bool(isascii(c));
}

bool silofs_chr_isblank(char c)
{
	return int_to_bool(isblank(c));
}

bool silofs_chr_iscntrl(char c)
{
	return int_to_bool(iscntrl(c));
}

bool silofs_chr_isdigit(char c)
{
	return int_to_bool(isdigit(c));
}

bool silofs_chr_isgraph(char c)
{
	return int_to_bool(isgraph(c));
}

bool silofs_chr_islower(char c)
{
	return int_to_bool(islower(c));
}

bool silofs_chr_isprint(char c)
{
	return int_to_bool(isprint(c));
}

bool silofs_chr_ispunct(char c)
{
	return int_to_bool(ispunct(c));
}

bool silofs_chr_isspace(char c)
{
	return int_to_bool(isspace(c));
}

bool silofs_chr_isupper(char c)
{
	return int_to_bool(isupper(c));
}

bool silofs_chr_isxdigit(char c)
{
	return int_to_bool(isxdigit(c));
}

int silofs_chr_toupper(char c)
{
	return toupper(c);
}

int silofs_chr_tolower(char c)
{
	return tolower(c);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define substr_out_of_range(ss, pos, sz)                \
	silofs_panic("out-of-range pos=%ld sz=%ld ss=%s",      \
	             (long)(pos), (long)(sz), ((const char*)(ss)->str))


static size_t substr_max_size(void)
{
	return ULONG_MAX >> 2;
}
size_t silofs_substr_max_size(void)
{
	return substr_max_size();
}

static size_t substr_npos(void)
{
	return substr_max_size();
}
size_t silofs_substr_npos(void)
{
	return substr_npos();
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Immutable String Operations:
 */

/* Returns the offset of p within substr */
static size_t substr_offset(const struct silofs_substr *ss, const char *p)
{
	size_t off;

	off = substr_npos();
	if (p != NULL) {
		if ((p >= ss->str) && (p < (ss->str + ss->len))) {
			off = (size_t)(p - ss->str);
		}
	}
	return off;
}

void silofs_substr_init(struct silofs_substr *ss, const char *s)
{
	silofs_substr_init_rd(ss, s, str_length(s));
}

void silofs_substr_init_rd(struct silofs_substr *ss, const char *s, size_t n)
{
	silofs_substr_init_rw(ss, unconst_str(s), n, 0UL);
}

void silofs_substr_init_rwa(struct silofs_substr *ss, char *s)
{
	const size_t len = str_length(s);

	silofs_substr_init_rw(ss, s, len, len);
}

void silofs_substr_init_rw(struct silofs_substr *ss,
                           char *s, size_t nrd, size_t nwr)
{
	ss->str  = s;
	ss->len  = nrd;
	ss->nwr  = nwr;
}

void silofs_substr_inits(struct silofs_substr *ss)
{
	static const char *es = "";
	silofs_substr_init(ss, es);
}

void silofs_substr_clone(const struct silofs_substr *ss,
                         struct silofs_substr *other)
{
	other->str = ss->str;
	other->len = ss->len;
	other->nwr = ss->nwr;
}

void silofs_substr_destroy(struct silofs_substr *ss)
{
	ss->str  = NULL;
	ss->len  = 0;
	ss->nwr  = 0;
}


static const char *substr_data(const struct silofs_substr *ss)
{
	return ss->str;
}

static char *substr_mutable_data(const struct silofs_substr *ss)
{
	return unconst_str(ss->str);
}

static size_t substr_size(const struct silofs_substr *ss)
{
	return ss->len;
}

size_t silofs_substr_size(const struct silofs_substr *ss)
{
	return substr_size(ss);
}

static size_t substr_wrsize(const struct silofs_substr *ss)
{
	return ss->nwr;
}

size_t silofs_substr_wrsize(const struct silofs_substr *ss)
{
	return substr_wrsize(ss);
}

static bool substr_isempty(const struct silofs_substr *ss)
{
	return (substr_size(ss) == 0);
}

bool silofs_substr_isempty(const struct silofs_substr *ss)
{
	return substr_isempty(ss);
}

static const char *substr_begin(const struct silofs_substr *ss)
{
	return substr_data(ss);
}

const char *silofs_substr_begin(const struct silofs_substr *ss)
{
	return substr_begin(ss);
}

static const char *substr_end(const struct silofs_substr *ss)
{
	return (substr_data(ss) + substr_size(ss));
}

const char *silofs_substr_end(const struct silofs_substr *ss)
{
	return substr_end(ss);
}

size_t silofs_substr_offset(const struct silofs_substr *ss, const char *p)
{
	return substr_offset(ss, p);
}

const char *silofs_substr_at(const struct silofs_substr *ss, size_t n)
{
	const size_t sz = substr_size(ss);

	if (!(n < sz)) {
		substr_out_of_range(ss, n, sz);
	}
	return substr_data(ss) + n;
}

int silofs_substr_isvalid_index(const struct silofs_substr *ss, size_t i)
{
	return (i < substr_size(ss));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_copyto(const struct silofs_substr *ss,
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

int silofs_substr_compare(const struct silofs_substr *ss, const char *s)
{
	return silofs_substr_ncompare(ss, s, str_length(s));
}

int silofs_substr_ncompare(const struct silofs_substr *ss,
                           const char *s, size_t n)
{
	int res = 0;

	if ((ss->str != s) || (ss->len != n)) {
		res = silofs_str_ncompare(ss->str, ss->len, s, n);
	}
	return res;
}

bool silofs_substr_isequal(const struct silofs_substr *ss, const char *s)
{
	return silofs_substr_nisequal(ss, s, silofs_str_length(s));
}

bool silofs_substr_nisequal(const struct silofs_substr *ss,
                            const char *s, size_t n)
{
	const char *str;

	if (substr_size(ss) != n) {
		return false;
	}
	str = substr_data(ss);
	if (str == s) {
		return true;
	}
	return (silofs_str_compare(str, s, n) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_count(const struct silofs_substr *ss, const char *s)
{
	return silofs_substr_ncount(ss, s, str_length(s));
}

size_t silofs_substr_ncount(const struct silofs_substr *ss,
                            const char *s, size_t n)
{
	size_t i;
	size_t pos = 0;
	size_t cnt = 0;
	const size_t sz = substr_size(ss);

	i = silofs_substr_nfind(ss, pos, s, n);
	while (i < sz) {
		++cnt;
		pos = i + n;
		i = silofs_substr_nfind(ss, pos, s, n);
	}
	return cnt;
}

size_t silofs_substr_count_chr(const struct silofs_substr *ss, char c)
{
	size_t i;
	size_t pos = 0;
	size_t cnt = 0;
	const size_t sz = substr_size(ss);

	i = silofs_substr_find_chr(ss, pos, c);
	while (i < sz) {
		++cnt;
		pos = i + 1;
		i = silofs_substr_find_chr(ss, pos, c);
	}
	return cnt;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_find(const struct silofs_substr *ss, const char *s)
{
	return silofs_substr_nfind(ss, 0UL, s, silofs_str_length(s));
}

size_t silofs_substr_nfind(const struct silofs_substr *ss,
                           size_t pos, const char *s, size_t n)
{
	size_t sz;
	const char *dat;
	const char *p = NULL;

	dat = substr_data(ss);
	sz  = substr_size(ss);

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
	return substr_offset(ss, p);
}

size_t silofs_substr_find_chr(const struct silofs_substr *ss, size_t pos,
                              char c)
{
	size_t sz;
	const char *dat;
	const char *p = NULL;

	dat = substr_data(ss);
	sz  = substr_size(ss);

	if (pos < sz) {
		p = silofs_str_find_chr(dat + pos, sz - pos, c);
	}
	return substr_offset(ss, p);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_rfind(const struct silofs_substr *ss, const char *s)
{
	const size_t pos = substr_size(ss);

	return silofs_substr_nrfind(ss, pos, s, silofs_str_length(s));
}

size_t silofs_substr_nrfind(const struct silofs_substr *ss,
                            size_t pos, const char *s, size_t n)
{
	size_t k;
	const char *p;
	const char *q;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

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
	return substr_offset(ss, p);
}

size_t silofs_substr_rfind_chr(const struct silofs_substr *ss,
                               size_t pos, char c)
{
	size_t k;
	const char *p;
	const size_t sz = substr_size(ss);
	const char *dat = substr_data(ss);

	k = (pos < sz) ? pos + 1 : sz;
	p = silofs_str_rfind_chr(dat, k, c);
	return substr_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_find_first_of(const struct silofs_substr *ss,
                                   const char *s)
{
	return silofs_substr_nfind_first_of(ss, 0UL, s, silofs_str_length(s));
}

size_t silofs_substr_nfind_first_of(const struct silofs_substr *ss,
                                    size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if ((n != 0) && (pos < sz)) {
		if (n == 1) {
			p = silofs_str_find_chr(dat + pos, sz - pos, *q);
		} else {
			p = silofs_str_find_first_of(dat + pos,
			                             sz - pos, q, n);
		}
	}
	return substr_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_find_last_of(const struct silofs_substr *ss,
                                  const char *s)
{
	return silofs_substr_nfind_last_of(ss, substr_size(ss),
	                                   s, str_length(s));
}

size_t silofs_substr_nfind_last_of(const struct silofs_substr *ss, size_t pos,
                                   const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if (n != 0) {
		const size_t k = (pos < sz) ? pos + 1 : sz;

		if (n == 1) {
			p = silofs_str_rfind_chr(dat, k, *q);
		} else {
			p = silofs_str_find_last_of(dat, k, q, n);
		}
	}
	return substr_offset(ss, p);
}

size_t silofs_substr_find_first_not_of(const struct silofs_substr *ss,
                                       const char *s)
{
	return silofs_substr_nfind_first_not_of(ss, 0UL, s, str_length(s));
}

size_t silofs_substr_nfind_first_not_of(const struct silofs_substr *ss,
                                        size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

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

	return substr_offset(ss, p);
}

size_t silofs_substr_find_first_not(const struct silofs_substr *ss,
                                    size_t pos, char c)
{
	const char *p = NULL;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		p = silofs_str_find_first_not_eq(dat + pos, sz - pos, c);
	}
	return substr_offset(ss, p);
}

size_t silofs_substr_find_last_not_of(const struct silofs_substr *ss,
                                      const char *s)
{
	return silofs_substr_nfind_last_not_of(ss, substr_size(ss),
	                                       s, str_length(s));
}

size_t silofs_substr_nfind_last_not_of(const struct silofs_substr *ss,
                                       size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

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
	return substr_offset(ss, p);
}

size_t silofs_substr_find_last_not(const struct silofs_substr *ss,
                                   size_t pos, char c)
{
	const size_t sz = substr_size(ss);
	const size_t k = (pos < sz) ? pos + 1 : sz;
	const char *dat = substr_data(ss);
	const char *p  = silofs_str_find_last_not_eq(dat, k, c);

	return substr_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_sub(const struct silofs_substr *ss,
                       size_t i, size_t n, struct silofs_substr *out_ss)
{
	const size_t sz  = substr_size(ss);
	const size_t j   = silofs_min(i, sz);
	const size_t n1  = silofs_min(n, sz - j);
	const size_t wr  = substr_wrsize(ss);
	const size_t k   = silofs_min(i, wr);
	const size_t n2  = silofs_min(n, wr - k);

	silofs_substr_init_rw(out_ss, substr_mutable_data(ss) + j, n1, n2);
}

void silofs_substr_rsub(const struct silofs_substr *ss,
                        size_t n, struct silofs_substr *out_ss)
{
	const size_t sz  = substr_size(ss);
	const size_t n1  = silofs_min(n, sz);
	const size_t j   = sz - n1;
	const size_t wr  = substr_wrsize(ss);
	const size_t k   = silofs_min(j, wr);
	const size_t n2  = wr - k;

	silofs_substr_init_rw(out_ss, substr_mutable_data(ss) + j, n1, n2);
}

void silofs_substr_intersection(const struct silofs_substr *s1,
                                const struct silofs_substr *s2,
                                struct silofs_substr *out_ss)
{
	size_t i = 0;
	size_t n = 0;
	const char *s1_begin;
	const char *s1_end;
	const char *s2_begin;
	const char *s2_end;

	s1_begin = substr_begin(s1);
	s2_begin = substr_begin(s2);
	if (s1_begin <= s2_begin) {
		i = n = 0;

		s1_end = substr_end(s1);
		s2_end = substr_end(s2);

		/* Case 1:  [.s1...)  [..s2.....) -- Return empty substring */
		if (s1_end <= s2_begin) {
			i = substr_size(s2);
		}
		/* Case 2: [.s1........)
		                [.s2..) */
		else if (s2_end <= s1_end) {
			n = substr_size(s2);
		}
		/* Case 3: [.s1.....)
		               [.s2......) */
		else {
			n = (size_t)(s1_end - s2_begin);
		}
		silofs_substr_sub(s2, i, n, out_ss);
	} else {
		/* One step recursion -- its ok */
		silofs_substr_intersection(s2, s1, out_ss);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Helper function to create split-of-substrings */
static void substr_make_split_pair(const struct silofs_substr *ss,
                                   size_t i1, size_t n1,
                                   size_t i2, size_t n2,
                                   struct silofs_substr_pair *out_ss_pair)
{
	silofs_substr_sub(ss, i1, n1, &out_ss_pair->first);
	silofs_substr_sub(ss, i2, n2, &out_ss_pair->second);
}

void silofs_substr_split(const struct silofs_substr *ss, const char *seps,
                         struct silofs_substr_pair *out_ss_pair)
{

	silofs_substr_nsplit(ss, seps, str_length(seps), out_ss_pair);
}

void silofs_substr_nsplit(const struct silofs_substr *ss,
                          const char *seps, size_t n,
                          struct silofs_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = silofs_substr_nfind_first_of(ss, 0UL, seps, n);
	const size_t j = (i >= sz) ? sz :
	                 silofs_substr_nfind_first_not_of(ss, i, seps, n);

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

void silofs_substr_split_chr(const struct silofs_substr *ss, char sep,
                             struct silofs_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = silofs_substr_find_chr(ss, 0UL, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

void silofs_substr_split_str(const struct silofs_substr *ss, const char *str,
                             struct silofs_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = silofs_substr_find(ss, str);
	const size_t j = (i < sz) ? i + str_length(str) : sz;

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_rsplit(const struct silofs_substr *ss, const char *seps,
                          struct silofs_substr_pair *out_ss_pair)
{
	silofs_substr_nrsplit(ss, seps, str_length(seps), out_ss_pair);
}

void silofs_substr_nrsplit(const struct silofs_substr *ss,
                           const char *seps, size_t n,
                           struct silofs_substr_pair *out_ss_pair)
{
	size_t i;
	size_t j;
	const size_t sz = substr_size(ss);

	i = silofs_substr_nfind_last_of(ss, sz, seps, n);
	if (i < sz) {
		j = silofs_substr_nfind_last_not_of(ss, i, seps, n);

		if (j < sz) {
			++i;
			++j;
		} else {
			i = j = sz;
		}
	} else {
		j = sz;
	}
	substr_make_split_pair(ss, 0UL, j, i, sz, out_ss_pair);
}

void silofs_substr_rsplit_chr(const struct silofs_substr *ss, char sep,
                              struct silofs_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = silofs_substr_rfind_chr(ss, sz, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_trim(const struct silofs_substr *ss, size_t n,
                        struct silofs_substr *out_ss)
{
	silofs_substr_sub(ss, n, substr_size(ss), out_ss);
}

void silofs_substr_trim_any_of(const struct silofs_substr *ss,
                               const char *set, struct silofs_substr *out_ss)
{
	silofs_substr_ntrim_any_of(ss, set, str_length(set), out_ss);
}

void silofs_substr_ntrim_any_of(const struct silofs_substr *ss,
                                const char *set, size_t n,
                                struct silofs_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t i = silofs_substr_nfind_first_not_of(ss, 0UL, set, n);

	silofs_substr_sub(ss, i, sz, out_ss);
}

void silofs_substr_trim_chr(const struct silofs_substr *ss, char c,
                            struct silofs_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t i = silofs_substr_find_first_not(ss, 0UL, c);

	silofs_substr_sub(ss, i, sz, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_chop(const struct silofs_substr *ss,
                        size_t n, struct silofs_substr *out_ss)
{
	char *dat = substr_mutable_data(ss);
	const size_t sz = substr_size(ss);
	const size_t wr = substr_wrsize(ss);
	const size_t k = silofs_min(sz, n);

	silofs_substr_init_rw(out_ss, dat, sz - k, wr);
}

void silofs_substr_chop_any_of(const struct silofs_substr *ss,
                               const char *set, struct silofs_substr *out_ss)
{
	silofs_substr_nchop_any_of(ss, set, str_length(set), out_ss);
}

void silofs_substr_nchop_any_of(const struct silofs_substr *ss,
                                const char *set, size_t n,
                                struct silofs_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t j = silofs_substr_nfind_last_not_of(ss, sz, set, n);

	silofs_substr_sub(ss, 0UL, ((j < sz) ? j + 1 : 0), out_ss);
}

void silofs_substr_chop_chr(const struct silofs_substr *ss, char c,
                            struct silofs_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t j = silofs_substr_find_last_not(ss, sz, c);

	silofs_substr_sub(ss, 0UL, ((j < sz) ? j + 1 : 0), out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_strip_any_of(const struct silofs_substr *ss,
                                const char *set, struct silofs_substr *result)
{
	silofs_substr_nstrip_any_of(ss, set, str_length(set), result);
}

void silofs_substr_nstrip_any_of(const struct silofs_substr *ss,
                                 const char *set, size_t n,
                                 struct silofs_substr *result)
{
	struct silofs_substr sub;

	silofs_substr_ntrim_any_of(ss, set, n, &sub);
	silofs_substr_nchop_any_of(&sub, set, n, result);
}

void silofs_substr_strip_chr(const struct silofs_substr *ss, char c,
                             struct silofs_substr *result)
{
	struct silofs_substr sub;

	silofs_substr_trim_chr(ss, c, &sub);
	silofs_substr_chop_chr(&sub, c, result);
}

void silofs_substr_strip_ws(const struct silofs_substr *ss,
                            struct silofs_substr *out_ss)
{
	const char *spaces = " \n\t\r\v\f";

	silofs_substr_strip_any_of(ss, spaces, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_find_token(const struct silofs_substr *ss,
                              const char *seps, struct silofs_substr *result)
{
	silofs_substr_nfind_token(ss, seps, str_length(seps), result);
}

void silofs_substr_nfind_token(const struct silofs_substr *ss,
                               const char *seps, size_t n,
                               struct silofs_substr *result)
{
	const size_t sz = substr_size(ss);
	const size_t ki = silofs_substr_nfind_first_not_of(ss, 0UL, seps, n);
	const size_t i = silofs_min(ki, sz);
	const size_t kj = silofs_substr_nfind_first_of(ss, i, seps, n);
	const size_t j = silofs_min(kj, sz);

	silofs_substr_sub(ss, i, j - i, result);
}

void silofs_substr_find_token_chr(const struct silofs_substr *ss, char sep,
                                  struct silofs_substr *result)
{
	const size_t sz = substr_size(ss);
	const size_t ki = silofs_substr_find_first_not(ss, 0UL, sep);
	const size_t i = silofs_min(ki, sz);
	const size_t kj = silofs_substr_find_chr(ss, i, sep);
	const size_t j  = silofs_min(kj, sz);

	silofs_substr_sub(ss, i, j - i, result);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_find_next_token(const struct silofs_substr *ss,
                                   const struct silofs_substr *tok,
                                   const char *seps,
                                   struct silofs_substr *out_ss)
{
	silofs_substr_nfind_next_token(ss, tok, seps,
	                               str_length(seps), out_ss);
}

void silofs_substr_nfind_next_token(const struct silofs_substr *ss,
                                    const struct silofs_substr *tok,
                                    const char *seps, size_t n,
                                    struct silofs_substr *result)
{
	struct silofs_substr sub;
	const size_t sz  = substr_size(ss);
	const char *p = substr_end(tok);
	const size_t i = substr_offset(ss, p);

	silofs_substr_sub(ss, i, sz, &sub);
	silofs_substr_nfind_token(&sub, seps, n, result);
}

void silofs_substr_find_next_token_chr(const struct silofs_substr *ss,
                                       const struct silofs_substr *tok,
                                       char sep, struct silofs_substr *out_ss)
{
	struct silofs_substr sub;
	const size_t sz = substr_size(ss);
	const size_t i = substr_offset(ss, substr_end(tok));

	silofs_substr_sub(ss, i, sz, &sub);
	silofs_substr_find_token_chr(&sub, sep, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_substr_tokenize(const struct silofs_substr *ss,
                           const char *seps,
                           struct silofs_substr tok_list[],
                           size_t list_size, size_t *out_ntok)
{
	return silofs_substr_ntokenize(ss, seps, str_length(seps),
	                               tok_list, list_size, out_ntok);
}

int silofs_substr_ntokenize(const struct silofs_substr *ss,
                            const char *seps, size_t n,
                            struct silofs_substr tok_list[],
                            size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct silofs_substr tok;
	struct silofs_substr *tgt = NULL;

	silofs_substr_nfind_token(ss, seps, n, &tok);
	while (!silofs_substr_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		silofs_substr_clone(&tok, tgt);

		silofs_substr_nfind_next_token(ss, &tok, seps, n, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

int silofs_substr_tokenize_chr(const struct silofs_substr *ss, char sep,
                               struct silofs_substr tok_list[],
                               size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct silofs_substr tok;
	struct silofs_substr *tgt = NULL;

	silofs_substr_find_token_chr(ss, sep, &tok);
	while (!silofs_substr_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		silofs_substr_clone(&tok, tgt);

		silofs_substr_find_next_token_chr(ss, &tok, sep, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_common_prefix(const struct silofs_substr *ss,
                                   const char *s)
{
	return silofs_substr_ncommon_prefix(ss, s, str_length(s));
}

size_t silofs_substr_ncommon_prefix(const struct silofs_substr *ss,
                                    const char *s, size_t n)
{
	const size_t sz = substr_size(ss);
	const size_t nn = silofs_min(n, sz);

	return silofs_str_common_prefix(substr_data(ss), s, nn);
}

bool silofs_substr_starts_with(const struct silofs_substr *ss, char c)
{
	return !substr_isempty(ss) && chr_eq(c, *substr_data(ss));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_common_suffix(const struct silofs_substr *ss,
                                   const char *s)
{
	return silofs_substr_ncommon_suffix(ss, s, str_length(s));
}

size_t silofs_substr_ncommon_suffix(const struct silofs_substr *ss,
                                    const char *s, size_t n)
{
	size_t k;
	const size_t sz = substr_size(ss);
	const char *dat = substr_data(ss);

	if (n > sz) {
		k = silofs_str_common_suffix(dat, s + (n - sz), sz);
	} else {
		k = silofs_str_common_suffix(dat + (sz - n), s, n);
	}
	return k;
}

int silofs_substr_ends_with(const struct silofs_substr *ss, char c)
{
	const size_t sz = substr_size(ss);

	return (sz > 0) && chr_eq(c, substr_data(ss)[sz - 1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Mutable String Operations:
 */
char *silofs_substr_data(const struct silofs_substr *ss)
{
	return substr_mutable_data(ss);
}

/* Set EOS characters at the end of characters array (if possible) */
static void substr_terminate(struct silofs_substr *ss)
{
	char *dat;
	const size_t sz = substr_size(ss);
	const size_t wr = substr_wrsize(ss);

	if (sz < wr) {
		dat = substr_mutable_data(ss);
		silofs_str_terminate(dat, sz);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Inserts a copy of s before position pos. */
static void substr_insert(struct silofs_substr *ss,
                          size_t pos, const char *s, size_t n)
{
	char *dat = silofs_substr_data(ss);

	/* Start insertion before position j. */
	const size_t sz = substr_size(ss);
	const size_t j = silofs_min(pos, sz);

	/* Number of writable elements after j. */
	const size_t wr = substr_wrsize(ss);
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* Number of elements of ss after j (to be moved fwd). */
	const size_t k = sz - j;

	/*
	 * Insert n elements of p: try as many as possible, truncate tail in
	 * case of insufficient buffer capacity.
	 */
	ss->len = j + silofs_str_insert(dat + j, rem, k, s, n);
	substr_terminate(ss);
}

/* Inserts n copies of c before position pos. */
static void substr_insert_fill(struct silofs_substr *ss,
                               size_t pos, size_t n, char c)
{
	char *dat = silofs_substr_data(ss);

	/* Start insertion before position j. */
	const size_t sz  = substr_size(ss);
	const size_t j = silofs_min(pos, sz);

	/* Number of writable elements after j. */
	const size_t wr = substr_wrsize(ss);
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* Number of elements of ss after j (to be moved fwd). */
	const size_t k = sz - j;

	/*
	 * Insert n copies of c: try as many as possible; truncate tail in
	 * case of insufficient buffer capacity.
	 */
	ss->len = j + silofs_str_insert_chr(dat + j, rem, k, n, c);
	substr_terminate(ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Replaces a substring of *this with a copy of s. */
static void substr_replace(struct silofs_substr *ss, size_t pos, size_t n1,
                           const char *s, size_t n)
{
	/* Number of elements to replace (assuming pos <= size). */
	const size_t sz = substr_size(ss);
	const size_t k = silofs_min(sz - pos, n1);

	/*
	 * Replace k elements after pos with s; truncate tail in case of
	 * insufficient buffer capacity.
	 */
	char *dat = substr_mutable_data(ss);
	const size_t wr = substr_wrsize(ss);

	ss->len = pos + silofs_str_replace(dat + pos, wr - pos,
	                                   sz - pos, k, s, n);
	substr_terminate(ss);
}

/* Replaces a substring of *this with n2 copies of c. */
static void substr_replace_fill(struct silofs_substr *ss,
                                size_t pos, size_t n1, size_t n2, char c)
{
	char *dat = substr_mutable_data(ss);

	/* Number of elements to replace (assuming pos <= size). */
	const size_t sz = substr_size(ss);
	const size_t k = silofs_min(sz - pos, n1);

	/*
	 * Replace k elements after pos with n2 copies of c; truncate tail in
	 * case of insufficient buffer capacity.
	 */
	const size_t wr = substr_wrsize(ss);

	ss->len = pos +  silofs_str_replace_chr(dat + pos, wr - pos,
	                                        sz - pos, k, n2, c);
	substr_terminate(ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_assign(struct silofs_substr *ss, const char *s)
{
	silofs_substr_nassign(ss, s, str_length(s));
}

void silofs_substr_nassign(struct silofs_substr *ss, const char *s, size_t len)
{
	silofs_substr_nreplace(ss, 0, substr_size(ss), s, len);
}

void silofs_substr_assign_chr(struct silofs_substr *ss, size_t n, char c)
{
	silofs_substr_replace_chr(ss, 0, substr_size(ss), n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_push_back(struct silofs_substr *ss, char c)
{
	silofs_substr_append_chr(ss, 1, c);
}

void silofs_substr_append(struct silofs_substr *ss, const char *s)
{
	silofs_substr_nappend(ss, s, str_length(s));
}

void silofs_substr_nappend(struct silofs_substr *ss, const char *s, size_t len)
{
	silofs_substr_ninsert(ss, substr_size(ss), s, len);
}

void silofs_substr_append_chr(struct silofs_substr *ss, size_t n, char c)
{
	silofs_substr_insert_chr(ss, substr_size(ss), n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_insert(struct silofs_substr *ss, size_t pos, const char *s)
{
	silofs_substr_ninsert(ss, pos, s, str_length(s));
}

void silofs_substr_ninsert(struct silofs_substr *ss, size_t pos,
                           const char *s, size_t len)
{
	const size_t sz = substr_size(ss);

	if (pos <= sz) {
		substr_insert(ss, pos, s, len);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

void silofs_substr_insert_chr(struct silofs_substr *ss, size_t pos, size_t n,
                              char c)
{
	const size_t sz = substr_size(ss);

	if (pos <= sz) {
		substr_insert_fill(ss, pos, n, c);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_substr_replace(struct silofs_substr *ss,
                           size_t pos, size_t n, const char *s)
{
	silofs_substr_nreplace(ss, pos, n, s, str_length(s));
}

void silofs_substr_nreplace(struct silofs_substr *ss,
                            size_t pos, size_t n,  const char *s, size_t len)
{
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		substr_replace(ss, pos, n, s, len);
	} else if (pos == sz) {
		substr_insert(ss, pos, s, len);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

void silofs_substr_replace_chr(struct silofs_substr *ss,
                               size_t pos, size_t n1, size_t n2, char c)
{
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		substr_replace_fill(ss, pos, n1, n2, c);
	} else if (pos == sz) {
		substr_insert_fill(ss, pos, n2, c);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

void silofs_substr_erase(struct silofs_substr *ss, size_t pos, size_t n)
{
	silofs_substr_replace_chr(ss, pos, n, 0, '\0');
}

void silofs_substr_reverse(struct silofs_substr *ss)
{
	const size_t sz  = substr_size(ss);
	const size_t wr  = substr_wrsize(ss);
	const size_t len = silofs_min(sz, wr);

	silofs_str_reverse(silofs_substr_data(ss), len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic Operations:
 */
static size_t substr_find_if(const struct silofs_substr *ss,
                             silofs_chr_testif_fn fn, bool c)
{
	const char *p = substr_begin(ss);
	const char *q = substr_end(ss);

	while (p < q) {
		if (fn(*p) == c) {
			return substr_offset(ss, p);
		}
		++p;
	}
	return substr_npos();
}

size_t silofs_substr_find_if(const struct silofs_substr *ss,
                             silofs_chr_testif_fn fn)
{
	return substr_find_if(ss, fn, 1);
}

size_t silofs_substr_find_if_not(const struct silofs_substr *ss,
                                 silofs_chr_testif_fn fn)
{
	return substr_find_if(ss, fn, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t substr_rfind_if(const struct silofs_substr *ss,
                              silofs_chr_testif_fn fn, bool c)
{
	const char *p = substr_end(ss);
	const char *q = substr_begin(ss);

	while (p-- > q) {
		if (fn(*p) == c) {
			return substr_offset(ss, p);
		}
	}
	return substr_npos();
}

size_t silofs_substr_rfind_if(const struct silofs_substr *ss,
                              silofs_chr_testif_fn fn)
{
	return substr_rfind_if(ss, fn, true);
}

size_t silofs_substr_rfind_if_not(const struct silofs_substr *ss,
                                  silofs_chr_testif_fn fn)
{
	return substr_rfind_if(ss, fn, false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_substr_count_if(const struct silofs_substr *ss,
                              silofs_chr_testif_fn fn)
{
	size_t cnt = 0;
	const char *p = substr_begin(ss);
	const char *q = substr_end(ss);

	while (p < q) {
		if (fn(*p++)) {
			++cnt;
		}
	}
	return cnt;
}

bool silofs_substr_test_if(const struct silofs_substr *ss,
                           silofs_chr_testif_fn fn)
{
	const char *p = substr_begin(ss);
	const char *q = substr_end(ss);

	while (p < q) {
		if (!fn(*p++)) {
			return false;
		}
	}
	return true;
}

void silofs_substr_trim_if(const struct silofs_substr *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_substr *out_ss)
{
	size_t pos;
	const size_t sz = substr_size(ss);

	pos  = silofs_substr_find_if_not(ss, fn);
	silofs_substr_sub(ss, pos, sz, out_ss);
}

void silofs_substr_chop_if(const struct silofs_substr *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_substr *out_ss)
{
	size_t pos;
	const size_t sz = substr_size(ss);

	pos = silofs_substr_rfind_if_not(ss, fn);
	silofs_substr_sub(ss, 0UL, ((pos < sz) ? pos + 1 : 0), out_ss);
}

void silofs_substr_strip_if(const struct silofs_substr *ss,
                            silofs_chr_testif_fn fn,
                            struct silofs_substr *out_ss)
{
	struct silofs_substr sub;

	silofs_substr_trim_if(ss, fn, &sub);
	silofs_substr_chop_if(&sub, fn, out_ss);
}

void silofs_substr_foreach(struct silofs_substr *ss, silofs_chr_modify_fn fn)
{
	char *p;
	const size_t sz = substr_wrsize(ss);

	p = substr_mutable_data(ss);
	for (size_t i = 0; i < sz; ++i) {
		fn(p++);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Ctype Operations:
 */
bool silofs_substr_isalnum(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isalnum);
}

bool silofs_substr_isalpha(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isalpha);
}

bool silofs_substr_isascii(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isascii);
}

bool silofs_substr_isblank(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isblank);
}

bool silofs_substr_iscntrl(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_iscntrl);
}

bool silofs_substr_isdigit(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isdigit);
}

bool silofs_substr_isgraph(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isgraph);
}

bool silofs_substr_islower(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_islower);
}

bool silofs_substr_isprint(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isprint);
}

bool silofs_substr_ispunct(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_ispunct);
}

bool silofs_substr_isspace(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isspace);
}

bool silofs_substr_isupper(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isupper);
}

bool silofs_substr_isxdigit(const struct silofs_substr *ss)
{
	return silofs_substr_test_if(ss, silofs_chr_isxdigit);
}

static void chr_toupper(char *c)
{
	*c = (char)silofs_chr_toupper(*c);
}

static void chr_tolower(char *c)
{
	*c = (char)silofs_chr_tolower(*c);
}

void silofs_substr_toupper(struct silofs_substr *ss)
{
	silofs_substr_foreach(ss, chr_toupper);
}

void silofs_substr_tolower(struct silofs_substr *ss)
{
	silofs_substr_foreach(ss, chr_tolower);
}

void silofs_substr_capitalize(struct silofs_substr *ss)
{
	if (ss->len) {
		chr_toupper(ss->str);
	}
}
