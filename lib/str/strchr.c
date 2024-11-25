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
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>

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

int silofs_str_ncompare(const char *s1, size_t n1, const char *s2, size_t n2)
{
	int res;
	size_t n;

	n = silofs_min(n1, n2);
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

const char *
silofs_str_find(const char *s1, size_t n1, const char *s2, size_t n2)
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

const char *
silofs_str_rfind(const char *s1, size_t n1, const char *s2, size_t n2)
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

const char *
silofs_str_find_first_of(const char *s1, size_t n1, const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = s1; p < q; ++p) {
		if (silofs_str_find_chr(s2, n2, *p) != NULL) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_find_first_not_of(const char *s1, size_t n1,
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
silofs_str_find_last_of(const char *s1, size_t n1, const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = q; p > s1;) {
		if (silofs_str_find_chr(s2, n2, *--p) != NULL) {
			return p;
		}
	}
	return NULL;
}

const char *silofs_str_find_last_not_of(const char *s1, size_t n1,
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
	const char *p = s1 + n;
	const char *q = s2 + n;

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

size_t
silofs_str_overlaps(const char *s1, size_t n1, const char *s2, size_t n2)
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
str_insert_no_overlap(char *p, size_t sz, size_t n1, const char *s, size_t n2)
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
static size_t str_insert_with_overlap(char *p, size_t sz, size_t n1,
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

size_t
silofs_str_insert(char *p, size_t sz, size_t n1, const char *s, size_t n2)
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
size_t silofs_str_insert_chr(char *p, size_t sz, size_t n1, size_t n2, char c)
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
			m = silofs_str_insert(p + k, sz - k, len - k, s + k,
					      n2 - k);
			silofs_str_copy(p, s, k);
		} else {
			k = n1;
			silofs_str_copy(p, s, n1);
			m = silofs_str_insert(p + k, sz - k, len - k, s + k,
					      n2 - k);
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

size_t silofs_str_replace_chr(char *p, size_t sz, size_t len, size_t n1,
			      size_t n2, char c)
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
