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
#include <silofs/str/strspan.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#define strspan_out_of_range(ss_, pos_) \
        silofs_panic("strspan out-of-range: pos=%ld len=%ld n=%ld ss=%p", \
                     (long)(pos_), (long)((ss_)->v.len), \
                (long)((ss_)->n), ((const void *)ss_))

#define strspan_check_range(ss_, pos_) \
        do { \
                if ((pos_) > (ss_)->n) { \
                        strspan_out_of_range(ss_, pos_); \
                } \
        } while (0)


size_t silofs_strspan_max_size(void)
{
	return silofs_strview_max_size();
}

size_t silofs_strspan_npos(void)
{
	return silofs_strspan_max_size();
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strspan_init(struct silofs_strspan *ss, char *s)
{
	const size_t len = silofs_str_length(s);

	silofs_strspan_initn(ss, s, len);
}

void silofs_strspan_initn(struct silofs_strspan *ss, char *s, size_t n)
{
	silofs_strspan_initk(ss, s, n, n);
}

void silofs_strspan_initk(struct silofs_strspan *ss,
                          char *s, size_t k, size_t n)
{
	silofs_strview_initn(&ss->v, s, silofs_min(n, k));
	ss->s = s;
	ss->n = n;
}

void silofs_strspan_initz(struct silofs_strspan *ss)
{
	static char z[1] = "";

	silofs_strspan_initk(ss, z, 0, 0);
}

void silofs_strspan_init_by(struct silofs_strspan *ss,
                            const struct silofs_strspan *other)
{
	silofs_strview_init_by(&ss->v, &other->v);
	ss->s = other->s;
	ss->n = other->n;
}

void silofs_strspan_fini(struct silofs_strspan *ss)
{
	silofs_strview_fini(&ss->v);
	ss->s = NULL;
	ss->n = 0;
}

size_t silofs_strspan_size(const struct silofs_strspan *ss)
{
	return silofs_strview_size(&ss->v);
}

size_t silofs_strspan_wrsize(const struct silofs_strspan *ss)
{
	return ss->n;
}

const struct silofs_strview *
silofs_strspan_view(const struct silofs_strspan *ss)
{
	return &ss->v;
}

void silofs_strspan_mkview(const struct silofs_strspan *ss,
                           struct silofs_strview *out_sv)
{
	silofs_strview_init_by(out_sv, &ss->v);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strspan_sub(const struct silofs_strspan *ss,
                        size_t i, size_t n, struct silofs_strspan *out_ss)
{
	const size_t sz  = ss->v.len;
	const size_t j   = silofs_min(i, sz);
	const size_t n1  = silofs_min(n, sz - j);
	const size_t wr  = ss->n;
	const size_t k   = silofs_min(i, wr);
	const size_t n2  = silofs_min(n, wr - k);

	silofs_strspan_initk(out_ss, ss->s + j, n1, n2);
}

void silofs_strspan_rsub(const struct silofs_strspan *ss,
                         size_t n, struct silofs_strspan *out_ss)
{
	const size_t sz  = ss->v.len;
	const size_t n1  = silofs_min(n, sz);
	const size_t j   = sz - n1;
	const size_t wr  = ss->n;
	const size_t k   = silofs_min(j, wr);
	const size_t n2  = wr - k;

	silofs_strspan_initk(out_ss, ss->s + j, n1, n2);
}

void silofs_strspan_vsub(const struct silofs_strspan *ss,
                         const struct silofs_strview *sv,
                         struct silofs_strspan *out_ss)
{
	const size_t i = silofs_strview_offset(&ss->v, sv->str);
	const size_t n = (i < ss->v.len) ? sv->len : 0;

	silofs_strspan_sub(ss, i, n, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

char *silofs_strspan_data(const struct silofs_strspan *ss)
{
	return ss->s;
}

/* sets EOS characters at the end of characters array (if possible) */
static void strspan_terminate(struct silofs_strspan *ss)
{
	if (ss->v.len < ss->n) {
		silofs_str_terminate(ss->s, ss->v.len);
	}
}

/* inserts a copy of s before position pos */
static size_t strspan_insert(struct silofs_strspan *ss,
                             size_t pos, const char *s, size_t n)
{
	/* start insertion before position j */
	const size_t sz = ss->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of writable elements after j */
	const size_t wr = ss->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* number of elements after j (to be moved fwd) */
	const size_t k = sz - j;

	/* insert n elements of p: try to copy as many as possible, truncate
	 * tail in case of insufficient buffer capacity. */
	const size_t ni = silofs_str_insert(ss->s + j, rem, k, s, n);

	/* update length + try to keep null-terminated string */
	ss->v.len = j + ni;
	strspan_terminate(ss);

	return ni;
}

/* inserts n copies of c before position pos */
static size_t strspan_insert_fill(struct silofs_strspan *ss,
                                  size_t pos, size_t n, char c)
{
	/* start insertion before position j */
	const size_t sz = ss->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of writable elements after j */
	const size_t wr = ss->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* number of elements after j (to be moved fwd) */
	const size_t k = sz - j;

	/* insert n copies of c: try as many as possible; truncate tail in case
	 * of insufficient buffer capacity. */
	const size_t ni = silofs_str_insert_chr(ss->s + j, rem, k, n, c);

	/* update length + try to keep null-terminated string */
	ss->v.len = j + ni;
	strspan_terminate(ss);

	return ni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Replaces a sub-string with a copy of s. */
static size_t strspan_replace(struct silofs_strspan *ss, size_t pos,
                              size_t n1,
                              const char *s, size_t n)
{
	/* pos beyond end-of-string is append */
	const size_t sz = ss->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of elements to replace */
	const size_t k = silofs_min(sz - j, n1);

	/* number of mutable elements */
	const size_t wr = ss->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* replace k elements after pos with s; truncate tail in case of
	 * insufficient buffer capacity */
	const size_t nr = silofs_str_replace(ss->s + j, rem,
	                                     sz - j, k, s, n);

	/* update length + try to keep null-terminated string */
	ss->v.len = j + nr;
	strspan_terminate(ss);

	return nr;
}

/* Replaces a strspaning of *this with n2 copies of c. */
static size_t strspan_replace_fill(struct silofs_strspan *ss,
                                   size_t pos, size_t n1, size_t n2, char c)
{
	/* pos beyond end-of-string is append */
	const size_t sz = ss->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of elements to replace */
	const size_t k = silofs_min(sz - j, n1);

	/* number of mutable elements */
	const size_t wr = ss->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* replace k elements after pos with n2 copies of c; truncate tail in
	 * case of insufficient buffer capacity */
	const size_t nr = silofs_str_replace_chr(ss->s + j, rem,
	                  sz - j, k, n2, c);

	/* update length + try to keep null-terminated string */
	ss->v.len = j + nr;
	strspan_terminate(ss);

	return nr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strspan_assign(struct silofs_strspan *ss, const char *s)
{
	return silofs_strspan_nassign(ss, s, silofs_str_length(s));
}

size_t silofs_strspan_nassign(struct silofs_strspan *ss,
                              const char *s, size_t len)
{
	return silofs_strspan_nreplace(ss, 0, ss->v.len, s, len);
}

size_t silofs_strspan_vassign(struct silofs_strspan *ss,
                              const struct silofs_strview *sv)
{
	return silofs_strspan_nassign(ss, sv->str, sv->len);
}

size_t silofs_strspan_assign_chr(struct silofs_strspan *ss, size_t n, char c)
{
	return silofs_strspan_replace_chr(ss, 0, ss->v.len, n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strspan_push_back(struct silofs_strspan *ss, char c)
{
	return silofs_strspan_append_chr(ss, 1, c);
}

size_t silofs_strspan_append(struct silofs_strspan *ss, const char *s)
{
	return silofs_strspan_nappend(ss, s, silofs_str_length(s));
}

size_t silofs_strspan_nappend(struct silofs_strspan *ss,
                              const char *s, size_t len)
{
	return silofs_strspan_ninsert(ss, ss->v.len, s, len);
}

size_t silofs_strspan_append_chr(struct silofs_strspan *ss, size_t n, char c)
{
	return silofs_strspan_insert_chr(ss, ss->v.len, n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strspan_insert(struct silofs_strspan *ss, size_t pos,
                             const char *s)
{
	return silofs_strspan_ninsert(ss, pos, s, silofs_str_length(s));
}

size_t silofs_strspan_ninsert(struct silofs_strspan *ss, size_t pos,
                              const char *s, size_t len)
{
	size_t ni = 0;

	strspan_check_range(ss, pos);
	if (pos <= ss->v.len) {
		ni = strspan_insert(ss, pos, s, len);
	}
	return ni;
}

size_t silofs_strspan_insert_chr(struct silofs_strspan *ss,
                                 size_t pos, size_t n, char c)
{
	size_t ni = 0;

	strspan_check_range(ss, pos);
	if (pos <= ss->v.len) {
		ni = strspan_insert_fill(ss, pos, n, c);
	}
	return ni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strspan_replace(struct silofs_strspan *ss,
                              size_t pos, size_t n, const char *s)
{
	return silofs_strspan_nreplace(ss, pos, n, s, silofs_str_length(s));
}

size_t silofs_strspan_nreplace(struct silofs_strspan *ss, size_t pos,
                               size_t n,  const char *s, size_t len)
{
	size_t nr = 0;

	strspan_check_range(ss, pos);
	if (pos < ss->v.len) {
		nr = strspan_replace(ss, pos, n, s, len);
	} else if (pos == ss->v.len) {
		nr = strspan_insert(ss, pos, s, len);
	}
	return nr;
}

size_t silofs_strspan_replace_chr(struct silofs_strspan *ss,
                                  size_t pos, size_t n1, size_t n2, char c)
{
	size_t nr = 0;

	strspan_check_range(ss, pos);
	if (pos < ss->v.len) {
		nr = strspan_replace_fill(ss, pos, n1, n2, c);
	} else if (pos == ss->v.len) {
		nr = strspan_insert_fill(ss, pos, n2, c);
	}
	return nr;
}

void silofs_strspan_erase(struct silofs_strspan *ss, size_t pos, size_t n)
{
	silofs_strspan_replace_chr(ss, pos, n, 0, '\0');
}

void silofs_strspan_clear(struct silofs_strspan *ss)
{
	silofs_strspan_initk(ss, ss->s, 0, ss->n);
	strspan_terminate(ss);
}

void silofs_strspan_reverse(struct silofs_strspan *ss)
{
	silofs_str_reverse(ss->s, ss->v.len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strspan_foreach(struct silofs_strspan *ss,
                            silofs_chr_modify_fn fn)
{
	char *p = ss->s;
	const char *q = p + ss->n;

	while (p < q) {
		fn(p++);
	}
}

static void chr_toupper(char *c)
{
	*c = (char)silofs_chr_toupper(*c);
}

static void chr_tolower(char *c)
{
	*c = (char)silofs_chr_tolower(*c);
}

void silofs_strspan_toupper(struct silofs_strspan *ss)
{
	silofs_strspan_foreach(ss, chr_toupper);
}

void silofs_strspan_tolower(struct silofs_strspan *ss)
{
	silofs_strspan_foreach(ss, chr_tolower);
}

void silofs_strspan_capitalize(struct silofs_strspan *ss)
{
	if (ss->v.len) {
		chr_toupper(ss->s);
	}
}
