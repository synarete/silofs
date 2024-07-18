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
#include <silofs/str/strmref.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#define strmref_out_of_range(smr_, pos_) \
	silofs_panic("strmref out-of-range: pos=%ld len=%ld n=%ld smr=%p", \
	             (long)(pos_), (long)((smr_)->v.len), \
	             (long)((smr_)->n), (smr_))

#define strmref_check_range(smr_, pos_) \
	do { \
		if ((pos_) > (smr_)->n) { \
			strmref_out_of_range(smr_, pos_); \
		} \
	} while (0)


size_t silofs_strmref_max_size(void)
{
	return silofs_strview_max_size();
}

size_t silofs_strmref_npos(void)
{
	return silofs_strmref_max_size();
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strmref_init(struct silofs_strmref *smr, char *s)
{
	const size_t len = silofs_str_length(s);

	silofs_strmref_initn(smr, s, len);
}

void silofs_strmref_initn(struct silofs_strmref *smr, char *s, size_t n)
{
	silofs_strmref_initk(smr, s, n, n);
}

void silofs_strmref_initk(struct silofs_strmref *smr,
                          char *s, size_t k, size_t n)
{
	silofs_strview_initn(&smr->v, s, silofs_min(n, k));
	smr->s = s;
	smr->n = n;
}

void silofs_strmref_initz(struct silofs_strmref *smr)
{
	static char z[1] = "";

	silofs_strmref_initk(smr, z, 0, 0);
}

void silofs_strmref_init_by(struct silofs_strmref *smr,
                            const struct silofs_strmref *other)
{
	silofs_strview_init_by(&smr->v, &other->v);
	smr->s = other->s;
	smr->n = other->n;
}

void silofs_strmref_fini(struct silofs_strmref *smr)
{
	silofs_strview_fini(&smr->v);
	smr->s = NULL;
	smr->n = 0;
}

size_t silofs_strmref_size(const struct silofs_strmref *smr)
{
	return silofs_strview_size(&smr->v);
}

size_t silofs_strmref_wrsize(const struct silofs_strmref *smr)
{
	return smr->n;
}

const struct silofs_strview *
silofs_strmref_view(const struct silofs_strmref *smr)
{
	return &smr->v;
}

void silofs_strmref_mkview(const struct silofs_strmref *smr,
                           struct silofs_strview *out_sv)
{
	silofs_strview_init_by(out_sv, &smr->v);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strmref_sub(const struct silofs_strmref *smr,
                        size_t i, size_t n, struct silofs_strmref *out_smr)
{
	const size_t sz  = smr->v.len;
	const size_t j   = silofs_min(i, sz);
	const size_t n1  = silofs_min(n, sz - j);
	const size_t wr  = smr->n;
	const size_t k   = silofs_min(i, wr);
	const size_t n2  = silofs_min(n, wr - k);

	silofs_strmref_initk(out_smr, smr->s + j, n1, n2);
}

void silofs_strmref_rsub(const struct silofs_strmref *smr,
                         size_t n, struct silofs_strmref *out_smr)
{
	const size_t sz  = smr->v.len;
	const size_t n1  = silofs_min(n, sz);
	const size_t j   = sz - n1;
	const size_t wr  = smr->n;
	const size_t k   = silofs_min(j, wr);
	const size_t n2  = wr - k;

	silofs_strmref_initk(out_smr, smr->s + j, n1, n2);
}

void silofs_strmref_vsub(const struct silofs_strmref *smr,
                         const struct silofs_strview *sv,
                         struct silofs_strmref *out_smr)
{
	const size_t i = silofs_strview_offset(&smr->v, sv->str);
	const size_t n = (i < smr->v.len) ? sv->len : 0;

	silofs_strmref_sub(smr, i, n, out_smr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

char *silofs_strmref_data(const struct silofs_strmref *smr)
{
	return smr->s;
}

/* sets EOS characters at the end of characters array (if possible) */
static void strmref_terminate(struct silofs_strmref *smr)
{
	if (smr->v.len < smr->n) {
		silofs_str_terminate(smr->s, smr->v.len);
	}
}

/* inserts a copy of s before position pos */
static size_t strmref_insert(struct silofs_strmref *smr,
                             size_t pos, const char *s, size_t n)
{
	/* start insertion before position j */
	const size_t sz = smr->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of writable elements after j */
	const size_t wr = smr->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* number of elements after j (to be moved fwd) */
	const size_t k = sz - j;

	/* insert n elements of p: try to copy as many as possible, truncate
	 * tail in case of insufficient buffer capacity. */
	const size_t ni = silofs_str_insert(smr->s + j, rem, k, s, n);

	/* update length + try to keep null-terminated string */
	smr->v.len = j + ni;
	strmref_terminate(smr);

	return ni;
}

/* inserts n copies of c before position pos */
static size_t strmref_insert_fill(struct silofs_strmref *smr,
                                  size_t pos, size_t n, char c)
{
	/* start insertion before position j */
	const size_t sz = smr->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of writable elements after j */
	const size_t wr = smr->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* number of elements after j (to be moved fwd) */
	const size_t k = sz - j;

	/* insert n copies of c: try as many as possible; truncate tail in case
	 * of insufficient buffer capacity. */
	const size_t ni = silofs_str_insert_chr(smr->s + j, rem, k, n, c);

	/* update length + try to keep null-terminated string */
	smr->v.len = j + ni;
	strmref_terminate(smr);

	return ni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Replaces a sub-string with a copy of s. */
static size_t strmref_replace(struct silofs_strmref *smr, size_t pos,
                              size_t n1,
                              const char *s, size_t n)
{
	/* pos beyond end-of-string is append */
	const size_t sz = smr->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of elements to replace */
	const size_t k = silofs_min(sz - j, n1);

	/* number of mutable elements */
	const size_t wr = smr->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* replace k elements after pos with s; truncate tail in case of
	 * insufficient buffer capacity */
	const size_t nr = silofs_str_replace(smr->s + j, rem,
	                                     sz - j, k, s, n);

	/* update length + try to keep null-terminated string */
	smr->v.len = j + nr;
	strmref_terminate(smr);

	return nr;
}

/* Replaces a strmrefing of *this with n2 copies of c. */
static size_t strmref_replace_fill(struct silofs_strmref *smr,
                                   size_t pos, size_t n1, size_t n2, char c)
{
	/* pos beyond end-of-string is append */
	const size_t sz = smr->v.len;
	const size_t j = silofs_min(pos, sz);

	/* number of elements to replace */
	const size_t k = silofs_min(sz - j, n1);

	/* number of mutable elements */
	const size_t wr = smr->n;
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* replace k elements after pos with n2 copies of c; truncate tail in
	 * case of insufficient buffer capacity */
	const size_t nr = silofs_str_replace_chr(smr->s + j, rem,
	                  sz - j, k, n2, c);

	/* update length + try to keep null-terminated string */
	smr->v.len = j + nr;
	strmref_terminate(smr);

	return nr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strmref_assign(struct silofs_strmref *smr, const char *s)
{
	return silofs_strmref_nassign(smr, s, silofs_str_length(s));
}

size_t silofs_strmref_nassign(struct silofs_strmref *smr,
                              const char *s, size_t len)
{
	return silofs_strmref_nreplace(smr, 0, smr->v.len, s, len);
}

size_t silofs_strmref_assign_chr(struct silofs_strmref *smr, size_t n, char c)
{
	return silofs_strmref_replace_chr(smr, 0, smr->v.len, n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strmref_push_back(struct silofs_strmref *smr, char c)
{
	return silofs_strmref_append_chr(smr, 1, c);
}

size_t silofs_strmref_append(struct silofs_strmref *smr, const char *s)
{
	return silofs_strmref_nappend(smr, s, silofs_str_length(s));
}

size_t silofs_strmref_nappend(struct silofs_strmref *smr,
                              const char *s, size_t len)
{
	return silofs_strmref_ninsert(smr, smr->v.len, s, len);
}

size_t silofs_strmref_append_chr(struct silofs_strmref *smr, size_t n, char c)
{
	return silofs_strmref_insert_chr(smr, smr->v.len, n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strmref_insert(struct silofs_strmref *smr, size_t pos,
                             const char *s)
{
	return silofs_strmref_ninsert(smr, pos, s, silofs_str_length(s));
}

size_t silofs_strmref_ninsert(struct silofs_strmref *smr, size_t pos,
                              const char *s, size_t len)
{
	size_t ni = 0;

	strmref_check_range(smr, pos);
	if (pos <= smr->v.len) {
		ni = strmref_insert(smr, pos, s, len);
	}
	return ni;
}

size_t silofs_strmref_insert_chr(struct silofs_strmref *smr,
                                 size_t pos, size_t n, char c)
{
	size_t ni = 0;

	strmref_check_range(smr, pos);
	if (pos <= smr->v.len) {
		ni = strmref_insert_fill(smr, pos, n, c);
	}
	return ni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_strmref_replace(struct silofs_strmref *smr,
                              size_t pos, size_t n, const char *s)
{
	return silofs_strmref_nreplace(smr, pos, n, s, silofs_str_length(s));
}

size_t silofs_strmref_nreplace(struct silofs_strmref *smr, size_t pos,
                               size_t n,  const char *s, size_t len)
{
	size_t nr = 0;

	strmref_check_range(smr, pos);
	if (pos < smr->v.len) {
		nr = strmref_replace(smr, pos, n, s, len);
	} else if (pos == smr->v.len) {
		nr = strmref_insert(smr, pos, s, len);
	}
	return nr;
}

size_t silofs_strmref_replace_chr(struct silofs_strmref *smr,
                                  size_t pos, size_t n1, size_t n2, char c)
{
	size_t nr = 0;

	strmref_check_range(smr, pos);
	if (pos < smr->v.len) {
		nr = strmref_replace_fill(smr, pos, n1, n2, c);
	} else if (pos == smr->v.len) {
		nr = strmref_insert_fill(smr, pos, n2, c);
	}
	return nr;
}

void silofs_strmref_erase(struct silofs_strmref *smr, size_t pos, size_t n)
{
	silofs_strmref_replace_chr(smr, pos, n, 0, '\0');
}

void silofs_strmref_reverse(struct silofs_strmref *smr)
{
	silofs_str_reverse(smr->s, smr->v.len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_strmref_foreach(struct silofs_strmref *smr,
                            silofs_chr_modify_fn fn)
{
	char *p = smr->s;
	const char *q = p + smr->n;

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

void silofs_strmref_toupper(struct silofs_strmref *smr)
{
	silofs_strmref_foreach(smr, chr_toupper);
}

void silofs_strmref_tolower(struct silofs_strmref *smr)
{
	silofs_strmref_foreach(smr, chr_tolower);
}

void silofs_strmref_capitalize(struct silofs_strmref *smr)
{
	if (smr->v.len) {
		chr_toupper(smr->s);
	}
}
