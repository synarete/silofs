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
#ifndef SILOFS_STRMREF_H_
#define SILOFS_STRMREF_H_

#include <silofs/str/strchr.h>
#include <silofs/str/strview.h>

/*
 * String mutable reference: pointer to start of read-write characters array
 * and number of writable elements. Extends string-view. Always points to an
 * existing characters array without any implicit dynamic memory allocations.
 */
struct silofs_strmref {
	struct silofs_strview v;
	char  *s;
	size_t n;
};

struct silofs_strmref_pair {
	struct silofs_strmref first, second;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns the largest possible size a strmref may have */
size_t silofs_strmref_max_size(void);

/* "Not-a-pos" (synonym to silofs_strmref_max_size()) */
size_t silofs_strmref_npos(void);


/* Constructor: reference null-terminated mutable string */
void silofs_strmref_init(struct silofs_strmref *smr, char *s);

/* Constructor: reference n-mutable characters */
void silofs_strmref_initn(struct silofs_strmref *smr, char *s, size_t n);

/* Constructor: reference n-mutable characters with initial length of k */
void silofs_strmref_initk(struct silofs_strmref *smr,
                          char *s, size_t k, size_t n);

/* Constructor: reference zero-length characters array */
void silofs_strmref_initz(struct silofs_strmref *smr);

/* Copy constructor (shallow, references only) */
void silofs_strmref_init_by(struct silofs_strmref *smr,
                            const struct silofs_strmref *other);

/* Destructor: reset all */
void silofs_strmref_fini(struct silofs_strmref *ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns the string's length. Synonym to smr->v.len */
size_t silofs_strmref_size(const struct silofs_strmref *smr);

/* Returns the writable-size. Synonym to smr->n */
size_t silofs_strmref_wrsize(const struct silofs_strmref *smr);

/* Returns internal string-view. Synonym to &smr->v */
const struct silofs_strview *
silofs_strmref_view(const struct silofs_strmref *smr);

/* Create a copy of smr->v internal view */
void silofs_strmref_mkview(const struct silofs_strmref *smr,
                           struct silofs_strview *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a string-reference which refers to n characters after position i.
 * If i is an invalid index, the result is empty. If there are less then n
 * characters after position i, the result will refer only to the elements
 * which are members of source.
 */
void silofs_strmref_sub(const struct silofs_strmref *smr,
                        size_t i, size_t n,  struct silofs_strmref *out_ss);

/*
 * Creates a string-reference which refers to the last n chararacters. The
 * result will not refer to currently valid elements.
 */
void silofs_strmref_rsub(const struct silofs_strmref *smr,
                         size_t n, struct silofs_strmref *out_ss);

/*
 * Creates a string-reference which refers to the intersection of string-view
 * with current characters array.
 */
void silofs_strmref_vsub(const struct silofs_strmref *smr,
                         const struct silofs_strview *sv,
                         struct silofs_strmref *out_smr);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns pointer to beginning of characters sequence. Synonym to smr->s */
char *silofs_strmref_data(const struct silofs_strmref *smr);

/* Assigns s, truncates result in case of insufficient room. Return the number
   of added cheracters */
size_t silofs_strmref_assign(struct silofs_strmref *smr, const char *s);
size_t silofs_strmref_nassign(struct silofs_strmref *smr,
                              const char *s, size_t len);
size_t silofs_strmref_vassign(struct silofs_strmref *smr,
                              const struct silofs_strview *sv);


/* Assigns n copies of c. Return the number of added cheracters */
size_t silofs_strmref_assign_chr(struct silofs_strmref *smr, size_t n, char c);

/* Appends s. Return the number of added cheracters */
size_t silofs_strmref_append(struct silofs_strmref *smr, const char *s);
size_t silofs_strmref_nappend(struct silofs_strmref *smr,
                              const char *s, size_t len);

/* Appends n copies of c. */
size_t silofs_strmref_append_chr(struct silofs_strmref *ss, size_t n, char c);

/* Appends single char. Returns 1 in case of success, 0 is no room */
size_t silofs_strmref_push_back(struct silofs_strmref *ss, char c);

/* Inserts s before position pos. Returns the number of added characters */
size_t silofs_strmref_insert(struct silofs_strmref *smr,
                             size_t pos, const char *s);

size_t silofs_strmref_ninsert(struct silofs_strmref *smr,
                              size_t pos, const char *s, size_t len);

/* Inserts n copies of c before position pos. Returns the number of added
   characters */
size_t silofs_strmref_insert_chr(struct silofs_strmref *smr,
                                 size_t pos, size_t n, char c);

/* Replaces a part of sub-string with the string s. Returns the number of added
   characters */
size_t silofs_strmref_replace(struct silofs_strmref *smr,
                              size_t pos, size_t n, const char *s);
size_t silofs_strmref_nreplace(struct silofs_strmref *smr, size_t pos,
                               size_t n, const char *s, size_t len);

/* Replaces part of sub-string with n2 copies of c */
size_t silofs_strmref_replace_chr(struct silofs_strmref *smr,
                                  size_t pos, size_t n1, size_t n2, char c);

/* Erases part of sub-string */
void silofs_strmref_erase(struct silofs_strmref *smr, size_t pos, size_t n);

/* Erases the entire sub-string */
void silofs_strmref_clear(struct silofs_strmref *smr);

/* Reverse the writable portion of sub-string */
void silofs_strmref_reverse(struct silofs_strmref *ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Apply fn for every element within mutable range */
void silofs_strmref_foreach(struct silofs_strmref *smr,
                            silofs_chr_modify_fn fn);

/* Case sensitive operations */
void silofs_strmref_toupper(struct silofs_strmref *ss);
void silofs_strmref_tolower(struct silofs_strmref *ss);
void silofs_strmref_capitalize(struct silofs_strmref *ss);

#endif /* SILOFS_STRMREF_H_ */
