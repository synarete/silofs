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
#ifndef SILOFS_STRSPAN_H_
#define SILOFS_STRSPAN_H_

#include <silofs/str/strchr.h>
#include <silofs/str/strview.h>

/*
 * String mutable reference: pointer to start of read-write characters array
 * and number of writable elements. Extends string-view. Always points to an
 * existing characters array without any implicit dynamic memory allocations.
 */
struct silofs_strspan {
	struct silofs_strview v;
	char                 *s;
	size_t                n;
};

struct silofs_strspan_pair {
	struct silofs_strspan first, second;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns the largest possible size a strspan may have */
size_t silofs_strspan_max_size(void);

/* "Not-a-pos" (synonym to silofs_strspan_max_size()) */
size_t silofs_strspan_npos(void);

/* Constructor: reference null-terminated mutable string */
void silofs_strspan_init(struct silofs_strspan *ss, char *s);

/* Constructor: reference n-mutable characters */
void silofs_strspan_initn(struct silofs_strspan *ss, char *s, size_t n);

/* Constructor: reference n-mutable characters with initial length of k */
void silofs_strspan_initk(struct silofs_strspan *ss, char *s, size_t k,
			  size_t n);

/* Constructor: reference zero-length characters array */
void silofs_strspan_initz(struct silofs_strspan *ss);

/* Copy constructor (shallow, references only) */
void silofs_strspan_init_by(struct silofs_strspan       *ss,
			    const struct silofs_strspan *other);

/* Destructor: reset all */
void silofs_strspan_fini(struct silofs_strspan *ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns the string's length. Synonym to ss->v.len */
size_t silofs_strspan_size(const struct silofs_strspan *ss);

/* Returns the writable-size. Synonym to ss->n */
size_t silofs_strspan_wrsize(const struct silofs_strspan *ss);

/* Returns internal string-view. Synonym to &ss->v */
const struct silofs_strview *
silofs_strspan_view(const struct silofs_strspan *ss);

/* Create a copy of ss->v internal view */
void silofs_strspan_mkview(const struct silofs_strspan *ss,
			   struct silofs_strview       *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a string-reference which refers to n characters after position i.
 * If i is an invalid index, the result is empty. If there are less then n
 * characters after position i, the result will refer only to the elements
 * which are members of source.
 */
void silofs_strspan_sub(const struct silofs_strspan *ss, size_t i, size_t n,
			struct silofs_strspan *out_ss);

/*
 * Creates a string-reference which refers to the last n chararacters. The
 * result will not refer to currently valid elements.
 */
void silofs_strspan_rsub(const struct silofs_strspan *ss, size_t n,
			 struct silofs_strspan *out_ss);

/*
 * Creates a string-reference which refers to the intersection of string-view
 * with current characters array.
 */
void silofs_strspan_vsub(const struct silofs_strspan *ss,
			 const struct silofs_strview *sv,
			 struct silofs_strspan       *out_ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns pointer to beginning of characters sequence. Synonym to ss->s */
char *silofs_strspan_data(const struct silofs_strspan *ss);

/* Assigns s, truncates result in case of insufficient room. Return the number
   of added cheracters */
size_t silofs_strspan_assign(struct silofs_strspan *ss, const char *s);
size_t
silofs_strspan_nassign(struct silofs_strspan *ss, const char *s, size_t len);
size_t silofs_strspan_vassign(struct silofs_strspan       *ss,
			      const struct silofs_strview *sv);

/* Assigns n copies of c. Return the number of added cheracters */
size_t silofs_strspan_assign_chr(struct silofs_strspan *ss, size_t n, char c);

/* Appends s. Return the number of added cheracters */
size_t silofs_strspan_append(struct silofs_strspan *ss, const char *s);
size_t
silofs_strspan_nappend(struct silofs_strspan *ss, const char *s, size_t len);

/* Appends n copies of c. */
size_t silofs_strspan_append_chr(struct silofs_strspan *ss, size_t n, char c);

/* Appends single char. Returns 1 in case of success, 0 is no room */
size_t silofs_strspan_push_back(struct silofs_strspan *ss, char c);

/* Inserts s before position pos. Returns the number of added characters */
size_t
silofs_strspan_insert(struct silofs_strspan *ss, size_t pos, const char *s);

size_t silofs_strspan_ninsert(struct silofs_strspan *ss, size_t pos,
			      const char *s, size_t len);

/* Inserts n copies of c before position pos. Returns the number of added
   characters */
size_t silofs_strspan_insert_chr(struct silofs_strspan *ss, size_t pos,
				 size_t n, char c);

/* Replaces a part of sub-string with the string s. Returns the number of added
   characters */
size_t silofs_strspan_replace(struct silofs_strspan *ss, size_t pos, size_t n,
			      const char *s);
size_t silofs_strspan_nreplace(struct silofs_strspan *ss, size_t pos,
			       size_t n, const char *s, size_t len);

/* Replaces part of sub-string with n2 copies of c */
size_t silofs_strspan_replace_chr(struct silofs_strspan *ss, size_t pos,
				  size_t n1, size_t n2, char c);

/* Erases part of sub-string */
void silofs_strspan_erase(struct silofs_strspan *ss, size_t pos, size_t n);

/* Erases the entire sub-string */
void silofs_strspan_clear(struct silofs_strspan *ss);

/* Reverse the writable portion of sub-string */
void silofs_strspan_reverse(struct silofs_strspan *ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Apply fn for every element within mutable range */
void silofs_strspan_foreach(struct silofs_strspan *ss,
			    silofs_chr_modify_fn   fn);

/* Case sensitive operations */
void silofs_strspan_toupper(struct silofs_strspan *ss);
void silofs_strspan_tolower(struct silofs_strspan *ss);
void silofs_strspan_capitalize(struct silofs_strspan *ss);

#endif /* SILOFS_STRSPAN_H_ */
