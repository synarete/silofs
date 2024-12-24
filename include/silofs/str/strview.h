/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_STRVIEW_H_
#define SILOFS_STRVIEW_H_

#include <silofs/str/strchr.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * String-view: reference to immutable (read-only) characters-array with
 * explict length field. Does not require str to be null terminated.
 */
struct silofs_strview {
	const char *str;
	size_t      len;
};

struct silofs_strview_pair {
	struct silofs_strview first, second;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns the largest possible size a sub-string may have */
size_t silofs_strview_max_size(void);

/* "Not-a-pos" (synonym to silofs_strview_max_size()) */
size_t silofs_strview_npos(void);

/* Constructor from null terminated string */
void silofs_strview_init(struct silofs_strview *sv, const char *str);

/* Constructor from explicit string + length */
void silofs_strview_initn(struct silofs_strview *sv, const char *s, size_t n);

/* Constructor from zero-length empty string */
void silofs_strview_initz(struct silofs_strview *sv);

/* Copy constructor (shallow) */
void silofs_strview_initv(struct silofs_strview       *sv,
                          const struct silofs_strview *other);

/* Copy constructor (shallow copy) */
void silofs_strview_init_by(struct silofs_strview       *sv,
                            const struct silofs_strview *other);

/* Destructor: set to NULL */
void silofs_strview_fini(struct silofs_strview *sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns the string-view read-length. Synonym to sv->len */
size_t silofs_strview_size(const struct silofs_strview *sv);

/* Returns pointer to beginning of immutable characters array */
const char *silofs_strview_data(const struct silofs_strview *sv);

/* Returns TRUE if the string-view length is zero */
bool silofs_strview_isempty(const struct silofs_strview *sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns a read-only pointer (iterator) to the beginning of view */
const char *silofs_strview_begin(const struct silofs_strview *sv);

/* Returns a read-only pointer (iterator) pointing to the end of the view */
const char *silofs_strview_end(const struct silofs_strview *sv);

/* Returns the number of elements between begin() and p; if p is out-of-range,
 * returns npos */
size_t silofs_strview_offset(const struct silofs_strview *sv, const char *p);

/* Returns pointer to the n'th character. Performs out-of-range check and
 * panics in case n is out of range */
const char *silofs_strview_at(const struct silofs_strview *sv, size_t n);

/* Returns TRUE if pos is within the range [0,ss->len) */
bool silofs_strview_haspos(const struct silofs_strview *sv, size_t pos);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Copy data into buffer, return number of characters assigned. Assign
 * no more than min(n, size()) bytes.
 *
 * Returns the number of characters copied to buf, not including possible null
 * termination character. Result buf will be a null-terminated characters
 * string only if there is enough room.
 */
size_t
silofs_strview_copyto(const struct silofs_strview *sv, void *buf, size_t n);

/* Three-way lexicographical comparison */
int silofs_strview_compare(const struct silofs_strview *sv, const char *s);
int silofs_strview_ncompare(const struct silofs_strview *sv, const char *s,
                            size_t n);

/* Returns TRUE if equal size and equal data */
bool silofs_strview_isequal(const struct silofs_strview *sv, const char *s);
bool silofs_strview_nisequal(const struct silofs_strview *sv, const char *s,
                             size_t n);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Returns the number of (non-overlapping) occurrences of s (or c) within sv */
size_t silofs_strview_count(const struct silofs_strview *sv, const char *s);
size_t silofs_strview_ncount(const struct silofs_strview *sv, const char *s,
                             size_t n);
size_t silofs_strview_count_chr(const struct silofs_strview *sv, char c);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Searches sv, beginning at position pos, for the first occurrence of s
 * (or c); if search fails, returns npos */
size_t silofs_strview_find(const struct silofs_strview *sv, const char *str);
size_t silofs_strview_nfind(const struct silofs_strview *sv, size_t pos,
                            const char *s, size_t n);
size_t
silofs_strview_find_chr(const struct silofs_strview *sv, size_t pos, char c);

/* Searches sv backwards, beginning at position pos, for the last occurrence of
 * s (or c); if search fails, returns npos */
size_t silofs_strview_rfind(const struct silofs_strview *sv, const char *s);
size_t silofs_strview_nrfind(const struct silofs_strview *sv, size_t pos,
                             const char *s, size_t n);
size_t
silofs_strview_rfind_chr(const struct silofs_strview *sv, size_t pos, char c);

/* Searches sv, beginning at position pos, for the first character that is
 * equal to any one of the characters of s */
size_t
silofs_strview_find_first_of(const struct silofs_strview *sv, const char *s);
size_t silofs_strview_nfind_first_of(const struct silofs_strview *sv,
                                     size_t pos, const char *s, size_t n);

/* Searches sv backwards, beginning at position pos, for the last character
 * that is equal to any of the characters of s */
size_t
silofs_strview_find_last_of(const struct silofs_strview *sv, const char *s);
size_t silofs_strview_nfind_last_of(const struct silofs_strview *sv,
                                    size_t pos, const char *s, size_t n);

/* Searches sv, beginning at position pos, for the first character that is not
 * equal to any of the characters of s */
size_t silofs_strview_find_first_not_of(const struct silofs_strview *sv,
                                        const char                  *s);
size_t silofs_strview_nfind_first_not_of(const struct silofs_strview *sv,
                                         size_t pos, const char *s, size_t n);
size_t silofs_strview_find_first_not(const struct silofs_strview *sv,
                                     size_t pos, char c);

/* Searches sv backwards, beginning at position pos, for the last character
 * that is not equal to any of the characters of s (or c) */
size_t silofs_strview_find_last_not_of(const struct silofs_strview *sv,
                                       const char                  *s);
size_t silofs_strview_nfind_last_not_of(const struct silofs_strview *sv,
                                        size_t pos, const char *s, size_t n);
size_t silofs_strview_find_last_not(const struct silofs_strview *sv,
                                    size_t pos, char c);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Creates a sub-strview of sv, which refers to n characters after position i.
 * If i is an invalid index, the result is empty. If there are less then n
 * characters after position i, the result will refer only to the elements
 * which are members of sv */
void silofs_strview_sub(const struct silofs_strview *sv, size_t i, size_t n,
                        struct silofs_strview *out_sv);

/* Creates a sub-strview of sv, which refers to the last n chars. The result
 * will not refer to more then sv->len elements */
void silofs_strview_rsub(const struct silofs_strview *sv, size_t n,
                         struct silofs_strview *out_sv);

/* Creates a sub-strview with all the characters that are in the range of
 * both sv1 and sv2. That is, all elements within both ranges (same address) */
void silofs_strview_intersection(const struct silofs_strview *sv1,
                                 const struct silofs_strview *sv2,
                                 struct silofs_strview       *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Creates a pair of strview, which are divided by any of the first characters
 * of seps. If none of the characters of seps is in sv, the first element
 * of the result-pair is equals to sv and the second element is empty
 *
 *  Examples:
 *  split("root@foo//bar", "/@:")  --> "root", "foo//bar"
 *  split("foo///:bar::zoo", ":/") --> "foo", "bar:zoo"
 *  split("root@foo.bar", ":/")    --> "root@foo.bar", ""
 */
void silofs_strview_split(const struct silofs_strview *sv, const char *seps,
                          struct silofs_strview_pair *out_sv_pair);

void silofs_strview_nsplit(const struct silofs_strview *sv, const char *seps,
                           size_t n, struct silofs_strview_pair *out_sv_pair);

void silofs_strview_split_chr(const struct silofs_strview *sv, char sep,
                              struct silofs_strview_pair *out_sv_pair);

void silofs_strview_split_str(const struct silofs_strview *sv, const char *str,
                              struct silofs_strview_pair *out_sv_pair);

/*
 * Creates a pair of strview, which are divided by any of the first n
 * characters of seps, while searching sv backwards. If none of the characters
 * of seps is in sv, the first element of the pair equals to sv and the second
 * element is empty.
 */
void silofs_strview_rsplit(const struct silofs_strview *sv, const char *seps,
                           struct silofs_strview_pair *out_sv_pair);

void silofs_strview_nrsplit(const struct silofs_strview *sv, const char *seps,
                            size_t n, struct silofs_strview_pair *out_sv_pair);

void silofs_strview_rsplit_chr(const struct silofs_strview *sv, char sep,
                               struct silofs_strview_pair *out_sv_pair);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Creates a sub-strview of sv without the first n leading characters */
void silofs_strview_trim(const struct silofs_strview *sv, size_t n,
                         struct silofs_strview *out_sv);

/* Creates a sub-strview of sv without any leading characters which are members
 * of set (or c) */
void silofs_strview_trim_any_of(const struct silofs_strview *sv,
                                const char                  *set,
                                struct silofs_strview       *out_sv);

void silofs_strview_ntrim_any_of(const struct silofs_strview *sv,
                                 const char *set, size_t n,
                                 struct silofs_strview *out_sv);

void silofs_strview_trim_chr(const struct silofs_strview *sv, char c,
                             struct silofs_strview *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Creates a sub-strview of sv without the last n trailing characters */
void silofs_strview_chop(const struct silofs_strview *sv, size_t n,
                         struct silofs_strview *out_sv);

/* Creates a sub-strview of sv without any trailing characters which are
 * members of set */
void silofs_strview_chop_any_of(const struct silofs_strview *sv,
                                const char                  *set,
                                struct silofs_strview       *out_sv);

void silofs_strview_nchop_any_of(const struct silofs_strview *sv,
                                 const char *set, size_t n,
                                 struct silofs_strview *out_sv);

/* Creates a sub-strview of sv without any trailing characters that equals c */
void silofs_strview_chop_chr(const struct silofs_strview *sv, char c,
                             struct silofs_strview *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Creates a sub-strview of sv without any leading and trailing characters
 * which are members of set */
void silofs_strview_strip_any_of(const struct silofs_strview *sv,
                                 const char                  *set,
                                 struct silofs_strview       *out_sv);

void silofs_strview_nstrip_any_of(const struct silofs_strview *sv,
                                  const char *set, size_t n,
                                  struct silofs_strview *out_sv);

/* Creates a sub-strview of sv without any leading and trailing characters
 * which are equal to c */
void silofs_strview_strip_chr(const struct silofs_strview *sv, char c,
                              struct silofs_strview *out_sv);

/* Strip white-spaces */
void silofs_strview_strip_ws(const struct silofs_strview *ss,
                             struct silofs_strview       *out_ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Finds the first sub-strview of sv that is a token delimited by any of the
 * characters of sep(s) */
void silofs_strview_find_token(const struct silofs_strview *sv,
                               const char                  *seps,
                               struct silofs_strview       *out_sv);

void silofs_strview_nfind_token(const struct silofs_strview *sv,
                                const char *seps, size_t n,
                                struct silofs_strview *out_sv);

void silofs_strview_find_token_chr(const struct silofs_strview *sv, char sep,
                                   struct silofs_strview *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Finds the next token in sv after tok, which is delimited by any of the
 * characters of sep(s) */
void silofs_strview_find_next_token(const struct silofs_strview *sv,
                                    const struct silofs_strview *tok,
                                    const char                  *seps,
                                    struct silofs_strview       *out_sv);

void silofs_strview_nfind_next_token(const struct silofs_strview *sv,
                                     const struct silofs_strview *tok,
                                     const char *seps, size_t n,
                                     struct silofs_strview *out_sv);

void silofs_strview_find_next_token_chr(const struct silofs_strview *ss,
                                        const struct silofs_strview *tok,
                                        char sep, struct silofs_strview *out);

/* Parses sv into tokens, delimited by separators seps and inserts them into
 * tok_list. Inserts no more then list_size tokens.
 *
 * Returns 0 if all tokens assigned to tok_list, or -1 in case of insufficient
 * space. The number of parsed tokens is assigned into out_ntok.
 */
int silofs_strview_tokenize(const struct silofs_strview *sv, const char *seps,
                            struct silofs_strview tok_list[], size_t list_size,
                            size_t *out_ntok);

int silofs_strview_ntokenize(const struct silofs_strview *sv, const char *seps,
                             size_t n, struct silofs_strview tok_list[],
                             size_t list_size, size_t *out_ntok);

int silofs_strview_tokenize_chr(const struct silofs_strview *sv, char sep,
                                struct silofs_strview tok_list[],
                                size_t list_size, size_t *out_ntok);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Scans sv for the longest common prefix with s */
size_t
silofs_strview_common_prefix(const struct silofs_strview *sv, const char *s);
size_t silofs_strview_ncommon_prefix(const struct silofs_strview *sv,
                                     const char *s, size_t n);

/* Return TRUE if the first character of ss equals c */
bool silofs_strview_starts_with(const struct silofs_strview *sv, char c);

/* Scans sv backwards for the longest common suffix with s */
size_t
silofs_strview_common_suffix(const struct silofs_strview *sv, const char *s);
size_t silofs_strview_ncommon_suffix(const struct silofs_strview *sv,
                                     const char *s, size_t n);

/* Return TRUE if the last character of sv equals c */
int silofs_strview_ends_with(const struct silofs_strview *sv, char c);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic:
 */

/* Returns the index of the first element of sv that satisfy the unary
 * predicate fn (or !fn), or npos if no such element exist */
size_t silofs_strview_find_if(const struct silofs_strview *sv,
                              silofs_chr_testif_fn         fn);
size_t silofs_strview_find_if_not(const struct silofs_strview *sv,
                                  silofs_chr_testif_fn         fn);

/* Returns the index of the last element of sv that satisfy the unary
 * predicate fn (or !fn), or npos if no such element exist */
size_t silofs_strview_rfind_if(const struct silofs_strview *sv,
                               silofs_chr_testif_fn         fn);
size_t silofs_strview_rfind_if_not(const struct silofs_strview *sv,
                                   silofs_chr_testif_fn         fn);

/* Returns the number of elements in sv that satisfy the unary predicate fn */
size_t silofs_strview_count_if(const struct silofs_strview *sv,
                               silofs_chr_testif_fn         fn);

/* Returns TRUE if all characters of ss satisfy unary predicate fn */
bool silofs_strview_test_if(const struct silofs_strview *sv,
                            silofs_chr_testif_fn         fn);

/* Creates a sub-strview of sv without leading characters that satisfy unary
 * predicate fn */
void silofs_strview_trim_if(const struct silofs_strview *sv,
                            silofs_chr_testif_fn         fn,
                            struct silofs_strview       *out_sv);

/* Creates a sub-strview of sv without trailing characters that satisfy unary
 * predicate fn */
void silofs_strview_chop_if(const struct silofs_strview *sv,
                            silofs_chr_testif_fn         fn,
                            struct silofs_strview       *out_sv);

/* Creates a sub-strview of sv without any leading and trailing characters that
 * satisfy unary predicate fn */
void silofs_strview_strip_if(const struct silofs_strview *sv,
                             silofs_chr_testif_fn         fn,
                             struct silofs_strview       *out_sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Returns TRUE if all characters of sv satisfy ctype predicate */
bool silofs_strview_isalnum(const struct silofs_strview *sv);
bool silofs_strview_isalpha(const struct silofs_strview *sv);
bool silofs_strview_isascii(const struct silofs_strview *sv);
bool silofs_strview_isblank(const struct silofs_strview *sv);
bool silofs_strview_iscntrl(const struct silofs_strview *sv);
bool silofs_strview_isdigit(const struct silofs_strview *sv);
bool silofs_strview_isgraph(const struct silofs_strview *sv);
bool silofs_strview_islower(const struct silofs_strview *sv);
bool silofs_strview_isprint(const struct silofs_strview *sv);
bool silofs_strview_ispunct(const struct silofs_strview *sv);
bool silofs_strview_isspace(const struct silofs_strview *sv);
bool silofs_strview_isupper(const struct silofs_strview *sv);
bool silofs_strview_isxdigit(const struct silofs_strview *sv);

#endif /* SILOFS_STRVIEW_H_ */
