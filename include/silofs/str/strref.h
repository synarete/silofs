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
#ifndef SILOFS_STRREF_H_
#define SILOFS_STRREF_H_

#include <stddef.h>
#include <stdbool.h>


/*
 * Sub-string: reference to characters-array. When nwr is zero, referring to
 * immutable (read-only) string. In all cases, never overlap writable region.
 * All possible dynamic-allocation must be made explicitly by the user.
 */
struct silofs_strref {
	char  *str; /* Beginning of characters-array (rd & wr)    */
	size_t len; /* Number of readable chars (string's length) */
	size_t nwr; /* Number of writable chars from beginning    */
};

struct silofs_strref_pair {
	struct silofs_strref first, second;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Returns the largest possible size a sub-string may have.
 */
size_t silofs_strref_max_size(void);

/*
 * "Not-a-pos" (synonym to silofs_strref_max_size())
 */
size_t silofs_strref_npos(void);


/*
 * Constructors:
 * The first two create read-only strrefings, the next two creates a mutable
 * (for write) strrefing. The last one creates read-only empty string.
 */
void silofs_strref_init(struct silofs_strref *ss, const char *str);
void silofs_strref_init_rd(struct silofs_strref *ss, const char *s, size_t n);
void silofs_strref_init_rwa(struct silofs_strref *ss, char *);
void silofs_strref_init_rw(struct silofs_strref *ss, char *, size_t nrd,
                           size_t nwr);
void silofs_strref_inits(struct silofs_strref *ss);

/*
 * Shallow-copy constructor (without deep copy).
 */
void silofs_strref_clone(const struct silofs_strref *ss,
                         struct silofs_strref *other);

/*
 * Destructor: zero all
 */
void silofs_strref_destroy(struct silofs_strref *ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Returns the string's read-length. Synonym to ss->len.
 */
size_t silofs_strref_size(const struct silofs_strref *ss);

/*
 * Returns the writable-size of sub-string.
 */
size_t silofs_strref_wrsize(const struct silofs_strref *ss);

/*
 * Returns TRUE if sub-string's length is zero.
 */
bool silofs_strref_isempty(const struct silofs_strref *ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Returns an iterator pointing to the beginning of the characters sequence.
 */
const char *silofs_strref_begin(const struct silofs_strref *ss);

/*
 * Returns an iterator pointing to the end of the characters sequence.
 */
const char *silofs_strref_end(const struct silofs_strref *ss);

/*
 * Returns the number of elements between begin() and p. If p is out-of-range,
 * returns npos.
 */
size_t silofs_strref_offset(const struct silofs_strref *ss, const char *p);

/*
 * Returns pointer to the n'th character. Performs out-of-range check:
 * panics in case n is out of range.
 */
const char *silofs_strref_at(const struct silofs_strref *ss, size_t n);

/*
 * Returns TRUE if ss->ss_str[i] is a valid strrefing-index (i < s->ss_len).
 */
int silofs_strref_isvalid_index(const struct silofs_strref *ss, size_t i);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 *  Copy data into buffer, return number of characters assigned. Assign
 *  no more than min(n, size()) bytes.
 *
 *  Returns the number of characters copied to buf, not including possible null
 *  termination character.
 *
 *  NB: Result buf will be null-terminated only if there is enough
 *          room (i.e. n > size()).
 */
size_t silofs_strref_copyto(const struct silofs_strref *ss, char *buf,
                            size_t n);

/*
 * Three-way lexicographical comparison
 */
int silofs_strref_compare(const struct silofs_strref *ss, const char *s);
int silofs_strref_ncompare(const struct silofs_strref *ss, const char *s,
                           size_t n);

/*
 * Returns TRUE in case of equal size and equal data
 */
bool silofs_strref_isequal(const struct silofs_strref *ss, const char *s);
bool silofs_strref_nisequal(const struct silofs_strref *ss,
                            const char *s, size_t n);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Returns the number of (non-overlapping) occurrences of s (or c) as a
 * strrefing of ss.
 */
size_t silofs_strref_count(const struct silofs_strref *ss, const char *s);
size_t silofs_strref_ncount(const struct silofs_strref *ss,
                            const char *s, size_t n);
size_t silofs_strref_count_chr(const struct silofs_strref *ss, char c);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Searches ss, beginning at position pos, for the first occurrence of s (or
 * single-character c). If search fails, returns npos.
 */
size_t silofs_strref_find(const struct silofs_strref *ss, const char *str);
size_t silofs_strref_nfind(const struct silofs_strref *ss,
                           size_t pos, const char *s, size_t n);
size_t silofs_strref_find_chr(const struct silofs_strref *ss, size_t pos,
                              char c);


/*
 * Searches ss backwards, beginning at position pos, for the last occurrence of
 * s (or single-character c). If search fails, returns npos.
 */
size_t silofs_strref_rfind(const struct silofs_strref *ss, const char *s);
size_t silofs_strref_nrfind(const struct silofs_strref *ss,
                            size_t pos, const char *s, size_t n);
size_t silofs_strref_rfind_chr(const struct silofs_strref *ss,
                               size_t pos, char c);


/*
 * Searches ss, beginning at position pos, for the first character that is
 * equal to any one of the characters of s.
 */
size_t silofs_strref_find_first_of(const struct silofs_strref *ss,
                                   const char *s);
size_t silofs_strref_nfind_first_of(const struct silofs_strref *ss,
                                    size_t pos, const char *s, size_t n);


/*
 * Searches ss backwards, beginning at position pos, for the last character
 * that is equal to any of the characters of s.
 */
size_t silofs_strref_find_last_of(const struct silofs_strref *ss,
                                  const char *s);
size_t silofs_strref_nfind_last_of(const struct silofs_strref *ss,
                                   size_t pos, const char *s, size_t n);


/*
 * Searches ss, beginning at position pos, for the first character that is not
 * equal to any of the characters of s.
 */
size_t silofs_strref_find_first_not_of(const struct silofs_strref *ss,
                                       const char *s);
size_t silofs_strref_nfind_first_not_of(const struct silofs_strref *ss,
                                        size_t pos, const char *s, size_t n);
size_t silofs_strref_find_first_not(const struct silofs_strref *ss,
                                    size_t pos, char c);



/*
 * Searches ss backwards, beginning at position pos, for the last character
 * that is not equal to any of the characters of s (or c).
 */
size_t silofs_strref_find_last_not_of(const struct silofs_strref *ss,
                                      const char *s);
size_t silofs_strref_nfind_last_not_of(const struct silofs_strref *ss,
                                       size_t pos, const char *s, size_t n);
size_t silofs_strref_find_last_not(const struct silofs_strref *ss,
                                   size_t pos, char c);



/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a strrefing of ss, which refers to n characters after position i.
 * If i is an invalid index, the result strrefing is empty. If there are less
 * then n characters after position i, the result strrefing will refer only to
 * the elements which are members of ss.
 */
void silofs_strref_sub(const struct silofs_strref *ss,
                       size_t i, size_t n,  struct silofs_strref *out_ss);

/*
 * Creates a strrefing of ss, which refers to the last n chars. The result
 * strrefing will not refer to more then ss->ss_len elements.
 */
void silofs_strref_rsub(const struct silofs_strref *ss,
                        size_t n, struct silofs_strref *out_ss);

/*
 * Creates a strrefing with all the characters that are in the range of
 * both s1 and s2. That is, all elements within the range
 * [s1.begin(),s1.end()) which are also in the range
 * [s2.begin(), s2.end()) (i.e. have the same address).
 */
void silofs_strref_intersection(const struct silofs_strref *s1,
                                const struct silofs_strref *s2,
                                struct silofs_strref *out_ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Creates a pair of strrefings of ss, which are divided by any of the first
 * characters of seps. If none of the characters of seps is in ss, the first
 * first element of the result-pair is equal to ss and the second element is an
 * empty strrefing.
 *
 *  Examples:
 *  split("root@foo//bar", "/@:")  --> "root", "foo//bar"
 *  split("foo///:bar::zoo", ":/") --> "foo", "bar:zoo"
 *  split("root@foo.bar", ":/")    --> "root@foo.bar", ""
 */
void silofs_strref_split(const struct silofs_strref *ss, const char *seps,
                         struct silofs_strref_pair *out_ss_pair);

void silofs_strref_nsplit(const struct silofs_strref *ss,
                          const char *seps, size_t n,
                          struct silofs_strref_pair *out_ss_pair);

void silofs_strref_split_chr(const struct silofs_strref *ss, char sep,
                             struct silofs_strref_pair *out_ss_pair);

void silofs_strref_split_str(const struct silofs_strref *ss, const char *str,
                             struct silofs_strref_pair *out_ss_pair);


/*
 * Creates a pair of strrefings of ss, which are divided by any of the first n
 * characters of seps, while searching ss backwards. If none of the characters
 * of seps is in ss, the first element of the pair equal to ss and the second
 * element is an empty strrefing.
 */
void silofs_strref_rsplit(const struct silofs_strref *ss, const char *seps,
                          struct silofs_strref_pair *out_ss_pair);

void silofs_strref_nrsplit(const struct silofs_strref *ss,
                           const char *seps, size_t n,
                           struct silofs_strref_pair *out_ss_pair);

void silofs_strref_rsplit_chr(const struct silofs_strref *ss, char sep,
                              struct silofs_strref_pair *out_ss_pair);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Creates a strrefing of ss without the first n leading characters.
 */
void silofs_strref_trim(const struct silofs_strref *ss, size_t n,
                        struct silofs_strref *out_ss);


/*
 * Creates a strrefing of ss without any leading characters which are members
 * of set.
 */
void silofs_strref_trim_any_of(const struct silofs_strref *ss, const char *set,
                               struct silofs_strref *out_ss);

void silofs_strref_ntrim_any_of(const struct silofs_strref *ss,
                                const char *set, size_t n,
                                struct silofs_strref *out_ss);

void silofs_strref_trim_chr(const struct silofs_strref *ss, char c,
                            struct silofs_strref *out_ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a strrefing of ss without the last n trailing characters.
 * If n >= ss->ss_len the result strrefing is empty.
 */
void silofs_strref_chop(const struct silofs_strref *ss, size_t n,
                        struct silofs_strref *);

/*
 * Creates a strrefing of ss without any trailing characters which are members
 * of set.
 */
void silofs_strref_chop_any_of(const struct silofs_strref *ss,
                               const char *set, struct silofs_strref *out_ss);

void silofs_strref_nchop_any_of(const struct silofs_strref *ss,
                                const char *set, size_t n,
                                struct silofs_strref *out_ss);

/*
 * Creates a strrefing of ss without any trailing characters that equals c.
 */

void silofs_strref_chop_chr(const struct silofs_strref *ss, char c,
                            struct silofs_strref *out_ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a strrefing of ss without any leading and trailing characters which
 * are members of set.
 */
void silofs_strref_strip_any_of(const struct silofs_strref *ss,
                                const char *set, struct silofs_strref *result);

void silofs_strref_nstrip_any_of(const struct silofs_strref *ss,
                                 const char *set, size_t n,
                                 struct silofs_strref *result);

/*
 * Creates a strrefing of strref without any leading and trailing
 * characters which are equal to c.
 */
void silofs_strref_strip_chr(const struct silofs_strref *ss, char c,
                             struct silofs_strref *result);


/*
 * Strip white-spaces
 */
void silofs_strref_strip_ws(const struct silofs_strref *ss,
                            struct silofs_strref *out_ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Finds the first strrefing of ss that is a token delimited by any of the
 * characters of sep(s).
 */
void silofs_strref_find_token(const struct silofs_strref *ss,
                              const char *seps, struct silofs_strref *result);

void silofs_strref_nfind_token(const struct silofs_strref *ss,
                               const char *seps, size_t n,
                               struct silofs_strref *result);

void silofs_strref_find_token_chr(const struct silofs_strref *ss, char sep,
                                  struct silofs_strref *result);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Finds the next token in ss after tok, which is delimited by any of the
 * characters of sep(s).
 */

void silofs_strref_find_next_token(const struct silofs_strref *ss,
                                   const struct silofs_strref *tok,
                                   const char *seps,
                                   struct silofs_strref *out_ss);

void silofs_strref_nfind_next_token(const struct silofs_strref *ss,
                                    const struct silofs_strref *tok,
                                    const char *seps, size_t n,
                                    struct silofs_strref *result);

void silofs_strref_find_next_token_chr(const struct silofs_strref *ss,
                                       const struct silofs_strref *tok,
                                       char sep, struct silofs_strref *out_ss);

/*
 * Parses the strrefing ss into tokens, delimited by separators seps and
 * inserts them into tok_list. Inserts no more then max_sz tokens.
 *
 * Returns 0 if all tokens assigned to tok_list, or -1 in case of insufficient
 * space. If p_ntok is not NULL it is set to the number of parsed tokens.
 */
int silofs_strref_tokenize(const struct silofs_strref *ss, const char *seps,
                           struct silofs_strref tok_list[], size_t list_size,
                           size_t *out_ntok);

int silofs_strref_ntokenize(const struct silofs_strref *ss,
                            const char *seps, size_t n,
                            struct silofs_strref tok_list[],
                            size_t list_size, size_t *out_ntok);

int silofs_strref_tokenize_chr(const struct silofs_strref *ss, char sep,
                               struct silofs_strref tok_list[],
                               size_t list_size, size_t *out_ntok);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Scans ss for the longest common prefix with s.
 */
size_t silofs_strref_common_prefix(const struct silofs_strref *ss,
                                   const char *str);
size_t silofs_strref_ncommon_prefix(const struct silofs_strref *ss,
                                    const char *s, size_t n);

/*
 * Return TRUE if the first character of ss equals c.
 */
bool silofs_strref_starts_with(const struct silofs_strref *ss, char c);


/*
 * Scans ss backwards for the longest common suffix with s.
 */
size_t silofs_strref_common_suffix(const struct silofs_strref *ss,
                                   const char *s);
size_t silofs_strref_ncommon_suffix(const struct silofs_strref *ss,
                                    const char *s, size_t n);

/*
 * Return TRUE if the last character of ss equals c.
 */
int silofs_strref_ends_with(const struct silofs_strref *ss, char c);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 *  Returns pointer to beginning of characters sequence.
 */
char *silofs_strref_data(const struct silofs_strref *ss);

/*
 * Assigns s, truncates result in case of insufficient room.
 */
void silofs_strref_assign(struct silofs_strref *ss, const char *s);
void silofs_strref_nassign(struct silofs_strref *ss, const char *s,
                           size_t len);

/*
 * Assigns n copies of c.
 */
void silofs_strref_assign_chr(struct silofs_strref *ss, size_t n, char c);


/*
 * Appends s.
 */
void silofs_strref_append(struct silofs_strref *ss, const char *s);
void silofs_strref_nappend(struct silofs_strref *ss, const char *s,
                           size_t len);

/*
 * Appends n copies of c.
 */
void silofs_strref_append_chr(struct silofs_strref *ss, size_t n, char c);

/*
 * Appends single char.
 */
void silofs_strref_push_back(struct silofs_strref *ss, char c);

/*
 * Inserts s before position pos.
 */
void silofs_strref_insert(struct silofs_strref *ss, size_t pos, const char *s);
void silofs_strref_ninsert(struct silofs_strref *ss,
                           size_t pos, const char *s, size_t len);

/*
 * Inserts n copies of c before position pos.
 */
void silofs_strref_insert_chr(struct silofs_strref *ss,
                              size_t pos, size_t n, char c);

/*
 * Replaces a part of sub-string with the string s.
 */
void silofs_strref_replace(struct silofs_strref *ss,
                           size_t pos, size_t n, const char *s);
void silofs_strref_nreplace(struct silofs_strref *ss,
                            size_t pos, size_t n, const char *s, size_t len);

/*
 * Replaces part of sub-string with n2 copies of c.
 */
void silofs_strref_replace_chr(struct silofs_strref *ss,
                               size_t pos, size_t n1, size_t n2, char c);


/*
 * Erases part of sub-string.
 */
void silofs_strref_erase(struct silofs_strref *ss, size_t pos, size_t n);

/*
 * Reverse the writable portion of sub-string.
 */
void silofs_strref_reverse(struct silofs_strref *ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic:
 */

/*
 * Returns the index of the first element of ss that satisfy the unary
 * predicate fn (or !fn), or npos if no such element exist.
 */
size_t silofs_strref_find_if(const struct silofs_strref *ss,
                             silofs_chr_testif_fn fn);
size_t silofs_strref_find_if_not(const struct silofs_strref *ss,
                                 silofs_chr_testif_fn fn);


/*
 * Returns the index of the last element of ss that satisfy the unary
 * predicate fn (or !fn), or npos if no such element exist.
 */
size_t silofs_strref_rfind_if(const struct silofs_strref *ss,
                              silofs_chr_testif_fn fn);
size_t silofs_strref_rfind_if_not(const struct silofs_strref *ss,
                                  silofs_chr_testif_fn fn);

/*
 * Returns the number of elements in ss that satisfy the unary predicate fn.
 */
size_t silofs_strref_count_if(const struct silofs_strref *ss,
                              silofs_chr_testif_fn fn);

/*
 * Returns TRUE if all characters of ss satisfy unary predicate fn.
 */
bool silofs_strref_test_if(const struct silofs_strref *ss,
                           silofs_chr_testif_fn fn);


/*
 * Creates a strrefing of ss without leading characters that satisfy unary
 * predicate fn.
 */
void silofs_strref_trim_if(const struct silofs_strref *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_strref *out_ss);

/*
 * Creates a strrefing of ss without trailing characters that satisfy unary
 * predicate fn.
 */
void silofs_strref_chop_if(const struct silofs_strref *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_strref *out_ss);

/*
 * Creates a strrefing of ss without any leading and trailing characters that
 * satisfy unary predicate fn.
 */
void silofs_strref_strip_if(const struct silofs_strref *ss,
                            silofs_chr_testif_fn fn,
                            struct silofs_strref *out_ss);


/*
 * Apply fn for every element in sub-string.
 */
void silofs_strref_foreach(struct silofs_strref *ss, silofs_chr_modify_fn fn);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Returns TRUE if all characters of ss satisfy ctype predicate.
 */
bool silofs_strref_isalnum(const struct silofs_strref *ss);
bool silofs_strref_isalpha(const struct silofs_strref *ss);
bool silofs_strref_isascii(const struct silofs_strref *ss);
bool silofs_strref_isblank(const struct silofs_strref *ss);
bool silofs_strref_iscntrl(const struct silofs_strref *ss);
bool silofs_strref_isdigit(const struct silofs_strref *ss);
bool silofs_strref_isgraph(const struct silofs_strref *ss);
bool silofs_strref_islower(const struct silofs_strref *ss);
bool silofs_strref_isprint(const struct silofs_strref *ss);
bool silofs_strref_ispunct(const struct silofs_strref *ss);
bool silofs_strref_isspace(const struct silofs_strref *ss);
bool silofs_strref_isupper(const struct silofs_strref *ss);
bool silofs_strref_isxdigit(const struct silofs_strref *ss);

/*
 * Case sensitive operations:
 */
void silofs_strref_toupper(struct silofs_strref *ss);
void silofs_strref_tolower(struct silofs_strref *ss);
void silofs_strref_capitalize(struct silofs_strref *ss);

#endif /* SILOFS_STRREF_H_ */
