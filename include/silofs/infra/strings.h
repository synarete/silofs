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
#ifndef SILOFS_STRINGS_H_
#define SILOFS_STRINGS_H_

#include <stddef.h>
#include <stdbool.h>


/*
 * Sub-string: reference to characters-array. When nwr is zero, referring to
 * immutable (read-only) string. In all cases, never overlap writable region.
 * All possible dynamic-allocation must be made explicitly by the user.
 */
struct silofs_substr {
	char  *str; /* Beginning of characters-array (rd & wr)    */
	size_t len; /* Number of readable chars (string's length) */
	size_t nwr; /* Number of writable chars from beginning    */
};

struct silofs_substr_pair {
	struct silofs_substr first, second;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Returns the largest possible size a sub-string may have.
 */
size_t silofs_substr_max_size(void);

/*
 * "Not-a-pos" (synonym to silofs_substr_max_size())
 */
size_t silofs_substr_npos(void);


/*
 * Constructors:
 * The first two create read-only substrings, the next two creates a mutable
 * (for write) substring. The last one creates read-only empty string.
 */
void silofs_substr_init(struct silofs_substr *ss, const char *str);
void silofs_substr_init_rd(struct silofs_substr *ss, const char *s, size_t n);
void silofs_substr_init_rwa(struct silofs_substr *ss, char *);
void silofs_substr_init_rw(struct silofs_substr *ss, char *, size_t nrd,
                           size_t nwr);
void silofs_substr_inits(struct silofs_substr *ss);

/*
 * Shallow-copy constructor (without deep copy).
 */
void silofs_substr_clone(const struct silofs_substr *ss,
                         struct silofs_substr *other);

/*
 * Destructor: zero all
 */
void silofs_substr_destroy(struct silofs_substr *ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Returns the string's read-length. Synonym to ss->len.
 */
size_t silofs_substr_size(const struct silofs_substr *ss);

/*
 * Returns the writable-size of sub-string.
 */
size_t silofs_substr_wrsize(const struct silofs_substr *ss);

/*
 * Returns TRUE if sub-string's length is zero.
 */
bool silofs_substr_isempty(const struct silofs_substr *ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Returns an iterator pointing to the beginning of the characters sequence.
 */
const char *silofs_substr_begin(const struct silofs_substr *ss);

/*
 * Returns an iterator pointing to the end of the characters sequence.
 */
const char *silofs_substr_end(const struct silofs_substr *ss);

/*
 * Returns the number of elements between begin() and p. If p is out-of-range,
 * returns npos.
 */
size_t silofs_substr_offset(const struct silofs_substr *ss, const char *p);

/*
 * Returns pointer to the n'th character. Performs out-of-range check:
 * panics in case n is out of range.
 */
const char *silofs_substr_at(const struct silofs_substr *ss, size_t n);

/*
 * Returns TRUE if ss->ss_str[i] is a valid substring-index (i < s->ss_len).
 */
int silofs_substr_isvalid_index(const struct silofs_substr *ss, size_t i);


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
size_t silofs_substr_copyto(const struct silofs_substr *ss, char *buf,
                            size_t n);

/*
 * Three-way lexicographical comparison
 */
int silofs_substr_compare(const struct silofs_substr *ss, const char *s);
int silofs_substr_ncompare(const struct silofs_substr *ss, const char *s,
                           size_t n);

/*
 * Returns TRUE in case of equal size and equal data
 */
bool silofs_substr_isequal(const struct silofs_substr *ss, const char *s);
bool silofs_substr_nisequal(const struct silofs_substr *ss,
                            const char *s, size_t n);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Returns the number of (non-overlapping) occurrences of s (or c) as a
 * substring of ss.
 */
size_t silofs_substr_count(const struct silofs_substr *ss, const char *s);
size_t silofs_substr_ncount(const struct silofs_substr *ss,
                            const char *s, size_t n);
size_t silofs_substr_count_chr(const struct silofs_substr *ss, char c);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Searches ss, beginning at position pos, for the first occurrence of s (or
 * single-character c). If search fails, returns npos.
 */
size_t silofs_substr_find(const struct silofs_substr *ss, const char *str);
size_t silofs_substr_nfind(const struct silofs_substr *ss,
                           size_t pos, const char *s, size_t n);
size_t silofs_substr_find_chr(const struct silofs_substr *ss, size_t pos,
                              char c);


/*
 * Searches ss backwards, beginning at position pos, for the last occurrence of
 * s (or single-character c). If search fails, returns npos.
 */
size_t silofs_substr_rfind(const struct silofs_substr *ss, const char *s);
size_t silofs_substr_nrfind(const struct silofs_substr *ss,
                            size_t pos, const char *s, size_t n);
size_t silofs_substr_rfind_chr(const struct silofs_substr *ss,
                               size_t pos, char c);


/*
 * Searches ss, beginning at position pos, for the first character that is
 * equal to any one of the characters of s.
 */
size_t silofs_substr_find_first_of(const struct silofs_substr *ss,
                                   const char *s);
size_t silofs_substr_nfind_first_of(const struct silofs_substr *ss,
                                    size_t pos, const char *s, size_t n);


/*
 * Searches ss backwards, beginning at position pos, for the last character
 * that is equal to any of the characters of s.
 */
size_t silofs_substr_find_last_of(const struct silofs_substr *ss,
                                  const char *s);
size_t silofs_substr_nfind_last_of(const struct silofs_substr *ss,
                                   size_t pos, const char *s, size_t n);


/*
 * Searches ss, beginning at position pos, for the first character that is not
 * equal to any of the characters of s.
 */
size_t silofs_substr_find_first_not_of(const struct silofs_substr *ss,
                                       const char *s);
size_t silofs_substr_nfind_first_not_of(const struct silofs_substr *ss,
                                        size_t pos, const char *s, size_t n);
size_t silofs_substr_find_first_not(const struct silofs_substr *ss,
                                    size_t pos, char c);



/*
 * Searches ss backwards, beginning at position pos, for the last character
 * that is not equal to any of the characters of s (or c).
 */
size_t silofs_substr_find_last_not_of(const struct silofs_substr *ss,
                                      const char *s);
size_t silofs_substr_nfind_last_not_of(const struct silofs_substr *ss,
                                       size_t pos, const char *s, size_t n);
size_t silofs_substr_find_last_not(const struct silofs_substr *ss,
                                   size_t pos, char c);



/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a substring of ss, which refers to n characters after position i.
 * If i is an invalid index, the result substring is empty. If there are less
 * then n characters after position i, the result substring will refer only to
 * the elements which are members of ss.
 */
void silofs_substr_sub(const struct silofs_substr *ss,
                       size_t i, size_t n,  struct silofs_substr *out_ss);

/*
 * Creates a substring of ss, which refers to the last n chars. The result
 * substring will not refer to more then ss->ss_len elements.
 */
void silofs_substr_rsub(const struct silofs_substr *ss,
                        size_t n, struct silofs_substr *out_ss);

/*
 * Creates a substring with all the characters that are in the range of
 * both s1 and s2. That is, all elements within the range
 * [s1.begin(),s1.end()) which are also in the range
 * [s2.begin(), s2.end()) (i.e. have the same address).
 */
void silofs_substr_intersection(const struct silofs_substr *s1,
                                const struct silofs_substr *s2,
                                struct silofs_substr *out_ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Creates a pair of substrings of ss, which are divided by any of the first
 * characters of seps. If none of the characters of seps is in ss, the first
 * first element of the result-pair is equal to ss and the second element is an
 * empty substring.
 *
 *  Examples:
 *  split("root@foo//bar", "/@:")  --> "root", "foo//bar"
 *  split("foo///:bar::zoo", ":/") --> "foo", "bar:zoo"
 *  split("root@foo.bar", ":/")    --> "root@foo.bar", ""
 */
void silofs_substr_split(const struct silofs_substr *ss, const char *seps,
                         struct silofs_substr_pair *out_ss_pair);

void silofs_substr_nsplit(const struct silofs_substr *ss,
                          const char *seps, size_t n,
                          struct silofs_substr_pair *out_ss_pair);

void silofs_substr_split_chr(const struct silofs_substr *ss, char sep,
                             struct silofs_substr_pair *out_ss_pair);

void silofs_substr_split_str(const struct silofs_substr *ss, const char *str,
                             struct silofs_substr_pair *out_ss_pair);


/*
 * Creates a pair of substrings of ss, which are divided by any of the first n
 * characters of seps, while searching ss backwards. If none of the characters
 * of seps is in ss, the first element of the pair equal to ss and the second
 * element is an empty substring.
 */
void silofs_substr_rsplit(const struct silofs_substr *ss, const char *seps,
                          struct silofs_substr_pair *out_ss_pair);

void silofs_substr_nrsplit(const struct silofs_substr *ss,
                           const char *seps, size_t n,
                           struct silofs_substr_pair *out_ss_pair);

void silofs_substr_rsplit_chr(const struct silofs_substr *ss, char sep,
                              struct silofs_substr_pair *out_ss_pair);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Creates a substring of ss without the first n leading characters.
 */
void silofs_substr_trim(const struct silofs_substr *ss, size_t n,
                        struct silofs_substr *out_ss);


/*
 * Creates a substring of ss without any leading characters which are members
 * of set.
 */
void silofs_substr_trim_any_of(const struct silofs_substr *ss, const char *set,
                               struct silofs_substr *out_ss);

void silofs_substr_ntrim_any_of(const struct silofs_substr *ss,
                                const char *set, size_t n,
                                struct silofs_substr *out_ss);

void silofs_substr_trim_chr(const struct silofs_substr *ss, char c,
                            struct silofs_substr *out_ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a substring of ss without the last n trailing characters.
 * If n >= ss->ss_len the result substring is empty.
 */
void silofs_substr_chop(const struct silofs_substr *ss, size_t n,
                        struct silofs_substr *);

/*
 * Creates a substring of ss without any trailing characters which are members
 * of set.
 */
void silofs_substr_chop_any_of(const struct silofs_substr *ss,
                               const char *set, struct silofs_substr *out_ss);

void silofs_substr_nchop_any_of(const struct silofs_substr *ss,
                                const char *set, size_t n,
                                struct silofs_substr *out_ss);

/*
 * Creates a substring of ss without any trailing characters that equals c.
 */

void silofs_substr_chop_chr(const struct silofs_substr *ss, char c,
                            struct silofs_substr *out_ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Creates a substring of ss without any leading and trailing characters which
 * are members of set.
 */
void silofs_substr_strip_any_of(const struct silofs_substr *ss,
                                const char *set, struct silofs_substr *result);

void silofs_substr_nstrip_any_of(const struct silofs_substr *ss,
                                 const char *set, size_t n,
                                 struct silofs_substr *result);

/*
 * Creates a substring of substr without any leading and trailing
 * characters which are equal to c.
 */
void silofs_substr_strip_chr(const struct silofs_substr *ss, char c,
                             struct silofs_substr *result);


/*
 * Strip white-spaces
 */
void silofs_substr_strip_ws(const struct silofs_substr *ss,
                            struct silofs_substr *out_ss);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Finds the first substring of ss that is a token delimited by any of the
 * characters of sep(s).
 */
void silofs_substr_find_token(const struct silofs_substr *ss,
                              const char *seps, struct silofs_substr *result);

void silofs_substr_nfind_token(const struct silofs_substr *ss,
                               const char *seps, size_t n,
                               struct silofs_substr *result);

void silofs_substr_find_token_chr(const struct silofs_substr *ss, char sep,
                                  struct silofs_substr *result);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Finds the next token in ss after tok, which is delimited by any of the
 * characters of sep(s).
 */

void silofs_substr_find_next_token(const struct silofs_substr *ss,
                                   const struct silofs_substr *tok,
                                   const char *seps,
                                   struct silofs_substr *out_ss);

void silofs_substr_nfind_next_token(const struct silofs_substr *ss,
                                    const struct silofs_substr *tok,
                                    const char *seps, size_t n,
                                    struct silofs_substr *result);

void silofs_substr_find_next_token_chr(const struct silofs_substr *ss,
                                       const struct silofs_substr *tok,
                                       char sep, struct silofs_substr *out_ss);

/*
 * Parses the substring ss into tokens, delimited by separators seps and
 * inserts them into tok_list. Inserts no more then max_sz tokens.
 *
 * Returns 0 if all tokens assigned to tok_list, or -1 in case of insufficient
 * space. If p_ntok is not NULL it is set to the number of parsed tokens.
 */
int silofs_substr_tokenize(const struct silofs_substr *ss, const char *seps,
                           struct silofs_substr tok_list[], size_t list_size,
                           size_t *out_ntok);

int silofs_substr_ntokenize(const struct silofs_substr *ss,
                            const char *seps, size_t n,
                            struct silofs_substr tok_list[],
                            size_t list_size, size_t *out_ntok);

int silofs_substr_tokenize_chr(const struct silofs_substr *ss, char sep,
                               struct silofs_substr tok_list[],
                               size_t list_size, size_t *out_ntok);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Scans ss for the longest common prefix with s.
 */
size_t silofs_substr_common_prefix(const struct silofs_substr *ss,
                                   const char *str);
size_t silofs_substr_ncommon_prefix(const struct silofs_substr *ss,
                                    const char *s, size_t n);

/*
 * Return TRUE if the first character of ss equals c.
 */
bool silofs_substr_starts_with(const struct silofs_substr *ss, char c);


/*
 * Scans ss backwards for the longest common suffix with s.
 */
size_t silofs_substr_common_suffix(const struct silofs_substr *ss,
                                   const char *s);
size_t silofs_substr_ncommon_suffix(const struct silofs_substr *ss,
                                    const char *s, size_t n);

/*
 * Return TRUE if the last character of ss equals c.
 */
int silofs_substr_ends_with(const struct silofs_substr *ss, char c);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 *  Returns pointer to beginning of characters sequence.
 */
char *silofs_substr_data(const struct silofs_substr *ss);

/*
 * Assigns s, truncates result in case of insufficient room.
 */
void silofs_substr_assign(struct silofs_substr *ss, const char *s);
void silofs_substr_nassign(struct silofs_substr *ss, const char *s,
                           size_t len);

/*
 * Assigns n copies of c.
 */
void silofs_substr_assign_chr(struct silofs_substr *ss, size_t n, char c);


/*
 * Appends s.
 */
void silofs_substr_append(struct silofs_substr *ss, const char *s);
void silofs_substr_nappend(struct silofs_substr *ss, const char *s,
                           size_t len);

/*
 * Appends n copies of c.
 */
void silofs_substr_append_chr(struct silofs_substr *ss, size_t n, char c);

/*
 * Appends single char.
 */
void silofs_substr_push_back(struct silofs_substr *ss, char c);

/*
 * Inserts s before position pos.
 */
void silofs_substr_insert(struct silofs_substr *ss, size_t pos, const char *s);
void silofs_substr_ninsert(struct silofs_substr *ss,
                           size_t pos, const char *s, size_t len);

/*
 * Inserts n copies of c before position pos.
 */
void silofs_substr_insert_chr(struct silofs_substr *ss,
                              size_t pos, size_t n, char c);

/*
 * Replaces a part of sub-string with the string s.
 */
void silofs_substr_replace(struct silofs_substr *ss,
                           size_t pos, size_t n, const char *s);
void silofs_substr_nreplace(struct silofs_substr *ss,
                            size_t pos, size_t n, const char *s, size_t len);

/*
 * Replaces part of sub-string with n2 copies of c.
 */
void silofs_substr_replace_chr(struct silofs_substr *ss,
                               size_t pos, size_t n1, size_t n2, char c);


/*
 * Erases part of sub-string.
 */
void silofs_substr_erase(struct silofs_substr *ss, size_t pos, size_t n);

/*
 * Reverse the writable portion of sub-string.
 */
void silofs_substr_reverse(struct silofs_substr *ss);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic:
 */

/*
 * Returns the index of the first element of ss that satisfy the unary
 * predicate fn (or !fn), or npos if no such element exist.
 */
size_t silofs_substr_find_if(const struct silofs_substr *ss,
                             silofs_chr_testif_fn fn);
size_t silofs_substr_find_if_not(const struct silofs_substr *ss,
                                 silofs_chr_testif_fn fn);


/*
 * Returns the index of the last element of ss that satisfy the unary
 * predicate fn (or !fn), or npos if no such element exist.
 */
size_t silofs_substr_rfind_if(const struct silofs_substr *ss,
                              silofs_chr_testif_fn fn);
size_t silofs_substr_rfind_if_not(const struct silofs_substr *ss,
                                  silofs_chr_testif_fn fn);

/*
 * Returns the number of elements in ss that satisfy the unary predicate fn.
 */
size_t silofs_substr_count_if(const struct silofs_substr *ss,
                              silofs_chr_testif_fn fn);

/*
 * Returns TRUE if all characters of ss satisfy unary predicate fn.
 */
bool silofs_substr_test_if(const struct silofs_substr *ss,
                           silofs_chr_testif_fn fn);


/*
 * Creates a substring of ss without leading characters that satisfy unary
 * predicate fn.
 */
void silofs_substr_trim_if(const struct silofs_substr *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_substr *out_ss);

/*
 * Creates a substring of ss without trailing characters that satisfy unary
 * predicate fn.
 */
void silofs_substr_chop_if(const struct silofs_substr *ss,
                           silofs_chr_testif_fn fn,
                           struct silofs_substr *out_ss);

/*
 * Creates a substring of ss without any leading and trailing characters that
 * satisfy unary predicate fn.
 */
void silofs_substr_strip_if(const struct silofs_substr *ss,
                            silofs_chr_testif_fn fn,
                            struct silofs_substr *out_ss);


/*
 * Apply fn for every element in sub-string.
 */
void silofs_substr_foreach(struct silofs_substr *ss, silofs_chr_modify_fn fn);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Returns TRUE if all characters of ss satisfy ctype predicate.
 */
bool silofs_substr_isalnum(const struct silofs_substr *ss);
bool silofs_substr_isalpha(const struct silofs_substr *ss);
bool silofs_substr_isascii(const struct silofs_substr *ss);
bool silofs_substr_isblank(const struct silofs_substr *ss);
bool silofs_substr_iscntrl(const struct silofs_substr *ss);
bool silofs_substr_isdigit(const struct silofs_substr *ss);
bool silofs_substr_isgraph(const struct silofs_substr *ss);
bool silofs_substr_islower(const struct silofs_substr *ss);
bool silofs_substr_isprint(const struct silofs_substr *ss);
bool silofs_substr_ispunct(const struct silofs_substr *ss);
bool silofs_substr_isspace(const struct silofs_substr *ss);
bool silofs_substr_isupper(const struct silofs_substr *ss);
bool silofs_substr_isxdigit(const struct silofs_substr *ss);

/*
 * Case sensitive operations:
 */
void silofs_substr_toupper(struct silofs_substr *ss);
void silofs_substr_tolower(struct silofs_substr *ss);
void silofs_substr_capitalize(struct silofs_substr *ss);

#endif /* SILOFS_STRINGS_H_ */
