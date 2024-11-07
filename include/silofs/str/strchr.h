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
#ifndef SILOFS_STRCHR_H_
#define SILOFS_STRCHR_H_

#include <stddef.h>
#include <stdbool.h>

typedef bool (*silofs_chr_testif_fn)(char);
typedef void (*silofs_chr_modify_fn)(char *);


/*
 * Returns the number of characters in s before the first null character.
 */
size_t silofs_str_length(const char *s);

/*
 * Three way lexicographic compare of two characters-arrays.
 */
int silofs_str_compare(const char *s1, const char *s2, size_t n);
int silofs_str_ncompare(const char *s1, size_t n1,
                        const char *s2, size_t n2);

/*
 * Returns the first occurrence of s2 as a strspaning of s1, or null if no such
 * strspaning.
 */
const char *silofs_str_find(const char *s1, size_t n1,
                            const char *s2, size_t n2);


/*
 * Returns the last occurrence of s2 as strspaning of s1.
 */
const char *silofs_str_rfind(const char *s1, size_t n1,
                             const char *s2, size_t n2);


const char *silofs_str_find_chr(const char *s, size_t n, char a);


/*
 * Returns the last occurrence of c within the first n characters of s
 */
const char *silofs_str_rfind_chr(const char *s, size_t n, char c);

/*
 * Returns the first occurrence of any of the characters of s2 in s1.
 */
const char *silofs_str_find_first_of(const char *s1, size_t n1,
                                     const char *s2, size_t n2);

/*
 * Returns the first occurrence of any of the char of s2 which is not in s1.
 */
const char *
silofs_str_find_first_not_of(const char *s1, size_t n1,
                             const char *s2, size_t n2);

/*
 * Returns the first character in s which is not equal to c.
 */
const char *silofs_str_find_first_not_eq(const char *s, size_t n, char c);

/*
 * Returns the last occurrence of any of the characters of s2 within the first
 * n1 characters of s1.
 */
const char *silofs_str_find_last_of(const char *s1, size_t n1,
                                    const char *s2, size_t n2);

/*
 * Returns the last occurrence of any of the characters of s2 which is not in
 * the first n1 characters of s1.
 */
const char *
silofs_str_find_last_not_of(const char *s1, size_t n1,
                            const char *s2, size_t n2);

/*
 * Returns the last character within the first n characters of s which is not
 * equal to c.
 */
const char *
silofs_str_find_last_not_eq(const char *s, size_t n, char c);

/*
 * Returns the number of matching equal characters from the first n characters
 * of s1 and s2.
 */
size_t silofs_str_common_prefix(const char *s1, const char *s2, size_t n);

/*
 * Returns the number of matching equal characters from the last n characters
 * of s1 and s2.
 */
size_t silofs_str_common_suffix(const char *s1, const char *s2, size_t n);


/*
 * Returns the number of of characters from the first n1 elements of s1 that
 * overlaps any of the characters of the first n2 elements of s2.
 */
__attribute__((const))
size_t silofs_str_overlaps(const char *s1, size_t n1,
                           const char *s2, size_t n2);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Copy the first n characters of s into p. In case of overlap, uses safe copy.
 */
void silofs_str_copy(char *t, const char *s, size_t n);


/*
 * Assigns n copies of c to the first n elements of s.
 */
void silofs_str_fill(char *s, size_t n, char c);

/*
 * Assign EOS character ('\0') in s[n]
 */
void silofs_str_terminate(char *s, size_t n);

/*
 * Revere the order of characters in s.
 */
void silofs_str_reverse(char *s, size_t n);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Inserts the first n2 characters of s to in front of the first n1 characters
 * of p. In case of insufficient buffer-size, the result string is truncated.
 *
 * p   Target buffer
 * sz  Size of buffer: number of writable elements after p.
 * n1  Number of chars already inp (must be less or equal to sz)
 * s   Source string (may overlap any of the characters of p)
 * n2  Number of chars in s
 *
 * Returns the number of characters in p after insertion (always less or equal
 * to sz).
 */
size_t silofs_str_insert(char *p, size_t sz, size_t n1,
                         const char *s, size_t n2);


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
size_t silofs_str_insert_chr(char *p, size_t sz,
                             size_t n1, size_t n2, char c);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Replaces the first n1 characters of p with the first n2 characters of s.
 *
 * p   Target buffer
 * sz  Size of buffer: number of writable elements after p.
 * len Length of current string in p.
 * n1  Number of chars to replace (must be less or equal to len).
 * s   Source string (may overlap any of the characters of p)
 * n2  Number of chars in s
 *
 * Returns the number of characters in p after replacement (always less or
 * equal to sz).
 */
size_t silofs_str_replace(char *p, size_t sz, size_t len, size_t n1,
                          const char *s, size_t n2);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Replace the first n2 characters of p with n2 copies of c.
 *
 * Returns the number of characters in p after replacement (always less or
 * equal to sz).
 */
size_t silofs_str_replace_chr(char *p, size_t sz, size_t len,
                              size_t n1, size_t n2, char c);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Char-Traits Functions:
 */
bool silofs_chr_isalnum(char c);
bool silofs_chr_isalpha(char c);
bool silofs_chr_isascii(char c);
bool silofs_chr_isblank(char c);
bool silofs_chr_iscntrl(char c);
bool silofs_chr_isdigit(char c);
bool silofs_chr_isgraph(char c);
bool silofs_chr_islower(char c);
bool silofs_chr_isprint(char c);
bool silofs_chr_ispunct(char c);
bool silofs_chr_isspace(char c);
bool silofs_chr_isupper(char c);
bool silofs_chr_isxdigit(char c);

int silofs_chr_toupper(char c);
int silofs_chr_tolower(char c);

#endif /* SILOFS_STRCHR_H_ */
