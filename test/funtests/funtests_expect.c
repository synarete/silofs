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
#include "funtests.h"
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <error.h>

static const char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

__attribute__((__noreturn__))
static void do_error_at_line(const char *fl, int ln, const char *fmt, ...)
{
	char msg[512] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	error_at_line(EXIT_FAILURE, 0,  basename_of(fl),
	              (uint32_t)ln, "failed: %s", msg);
	abort();
}

void ft_do_expect_cond(int cond, const char *s, const char *fl, int ln)
{
	if (!cond) {
		do_error_at_line(fl, ln, "'%s'", s);
	}
}

void ft_do_expect_ok(int err, const char *fl, int ln)
{
	if (err) {
		do_error_at_line(fl, ln, "bad status-code: %d", err);
	}
}

void ft_do_expect_eq(intmax_t a, intmax_t b, const char *fl, int ln)
{
	if (a != b) {
		do_error_at_line(fl, ln, "%ld != %ld", a, b);
	}
}

void ft_do_expect_ne(intmax_t a, intmax_t b, const char *fl, int ln)
{
	if (a == b) {
		do_error_at_line(fl, ln, "%ld == %ld", a, b);
	}
}

void ft_do_expect_lt(intmax_t a, intmax_t b, const char *fl, int ln)
{
	if (a >= b) {
		do_error_at_line(fl, ln, "%ld >= %ld", a, b);
	}
}

void ft_do_expect_le(intmax_t a, intmax_t b, const char *fl, int ln)
{
	if (a > b) {
		do_error_at_line(fl, ln, "%ld > %ld", a, b);
	}
}

void ft_do_expect_gt(intmax_t a, intmax_t b, const char *fl, int ln)
{
	if (a <= b) {
		do_error_at_line(fl, ln, "%ld <= %ld", a, b);
	}
}

void ft_do_expect_ge(intmax_t a, intmax_t b, const char *fl, int ln)
{
	if (a < b) {
		do_error_at_line(fl, ln, "%ld < %ld", a, b);
	}
}

static size_t ft_memdif_at(const uint8_t *p, const uint8_t *q, size_t n)
{
	size_t pos = 0;

	for (size_t i = 0; i < n; ++i) {
		if (p[i] != q[i]) {
			break;
		}
		pos++;
	}
	return pos;
}

void ft_do_expect_eqm(const void *p, const void *q, size_t n,
                      const char *fl, int ln)
{
	const int cmp = ft_memcmp(p, q, n);

	if (cmp != 0) {
		const size_t pos = ft_memdif_at(p, q, n);

		do_error_at_line(fl, ln, "not equal mem: cmp=%d pos=%zu",
		                 cmp, pos);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_expect_st_dir(const struct stat *st, const char *fl, int ln)
{
	const mode_t mode = st->st_mode;

	if (!S_ISDIR(mode)) {
		do_error_at_line(fl, ln, "not a directory: mode=0%o", mode);
	}
}

void ft_do_expect_st_reg(const struct stat *st, const char *fl, int ln)
{
	const mode_t mode = st->st_mode;

	if (!S_ISREG(mode)) {
		do_error_at_line(fl, ln, "not regular-file: mode=0%o", mode);
	}
}

void ft_do_expect_st_lnk(const struct stat *st, const char *fl, int ln)
{
	const mode_t mode = st->st_mode;

	if (!S_ISLNK(mode)) {
		do_error_at_line(fl, ln, "not a symlink: mode=0%o", mode);
	}
}

void ft_do_expect_st_fifo(const struct stat *st, const char *fl, int ln)
{
	const mode_t mode = st->st_mode;

	if (!S_ISFIFO(mode)) {
		do_error_at_line(fl, ln, "not a fifo: mode=0%o", mode);
	}
}

void ft_do_expect_st_mtime_eq(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln)
{
	const long dif = ft_timespec_diff(&st1->st_mtim, &st2->st_mtim);

	if (dif != 0) {
		do_error_at_line(fl, ln, "mtime not equal: dif=%ld", dif);
	}
}

void ft_do_expect_st_mtime_gt(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln)
{
	const long dif = ft_timespec_diff(&st1->st_mtim, &st2->st_mtim);

	if (dif <= 0) {
		do_error_at_line(fl, ln, "mtime not greater: dif=%ld", dif);
	}
}

void ft_do_expect_st_ctime_eq(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln)
{
	const long dif = ft_timespec_diff(&st1->st_ctim, &st2->st_ctim);

	if (dif != 0) {
		do_error_at_line(fl, ln, "ctime not equal: dif=%ld", dif);
	}
}

void ft_do_expect_st_ctime_gt(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln)
{
	const long dif = ft_timespec_diff(&st1->st_ctim, &st2->st_ctim);

	if (dif <= 0) {
		do_error_at_line(fl, ln, "ctime not greater: dif=%ld", dif);
	}
}

void ft_do_expect_st_ctime_ge(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln)
{
	const long dif = ft_timespec_diff(&st1->st_ctim, &st2->st_ctim);

	if (dif < 0) {
		do_error_at_line(fl, ln, "ctime not greater-or-equal: "
		                 "dif=%ld", dif);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_expect_sys_ok(int err, const char *sc, const char *fl, int ln)
{
	if (err != 0) {
		do_error_at_line(fl, ln, "not ok: %s ==> %d", sc, err);
	}
}

void ft_do_expect_sys_err(int err, int exp, const char *sc,
                          const char *fl, int ln)
{
	if (err != exp) {
		do_error_at_line(fl, ln, "unexpected status-code: "
		                 "%s ==> %d (!%d)", sc, err, exp);
	}
}
