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
#ifndef SILOFS_FUNTESTS_EXPECT_H_
#define SILOFS_FUNTESTS_EXPECT_H_

#include <stdint.h>

#define ft_expect_true(cond_) \
	ft_do_expect_cond((cond_), FT_STR(cond_), FT_FL_LN_)

#define ft_expect_false(cond_) \
	ft_do_expect_cond(!(cond_), FT_STR(!cond_), FT_FL_LN_)

#define ft_expect_ok(err_) ft_do_expect_ok(err_, FT_FL_LN_)

#define ft_expect_eq(a_, b_) \
	ft_do_expect_eq((intmax_t)(a_), (intmax_t)(b_), FT_FL_LN_)

#define ft_expect_ne(a_, b_) \
	ft_do_expect_ne((intmax_t)(a_), (intmax_t)(b_), FT_FL_LN_)

#define ft_expect_lt(a_, b_) \
	ft_do_expect_lt((intmax_t)(a_), (intmax_t)(b_), FT_FL_LN_)

#define ft_expect_le(a_, b_) \
	ft_do_expect_le((intmax_t)(a_), (intmax_t)(b_), FT_FL_LN_)

#define ft_expect_gt(a_, b_) \
	ft_do_expect_gt((intmax_t)(a_), (intmax_t)(b_), FT_FL_LN_)

#define ft_expect_ge(a_, b_) \
	ft_do_expect_ge((intmax_t)(a_), (intmax_t)(b_), FT_FL_LN_)

#define ft_expect_eqm(a_, b_, n_) ft_do_expect_eqm(a_, b_, n_, FT_FL_LN_)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define ft_expect_st_dir(st_) ft_do_expect_st_dir(st_, FT_FL_LN_)

#define ft_expect_st_reg(st_) ft_do_expect_st_reg(st_, FT_FL_LN_)

#define ft_expect_st_lnk(st_) ft_do_expect_st_lnk(st_, FT_FL_LN_)

#define ft_expect_st_fifo(st_) ft_do_expect_st_fifo(st_, FT_FL_LN_)

#define ft_expect_st_mtime_eq(st1_, st2_) \
	ft_do_expect_st_mtime_eq(st1_, st2_, FT_FL_LN_)

#define ft_expect_st_mtime_gt(st1_, st2_) \
	ft_do_expect_st_mtime_gt(st1_, st2_, FT_FL_LN_)

#define ft_expect_st_ctime_eq(st1_, st2_) \
	ft_do_expect_st_ctime_eq(st1_, st2_, FT_FL_LN_)

#define ft_expect_st_ctime_gt(st1_, st2_) \
	ft_do_expect_st_ctime_gt(st1_, st2_, FT_FL_LN_)

#define ft_expect_st_ctime_ge(st1_, st2_) \
	ft_do_expect_st_ctime_ge(st1_, st2_, FT_FL_LN_)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define ft_expect_ts_eq(t1, t2) ft_expect_eq(ft_timespec_diff(t1, t2), 0)

#define ft_expect_ts_gt(t1, t2) ft_expect_gt(ft_timespec_diff(t1, t2), 0)

#define ft_expect_ts_ge(t1, t2) ft_expect_ge(ft_timespec_diff(t1, t2), 0)

#define ft_expect_xts_eq(xt1, xt2) \
	ft_expect_eq(ft_xtimestamp_diff(xt1, xt2), 0)

#define ft_expect_xts_gt(xt1, xt2) \
	ft_expect_gt(ft_xtimestamp_diff(xt1, xt2), 0)

#define ft_expect_xts_ge(xt1, xt2) \
	ft_expect_ge(ft_xtimestamp_diff(xt1, xt2), 0)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_expect_cond(int cond, const char *s, const char *fl, int ln);

void ft_do_expect_ok(int err, const char *fl, int ln);

void ft_do_expect_eq(long a, long b, const char *fl, int ln);

void ft_do_expect_ne(intmax_t a, intmax_t b, const char *fl, int ln);

void ft_do_expect_lt(intmax_t a, intmax_t b, const char *fl, int ln);

void ft_do_expect_le(intmax_t a, intmax_t b, const char *fl, int ln);

void ft_do_expect_gt(intmax_t a, intmax_t b, const char *fl, int ln);

void ft_do_expect_ge(intmax_t a, intmax_t b, const char *fl, int ln);

void ft_do_expect_eqm(const void *p, const void *q, size_t n, const char *fl,
                      int ln);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_expect_st_dir(const struct stat *st, const char *fl, int ln);

void ft_do_expect_st_reg(const struct stat *st, const char *fl, int ln);

void ft_do_expect_st_lnk(const struct stat *st, const char *fl, int ln);

void ft_do_expect_st_fifo(const struct stat *st, const char *fl, int ln);

void ft_do_expect_st_mtime_eq(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln);

void ft_do_expect_st_mtime_gt(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln);

void ft_do_expect_st_ctime_eq(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln);

void ft_do_expect_st_ctime_gt(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln);

void ft_do_expect_st_ctime_ge(const struct stat *st1, const struct stat *st2,
                              const char *fl, int ln);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_expect_sys_ok(int err, const char *sc, const char *fl, int ln);

void ft_do_expect_sys_err(int err, int exp, const char *sc, const char *fl,
                          int ln);

#endif /* SILOFS_FUNTESTS_EXPECT_H_ */
