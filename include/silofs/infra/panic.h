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
#ifndef SILOFS_PANIC_H_
#define SILOFS_PANIC_H_

#include <silofs/ccattr.h>

/*
 * TODO-0052: Define and use bug_on macros
 *
 * Define a set of complementary bug_on" macros to the "expect" one. Same logic
 * (though negative), but a meaningful naming within code itself.
 */

/* expect-or-die */
void silofs_expect_true_(int cond, const char *fl, int ln);
void silofs_expect_cond_(int cond, const char *str, const char *fl, int ln);
void silofs_expect_eq_(long a, long b, const char *fl, int ln);
void silofs_expect_ne_(long a, long b, const char *fl, int ln);
void silofs_expect_lt_(long a, long b, const char *fl, int ln);
void silofs_expect_le_(long a, long b, const char *fl, int ln);
void silofs_expect_gt_(long a, long b, const char *fl, int ln);
void silofs_expect_ge_(long a, long b, const char *fl, int ln);
void silofs_expect_ok_(int err, const char *fl, int ln);
void silofs_expect_err_(int err, int exp, const char *fl, int ln);
void silofs_expect_not_null_(const void *ptr, const char *fl, int ln);
void silofs_expect_null_(const void *ptr, const char *fl, int ln);
void silofs_expect_eqs_(const char *s, const char *z, const char *fl, int ln);
void silofs_expect_eqm_(const void *p, const void *q, size_t n, const char *fl,
                        int ln);
void silofs_expect_noop_(long a, long b);

#define silofs_expect(cond) \
	silofs_expect_cond_((cond), SILOFS_STR(cond), SILOFS_FL_LN_)
#define silofs_expect_eq(a, b) \
	silofs_expect_eq_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_expect_ne(a, b) \
	silofs_expect_ne_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_expect_lt(a, b) \
	silofs_expect_lt_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_expect_le(a, b) \
	silofs_expect_le_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_expect_gt(a, b) \
	silofs_expect_gt_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_expect_ge(a, b) \
	silofs_expect_ge_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_expect_not_null(ptr) \
	silofs_expect_not_null_(ptr, SILOFS_FL_LN_)
#define silofs_expect_null(ptr) silofs_expect_null_(ptr, SILOFS_FL_LN_)
#define silofs_expect_ok(err)   silofs_expect_ok_((int)(err), SILOFS_FL_LN_)
#define silofs_expect_err(err, exp) \
	silofs_expect_err_((int)(err), (int)(exp), SILOFS_FL_LN_)
#define silofs_expect_eqs(s1, s2) silofs_expect_eqs_(s1, s2, SILOFS_FL_LN_)
#define silofs_expect_eqm(m1, m2, nn) \
	silofs_expect_eqm_(m1, m2, nn, SILOFS_FL_LN_)

/* run-time assertions (debug mode only) */
#ifdef NDEBUG
#define silofs_assert(cond)         silofs_expect_noop_((cond), 0)
#define silofs_assert_eq(a, b)      silofs_expect_noop_((long)(a), (long)(b))
#define silofs_assert_ne(a, b)      silofs_expect_noop_((long)(a), (long)(b))
#define silofs_assert_lt(a, b)      silofs_expect_noop_((long)(a), (long)(b))
#define silofs_assert_le(a, b)      silofs_expect_noop_((long)(a), (long)(b))
#define silofs_assert_gt(a, b)      silofs_expect_noop_((long)(a), (long)(b))
#define silofs_assert_ge(a, b)      silofs_expect_noop_((long)(a), (long)(b))
#define silofs_assert_not_null(ptr) silofs_expect_noop_((long)(ptr), 1)
#define silofs_assert_null(ptr)     silofs_expect_noop_((long)(ptr), 0)
#define silofs_assert_ok(err)       silofs_expect_noop_((long)(err), 0)
#define silofs_assert_err(err, exp) \
	silofs_expect_noop_((long)(err), (long)(exp))
#define silofs_assert_eqs(s1, s2) silofs_expect_noop_((long)(s1), (long)(s2))
#define silofs_assert_eqm(m1, m2, nn) \
	silofs_expect_noop_((long)(m1), (long)(m2))
#else
#define silofs_assert(cond) \
	silofs_expect_cond_((cond), SILOFS_STR(cond), SILOFS_FL_LN_)
#define silofs_assert_eq(a, b) \
	silofs_expect_eq_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_assert_ne(a, b) \
	silofs_expect_ne_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_assert_lt(a, b) \
	silofs_expect_lt_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_assert_le(a, b) \
	silofs_expect_le_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_assert_gt(a, b) \
	silofs_expect_gt_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_assert_ge(a, b) \
	silofs_expect_ge_((long)(a), (long)(b), SILOFS_FL_LN_)
#define silofs_assert_not_null(ptr) \
	silofs_expect_not_null_(ptr, SILOFS_FL_LN_)
#define silofs_assert_null(ptr) silofs_expect_null_(ptr, SILOFS_FL_LN_)
#define silofs_assert_ok(err)   silofs_expect_ok_((int)(err), SILOFS_FL_LN_)
#define silofs_assert_err(err, exp) \
	silofs_expect_err_((int)(err), (int)(exp), SILOFS_FL_LN_)
#define silofs_assert_eqs(s1, s2) silofs_expect_eqs_(s1, s2, SILOFS_FL_LN_)
#define silofs_assert_eqm(m1, m2, nn) \
	silofs_expect_eqm_(m1, m2, nn, SILOFS_FL_LN_)
#endif

/* panic */
#define silofs_panic(fmt_, ...) \
	silofs_panicf(__FILE__, __LINE__, fmt_, __VA_ARGS__)

#define silofs_panic_if_null(ptr_)                                          \
	do {                                                                \
		if (silofs_unlikely(ptr_ == NULL)) {                        \
			silofs_panic("NULL pointer: %s", SILOFS_STR(ptr_)); \
		}                                                           \
	} while (0)

#define silofs_attr_dief(x_, y_) \
	silofs_attr_noreturn silofs_attr_printf(x_, y_)

silofs_attr_dief(3, 4) void silofs_panicf(const char *file, int line,
                                          const char *restrict fmt, ...);

/* die */
silofs_attr_dief(2, 3) void silofs_die(int er, const char *restrict fmt, ...);

silofs_attr_dief(4, 5) void silofs_die_at(int er, const char *fl, int ln,
                                          const char *restrict fmt, ...);

/* backtrace */
void silofs_backtrace(void);

#endif /* SILOFS_PANIC_H_ */
