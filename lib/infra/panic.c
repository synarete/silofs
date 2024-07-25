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
#include <silofs/macros.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/panic.h>
#include <silofs/infra/logging.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>

#ifdef SILOFS_WITH_LIBUNWIND
#ifndef HAVE_LIBUNWIND_H
#error "HAVE_LIBUNWIND_H not defined"
#endif
#define UNW_LOCAL_ONLY 1
#include <libunwind.h>
#endif

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_backtrace_args {
	const char *sym;
	void *ip;
	long  sp;
	long  off;
};

typedef int (*silofs_backtrace_cb)(const struct silofs_backtrace_args *);

#ifdef SILOFS_WITH_LIBUNWIND

struct silofs_backtrace_ctx {
	unw_context_t                   context;
	unw_cursor_t                    cursor;
	unw_word_t                      ip;
	unw_word_t                      sp;
	unw_word_t                      off;
	char                            sym[512];
	struct silofs_backtrace_args    args;
};

static int silofs_backtrace_calls(silofs_backtrace_cb bt_cb)
{
	struct silofs_backtrace_ctx bt_ctx;
	int err;

	memset(&bt_ctx, 0, sizeof(bt_ctx));
	bt_ctx.args.sym = bt_ctx.sym;

	err = unw_getcontext(&bt_ctx.context);
	if (err != UNW_ESUCCESS) {
		return err;
	}
	err = unw_init_local(&bt_ctx.cursor, &bt_ctx.context);
	if (err != UNW_ESUCCESS) {
		return err;
	}
	for (int step = 0; step < 80; ++step) {
		bt_ctx.ip = 0;
		bt_ctx.sp = 0;
		bt_ctx.off = 0;
		err = unw_step(&bt_ctx.cursor);
		if (err <= 0) {
			break;
		}
		err = unw_get_reg(&bt_ctx.cursor, UNW_REG_IP, &bt_ctx.ip);
		if (err) {
			return err;
		}
		err = unw_get_reg(&bt_ctx.cursor, UNW_REG_SP, &bt_ctx.sp);
		if (err) {
			return err;
		}
		err = unw_get_proc_name(&bt_ctx.cursor, bt_ctx.sym,
		                        sizeof(bt_ctx.sym) - 1, &bt_ctx.off);
		if (err) {
			bt_ctx.sym[0] = '\0';
		}
		bt_ctx.args.ip = (void *)bt_ctx.ip;
		bt_ctx.args.sp = (long)bt_ctx.sp;
		bt_ctx.args.off = (long)bt_ctx.off;
		err = bt_cb(&bt_ctx.args);
		if (err) {
			return err;
		}
	}
	return 0;
}
#else
static int silofs_backtrace_calls(silofs_backtrace_cb bt_cb)
{
	silofs_unused(bt_cb);
	return 0;
}
#endif /* SILOFS_WITH_LIBUNWIND */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool silofs_enable_backtrace = true;

static int log_err_bt(const struct silofs_backtrace_args *bt_args)
{
	silofs_log_error("[<%p>] 0x%lx %s+0x%lx",
	                 bt_args->ip, bt_args->sp,
	                 bt_args->sym, bt_args->off);
	return 0;
}

void silofs_backtrace(void)
{
	if (silofs_enable_backtrace) {
		silofs_backtrace_calls(log_err_bt);
	}
}

static void silofs_dump_backtrace(void)
{
	silofs_backtrace();
	silofs_enable_backtrace = false;
}

#ifdef SILOFS_WITH_LIBUNWIND
static void bt_addrs_to_str(char *buf, size_t bsz, void **bt_arr, int bt_len)
{
	size_t len;

	for (int i = 1; i < bt_len - 2; ++i) {
		len = strlen(buf);
		if ((len + 8) >= bsz) {
			break;
		}
		snprintf(buf + len, bsz - len, "%p ", bt_arr[i]);
	}
}

static void silofs_dump_addr2line(void)
{
	void *bt_arr[128];
	char bt_addrs[1024];
	const int bt_cnt = (int)(SILOFS_ARRAY_SIZE(bt_arr));
	int bt_len;

	memset(bt_arr, 0, sizeof(bt_arr));
	memset(bt_addrs, 0, sizeof(bt_addrs));

	bt_len = unw_backtrace(bt_arr, bt_cnt);
	bt_addrs_to_str(bt_addrs, sizeof(bt_addrs) - 1, bt_arr, bt_len);
	silofs_log_error("addr2line -a -C -e %s -f -p -s %s",
	                 program_invocation_name, bt_addrs);
}
#else
static void silofs_dump_addr2line(void)
{
	/* no-op */
}
#endif /* SILOFS_WITH_LIBUNWIND */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* file-line convenience pair */
struct silofs_fileline {
	const char *file;
	int line;
};

struct silofs_fatal_msg {
	char str[256];
	struct silofs_fileline fl;
};

static void fmtmsg(struct silofs_fatal_msg *msg, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(msg->str, sizeof(msg->str) - 1, fmt, ap);
	va_end(ap);

	len = silofs_min(sizeof(msg->str) - 1, (size_t)n);
	msg->str[len] = '\0';
}

__attribute__((__noreturn__))
static void silofs_abort(void)
{
	fflush(stdout);
	fflush(stderr);
	abort();
	silofs_unreachable();
}

__attribute__((__noreturn__))
static void silofs_fatal_at_(const char *msg, const struct silofs_fileline *fl)
{
	silofs_panicf(fl->file, fl->line, "fatal: '%s'", msg);
	silofs_unreachable();
}

__attribute__((__noreturn__))
static void silofs_fatal_by_(const struct silofs_fatal_msg *fm)
{
	silofs_fatal_at_(fm->str, &fm->fl);
}

__attribute__((__noreturn__))
static void silofs_fatal_op(long a, const char *op, long b,
                            const struct silofs_fileline *fl)
{
	struct silofs_fatal_msg fm = {
		.fl.file = fl->file,
		.fl.line = fl->line
	};

	fmtmsg(&fm, "%ld %s %ld", a, op, b);
	silofs_fatal_by_(&fm);
}

void silofs_expect_cond_(int cond, const char *str, const char *file, int line)
{
	if (silofs_unlikely(!cond)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_at_(str, &fl);
	}
}

void silofs_expect_true_(int cond, const char *file, int line)
{
	if (silofs_unlikely(!cond)) {
		struct silofs_fatal_msg fm = {
			.fl.file = file,
			.fl.line = line,
		};

		fmtmsg(&fm, "not-true: %d", cond);
		silofs_fatal_by_(&fm);
	}
}

void silofs_expect_eq_(long a, long b, const char *file, int line)
{
	if (silofs_unlikely(a != b)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_op(a, "!=", b, &fl);
	}
}

void silofs_expect_ne_(long a, long b, const char *file, int line)
{
	if (silofs_unlikely(a == b)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_op(a, "==", b, &fl);
	}
}

void silofs_expect_lt_(long a, long b, const char *file, int line)
{
	if (silofs_unlikely(a >= b)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_op(a, ">=", b, &fl);
	}
}

void silofs_expect_le_(long a, long b, const char *file, int line)
{
	if (silofs_unlikely(a > b)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_op(a, ">", b, &fl);
	}
}

void silofs_expect_gt_(long a, long b, const char *file, int line)
{
	if (silofs_unlikely(a <= b)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_op(a, "<=", b, &fl);
	}
}

void silofs_expect_ge_(long a, long b, const char *file, int line)
{
	if (silofs_unlikely(a < b)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_op(a, "<", b, &fl);
	}
}

void silofs_expect_ok_(int err, const char *file, int line)
{
	if (silofs_unlikely(err != 0)) {
		struct silofs_fatal_msg fm = {
			.fl.file = file,
			.fl.line = line
		};

		fmtmsg(&fm, "err=%d", err);
		silofs_fatal_by_(&fm);
	}
}

void silofs_expect_err_(int err, int exp, const char *file, int line)
{
	if (silofs_unlikely(err != exp)) {
		struct silofs_fatal_msg fm = {
			.fl.file = file,
			.fl.line = line
		};

		fmtmsg(&fm, "err=%d exp=%d", err, exp);
		silofs_fatal_by_(&fm);
	}
}

void silofs_expect_not_null_(const void *ptr, const char *file, int line)
{
	if (silofs_unlikely(ptr == NULL)) {
		const struct silofs_fileline fl = {
			.file = file,
			.line = line
		};

		silofs_fatal_at_("NULL pointer", &fl);
	}
}

void silofs_expect_null_(const void *ptr, const char *file, int line)
{
	if (silofs_unlikely(ptr != NULL)) {
		struct silofs_fatal_msg fm = {
			.fl.file = file,
			.fl.line = line
		};

		fmtmsg(&fm, "not NULL ptr=%p", ptr);
		silofs_fatal_by_(&fm);
	}
}

void silofs_expect_eqs_(const char *s, const char *z,
                        const char *file, int line)
{
	const int cmp = strcmp(s, z);

	if (silofs_unlikely(cmp != 0)) {
		struct silofs_fatal_msg fm = {
			.fl.file = file,
			.fl.line = line
		};

		fmtmsg(&fm, "str-not-equal: '%s' != '%s'", s, z);
		silofs_fatal_by_(&fm);
	}
}

static size_t find_first_not_eq(const uint8_t *p, const uint8_t *q, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		if (p[i] != q[i]) {
			return i;
		}
	}
	return n;
}

__attribute__((__noreturn__))
static void silofs_die_not_eqm(const uint8_t *p, const uint8_t *q,
                               size_t n, const char *file, int line)
{
	struct silofs_fatal_msg fm = {
		.fl.file = file,
		.fl.line = line
	};
	const size_t pos = find_first_not_eq(p, q, n);

	fmtmsg(&fm, "memory-not-equal-at: %zu (%u != %u)",
	       pos, (uint32_t)(p[pos]), (uint32_t)(q[pos]));
	silofs_fatal_by_(&fm);
}

void silofs_expect_eqm_(const void *p, const void *q,
                        size_t n, const char *fl, int ln)
{
	if (n && (memcmp(p, q, n) != 0)) {
		silofs_die_not_eqm(p, q, n, fl, ln);
	}
}

void silofs_expect_noop_(long a, long b)
{
	/* Just make clang-scan happy: map assertions to no-op */
	silofs_unused(a);
	silofs_unused(b);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

static void silofs_dump_panic_msg(const char *file, int line,
                                  const char *msg, int errnum)
{
	const char *es = " ";
	const char *name = basename_of(file);

	silofs_log_crit("%s", es);
	if (errnum) {
		silofs_log_crit("%s:%d: %s %d", name, line, msg, errnum);
	} else {
		silofs_log_crit("%s:%d: %s", name, line, msg);
	}
	silofs_log_crit("%s", es);
}

__attribute__((__noreturn__))
void silofs_panicf(const char *file, int line, const char *fmt, ...)
{
	char msg[256] = "";
	const int errnum = errno;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	silofs_dump_panic_msg(file, line, msg, errnum);
	silofs_dump_backtrace();
	silofs_dump_addr2line();
	silofs_abort();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

__attribute__((__noreturn__))
void silofs_die(int errnum, const char *fmt, ...)
{
	char msg[1024] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	error(EXIT_FAILURE, abs(errnum), "%s", msg);
	/* never gets here, but makes compiler happy */
	silofs_abort();
}

__attribute__((__noreturn__))
void silofs_die_at(int errnum, const char *fl, int ln, const char *fmt, ...)
{
	char msg[1024] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	error_at_line(EXIT_FAILURE, abs(errnum), fl, (uint32_t)ln, "%s", msg);
	/* never gets here, but makes compiler happy */
	silofs_abort();
}
