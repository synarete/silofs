/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/utility.h>
#include <silofs/panic.h>
#include <silofs/logging.h>
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

struct silofs_bt_info {
	void *ip;
	long  sp;
	const char *sym;
	long  off;
};

#ifdef SILOFS_WITH_LIBUNWIND

/* On aarch64 those two are too big to be allocated on stack */
struct silofs_bt_concur {
	unw_context_t context;
	unw_cursor_t  cursor;
};

static int silofs_backtrace_calls(int (*bt_cb)(const struct silofs_bt_info *))
{
	int err;
	int lim = 64;
	unw_word_t ip;
	unw_word_t sp;
	unw_word_t off;
	unw_context_t *context;
	unw_cursor_t *cursor;
	struct silofs_bt_concur *cc;
	struct silofs_bt_info bti;
	char sym[512];

	cc = (struct silofs_bt_concur *)malloc(sizeof(*cc));
	if (cc == NULL) {
		return -ENOMEM;
	}
	context = &cc->context;
	cursor = &cc->cursor;

	err = unw_getcontext(context);
	if (err != UNW_ESUCCESS) {
		goto out;
	}
	err = unw_init_local(cursor, context);
	if (err != UNW_ESUCCESS) {
		goto out;
	}
	memset(sym, 0, sizeof(sym));
	while (lim-- > 0) {
		ip = sp = off = 0;
		err = unw_step(cursor);
		if (err <= 0) {
			break;
		}
		err = unw_get_reg(cursor, UNW_REG_IP, &ip);
		if (err) {
			break;
		}
		err = unw_get_reg(cursor, UNW_REG_SP, &sp);
		if (err) {
			break;
		}
		off = 0;
		err = unw_get_proc_name(cursor, sym, sizeof(sym) - 1, &off);
		if (err) {
			sym[0] = '\0';
		}
		bti.ip = (void *)ip;
		bti.sp = (long)sp;
		bti.sym = sym;
		bti.off = (long)off;
		err = bt_cb(&bti);
		if (err) {
			break;
		}
	}
out:
	free(cc);
	return err;
}
#else
static int silofs_backtrace_calls(int (*bt_cb)(const struct silofs_bt_info *))
{
	silofs_unused(bt_cb);
	return 0;
}
#endif /* SILOFS_WITH_LIBUNWIND */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool silofs_enable_backtrace = true;

static int log_err_bt(const struct silofs_bt_info *bti)
{
	silofs_log_error("[<%p>] 0x%lx %s+0x%lx",
	                 bti->ip, bti->sp, bti->sym, bti->off);
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
	int bt_len;
	void *bt_arr[128];
	char bt_addrs[1024];
	const int bt_cnt = (int)(SILOFS_ARRAY_SIZE(bt_arr));

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

struct silofs_fatal_msg {
	char str[256];
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
static void
silofs_fatal_at(const char *msg, const char *fl, int ln)
{
	silofs_panicf(fl, ln, "failure: `%s'", msg);
	silofs_unreachable();
}

__attribute__((__noreturn__))
static void silofs_fatal_op(long a, const char *op, long b,
                            const char *fl, int ln)
{
	struct silofs_fatal_msg fm;

	fmtmsg(&fm, "'%ld %s %ld'", a, op, b);
	silofs_fatal_at(fm.str, fl, ln);
}

void silofs_expect_true_(int cond, const char *fl, int ln)
{
	struct silofs_fatal_msg fm;

	if (silofs_unlikely(!cond)) {
		fmtmsg(&fm, "not-true: %d", cond);
		silofs_fatal_at(fm.str, fl, ln);
	}
}

void silofs_expect_cond_(int cond, const char *str, const char *fl, int ln)
{
	if (silofs_unlikely(!cond)) {
		silofs_fatal_at(str, fl, ln);
	}
}

void silofs_expect_eq_(long a, long b, const char *fl, int ln)
{
	if (silofs_unlikely(a != b)) {
		silofs_fatal_op(a, "!=", b, fl, ln);
	}
}

void silofs_expect_ne_(long a, long b, const char *fl, int ln)
{
	if (silofs_unlikely(a == b)) {
		silofs_fatal_op(a, "==", b, fl, ln);
	}
}

void silofs_expect_lt_(long a, long b, const char *fl, int ln)
{
	if (silofs_unlikely(a >= b)) {
		silofs_fatal_op(a, ">=", b, fl, ln);
	}
}

void silofs_expect_le_(long a, long b, const char *fl, int ln)
{
	if (silofs_unlikely(a > b)) {
		silofs_fatal_op(a, ">", b, fl, ln);
	}
}

void silofs_expect_gt_(long a, long b, const char *fl, int ln)
{
	if (silofs_unlikely(a <= b)) {
		silofs_fatal_op(a, "<=", b, fl, ln);
	}
}

void silofs_expect_ge_(long a, long b, const char *fl, int ln)
{
	if (silofs_unlikely(a < b)) {
		silofs_fatal_op(a, "<", b, fl, ln);
	}
}

void silofs_expect_ok_(int err, const char *fl, int ln)
{
	struct silofs_fatal_msg fm;

	if (silofs_unlikely(err != 0)) {
		fmtmsg(&fm, "err=%d", err);
		silofs_fatal_at(fm.str, fl, ln);
	}
}

void silofs_expect_err_(int err, int exp, const char *fl, int ln)
{
	struct silofs_fatal_msg fm;

	if (silofs_unlikely(err != exp)) {
		fmtmsg(&fm, "err=%d exp=%d", err, exp);
		silofs_fatal_at(fm.str, fl, ln);
	}
}

void silofs_expect_not_null_(const void *ptr, const char *fl, int ln)
{
	if (silofs_unlikely(ptr == NULL)) {
		silofs_fatal_at("NULL pointer", fl, ln);
	}
}

void silofs_expect_null_(const void *ptr, const char *fl, int ln)
{
	struct silofs_fatal_msg fm;

	if (silofs_unlikely(ptr != NULL)) {
		fmtmsg(&fm, "not NULL ptr=%p", ptr);
		silofs_fatal_at(fm.str, fl, ln);
	}
}

void silofs_expect_eqs_(const char *s, const char *z, const char *fl, int ln)
{
	struct silofs_fatal_msg msg;
	const int cmp = strcmp(s, z);

	if (silofs_unlikely(cmp != 0)) {
		fmtmsg(&msg, "str-not-equal: %s != %s", s, z);
		silofs_fatal_at(msg.str, fl, ln);
	}
}

static void mem_to_str(const void *mem, size_t nn, char *str, size_t len)
{
	int b;
	size_t pos = 0;
	size_t i = 0;
	const uint8_t *ptr = mem;

	memset(str, 0, len);
	while ((i < nn) && ((pos + 4) < len)) {
		b = (int)ptr[i];
		str[pos++] = silofs_nibble_to_ascii(b >> 4);
		str[pos++] = silofs_nibble_to_ascii(b);
		i += 1;
	}
	if (i < nn) {
		while ((pos + 2) < len) {
			str[pos++] = '.';
		}
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
                               size_t n, const char *fl, int ln)
{
	char s1[20];
	char s2[20];
	struct silofs_fatal_msg fm;
	const size_t pos = find_first_not_eq(p, q, n);

	if (pos > sizeof(s1)) {
		fmtmsg(&fm, "memory-not-equal-at: %lu (%u != %u)",
		       pos, (uint32_t)(p[pos]), (uint32_t)(q[pos]));
	} else {
		mem_to_str(p, n, s1, sizeof(s1));
		mem_to_str(q, n, s2, sizeof(s2));
		fmtmsg(&fm, "memory-not-equal: %s != %s ", s1, s2);
	}
	silofs_fatal_at(fm.str, fl, ln);
}

void silofs_expect_eqm_(const void *p, const void *q,
                        size_t n, const char *fl, int ln)
{
	if (memcmp(p, q, n) != 0) {
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
	va_list ap;
	char msg[512] = "";
	const int errnum = errno;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	silofs_dump_panic_msg(file, line, msg, errnum);
	silofs_dump_backtrace();
	silofs_dump_addr2line();
	silofs_abort();
	silofs_unreachable();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

__attribute__((__noreturn__))
void silofs_die(int errnum, const char *fmt, ...)
{
	char msg[2048] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	error(EXIT_FAILURE, abs(errnum), "%s", msg);
	/* never gets here, but makes compiler happy */
	abort();
}

__attribute__((__noreturn__))
void silofs_die_at(int errnum, const char *fl, int ln, const char *fmt, ...)
{
	char msg[2048] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	error_at_line(EXIT_FAILURE, abs(errnum), fl,
	              (unsigned int)ln, "%s", msg);
	/* never gets here, but makes compiler happy */
	abort();
}