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
#include "unitests.h"

struct ut_thread_args {
	ino_t dino;
	loff_t off;
	size_t len;
	size_t cnt;
};

typedef void (*ut_th_exec_fn)(struct ut_env *, const struct ut_thread_args *);

struct ut_thread_xargs {
	struct ut_env *ute;
	ut_th_exec_fn exec;
	const struct ut_thread_args *args;
};

static struct silofs_thread *ute_malloc_threads(struct ut_env *ute, size_t cnt)
{
	struct silofs_thread *th_arr;

	th_arr = ut_zalloc(ute, cnt * sizeof(*th_arr));
	return th_arr;
}

static int do_start(struct silofs_thread *th)
{
	const struct ut_thread_xargs *xargs = th->arg;

	xargs->exec(xargs->ute, xargs->args);
	return 0;
}

static void
ut_create_threads(struct ut_env *ute, struct silofs_thread *th_arr, size_t nth,
                  ut_th_exec_fn exec, const struct ut_thread_args *args)
{
	struct ut_thread_xargs *xargs = NULL;
	int err;

	xargs = ut_zalloc(ute, sizeof(*xargs));
	xargs->ute = ute;
	xargs->exec = exec;
	xargs->args = args;

	for (size_t i = 0; i < nth; ++i) {
		err = silofs_thread_create(&th_arr[i], do_start, xargs, NULL);
		ut_expect_ok(err);
	}
}

static void
ut_join_threads(struct ut_env *ute, struct silofs_thread *th_arr, size_t nth)
{
	int err;

	for (size_t i = 0; i < nth; ++i) {
		err = silofs_thread_join(&th_arr[i]);
		ut_expect_ok(err);
	}
	ut_unused(ute);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_mt_exec(struct ut_env *ute, const struct ut_thread_args *args)
{
	const ino_t dino = args->dino;
	const size_t bsz = args->len;
	void *buf = ut_randbuf(ute, bsz);
	const char *name = ut_randstr(ute, 100);
	loff_t off = -1;
	ino_t ino = 0;

	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < args->cnt; ++i) {
		off = args->off + (long)(i * args->len);
		ut_write_read(ute, ino, buf, bsz, off);
		ut_trunacate_file(ute, ino, 0);
		ut_write_read(ute, ino, buf, bsz, off);
		ut_trunacate_file(ute, ino, off + (long)bsz + 1);
		ut_read_verify(ute, ino, buf, bsz, off);
		ut_trunacate_file(ute, ino, off);
		ut_write_read(ute, ino, buf, bsz, off);
	}
	ut_remove_file(ute, dino, name, ino);
}

static void
ut_file_mt_simple_(struct ut_env *ute, size_t nth, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	struct silofs_thread *th_arr = ute_malloc_threads(ute, nth);
	struct ut_thread_args args = {
		.off = off,
		.len = len,
		.cnt = 1,
	};

	ut_mkdir_at_root(ute, name, &args.dino);
	ut_create_threads(ute, th_arr, nth, ut_file_mt_exec, &args);
	ut_join_threads(ute, th_arr, nth);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_mt_simple(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, 100),
		UT_MKRANGE1(UT_1K - 1, 2 * UT_1K + 3),
		UT_MKRANGE1(UT_64K - 2, 4 * UT_64K),
		UT_MKRANGE1(UT_1M - 3, UT_1M / 3),
		UT_MKRANGE1(UT_1G - 4, UT_1M + 8),
	};
	size_t nth = 2;

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_mt_simple_(ute, nth, range[i].off, range[i].len);
		ut_relax_mem(ute);
		nth = ut_min(nth * 2, 32);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_mt_many_(struct ut_env *ute, size_t nth, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	struct silofs_thread *th_arr = ute_malloc_threads(ute, nth);
	struct ut_thread_args args = {
		.off = off,
		.len = len,
		.cnt = 20,
	};

	ut_mkdir_at_root(ute, name, &args.dino);
	ut_create_threads(ute, th_arr, nth, ut_file_mt_exec, &args);
	ut_join_threads(ute, th_arr, nth);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_mt_many(struct ut_env *ute)
{
	const size_t nth = (size_t)(2 * silofs_sc_nproc_onln());
	const struct ut_range range[] = {
		UT_MKRANGE1(1, 1000),
		UT_MKRANGE1(UT_1K - 1, 2 * UT_1K + 3),
		UT_MKRANGE1(UT_64K - 2, 4 * UT_64K),
		UT_MKRANGE1(UT_1T - 4, UT_1M / 2),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_mt_many_(ute, nth, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST2(ut_file_mt_simple),
	UT_DEFTEST2(ut_file_mt_many),
};

const struct ut_testdefs ut_tdefs_file_mthreads = UT_MKTESTS(ut_local_tests);
