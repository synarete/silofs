/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include "fftests.h"

/*
 * TODO-0053: Test fail when using O_DIRECT -- why?
 *
 * The stress-test fail when using O_DIRECT in open. Probably an issue on the
 * FUSE.ko side but need further investigation. Detected by LTP's dio_truncate
 * test.
 */

struct ft_xstress_ctx {
	struct silofs_thread th;
	struct ft_env  *fte;
	const char     *path;
	loff_t          off;
	size_t          len;
	int             niter_max;
	int             keep_run;
};


static void ft_close_n(int *fds, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_close(fds[i]);
	}
}

static void ft_unlink_n(const char **path_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_unlink(path_arr[i]);
	}
}

static void xs_bzero_ctx(struct ft_xstress_ctx *xs_ctx, size_t cnt)
{
	memset(xs_ctx, 0, cnt * sizeof(*xs_ctx));
}

static void xs_exec_thread(struct ft_xstress_ctx *xs_ctx,
                           silofs_execute_fn exec)
{
	int err;

	xs_ctx->keep_run = 1;
	err = silofs_thread_create(&xs_ctx->th, exec, xs_ctx, NULL);
	ft_expect_ok(err);
}

static void xs_exec_threads(struct ft_xstress_ctx *xs_ctx, size_t cnt,
                            silofs_execute_fn exec)
{
	for (size_t i = 0; i < cnt; ++i) {
		xs_exec_thread(&xs_ctx[i], exec);
	}
}

static void xs_wait_thread(const struct ft_xstress_ctx *xs_ctx)
{
	long iter = 0;

	while (xs_ctx->th.finish_time == 0) {
		iter += 1;
		ft_expect_lt(iter, 100000);
		ft_suspends(xs_ctx->fte, 1);
	}
}

static void xs_wait_threads(const struct ft_xstress_ctx *xs_ctx, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		xs_wait_thread(&xs_ctx[i]);
	}
}

static void xs_join_thread(struct ft_xstress_ctx *xs_ctx)
{
	int err;

	xs_ctx->keep_run = 0;
	err = silofs_thread_join(&xs_ctx->th);
	ft_expect_ok(err);
}

static void xs_join_threads(struct ft_xstress_ctx *xs_ctx, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		xs_join_thread(&xs_ctx[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void xs_read_zeros_(const struct ft_xstress_ctx *xs_ctx)
{
	struct ft_env *fte = xs_ctx->fte;
	uint8_t *buf1 = ft_new_buf_zeros(fte, xs_ctx->len);
	uint8_t *buf2 = ft_new_buf_zeros(fte, xs_ctx->len);
	size_t nrd = 0;
	int fd = -1;

	ft_open(xs_ctx->path, O_RDONLY, 0600, &fd);
	while (xs_ctx->keep_run) {
		ft_pread(fd, buf1, xs_ctx->len, xs_ctx->off, &nrd);
		ft_expect_eqm(buf1, buf2, nrd);
		nrd = 0;
	}
	ft_close(fd);
}

static void xs_write_zeros_trunc_(const struct ft_xstress_ctx *xs_ctx)
{
	struct ft_env *fte = xs_ctx->fte;
	uint8_t *buf = ft_new_buf_zeros(fte, xs_ctx->len);
	const loff_t end = ft_off_end(xs_ctx->off, xs_ctx->len);
	size_t nwr = 0;
	int iter = 0;
	int fd = -1;

	ft_open(xs_ctx->path, O_WRONLY, 0600, &fd);
	while (xs_ctx->keep_run && (iter++ < xs_ctx->niter_max)) {
		ft_ftruncate(fd, end);
		ft_pwrite(fd, buf, xs_ctx->len, xs_ctx->off, &nwr);
		ft_ftruncate(fd, 0);
		nwr = 0;
	}
	ft_close(fd);
}

static void xs_write_rands_trunc_(const struct ft_xstress_ctx *xs_ctx)
{
	struct ft_env *fte = xs_ctx->fte;
	uint8_t *buf = ft_new_buf_rands(fte, xs_ctx->len);
	const loff_t end = ft_off_end(xs_ctx->off, xs_ctx->len);
	size_t nwr = 0;
	int iter = 0;
	int fd = -1;

	ft_open(xs_ctx->path, O_WRONLY, 0600, &fd);
	while (xs_ctx->keep_run && (iter++ < xs_ctx->niter_max)) {
		ft_ftruncate(fd, end);
		ft_pwrite(fd, buf, xs_ctx->len, xs_ctx->off, &nwr);
		ft_ftruncate(fd, 0);
		nwr = 0;
	}
	ft_close(fd);
}

static int xs_read_zeros(struct silofs_thread *th)
{
	xs_read_zeros_(th->arg);
	return 0;
}

static int xs_write_zeros_trunc(struct silofs_thread *th)
{
	xs_write_zeros_trunc_(th->arg);
	return 0;
}

static int xs_write_rands_trunc(struct silofs_thread *th)
{
	xs_write_rands_trunc_(th->arg);
	return 0;
}

static void test_xstress_rw_trunc_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_xstress_ctx xs_ctx_wr[2];
	struct ft_xstress_ctx xs_ctx_rd[16];
	const char *path[2] = { NULL, NULL };
	const loff_t end = ft_off_end(off, len);
	const int niter_max = 1000;
	int fd[2] = { -1, -1 };

	xs_bzero_ctx(xs_ctx_wr, FT_ARRAY_SIZE(xs_ctx_wr));
	xs_bzero_ctx(xs_ctx_rd, FT_ARRAY_SIZE(xs_ctx_rd));
	for (size_t i = 0; i < FT_ARRAY_SIZE(path); ++i) {
		path[i] = ft_new_path_unique(fte);
		ft_open(path[i], O_CREAT | O_RDWR, 0600, &fd[i]);
		ft_ftruncate(fd[i], end);
	}

	for (size_t i = 0; i < FT_ARRAY_SIZE(xs_ctx_wr); ++i) {
		xs_ctx_wr[i].fte = fte;
		xs_ctx_wr[i].path = path[i];
		xs_ctx_wr[i].off = off;
		xs_ctx_wr[i].len = len;
		xs_ctx_wr[i].niter_max = niter_max;
		xs_ctx_wr[i].keep_run = 1;
	}

	for (size_t i = 0; i < FT_ARRAY_SIZE(xs_ctx_rd); ++i) {
		xs_ctx_rd[i].fte = fte;
		xs_ctx_rd[i].path = path[0]; /* all readers from same file */
		xs_ctx_rd[i].off = off;
		xs_ctx_rd[i].len = len;
		xs_ctx_rd[i].niter_max = niter_max;
		xs_ctx_rd[i].keep_run = 1;
	}

	xs_exec_threads(xs_ctx_rd, FT_ARRAY_SIZE(xs_ctx_rd), xs_read_zeros);
	xs_exec_threads(xs_ctx_wr, 1, xs_write_zeros_trunc);
	xs_exec_threads(xs_ctx_wr + 1, 1, xs_write_rands_trunc);
	xs_wait_threads(xs_ctx_wr, FT_ARRAY_SIZE(xs_ctx_wr));
	xs_join_threads(xs_ctx_rd, FT_ARRAY_SIZE(xs_ctx_rd));
	xs_join_threads(xs_ctx_wr, FT_ARRAY_SIZE(xs_ctx_wr));

	ft_close_n(fd, FT_ARRAY_SIZE(fd));
	ft_unlink_n(path, FT_ARRAY_SIZE(path));
}

static void test_xstress_rw_trunc(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
		/* unaligned */
		FT_MKRANGE(1, FT_1M),
		FT_MKRANGE(FT_1G - 11, FT_1M + 111),
		FT_MKRANGE(FT_1T - 111, FT_1M + 1111),
	};

	ft_exec_with_ranges(fte, test_xstress_rw_trunc_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_xstress_rw_trunc),
};

const struct ft_tests ft_test_xstress_mt = FT_DEFTESTS(ft_local_tests);

