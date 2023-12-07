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

struct ft_stress_executor {
	struct silofs_thread th;
	struct ft_env  *fte;
	const char     *path;
	size_t          niter;
	loff_t          off;
	size_t          len;
	loff_t          end;
	int             keep_run;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ft_new_path_unique_n(struct ft_env *fte, char **path_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		path_arr[i] = ft_new_path_unique(fte);
	}
}

static void ft_pclose(int *fd)
{
	if (fd != NULL) {
		ft_close(*fd);
		*fd = -1;
	}
}

static void ft_creat_n(char **path_arr, size_t n, ssize_t len)
{
	int fd = -1;

	for (size_t i = 0; i < n; ++i) {
		ft_open(path_arr[i], O_CREAT | O_RDWR, 0600, &fd);
		if (len > 0) {
			ft_ftruncate(fd, len);
		}
		ft_pclose(&fd);
	}
}

static void ft_unlink_n(char **path_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_unlink(path_arr[i]);
		path_arr[i] = NULL;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ste_run(struct ft_stress_executor *ste, silofs_execute_fn exec)
{
	int err;

	ste->keep_run = 1;
	err = silofs_thread_create(&ste->th, exec, ste, NULL);
	ft_expect_ok(err);
}

static void ste_nrun(struct ft_stress_executor *ste_arr,
                     size_t n, silofs_execute_fn exec)
{
	for (size_t i = 0; i < n; ++i) {
		ste_run(&ste_arr[i], exec);
	}
}

static void ste_wait(const struct ft_stress_executor *ste)
{
	long iter = 0;

	while (ste->th.finish_time == 0) {
		iter += 1;
		ft_expect_lt(iter, 100000);
		ft_suspend1(ste->fte);
	}
}

static void ste_nwait(const struct ft_stress_executor *ste_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ste_wait(&ste_arr[i]);
	}
}

static void ste_join(struct ft_stress_executor *ste)
{
	int err;

	ste->keep_run = 0;
	err = silofs_thread_join(&ste->th);
	ft_expect_ok(err);
}

static void ste_njoin(struct ft_stress_executor *ste, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ste_join(&ste[i]);
	}
}

static void ste_setup(struct ft_stress_executor *ste, struct ft_env *fte,
                      const char *path, size_t niter, loff_t off, size_t len)
{
	silofs_memzero(ste, sizeof(*ste));
	ste->fte = fte;
	ste->path = path;
	ste->niter = niter;
	ste->off = off;
	ste->len = len;
	ste->end = ft_off_end(off, len);
	ste->keep_run = 1;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ste_read_zeros(const struct ft_stress_executor *ste)
{
	uint8_t *buf1 = ft_new_buf_zeros(ste->fte, ste->len);
	uint8_t *buf2 = ft_new_buf_zeros(ste->fte, ste->len);
	size_t nrd = 0;
	int fd = -1;

	ft_open(ste->path, O_RDONLY, 0600, &fd);
	while (ste->keep_run) {
		ft_pread(fd, buf1, ste->len, ste->off, &nrd);
		ft_expect_eqm(buf1, buf2, nrd);
		nrd = 0;
	}
	ft_close(fd);
}

static void ste_write_zeros_trunc(const struct ft_stress_executor *ste)
{
	uint8_t *buf = ft_new_buf_zeros(ste->fte, ste->len);
	size_t nwr = 0;
	size_t iter = 0;
	int fd = -1;

	ft_open(ste->path, O_WRONLY, 0600, &fd);
	while (ste->keep_run && (iter++ < ste->niter)) {
		ft_ftruncate(fd, ste->end);
		ft_pwrite(fd, buf, ste->len, ste->off, &nwr);
		ft_ftruncate(fd, 0);
		nwr = 0;
	}
	ft_close(fd);
}

static void ste_write_rands_trunc(const struct ft_stress_executor *ste)
{
	uint8_t *buf = ft_new_buf_rands(ste->fte, ste->len);
	size_t nwr = 0;
	size_t iter = 0;
	int fd = -1;

	ft_open(ste->path, O_WRONLY, 0600, &fd);
	while (ste->keep_run && (iter++ < ste->niter)) {
		ft_ftruncate(fd, ste->end);
		ft_pwrite(fd, buf, ste->len, ste->off, &nwr);
		ft_ftruncate(fd, 0);
		nwr = 0;
	}
	ft_close(fd);
}

static void ste_rewrite_over(const struct ft_stress_executor *ste)
{
	struct stat st = { .st_size = -1 };
	uint8_t *buf1 = ft_new_buf_rands(ste->fte, ste->len);
	uint8_t *buf2 = ft_new_buf_rands(ste->fte, ste->len);
	size_t iter = 0;
	int fd = -1;

	ft_open(ste->path, O_RDWR, 0, &fd);
	while (ste->keep_run && (iter++ < ste->niter)) {
		ft_pwriten(fd, buf1, ste->len, ste->off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, ste->end);
		ft_preadn(fd, buf2, ste->len, ste->off);
		ft_expect_eqm(buf1, buf2, ste->len);
		buf1[iter % ste->len] = (uint8_t)iter;
		ft_pwriten(fd, buf1, ste->len, ste->off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, ste->end);
		ft_preadn(fd, buf2, ste->len, ste->off);
		ft_expect_eqm(buf1, buf2, ste->len);
		ft_ftruncate(fd, ste->off + 1);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, ste->off + 1);
		buf1[(iter + 1) % ste->len] = (uint8_t)iter;
		ft_pwriten(fd, buf1, ste->len, ste->off);
		ft_preadn(fd, buf2, ste->len, ste->off);
		ft_expect_eqm(buf1, buf2, ste->len);
		ft_ftruncate(fd, ste->off);
	}
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_read_zeros(struct silofs_thread *th)
{
	ste_read_zeros(th->arg);
	return 0;
}

static int do_write_zeros_trunc(struct silofs_thread *th)
{
	ste_write_zeros_trunc(th->arg);
	return 0;
}

static int do_write_rands_trunc(struct silofs_thread *th)
{
	ste_write_rands_trunc(th->arg);
	return 0;
}

static void stress_rw_trunc_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_stress_executor ste_wr[2];
	struct ft_stress_executor ste_rd[16];
	char *path[2] = { NULL, NULL };
	const size_t niter = 1000;

	ft_new_path_unique_n(fte, path, FT_ARRAY_SIZE(path));
	ft_creat_n(path, FT_ARRAY_SIZE(path), ft_off_end(off, len));
	for (size_t i = 0; i < FT_ARRAY_SIZE(ste_wr); ++i) {
		ste_setup(&ste_wr[i], fte, path[i], niter, off, len);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(ste_rd); ++i) {
		/* all readers from same file */
		ste_setup(&ste_rd[i], fte, path[0], niter, off, len);
	}
	ste_nrun(ste_rd, FT_ARRAY_SIZE(ste_rd), do_read_zeros);
	ste_nrun(ste_wr, 1, do_write_zeros_trunc);
	ste_nrun(ste_wr + 1, 1, do_write_rands_trunc);
	ste_nwait(ste_wr, FT_ARRAY_SIZE(ste_wr));
	ste_njoin(ste_rd, FT_ARRAY_SIZE(ste_rd));
	ste_njoin(ste_wr, FT_ARRAY_SIZE(ste_wr));
	ft_unlink_n(path, FT_ARRAY_SIZE(path));
}

static void stress_rw_trunc(struct ft_env *fte)
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

	ft_exec_with_ranges(fte, stress_rw_trunc_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_rewrite_over(struct silofs_thread *th)
{
	ste_rewrite_over(th->arg);
	return 0;
}

static void stress_rw_over_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_stress_executor ste[10];
	char *path[10];
	const size_t niter = 100;

	SILOFS_STATICASSERT_EQ(FT_ARRAY_SIZE(ste), FT_ARRAY_SIZE(path));

	ft_new_path_unique_n(fte, path, FT_ARRAY_SIZE(path));
	ft_creat_n(path, FT_ARRAY_SIZE(path), 0);
	for (size_t i = 0; i < FT_ARRAY_SIZE(ste); ++i) {
		ste_setup(&ste[i], fte, path[i], niter, off, len);
	}
	ste_nrun(ste, FT_ARRAY_SIZE(ste), do_rewrite_over);
	ste_nwait(ste, FT_ARRAY_SIZE(ste));
	ste_njoin(ste, FT_ARRAY_SIZE(ste));
	ft_unlink_n(path, FT_ARRAY_SIZE(path));
}

static void stress_rw_over(struct ft_env *fte)
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

	ft_exec_with_ranges(fte, stress_rw_over_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(stress_rw_trunc),
	FT_DEFTEST(stress_rw_over),
};

const struct ft_tests ft_stress_rw = FT_DEFTESTS(ft_local_tests);

