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
#include <sys/xattr.h>
#include <stdio.h>
#include "ftests.h"

/*
 * TODO-0053: Test fail when using O_DIRECT -- why?
 *
 * The stress-test fail when using O_DIRECT in open. Probably an issue on the
 * FUSE.ko side but need further investigation. Detected by LTP's dio_truncate
 * test.
 */

struct ft_sub_exec;
typedef void (*ft_sub_exec_fn)(struct ft_sub_exec *);

struct ft_sub_exec {
	struct silofs_thread th;
	ft_sub_exec_fn exec_fn;
	struct ft_env *fte;
	const char *path;
	size_t niter;
	loff_t off;
	size_t len;
	loff_t end;
	int keep_run;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ft_sub_exec(struct silofs_thread *th)
{
	struct ft_sub_exec *se = th->arg;

	se->exec_fn(se);
	return 0;
}

static void ft_sub_run(struct ft_sub_exec *se, ft_sub_exec_fn exec_fn)
{
	int err;

	se->keep_run = 1;
	se->exec_fn = exec_fn;
	err = silofs_thread_create(&se->th, ft_sub_exec, se, NULL);
	ft_expect_ok(err);
}

static void
ft_sub_nrun(struct ft_sub_exec *se_arr, size_t n, ft_sub_exec_fn exec_fn)
{
	for (size_t i = 0; i < n; ++i) {
		ft_sub_run(&se_arr[i], exec_fn);
	}
}

static void ft_sub_wait(const struct ft_sub_exec *se)
{
	long iter = 0;

	while (se->th.finish_time == 0) {
		iter += 1;
		ft_expect_lt(iter, 100000);
		ft_suspend1(se->fte);
	}
}

static void ft_sub_nwait(const struct ft_sub_exec *se_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_sub_wait(&se_arr[i]);
	}
}

static void ft_sub_join(struct ft_sub_exec *se)
{
	int err;

	se->keep_run = 0;
	err = silofs_thread_join(&se->th);
	ft_expect_ok(err);
}

static void ft_sub_njoin(struct ft_sub_exec *se_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_sub_join(&se_arr[i]);
	}
}

static void ft_sub_create_file(struct ft_sub_exec *se)
{
	ft_creat_resize(se->path, se->len);
}

static void ft_sub_create_nfiles(struct ft_sub_exec *se_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_sub_create_file(&se_arr[i]);
	}
}

static void ft_sub_unlink_file(struct ft_sub_exec *se)
{
	ft_unlink(se->path);
}

static void ft_sub_unlink_nfiles(struct ft_sub_exec *se_arr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ft_sub_unlink_file(&se_arr[i]);
	}
}

static void
ft_sub_setup(struct ft_sub_exec *se, struct ft_env *fte, const char *path,
	     size_t niter, loff_t off, size_t len)
{
	silofs_memzero(se, sizeof(*se));
	se->fte = fte;
	se->path = path;
	se->niter = niter;
	se->off = off;
	se->len = len;
	se->end = ft_off_end(off, len);
	se->keep_run = 1;
}

static void ft_sub_setup_uniq(struct ft_sub_exec *se, struct ft_env *fte,
			      size_t niter, loff_t off, size_t len)
{
	ft_sub_setup(se, fte, ft_new_path_unique(fte), niter, off, len);
}

static void
ft_sub_setup_nuniqs(struct ft_sub_exec *se_arr, size_t n, struct ft_env *fte,
		    size_t niter, loff_t off, size_t len)
{
	for (size_t i = 0; i < n; ++i) {
		ft_sub_setup_uniq(&se_arr[i], fte, niter, off, len);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void test_rdwr_trunc(struct ft_sub_exec *se)
{
	uint8_t *buf1 = ft_new_buf_rands(se->fte, se->len);
	uint8_t *buf2 = ft_new_buf_rands(se->fte, se->len);
	uint8_t byte = 0;
	size_t iter = 0;
	int fd1 = -1;
	int fd2 = -1;

	ft_open(se->path, O_WRONLY, 0600, &fd1);
	ft_open(se->path, O_RDONLY, 0600, &fd2);
	while (se->keep_run && (iter++ < se->niter)) {
		byte = (uint8_t)(iter + 1);
		buf1[0] = byte;
		ft_ftruncate(fd1, se->end);
		ft_pwriten(fd1, buf1, se->len, se->off);
		ft_preadn(fd2, buf2, se->len, se->off);
		ft_expect_eqm(buf1, buf2, se->len);
		ft_ftruncate(fd1, se->end - 1);
		ft_ftruncate(fd1, se->end);
		ft_preadn(fd2, &byte, 1, se->end - 1);
		ft_expect_eq(byte, 0);
		ft_ftruncate(fd1, se->off + 1);
		ft_ftruncate(fd1, se->off + 2);
		ft_preadn(fd2, &byte, 1, se->off);
		ft_expect_eq(byte, buf1[0]);
		ft_preadn(fd2, &byte, 1, se->off + 1);
		ft_expect_eq(byte, 0);
		ft_ftruncate(fd1, 0);
	}
	ft_close(fd1);
	ft_close(fd2);
}

static void test_stress_rw_trunc_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_sub_exec se[10];
	const size_t nse = FT_ARRAY_SIZE(se);

	ft_sub_setup_nuniqs(se, nse, fte, 100, off, len);
	ft_sub_create_nfiles(se, nse);
	ft_sub_nrun(se, nse, test_rdwr_trunc);
	ft_sub_nwait(se, nse);
	ft_sub_njoin(se, nse);
	ft_sub_unlink_nfiles(se, nse);
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

	ft_exec_with_ranges(fte, test_stress_rw_trunc_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rewrite_over(struct ft_sub_exec *se)
{
	struct stat st = { .st_size = -1 };
	uint8_t *buf1 = ft_new_buf_rands(se->fte, se->len);
	uint8_t *buf2 = ft_new_buf_rands(se->fte, se->len);
	size_t iter = 0;
	int fd = -1;

	ft_open(se->path, O_RDWR, 0, &fd);
	while (se->keep_run && (iter++ < se->niter)) {
		ft_pwriten(fd, buf1, se->len, se->off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, se->end);
		ft_preadn(fd, buf2, se->len, se->off);
		ft_expect_eqm(buf1, buf2, se->len);
		buf1[iter % se->len] = (uint8_t)iter;
		ft_pwriten(fd, buf1, se->len, se->off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, se->end);
		ft_preadn(fd, buf2, se->len, se->off);
		ft_expect_eqm(buf1, buf2, se->len);
		ft_ftruncate(fd, se->off + 1);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, se->off + 1);
		buf1[(iter + 1) % se->len] = (uint8_t)iter;
		ft_pwriten(fd, buf1, se->len, se->off);
		ft_preadn(fd, buf2, se->len, se->off);
		ft_expect_eqm(buf1, buf2, se->len);
		ft_ftruncate(fd, se->off);
	}
	ft_close(fd);
}

static void test_stress_rw_over_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_sub_exec se[10];
	const size_t nse = FT_ARRAY_SIZE(se);

	ft_sub_setup_nuniqs(se, nse, fte, 100, off, len);
	ft_sub_create_nfiles(se, nse);
	ft_sub_nrun(se, nse, test_rewrite_over);
	ft_sub_nwait(se, nse);
	ft_sub_njoin(se, nse);
	ft_sub_unlink_nfiles(se, nse);
}

static void test_stress_rw_over(struct ft_env *fte)
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

	ft_exec_with_ranges(fte, test_stress_rw_over_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rdwr_with_xattr(struct ft_sub_exec *se)
{
	char name1[64] = "";
	char name2[64] = "";
	const size_t valsz_max = 1024;
	uint8_t *buf1 = ft_new_buf_rands(se->fte, se->len);
	uint8_t *buf2 = ft_new_buf_rands(se->fte, se->len);
	uint8_t *buf3 = ft_new_buf_rands(se->fte, se->len);
	void *val1 = ft_new_buf_rands(se->fte, valsz_max);
	void *val2 = ft_new_buf_rands(se->fte, valsz_max);
	void *val3 = ft_new_buf_rands(se->fte, valsz_max);
	size_t valsz = 0;
	size_t iter = 0;
	size_t sz = 0;
	int fd = -1;

	ft_open(se->path, O_RDWR, 0, &fd);
	while (se->keep_run && (iter++ < se->niter)) {
		snprintf(name1, sizeof(name1) - 1, "user.xattr1-%lu", iter);
		snprintf(name2, sizeof(name2) - 1, "user.xattr2-%lu", iter);
		valsz = (iter % (valsz_max - 1)) + 1;
		ft_fsetxattr(fd, name1, val1, valsz, 0);
		ft_fgetxattr(fd, name1, NULL, 0, &sz);
		ft_expect_eq(sz, valsz);
		ft_pwriten(fd, buf1, se->len, se->off);
		ft_fgetxattr(fd, name1, val2, valsz, &sz);
		ft_expect_eq(sz, valsz);
		ft_expect_eqm(val1, val2, valsz);
		ft_preadn(fd, buf2, se->len, se->off);
		ft_expect_eqm(buf1, buf2, se->len);
		valsz = ((iter + 11) % (valsz_max - 1)) + 1;
		ft_fsetxattr(fd, name1, val3, valsz, XATTR_REPLACE);
		ft_fsetxattr(fd, name2, val2, valsz, 0);
		ft_pwriten(fd, buf3, se->len - 1, se->off);
		ft_fgetxattr(fd, name1, val2, valsz, &sz);
		ft_expect_eq(sz, valsz);
		ft_expect_eqm(val3, val2, valsz);
		ft_fremovexattr(fd, name1);
		ft_ftruncate(fd, se->off + (ssize_t)iter);
		ft_fremovexattr(fd, name2);
		buf1[(iter + 1) % se->len] = (uint8_t)iter;
		buf3[iter % se->len] = (uint8_t)iter;
	}
	ft_close(fd);
}

static void test_stress_rw_xattr_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_sub_exec se[10];
	const size_t nse = FT_ARRAY_SIZE(se);

	ft_sub_setup_nuniqs(se, nse, fte, 1000, off, len);
	ft_sub_create_nfiles(se, nse);
	ft_sub_nrun(se, nse, test_rdwr_with_xattr);
	ft_sub_nwait(se, nse);
	ft_sub_njoin(se, nse);
	ft_sub_unlink_nfiles(se, nse);
}

static void test_stress_rw_xattr(struct ft_env *fte)
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

	ft_exec_with_ranges(fte, test_stress_rw_xattr_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(stress_rw_trunc),
	FT_DEFTEST(test_stress_rw_over),
	FT_DEFTEST(test_stress_rw_xattr),
};

const struct ft_tests ft_stress_rw = FT_DEFTESTS(ft_local_tests);
