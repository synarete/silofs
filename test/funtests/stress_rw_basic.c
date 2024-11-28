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

/*
 * TODO-0053: Test fail when using O_DIRECT -- why?
 *
 * The stress-test fail when using O_DIRECT in open. Probably an issue on the
 * FUSE.ko side but need further investigation. Detected by LTP's dio_truncate
 * test.
 */

struct ft_stress_executor {
	struct silofs_thread th;
	struct ft_env *fte;
	const char *path;
	size_t niter;
	loff_t off;
	size_t len;
	loff_t end;
	int keep_run;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ft_pclose(int *fd)
{
	if (fd != NULL) {
		ft_close(*fd);
		*fd = -1;
	}
}

static void ft_creat_with_size(const char *path, size_t len)
{
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, (ssize_t)len);
	ft_pclose(&fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ste_run(struct ft_stress_executor *ste, silofs_execute_fn exec)
{
	int err;

	ste->keep_run = 1;
	err = silofs_thread_create(&ste->th, exec, ste, NULL);
	ft_expect_ok(err);
}

static void
ste_nrun(struct ft_stress_executor *ste_arr, size_t n, silofs_execute_fn exec)
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

static void ste_create(struct ft_stress_executor *ste)
{
	ft_creat_with_size(ste->path, ste->len);
}

static void ste_ncreate(struct ft_stress_executor *ste, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ste_create(&ste[i]);
	}
}

static void ste_unlink(struct ft_stress_executor *ste)
{
	ft_unlink(ste->path);
}

static void ste_nunlink(struct ft_stress_executor *ste, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		ste_unlink(&ste[i]);
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

static void ste_setup_uniq(struct ft_stress_executor *ste, struct ft_env *fte,
                           size_t niter, loff_t off, size_t len)
{
	ste_setup(ste, fte, ft_new_path_unique(fte), niter, off, len);
}

static void
ste_nsetup_uniq(struct ft_stress_executor *ste_arr, size_t n,
                struct ft_env *fte, size_t niter, loff_t off, size_t len)
{
	for (size_t i = 0; i < n; ++i) {
		ste_setup_uniq(&ste_arr[i], fte, niter, off, len);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ste_rdwr_trunc(const struct ft_stress_executor *ste)
{
	uint8_t *buf1 = ft_new_buf_rands(ste->fte, ste->len);
	uint8_t *buf2 = ft_new_buf_rands(ste->fte, ste->len);
	uint8_t byte = 0;
	size_t iter = 0;
	int fd1 = -1;
	int fd2 = -1;

	ft_open(ste->path, O_WRONLY, 0600, &fd1);
	ft_open(ste->path, O_RDONLY, 0600, &fd2);
	while (ste->keep_run && (iter++ < ste->niter)) {
		byte = (uint8_t)(iter + 1);
		buf1[0] = byte;
		ft_ftruncate(fd1, ste->end);
		ft_pwriten(fd1, buf1, ste->len, ste->off);
		ft_preadn(fd2, buf2, ste->len, ste->off);
		ft_expect_eqm(buf1, buf2, ste->len);
		ft_ftruncate(fd1, ste->end - 1);
		ft_ftruncate(fd1, ste->end);
		ft_preadn(fd2, &byte, 1, ste->end - 1);
		ft_expect_eq(byte, 0);
		ft_ftruncate(fd1, ste->off + 1);
		ft_ftruncate(fd1, ste->off + 2);
		ft_preadn(fd2, &byte, 1, ste->off);
		ft_expect_eq(byte, buf1[0]);
		ft_preadn(fd2, &byte, 1, ste->off + 1);
		ft_expect_eq(byte, 0);
		ft_ftruncate(fd1, 0);
	}
	ft_close(fd1);
	ft_close(fd2);
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

static void ste_rdwr_with_xattr(const struct ft_stress_executor *ste)
{
	char name1[64] = "";
	char name2[64] = "";
	const size_t valsz_max = 1024;
	uint8_t *buf1 = ft_new_buf_rands(ste->fte, ste->len);
	uint8_t *buf2 = ft_new_buf_rands(ste->fte, ste->len);
	uint8_t *buf3 = ft_new_buf_rands(ste->fte, ste->len);
	void *val1 = ft_new_buf_rands(ste->fte, valsz_max);
	void *val2 = ft_new_buf_rands(ste->fte, valsz_max);
	void *val3 = ft_new_buf_rands(ste->fte, valsz_max);
	size_t valsz = 0;
	size_t iter = 0;
	size_t sz = 0;
	int fd = -1;

	ft_open(ste->path, O_RDWR, 0, &fd);
	while (ste->keep_run && (iter++ < ste->niter)) {
		snprintf(name1, sizeof(name1) - 1, "user.xattr1-%lu", iter);
		snprintf(name2, sizeof(name2) - 1, "user.xattr2-%lu", iter);
		valsz = (iter % (valsz_max - 1)) + 1;
		ft_fsetxattr(fd, name1, val1, valsz, 0);
		ft_fgetxattr(fd, name1, NULL, 0, &sz);
		ft_expect_eq(sz, valsz);
		ft_pwriten(fd, buf1, ste->len, ste->off);
		ft_fgetxattr(fd, name1, val2, valsz, &sz);
		ft_expect_eq(sz, valsz);
		ft_expect_eqm(val1, val2, valsz);
		ft_preadn(fd, buf2, ste->len, ste->off);
		ft_expect_eqm(buf1, buf2, ste->len);
		valsz = ((iter + 11) % (valsz_max - 1)) + 1;
		ft_fsetxattr(fd, name1, val3, valsz, XATTR_REPLACE);
		ft_fsetxattr(fd, name2, val2, valsz, 0);
		ft_pwriten(fd, buf3, ste->len - 1, ste->off);
		ft_fgetxattr(fd, name1, val2, valsz, &sz);
		ft_expect_eq(sz, valsz);
		ft_expect_eqm(val3, val2, valsz);
		ft_fremovexattr(fd, name1);
		ft_ftruncate(fd, ste->off + (ssize_t)iter);
		ft_fremovexattr(fd, name2);
		buf1[(iter + 1) % ste->len] = (uint8_t)iter;
		buf3[iter % ste->len] = (uint8_t)iter;
	}
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_rdwr_trunc(struct silofs_thread *th)
{
	ste_rdwr_trunc(th->arg);
	return 0;
}

static void stress_rw_trunc_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_stress_executor ste[10];
	const size_t nste = FT_ARRAY_SIZE(ste);

	ste_nsetup_uniq(ste, nste, fte, 100, off, len);
	ste_ncreate(ste, nste);
	ste_nrun(ste, nste, do_rdwr_trunc);
	ste_nwait(ste, nste);
	ste_njoin(ste, nste);
	ste_nunlink(ste, nste);
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
	const size_t nste = FT_ARRAY_SIZE(ste);

	ste_nsetup_uniq(ste, nste, fte, 100, off, len);
	ste_ncreate(ste, nste);
	ste_nrun(ste, nste, do_rewrite_over);
	ste_nwait(ste, nste);
	ste_njoin(ste, nste);
	ste_nunlink(ste, nste);
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

static int do_rdwr_with_xattr(struct silofs_thread *th)
{
	ste_rdwr_with_xattr(th->arg);
	return 0;
}

static void stress_rw_xattr_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_stress_executor ste[10];
	const size_t nste = FT_ARRAY_SIZE(ste);

	ste_nsetup_uniq(ste, nste, fte, 1000, off, len);
	ste_ncreate(ste, nste);
	ste_nrun(ste, nste, do_rdwr_with_xattr);
	ste_nwait(ste, nste);
	ste_njoin(ste, nste);
	ste_nunlink(ste, nste);
}

static void stress_rw_xattr(struct ft_env *fte)
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

	ft_exec_with_ranges(fte, stress_rw_xattr_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(stress_rw_trunc),
	FT_DEFTEST(stress_rw_over),
	FT_DEFTEST(stress_rw_xattr),
};

const struct ft_tests ft_stress_rw = FT_DEFTESTS(ft_local_tests);
