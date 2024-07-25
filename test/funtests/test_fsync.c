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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fsync(3p) to return 0 after regular file write/read operation.
 */
static void test_fsync_reg_(struct ft_env *fte, loff_t base_off,
                            size_t bsz, loff_t step, size_t cnt)
{
	const char *path = ft_new_path_unique(fte);
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	loff_t off = -1;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		off = base_off + ((loff_t)i  * step);
		ft_pwriten(fd, buf1, bsz, off);
		ft_fsync(fd);
		ft_preadn(fd, buf2, bsz, off);
		ft_expect_eqm(buf1, buf2, bsz);
		buf2 = buf1;
		buf1 = ft_new_buf_rands(fte, bsz);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_fsync_reg_aligned(struct ft_env *fte)
{
	test_fsync_reg_(fte, 0, FT_1K, FT_1M, 100);
	ft_relax_mem(fte);
	test_fsync_reg_(fte, FT_1M, FT_64K, FT_1G, 100);
}

static void test_fsync_reg_unaligned(struct ft_env *fte)
{
	test_fsync_reg_(fte, 1, FT_1K - 1, FT_1M + 1, 100);
	ft_relax_mem(fte);
	test_fsync_reg_(fte, FT_1M - 1, 3 * FT_1K + 1, FT_1G - 1, 100);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fsync(3p) to return 0 after directory operations.
 */
static void test_fsync_dir_(struct ft_env *fte, size_t cnt)
{
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = NULL;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		path2 = ft_new_pathf(fte, path1, "%08x", i + 1);
		ft_creat(path2, 0640, &fd);
		ft_fsync(dfd);
		ft_close(fd);
		ft_fsync(dfd);
	}
	for (size_t j = 0; j < cnt; ++j) {
		path2 = ft_new_pathf(fte, path1, "%08x", j + 1);
		ft_unlink(path2);
		ft_fsync(dfd);
	}
	ft_close(dfd);
	ft_rmdir(path1);
}

static void test_fsync_dir(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_fsync_dir_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful fsync(3p) and stat(3p) on directory-fd in combination
 * with openat(2), renameat(2) and I/O calls.
 */
static void test_fsync_dir_io_(struct ft_env *fte, loff_t off_base, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name1 = NULL;
	const char *name2 = NULL;
	void *buf;
	size_t len;
	loff_t off;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		name1 = ft_new_namef(fte, "1-%08x", i + 1);
		name2 = ft_new_namef(fte, "2-%08x", i + 1);
		ft_openat(dfd, name1, O_CREAT | O_RDWR, 0600, &fd);
		ft_fsync(dfd);
		len = ft_strlen(name1);
		off = off_base + (long)i;
		ft_pwriten(fd, name1, len, off);
		ft_fsync(fd);
		ft_close(fd);
		ft_renameat(dfd, name1, dfd, name2);
	}
	for (size_t j = 0; j < cnt; ++j) {
		name1 = ft_new_namef(fte, "1-%08x", j + 1);
		name2 = ft_new_namef(fte, "2-%08x", j + 1);
		ft_fstatat(dfd, name2, &st, 0);
		ft_expect_st_reg(&st);
		ft_openat(dfd, name2, O_RDONLY, 0600, &fd);
		ft_unlinkat(dfd, name2, 0);
		ft_fsync(dfd);
		len = ft_strlen(name1);
		off = off_base + (long)j;
		buf = ft_new_buf_zeros(fte, len);
		ft_preadn(fd, buf, len, off);
		ft_close(fd);
		ft_expect_eqm(buf, name1, len);
	}
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_fsync_dir_io(struct ft_env *fte)
{
	const loff_t off[] = { 0, FT_64K, FT_1M, FT_1T };
	size_t cnt = 10;

	for (size_t i = 0; i < FT_ARRAY_SIZE(off); ++i) {
		test_fsync_dir_io_(fte, off[i], cnt);
		cnt *= 10;
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects syncfs(2) to return 0
 */
static void test_syncfs_simple(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_syncfs(fd);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful syncfs via ioctl.
 */
static void test_syncfs_by_ioctl(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	int dfd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_ioctl_syncfs(dfd);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_fsync_reg_aligned),
	FT_DEFTEST(test_fsync_reg_unaligned),
	FT_DEFTEST(test_fsync_dir),
	FT_DEFTEST(test_fsync_dir_io),
	FT_DEFTEST(test_syncfs_simple),
	FT_DEFTEST(test_syncfs_by_ioctl),
};

const struct ft_tests ft_test_fsync = FT_DEFTESTS(ft_local_tests);
