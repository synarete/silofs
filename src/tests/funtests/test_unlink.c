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
 * Expects successful unlink(3p) of directory entry.
 */
static void test_unlink_reg(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_unlink_noent(path);
	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_close(fd);
	ft_lstat(path, &st);
	ft_expect_st_reg(&st);
	ft_unlink(path);
	ft_unlink_noent(path);
	ft_lstat_err(path, -ENOENT);
}

static void test_unlink_symlink(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	int fd = -1;

	ft_unlink_noent(path0);
	ft_creat(path0, 0600, &fd);
	ft_close(fd);
	ft_symlink(path0, path1);
	ft_lstat(path1, &st);
	ft_expect_true(S_ISLNK(st.st_mode));
	ft_unlink(path1);
	ft_unlink_noent(path1);
	ft_unlink(path0);
	ft_unlink_noent(path0);
}

static void test_unlink_fifo(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);

	ft_unlink_noent(path);
	ft_mkfifo(path, 0644);
	ft_lstat(path, &st);
	ft_expect_st_fifo(&st);
	ft_unlink(path);
	ft_unlink_noent(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlink(3p) to return -ENOTDIR if a component of the path prefix
 * is not a directory.
 */
static void test_unlink_notdir(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);
	int fd = -1;

	ft_mkdir(path0, 0755);
	ft_stat(path0, &st);
	ft_open(path1, O_CREAT | O_RDWR, 0700, &fd);
	ft_close(fd);
	ft_unlink_err(path2, -ENOTDIR);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlink(3p) to return -EISDIR if target is a directory
 */
static void test_unlink_isdir(struct ft_env *fte)
{
	struct stat st = { .st_mode = 0 };
	const char *path = ft_new_path_unique(fte);

	ft_mkdir(path, 0700);
	ft_stat(path, &st);
	ft_expect_st_dir(&st);
	ft_unlink_err(path, -EISDIR);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlinkat(3p) to operate using dir-fd.
 */
static void test_unlinkat_simple(struct ft_env *fte)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st[0]);
	ft_fstatat(dfd, name, &st[1], 0);
	ft_expect_eq(st[0].st_ino, st[1].st_ino);
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_fstatat_err(dfd, name, 0, -ENOENT);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlinkat(3p) to operate with I/O
 */
static void test_unlinkat_io_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	void *data = ft_new_buf_zeros(fte, len);
	const loff_t end = ft_off_end(off, len);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, len, off);
	ft_fstatat(dfd, name, &st, 0);
	ft_expect_eq(st.st_size, end);
	ft_preadn(fd, data, len, off);
	ft_expect_eqm(data, buf1, len);
	ft_pwriten(fd, buf2, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, end);
	ft_preadn(fd, data, len, off);
	ft_expect_eqm(data, buf2, len);
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_fstatat_err(dfd, name, 0, -ENOENT);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_unlinkat_io_simple(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_1G, FT_1M),
	};

	ft_exec_with_ranges(fte, test_unlinkat_io_, ranges);
}

static void test_unlinkat_io(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_1K, FT_1K),
		FT_MKRANGE(2 * FT_1K, 2 * FT_4K),
		FT_MKRANGE(FT_4K, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_64K - FT_4K, 4 * FT_64K),
		FT_MKRANGE(FT_1M, FT_4K),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, 8 * FT_1M),
		/* unaligned */
		FT_MKRANGE(11, 11 * FT_1K + 111),
		FT_MKRANGE(FT_1K - 1, 2 * FT_1K),
		FT_MKRANGE(FT_4K - 1, FT_4K + 3),
		FT_MKRANGE(FT_64K - 1, FT_64K + 3),
		FT_MKRANGE(FT_1M - 1, FT_4K + 11),
		FT_MKRANGE(FT_1G - 11, FT_1M + 111),
		FT_MKRANGE(FT_1T - 111, 11 * FT_1M - 1111),
	};

	ft_exec_with_ranges(fte, test_unlinkat_io_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlinkat(3p) to recreate files with same name when previous one with
 * same-name has been unlinked but still open.
 */
static void test_unlinkat_same_name(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	size_t nfds = 0;
	int fds[64];
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < FT_ARRAY_SIZE(fds); ++i) {
		ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
		ft_unlinkat(dfd, name, 0);
		ft_pwriten(fd, &fd, sizeof(fd), fd);
		ft_fstat(dfd, &st);
		ft_expect_eq(st.st_nlink, 2);
		fds[nfds++] = fd;
	}
	for (size_t j = 0; j < FT_ARRAY_SIZE(fds); ++j) {
		fd = fds[j];
		ft_preadn(fd, &fd, sizeof(fd), fd);
		ft_expect_eq(fd, fds[j]);
		ft_fstat(fd, &st);
		ft_close(fd);
	}
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_unlink_reg),
	FT_DEFTEST(test_unlink_symlink),
	FT_DEFTEST(test_unlink_fifo),
	FT_DEFTEST(test_unlink_notdir),
	FT_DEFTEST(test_unlink_isdir),
	FT_DEFTEST(test_unlinkat_simple),
	FT_DEFTEST(test_unlinkat_io_simple),
	FT_DEFTEST(test_unlinkat_io),
	FT_DEFTEST(test_unlinkat_same_name),
};

const struct ft_tests ft_test_unlink = FT_DEFTESTS(ft_local_tests);

