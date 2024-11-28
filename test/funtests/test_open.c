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
 * Expects successful open(3p) with O_CREAT to set the file's access time
 */
static void test_open_atime(struct ft_env *fte)
{
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	int fd = -1;

	ft_mkdir(path0, 0755);
	ft_stat(path0, &st[0]);
	ft_suspend(fte, 3, 1);
	ft_open(path1, O_CREAT | O_WRONLY, 0644, &fd);
	ft_fstat(fd, &st[1]);
	ft_expect_true(st[0].st_atim.tv_sec < st[1].st_atim.tv_sec);
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful open(3p) with O_CREAT to update parent's ctime and mtime
 * only if file did *not* exist.
 */
static void test_open_mctime(struct ft_env *fte)
{
	struct stat st[4];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	int fd2 = -1;
	int fd1 = -1;

	ft_mkdir(path0, 0755);
	ft_stat(path0, &st[0]);
	ft_suspend(fte, 3, 2);
	ft_open(path1, O_CREAT | O_WRONLY, 0644, &fd1);
	ft_fstat(fd1, &st[1]);
	ft_expect_lt(st[0].st_mtim.tv_sec, st[1].st_mtim.tv_sec);
	ft_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	ft_stat(path0, &st[2]);
	ft_expect_lt(st[0].st_mtim.tv_sec, st[2].st_mtim.tv_sec);
	ft_expect_lt(st[0].st_ctim.tv_sec, st[2].st_ctim.tv_sec);
	ft_unlink(path1);
	ft_close(fd1);

	ft_creat(path1, 0644, &fd1);
	ft_fstat(fd1, &st[1]);
	ft_stat(path0, &st[0]);
	ft_suspend(fte, 3, 2);
	ft_open(path1, O_CREAT | O_RDONLY, 0644, &fd2);
	ft_fstat(fd2, &st[2]);
	ft_stat(path0, &st[3]);
	ft_expect_eq(st[1].st_mtim.tv_sec, st[2].st_mtim.tv_sec);
	ft_expect_eq(st[1].st_ctim.tv_sec, st[2].st_ctim.tv_sec);
	ft_expect_eq(st[0].st_mtim.tv_sec, st[3].st_mtim.tv_sec);
	ft_expect_eq(st[0].st_ctim.tv_sec, st[3].st_ctim.tv_sec);

	ft_unlink(path1);
	ft_rmdir(path0);
	ft_close(fd1);
	ft_close(fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) to return ELOOP if too many symbolic links are encountered
 * while resolving pathname, or O_NOFOLLOW was specified but pathname was a
 * symbolic link.
 */
static void test_open_loop(struct ft_env *fte)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_under(fte, path0);
	const char *path3 = ft_new_path_under(fte, path1);

	ft_symlink(path0, path1);
	ft_symlink(path1, path0);
	ft_open_err(path2, O_RDONLY, 0, -ELOOP);
	ft_open_err(path3, O_RDONLY, 0, -ELOOP);
	ft_unlink(path0);
	ft_unlink(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) to return EISDIR if the named file is a directory and
 * oflag includes O_WRONLY or O_RDWR.
 */
static void test_open_isdir(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_mkdir(path, 0755);
	ft_open(path, O_RDONLY, 0, &fd);
	ft_open_err(path, O_WRONLY, 0, -EISDIR);
	ft_open_err(path, O_RDWR, 0, -EISDIR);
	ft_open_err(path, O_RDONLY | O_TRUNC, 0, -EISDIR);
	ft_open_err(path, O_WRONLY | O_TRUNC, 0, -EISDIR);
	ft_open_err(path, O_RDWR | O_TRUNC, 0, -EISDIR);
	ft_close(fd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_TRUNC to reduce file-size to zero.
 */
static void test_open_trunc_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	void *buf = ft_new_buf_zeros(fte, len);
	const char *path = ft_new_path_unique(fte);
	int fd1 = -1;
	int fd2 = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_pwriten(fd1, buf, len, off);
	ft_fstat(fd1, &st);
	ft_expect_eq(st.st_size, off + (long)len);
	ft_expect_gt(st.st_blocks, 0);
	ft_close(fd1);
	ft_open(path, O_RDWR | O_TRUNC, 0, &fd1);
	ft_fstat(fd1, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);
	ft_pwriten(fd1, buf, len, off);
	ft_fstat(fd1, &st);
	ft_expect_eq(st.st_size, off + (long)len);
	ft_expect_gt(st.st_blocks, 0);
	ft_open(path, O_RDWR | O_TRUNC, 0, &fd2);
	ft_fstat(fd1, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);
	ft_close(fd1);
	ft_close(fd2);
	ft_unlink(path);
}

static void test_open_trunc(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_1K, FT_4K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G - 7, 7 * FT_1K),
		FT_MKRANGE(FT_1T - 11, FT_1M + 111),
	};

	ft_exec_with_ranges(fte, test_open_trunc_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_APPEND to set the file offset to the end prior to
 * each write.
 */
static void test_open_append_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	void *buf = ft_new_buf_zeros(fte, len);
	const char *path = ft_new_path_unique(fte);
	ssize_t sz = -1;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, off);
	ft_close(fd);
	ft_open(path, O_APPEND | O_RDWR, 0600, &fd);
	for (size_t i = 1; i <= 10; ++i) {
		ft_writen(fd, buf, len);
		sz = off + (ssize_t)(i * len);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, sz);
		ft_expect_gt(st.st_blocks, 0);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_open_append(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_1K, FT_4K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G - 7, 7 * FT_4K),
		FT_MKRANGE(FT_1T - 11, FT_1M + 111),
	};

	ft_exec_with_ranges(fte, test_open_append_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_open_atime),  //
	FT_DEFTEST(test_open_mctime), //
	FT_DEFTEST(test_open_loop),   //
	FT_DEFTEST(test_open_isdir),  //
	FT_DEFTEST(test_open_trunc),  //
	FT_DEFTEST(test_open_append), //
};

const struct ft_tests ft_test_open = FT_DEFTESTS(ft_local_tests);
