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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful unlink(3p) of directory entry.
 */
static void test_unlink_reg(struct ft_env *fte)
{
	int fd = -1;
	struct stat st;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_close(fd);
	ft_lstat(path, &st);
	ft_expect_reg(st.st_mode);
	ft_unlink(path);
	ft_unlink_noent(path);
	ft_lstat_err(path, -ENOENT);
}

static void test_unlink_symlink(struct ft_env *fte)
{
	int fd;
	struct stat st;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);

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
	struct stat st;
	const char *path = ft_new_path_unique(fte);

	ft_mkfifo(path, 0644);
	ft_lstat(path, &st);
	ft_expect_true(S_ISFIFO(st.st_mode));
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
	int fd = -1;
	struct stat st;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);

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
	struct stat st;
	const char *path = ft_new_path_unique(fte);

	ft_mkdir(path, 0700);
	ft_stat(path, &st);
	ft_expect_dir(st.st_mode);
	ft_unlink_err(path, -EISDIR);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlinkat(3p) to recreate files with same name when previous one with
 * same-name has been unlinked but still open.
 */
static void test_unlinkat_same_name(struct ft_env *fte)
{
	int dfd = -1;
	int fd = -1;
	int fds[64];
	size_t nfds = 0;
	struct stat st;
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);

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
	FT_DEFTEST(test_unlinkat_same_name),
};

const struct ft_tests ft_test_unlink = FT_DEFTESTS(ft_local_tests);


