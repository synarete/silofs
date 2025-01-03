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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects stat(3p) to successfully probe directory and return ENOENT if a
 * component of path does not name an existing file or path is an empty string.
 */
static void test_stat_simple(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const mode_t ifmt = S_IFMT;

	ft_mkdir(path0, 0700);
	ft_stat(path0, &st);
	ft_expect_st_dir(&st);
	ft_expect_eq((int)(st.st_mode & ~ifmt), 0700);
	ft_expect_eq((long)st.st_nlink, 2);
	ft_stat_noent(path1);
	ft_rmdir(path0);
	ft_stat_noent(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects stat(3p) to return ENOTDIR if a component of the path prefix is not
 * a directory.
 */
static void test_stat_notdir(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_stat(path0, &st);
	ft_expect_st_dir(&st);
	ft_open(path1, O_CREAT | O_RDWR, 0644, &fd);
	ft_stat(path1, &st);
	ft_expect_st_reg(&st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);
	ft_stat_err(path2, -ENOTDIR);
	ft_unlink(path1);
	ft_rmdir(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to return valid result for dir-path, reg-path or rd-open
 * file-descriptor.
 */
static void test_stat_statvfs(struct ft_env *fte)
{
	struct statvfs stv[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);
	const char *path3 = ft_new_path_under(fte, path0);
	int fd = -1;

	ft_mkdir(path0, 0750);
	ft_creat(path1, 0644, &fd);
	ft_statvfs(path0, &stv[0]);
	ft_statvfs(path1, &stv[1]);
	ft_expect_true((stv[0].f_bavail > 0));
	ft_expect_eq(stv[0].f_fsid, stv[1].f_fsid);
	ft_fstatvfs(fd, &stv[1]);
	ft_expect_eq(stv[0].f_fsid, stv[1].f_fsid);
	ft_statvfs_err(path2, -ENOTDIR);
	ft_statvfs_err(path3, -ENOENT);
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fstatat(2) to successfully probe sub-directory components.
 */
static void test_fstatat_simple(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *dname = ft_new_name_unique(fte);
	const char *fname = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_mkdirat(dfd, dname, 0750);
	ft_openat(dfd, fname, O_CREAT | O_RDWR, 0600, &fd);
	ft_writen(fd, fname, ft_strlen(fname));
	ft_close(fd);
	ft_fstatat(dfd, dname, &st, 0);
	ft_expect_st_dir(&st);
	ft_fstatat(dfd, fname, &st, 0);
	ft_expect_st_reg(&st);
	ft_expect_gt(st.st_size, 0);
	ft_unlinkat(dfd, fname, 0);
	ft_unlinkat(dfd, dname, AT_REMOVEDIR);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_stat_simple),
	FT_DEFTEST(test_stat_notdir),
	FT_DEFTESTF(test_stat_statvfs, FT_F_STATVFS),
	FT_DEFTEST(test_fstatat_simple),
};

const struct ft_tests ft_test_stat = FT_DEFTESTS(ft_local_tests);
