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
 * Expects stat(3p) to successfully probe directory and return ENOENT if a
 * component of path does not name an existing file or path is an empty string.
 */
static void test_stat_simple(struct ft_env *fte)
{
	struct stat st;
	const mode_t ifmt = S_IFMT;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);

	ft_mkdir(path0, 0700);
	ft_stat(path0, &st);
	ft_expect_dir(st.st_mode);
	ft_expect_eq((int)(st.st_mode & ~ifmt), 0700);
	ft_expect_eq((long)st.st_nlink, 2);
	ft_stat_noent(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects stat(3p) to return ENOTDIR if a component of the path prefix is not
 * a directory.
 */
static void test_stat_notdir(struct ft_env *fte)
{
	int fd = -1;
	struct stat st;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);

	ft_mkdir(path0, 0700);
	ft_stat(path0, &st);
	ft_expect_dir(st.st_mode);
	ft_open(path1, O_CREAT | O_RDWR, 0644, &fd);
	ft_stat(path1, &st);
	ft_expect_reg(st.st_mode);
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
 * Expects statx(2) to return valid and constant birth time.
 */
static void test_statx_btime(struct ft_env *fte)
{
	int fd = -1;
	int dfd = -1;
	struct statx stx[2];
	const char *name = ft_new_name_unique(fte);
	const char *path = ft_new_path_unique(fte);
	const int flags = AT_STATX_FORCE_SYNC;

	ft_mkdir(path, 0750);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);

	ft_statx(dfd, name, flags, STATX_ALL, &stx[0]);
	if (!(stx[0].stx_mask & STATX_BTIME)) {
		goto out; /* no FUSE statx */
	}
	ft_expect_eq(stx[0].stx_mask & STATX_ALL, STATX_ALL);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[0].stx_mtime);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[0].stx_ctime);
	ft_suspends(fte, 1);
	ft_writen(fd, name, strlen(name));
	ft_statx(dfd, name, flags, STATX_ALL, &stx[1]);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[1].stx_btime);
	ft_expect_xts_gt(&stx[1].stx_btime, &stx[1].stx_mtime);
	ft_expect_xts_gt(&stx[1].stx_btime, &stx[1].stx_ctime);
out:
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_stat_simple),
	FT_DEFTEST(test_stat_notdir),
	FT_DEFTESTF(test_stat_statvfs, FT_F_STAVFS),
	FT_DEFTEST(test_statx_btime),
};

const struct ft_tests ft_test_stat = FT_DEFTESTS(ft_local_tests);
