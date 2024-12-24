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
 * Expects statvfs(3p) to successfully obtain information about the file system
 * containing base-dir, and return ENOENT if a component of path does not name
 * an existing file.
 */
static void test_statvfs_simple(struct ft_env *fte)
{
	struct statvfs stv;
	const char *name = ft_new_name_unique(fte);
	const char *path = ft_new_path_name(fte, name);

	ft_statvfs(fte->params.testdir, &stv);
	ft_expect_gt(stv.f_bsize, 0);
	ft_expect_eq((stv.f_bsize % FT_FRGSIZE), 0);
	ft_expect_gt(stv.f_frsize, 0);
	ft_expect_eq(stv.f_frsize % FT_FRGSIZE, 0);
	ft_expect_gt(stv.f_namemax, ft_strlen(name));
	ft_statvfs_err(path, -ENOENT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to successfully obtain information about the file system
 * via open file-descriptor to regular-file.
 */
static void test_statvfs_reg(struct ft_env *fte)
{
	int fd = -1;
	struct statvfs stv;
	const char *path = ft_new_path_unique(fte);

	ft_creat(path, 0644, &fd);
	ft_fstatvfs(fd, &stv);
	ft_expect_gt(stv.f_bsize, 0);
	ft_expect_eq((stv.f_bsize % FT_FRGSIZE), 0);
	ft_expect_gt(stv.f_frsize, 0);
	ft_expect_eq((stv.f_frsize % FT_FRGSIZE), 0);
	ft_expect_lt(stv.f_bfree, stv.f_blocks);
	ft_expect_lt(stv.f_bavail, stv.f_blocks);
	ft_expect_lt(stv.f_ffree, stv.f_files);
	ft_expect_lt(stv.f_favail, stv.f_files);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to successfully obtain information about the file system
 * via open file-descriptor to directory
 */
static void test_statvfs_dir(struct ft_env *fte)
{
	int dfd = -1;
	struct statvfs stv;
	const char *path = ft_new_path_unique(fte);

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_fstatvfs(dfd, &stv);
	ft_expect_gt(stv.f_bsize, 0);
	ft_expect_eq((stv.f_bsize % FT_FRGSIZE), 0);
	ft_expect_gt(stv.f_frsize, 0);
	ft_expect_eq((stv.f_frsize % FT_FRGSIZE), 0);
	ft_expect_lt(stv.f_bfree, stv.f_blocks);
	ft_expect_lt(stv.f_bavail, stv.f_blocks);
	ft_expect_lt(stv.f_ffree, stv.f_files);
	ft_expect_lt(stv.f_favail, stv.f_files);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to return ENOTDIR if a component of the path prefix of
 * path is not a directory.
 */
static void test_statvfs_notdir(struct ft_env *fte)
{
	int fd = -1;
	struct statvfs stv[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);

	ft_mkdir(path0, 0700);
	ft_statvfs(path0, &stv[0]);
	ft_creat(path1, 0644, &fd);
	ft_fstatvfs(fd, &stv[1]);
	ft_statvfs_err(path2, -ENOTDIR);
	ft_unlink(path1);
	ft_rmdir(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to change statvfs.f_ffree upon objects create/unlink
 */
static void test_statvfs_ffree(struct ft_env *fte)
{
	int fd = -1;
	struct statvfs stv[2];
	char *dpath = ft_new_path_unique(fte);
	char *path0 = ft_new_path_under(fte, dpath);
	char *path1 = ft_new_path_under(fte, dpath);
	char *path2 = ft_new_path_under(fte, dpath);
	char *path3 = ft_new_path_under(fte, dpath);

	ft_mkdir(dpath, 0700);
	ft_statvfs(dpath, &stv[0]);
	ft_mkdir(path0, 0700);
	ft_statvfs(path0, &stv[1]);
	ft_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	ft_rmdir(path0);
	ft_statvfs(dpath, &stv[1]);
	ft_expect_eq(stv[0].f_ffree, stv[1].f_ffree);

	ft_statvfs(dpath, &stv[0]);
	ft_symlink(dpath, path1);
	ft_statvfs(path1, &stv[1]);
	ft_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	ft_unlink(path1);
	ft_statvfs(dpath, &stv[1]);
	ft_expect_eq(stv[0].f_ffree, stv[1].f_ffree);

	ft_statvfs(dpath, &stv[0]);
	ft_creat(path2, 0600, &fd);
	ft_close(fd);
	ft_statvfs(path2, &stv[1]);
	ft_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	ft_unlink(path2);
	ft_statvfs(dpath, &stv[1]);
	ft_expect_eq(stv[1].f_ffree, stv[0].f_ffree);

	ft_statvfs(dpath, &stv[0]);
	ft_creat(path3, 0600, &fd);
	ft_fstatvfs(fd, &stv[1]);
	ft_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	ft_unlink(path3);
	ft_statvfs(dpath, &stv[1]);
	ft_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	ft_close(fd);
	ft_statvfs(dpath, &stv[1]);
	ft_expect_eq(stv[0].f_ffree, stv[1].f_ffree);

	ft_rmdir(dpath);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to change statvfs.f_ffree upon sequence of creates
 * following sequence of unlinks.
 */
static void test_statvfs_ffree_nseq(struct ft_env *fte, size_t n)
{
	int fd = -1;
	struct statvfs stv[2];
	const char *fpath = NULL;
	const char *dpath = ft_new_path_unique(fte);

	ft_mkdir(dpath, 0700);
	ft_statvfs(dpath, &stv[0]);
	ft_statvfs(dpath, &stv[1]);

	for (size_t i = 0; i < n; ++i) {
		fpath = ft_new_pathf(fte, dpath, "%lu", i);
		ft_statvfs_err(fpath, -ENOENT);
		ft_creat(fpath, 0600, &fd);
		ft_close(fd);
		ft_statvfs(fpath, &stv[1]);
		ft_expect_eq((stv[0].f_ffree - (i + 1)), stv[1].f_ffree);
	}
	for (size_t j = n; j > 0; --j) {
		fpath = ft_new_pathf(fte, dpath, "%lu", (j - 1));
		ft_statvfs(fpath, &stv[1]);
		ft_expect_eq((stv[0].f_ffree - j), stv[1].f_ffree);
		ft_unlink(fpath);
	}

	ft_statvfs(dpath, &stv[1]);
	ft_expect_eq(stv[0].f_ffree, stv[1].f_ffree);
	ft_rmdir(dpath);
}

static void test_statvfs_ffree_seq(struct ft_env *fte)
{
	test_statvfs_ffree_nseq(fte, 16);
	test_statvfs_ffree_nseq(fte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to change statvfs.f_bfree upon write/trim.
 */
static void test_statvfs_bfree_(struct ft_env *fte, loff_t off, size_t bsz)
{
	struct stat st[2];
	struct statvfs stv[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st[0]);
	ft_fstatvfs(fd, &stv[0]);
	for (size_t i = 0; i < 2; ++i) {
		ft_pwriten(fd, buf1, bsz, off);
		ft_preadn(fd, buf2, bsz, off);
		ft_expect_eqm(buf1, buf2, bsz);
		ft_fstat(fd, &st[1]);
		ft_fstatvfs(fd, &stv[1]);
		ft_expect_gt(st[1].st_blocks, st[0].st_blocks);
		ft_expect_gt(stv[0].f_bfree, stv[1].f_bfree);
		ft_ftruncate(fd, 0);
		ft_fstat(fd, &st[1]);
		ft_fstatvfs(fd, &stv[1]);
		ft_expect_eq(st[1].st_blocks, st[0].st_blocks);
		ft_expect_eq(stv[1].f_bfree, stv[0].f_bfree);
	}
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

static void test_statvfs_bfree(struct ft_env *fte)
{
	test_statvfs_bfree_(fte, 0, FT_1M);
	test_statvfs_bfree_(fte, FT_1K, FT_1M - 1);
	test_statvfs_bfree_(fte, FT_BK_SIZE, 2 * FT_BK_SIZE);
	test_statvfs_bfree_(fte, FT_1M, FT_1M);
	test_statvfs_bfree_(fte, FT_1M + 1, FT_1M);
	test_statvfs_bfree_(fte, FT_1T - 11, FT_1M + 111);
	test_statvfs_bfree_(fte, FT_FILESIZE_MAX - FT_1M, FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTESTF(test_statvfs_simple, FT_F_STATVFS),
	FT_DEFTESTF(test_statvfs_reg, FT_F_STATVFS),
	FT_DEFTESTF(test_statvfs_dir, FT_F_STATVFS),
	FT_DEFTESTF(test_statvfs_notdir, FT_F_STATVFS),
	FT_DEFTESTF(test_statvfs_ffree, FT_F_STATVFS),
	FT_DEFTESTF(test_statvfs_ffree_seq, FT_F_STATVFS),
	FT_DEFTESTF(test_statvfs_bfree, FT_F_STATVFS),
};

const struct ft_tests ft_test_statvfs = FT_DEFTESTS(ft_local_tests);
