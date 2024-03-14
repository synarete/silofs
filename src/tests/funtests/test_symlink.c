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
 * Expects symlink(3p) to successfully create symbolic-links.
 */
static void test_symlink_simple(struct ft_env *fte)
{
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const mode_t ifmt = S_IFMT;
	int fd = -1;

	ft_creat(path0, 0600, &fd);
	ft_stat(path0, &st[0]);
	ft_expect_st_reg(&st[0]);
	ft_symlink(path0, path1);
	ft_stat(path1, &st[1]);
	ft_expect_eq(st[0].st_ino, st[1].st_ino);
	ft_lstat(path1, &st[1]);
	ft_expect_ne(st[0].st_ino, st[1].st_ino);
	ft_expect_st_lnk(&st[1]);
	ft_expect_eq((st[1].st_mode & ~ifmt), 0777);
	ft_unlink(path1);
	ft_stat_noent(path1);
	ft_unlink(path0);
	ft_stat_noent(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects readlink(3p) to successfully read symbolic-links and return EINVAL
 * if the path argument names a file that is not a symbolic link.
 */
static void test_symlink_readlink(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	char buf1[2] = "";
	const size_t bsz = SILOFS_PATH_MAX;
	char *buf = ft_new_buf_zeros(fte, bsz);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	size_t nch = 0;
	int fd = -1;

	ft_creat(path0, 0600, &fd);
	ft_symlink(path0, path1);
	ft_lstat(path1, &st);
	ft_expect_st_lnk(&st);
	ft_expect_eq(st.st_size, strlen(path0));

	ft_readlink(path1, buf, bsz, &nch);
	ft_expect_eq(nch, strlen(path0));
	ft_expect_eq(strncmp(buf, path0, nch), 0);
	ft_readlink_err(path0, buf, bsz, -EINVAL);
	ft_readlink_err(path2, buf, bsz, -ENOENT);

	ft_readlink(path1, buf1, 1, &nch);
	ft_expect_eq(nch, 1);
	ft_expect_eq(buf1[0], path0[0]);

	ft_unlink(path1);
	ft_unlink(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects readlink(3p) to update symlink access-time.
 */
static void test_symlink_readlink_atime(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const size_t bsz = SILOFS_PATH_MAX;
	char *buf = ft_new_buf_zeros(fte, bsz);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	time_t atime[2];
	size_t nch = 0;

	ft_mkdir(path0, 0700);
	ft_symlink(path0, path1);
	ft_lstat(path1, &st);
	ft_expect_st_lnk(&st);
	ft_expect_eq(st.st_size, strlen(path0));

	atime[0] = st.st_atim.tv_sec;
	ft_readlink(path1, buf, bsz, &nch);
	ft_lstat(path1, &st);
	atime[1] = st.st_atim.tv_sec;
	ft_expect_eqm(buf, path0, nch);
	ft_expect_le(atime[0], atime[1]);
	ft_suspend(fte, 3, 2);
	ft_readlink(path1, buf, bsz, &nch);
	ft_lstat(path1, &st);
	atime[1] = st.st_atim.tv_sec;
	ft_expect_eqm(buf, path0, nch);
	ft_expect_le(atime[0], atime[1]); /* XXX _lt */

	ft_unlink(path1);
	ft_rmdir(path0);
	ft_lstat_err(path1, -ENOENT);
	ft_stat_err(path0, -ENOENT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects symlink(3p) to successfully create symbolic-links in various length.
 */
static char *ft_new_path_dummy(struct ft_env *fte, size_t len)
{
	size_t cnt = 0;
	const size_t lim = (2 * len);
	char *name = ft_new_name_unique(fte);
	char *path = ft_new_buf_zeros(fte, lim + 1);

	while ((cnt = strlen(path)) < len) {
		snprintf(path + cnt, lim - cnt, "/%s", name);
	}
	path[len] = '\0';
	return path;
}

static void test_symlink_anylen_(struct ft_env *fte, size_t len)
{
	struct stat st = { .st_size = -1 };
	const mode_t ifmt = S_IFMT;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_dummy(fte, len);
	char *lnkbuf = ft_new_buf_zeros(fte, len + 1);
	size_t nch = 0;

	ft_symlink(path1, path0);
	ft_lstat(path0, &st);
	ft_expect_st_lnk(&st);
	ft_expect_eq((st.st_mode & ~ifmt), 0777);
	ft_readlink(path0, lnkbuf, len, &nch);
	ft_expect_eq(len, nch);
	ft_expect_eq(strncmp(path1, lnkbuf, len), 0);
	ft_unlink(path0);
}

static void test_symlink_anylen(struct ft_env *fte)
{
	const size_t symval_len_max = SILOFS_SYMLNK_MAX;

	for (size_t i = 1; i < symval_len_max; ++i) {
		test_symlink_anylen_(fte, i);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects symlink(3p) to successfully create symbolic-links in various length
 * while mixed with I/O operations.
 */
static void fill_name(char *name, size_t lim, size_t idx)
{
	snprintf(name, lim, "%061lx", idx);
}

static void test_symlink_with_io_(struct ft_env *fte, size_t cnt)
{
	char name[SILOFS_NAME_MAX + 1] = "";
	struct stat st = { .st_size = -1 };
	char *symval = NULL;
	char *buf = ft_new_buf_zeros(fte, 2 * cnt);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const mode_t ifmt = S_IFMT;
	size_t nch = 0;
	loff_t off = -1;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_open(path0, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 1; i < cnt; ++i) {
		fill_name(name, sizeof(name), i);
		symval = ft_new_path_dummy(fte, i);
		ft_symlinkat(symval, dfd, name);
		ft_fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		ft_expect_st_lnk(&st);
		off = (loff_t)(i * cnt);
		ft_pwriten(fd, symval, i, off);
	}
	for (size_t i = 1; i < cnt; ++i) {
		fill_name(name, sizeof(name), i);
		ft_fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		ft_expect_st_lnk(&st);
		symval = ft_new_path_dummy(fte, i + 1);
		ft_readlinkat(dfd, name, symval, i + 1, &nch);
		ft_expect_eq(nch, i);
		off = (loff_t)(i * cnt);
		ft_preadn(fd, buf, i, off);
		ft_expect_eqm(buf, symval, i);
	}
	for (size_t i = 1; i < cnt; ++i) {
		fill_name(name, sizeof(name), i);
		ft_fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		ft_expect_st_lnk(&st);
		ft_expect_eq((st.st_mode & ~ifmt), 0777);
		ft_unlinkat(dfd, name, 0);
		ft_fstatat_err(dfd, name, 0, -ENOENT);
	}
	ft_close(fd);
	ft_unlink(path1);
	ft_close(dfd);
	ft_rmdir(path0);
}

static void test_symlink_with_io(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100, SILOFS_SYMLNK_MAX };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_symlink_with_io_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects symlinkat(2)/readlinkat(2).
 */
static void test_symlinkat_simple(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *rname = ft_new_name_unique(fte);
	const char *sname = ft_new_name_unique(fte);
	const char *dpath = ft_new_path_unique(fte);
	const char *rpath = ft_new_path_nested(fte, dpath, rname);
	const char *spath = ft_new_path_nested(fte, dpath, sname);
	const size_t symval_bsz = 4096;
	char *symval = ft_new_buf_zeros(fte, symval_bsz);
	size_t len = 0;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(dpath, 0700);
	ft_open(dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, rname, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);
	ft_symlinkat(rpath, dfd, sname);
	ft_fstatat(dfd, sname, &st, AT_SYMLINK_NOFOLLOW);
	ft_expect_st_lnk(&st);
	ft_fstatat(dfd, sname, &st, 0);
	ft_expect_st_reg(&st);
	ft_stat(spath, &st);
	ft_expect_st_reg(&st);
	ft_readlinkat(dfd, sname, symval, symval_bsz, &len);
	ft_expect_eq(len, strlen(rpath));
	ft_expect_eqm(symval, rpath, len);
	ft_unlinkat(dfd, sname, 0);
	ft_fstatat_err(dfd, sname, 0, -ENOENT);
	ft_unlinkat(dfd, rname, 0);
	ft_fstatat_err(dfd, sname, 0, -ENOENT);
	ft_close(dfd);
	ft_rmdir(dpath);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_symlink_simple),
	FT_DEFTEST(test_symlink_readlink),
	FT_DEFTEST(test_symlink_readlink_atime),
	FT_DEFTEST(test_symlink_anylen),
	FT_DEFTEST(test_symlink_with_io),
	FT_DEFTEST(test_symlinkat_simple),
};

const struct ft_tests ft_test_symlink = FT_DEFTESTS(ft_local_tests);
