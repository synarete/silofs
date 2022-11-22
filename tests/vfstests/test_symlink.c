/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include "vfstests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects symlink(3p) to successfully create symbolic-links.
 */
static void test_symlink_simple(struct vt_env *vte)
{
	int fd = -1;
	struct stat st[2];
	const mode_t ifmt = S_IFMT;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);

	vt_creat(path0, 0600, &fd);
	vt_stat(path0, &st[0]);
	vt_expect_reg(st[0].st_mode);
	vt_expect_eq((st[0].st_mode & ~ifmt), 0600);

	vt_symlink(path0, path1);
	vt_stat(path1, &st[1]);
	vt_expect_eq(st[0].st_ino, st[1].st_ino);
	vt_lstat(path1, &st[1]);
	vt_expect_ne(st[0].st_ino, st[1].st_ino);
	vt_expect_lnk(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0777);
	vt_unlink(path1);
	vt_stat_noent(path1);
	vt_unlink(path0);
	vt_stat_noent(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects readlink(3p) to successfully read symbolic-links and return EINVAL
 * if the path argument names a file that is not a symbolic link.
 */
static void test_symlink_readlink(struct vt_env *vte)
{
	int fd = -1;
	size_t nch = 0;
	struct stat st;
	char buf1[2] = "";
	const size_t bsz = SILOFS_PATH_MAX;
	char *buf = vt_new_buf_zeros(vte, bsz);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_unique(vte);

	vt_creat(path0, 0600, &fd);
	vt_symlink(path0, path1);
	vt_lstat(path1, &st);
	vt_expect_lnk(st.st_mode);
	vt_expect_eq(st.st_size, strlen(path0));

	vt_readlink(path1, buf, bsz, &nch);
	vt_expect_eq(nch, strlen(path0));
	vt_expect_eq(strncmp(buf, path0, nch), 0);
	vt_readlink_err(path0, buf, bsz, -EINVAL);
	vt_readlink_err(path2, buf, bsz, -ENOENT);

	vt_readlink(path1, buf1, 1, &nch);
	vt_expect_eq(nch, 1);
	vt_expect_eq(buf1[0], path0[0]);

	vt_unlink(path1);
	vt_unlink(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects readlink(3p) to update symlink access-time.
 */
static void test_symlink_readlink_atime(struct vt_env *vte)
{
	size_t nch = 0;
	struct stat st;
	time_t atime[2];
	const size_t bsz = SILOFS_PATH_MAX;
	char *buf = vt_new_buf_zeros(vte, bsz);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);

	vt_mkdir(path0, 0700);
	vt_symlink(path0, path1);
	vt_lstat(path1, &st);
	vt_expect_lnk(st.st_mode);
	vt_expect_eq(st.st_size, strlen(path0));

	atime[0] = st.st_atim.tv_sec;
	vt_readlink(path1, buf, bsz, &nch);
	vt_lstat(path1, &st);
	atime[1] = st.st_atim.tv_sec;
	vt_expect_eqm(buf, path0, nch);
	vt_expect_le(atime[0], atime[1]);
	vt_suspend(vte, 3, 2);
	vt_readlink(path1, buf, bsz, &nch);
	vt_lstat(path1, &st);
	atime[1] = st.st_atim.tv_sec;
	vt_expect_eqm(buf, path0, nch);
	vt_expect_le(atime[0], atime[1]); /* XXX _lt */

	vt_unlink(path1);
	vt_rmdir(path0);
	vt_lstat_err(path1, -ENOENT);
	vt_stat_err(path0, -ENOENT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects symlink(3p) to successfully create symbolic-links in various length.
 */
static char *vt_new_path_dummy(struct vt_env *vte, size_t len)
{
	size_t cnt = 0;
	const size_t lim = (2 * len);
	char *name = vt_new_name_unique(vte);
	char *path = vt_new_buf_zeros(vte, lim + 1);

	while ((cnt = strlen(path)) < len) {
		snprintf(path + cnt, lim - cnt, "/%s", name);
	}
	path[len] = '\0';
	return path;
}

static void test_symlink_anylen_(struct vt_env *vte, size_t len)
{
	size_t nch = 0;
	struct stat st;
	const mode_t ifmt = S_IFMT;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_dummy(vte, len);
	char *lnkbuf = vt_new_buf_zeros(vte, len + 1);

	vt_symlink(path1, path0);
	vt_lstat(path0, &st);
	vt_expect_lnk(st.st_mode);
	vt_expect_eq((st.st_mode & ~ifmt), 0777);
	vt_readlink(path0, lnkbuf, len, &nch);
	vt_expect_eq(len, nch);
	vt_expect_eq(strncmp(path1, lnkbuf, len), 0);
	vt_unlink(path0);
}

static void test_symlink_anylen(struct vt_env *vte)
{
	const size_t symval_len_max = SILOFS_SYMLNK_MAX;

	for (size_t i = 1; i < symval_len_max; ++i) {
		test_symlink_anylen_(vte, i);
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

static void test_symlink_with_io_(struct vt_env *vte, size_t lim)
{
	int dfd = -1;
	int fd = -1;
	size_t nch = 0;
	loff_t off = 0;
	char *symval = NULL;
	struct stat st;
	const mode_t ifmt = S_IFMT;
	char name[SILOFS_NAME_MAX + 1] = "";
	char *buf = vt_new_buf_zeros(vte, 2 * lim);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0700);
	vt_open(path0, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 1; i < lim; ++i) {
		fill_name(name, sizeof(name), i);
		symval = vt_new_path_dummy(vte, i);
		vt_symlinkat(symval, dfd, name);
		vt_fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		vt_expect_lnk(st.st_mode);
		off = (loff_t)(i * lim);
		vt_pwriten(fd, symval, i, off);
	}
	for (size_t i = 1; i < lim; ++i) {
		fill_name(name, sizeof(name), i);
		vt_fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		vt_expect_lnk(st.st_mode);
		symval = vt_new_path_dummy(vte, i + 1);
		vt_readlinkat(dfd, name, symval, i + 1, &nch);
		vt_expect_eq(nch, i);
		off = (loff_t)(i * lim);
		vt_preadn(fd, buf, i, off);
		vt_expect_eqm(buf, symval, i);
	}
	for (size_t i = 1; i < lim; ++i) {
		fill_name(name, sizeof(name), i);
		vt_fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		vt_expect_lnk(st.st_mode);
		vt_expect_eq((st.st_mode & ~ifmt), 0777);
		vt_unlinkat(dfd, name, 0);
		vt_fstatat_err(dfd, name, 0, -ENOENT);
	}
	vt_close(fd);
	vt_unlink(path1);
	vt_close(dfd);
	vt_rmdir(path0);
}

static void test_symlink_with_io(struct vt_env *vte)
{
	test_symlink_with_io_(vte, 32);
	test_symlink_with_io_(vte, SILOFS_SYMLNK_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_symlink_simple),
	VT_DEFTEST(test_symlink_readlink),
	VT_DEFTEST(test_symlink_readlink_atime),
	VT_DEFTEST(test_symlink_anylen),
	VT_DEFTEST(test_symlink_with_io),
};

const struct vt_tests vt_test_symlink = VT_DEFTESTS(vt_local_tests);
