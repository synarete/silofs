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
#include "vfstests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful unlink(3p) of directory entry.
 */
static void test_unlink_reg(struct vt_env *vte)
{
	int fd = -1;
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0700, &fd);
	vt_close(fd);
	vt_lstat(path, &st);
	vt_expect_reg(st.st_mode);
	vt_unlink(path);
	vt_unlink_noent(path);
	vt_lstat_err(path, -ENOENT);
}

static void test_unlink_symlink(struct vt_env *vte)
{
	int fd;
	struct stat st;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);

	vt_creat(path0, 0600, &fd);
	vt_close(fd);
	vt_symlink(path0, path1);
	vt_lstat(path1, &st);
	vt_expect_true(S_ISLNK(st.st_mode));
	vt_unlink(path1);
	vt_unlink_noent(path1);
	vt_unlink(path0);
	vt_unlink_noent(path0);
}

static void test_unlink_fifo(struct vt_env *vte)
{
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_mkfifo(path, 0644);
	vt_lstat(path, &st);
	vt_expect_true(S_ISFIFO(st.st_mode));
	vt_unlink(path);
	vt_unlink_noent(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlink(3p) to return -ENOTDIR if a component of the path prefix
 * is not a directory.
 */
static void test_unlink_notdir(struct vt_env *vte)
{
	int fd = -1;
	struct stat st;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);

	vt_mkdir(path0, 0755);
	vt_stat(path0, &st);
	vt_open(path1, O_CREAT | O_RDWR, 0700, &fd);
	vt_close(fd);
	vt_unlink_err(path2, -ENOTDIR);
	vt_unlink(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlink(3p) to return -EISDIR if target is a directory
 */
static void test_unlink_isdir(struct vt_env *vte)
{
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0700);
	vt_stat(path, &st);
	vt_expect_dir(st.st_mode);
	vt_unlink_err(path, -EISDIR);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects unlinkat(3p) to recreate files with same name when previous one with
 * same-name has been unlinked but still open.
 */
static void test_unlinkat_same_name(struct vt_env *vte)
{
	int dfd = -1;
	int fd = -1;
	int fds[64];
	size_t nfds = 0;
	struct stat st;
	const char *path = vt_new_path_unique(vte);
	const char *name = vt_new_name_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < VT_ARRAY_SIZE(fds); ++i) {
		vt_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
		vt_unlinkat(dfd, name, 0);
		vt_pwriten(fd, &fd, sizeof(fd), fd);
		vt_fstat(dfd, &st);
		vt_expect_eq(st.st_nlink, 2);
		fds[nfds++] = fd;
	}
	for (size_t j = 0; j < VT_ARRAY_SIZE(fds); ++j) {
		fd = fds[j];
		vt_preadn(fd, &fd, sizeof(fd), fd);
		vt_expect_eq(fd, fds[j]);
		vt_fstat(fd, &st);
		vt_close(fd);
	}
	vt_close(dfd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_unlink_reg),
	VT_DEFTEST(test_unlink_symlink),
	VT_DEFTEST(test_unlink_fifo),
	VT_DEFTEST(test_unlink_notdir),
	VT_DEFTEST(test_unlink_isdir),
	VT_DEFTEST(test_unlinkat_same_name),
};

const struct vt_tests vt_test_unlink = VT_DEFTESTS(vt_local_tests);


