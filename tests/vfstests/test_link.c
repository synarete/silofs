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


/* Maximum hard-links per file */
static size_t get_link_max(void)
{
	long ret;
	const long lim = 2048;

	ret = sysconf(_PC_LINK_MAX);
	vt_expect_gt(ret, 0);
	vt_expect_lt(ret, VT_UGIGA);

	return (size_t)((ret < lim) ? ret : lim);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return EEXIST if the path2 argument resolves to an
 * existing file or refers to a symbolic link.
 */
static void test_link_exists(struct vt_env *vte)
{
	int fd0 = -1;
	int fd1 = -1;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_name(vte, "link-to-symlink-exist");

	vt_creat(path0, 0644, &fd0);
	vt_creat(path1, 0644, &fd1);

	vt_link_err(path0, path1, -EEXIST);
	vt_unlink(path1);

	vt_mkdir(path1, 0755);
	vt_link_err(path0, path1, -EEXIST);
	vt_rmdir(path1);

	vt_symlink(path1, path2);
	vt_link_err(path0, path2, -EEXIST);
	vt_unlink(path2);

	vt_mkfifo(path1, 0644);
	vt_link_err(path0, path1, -EEXIST);
	vt_unlink(path1);

	vt_unlink(path0);
	vt_close(fd0);
	vt_close(fd1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return ENOENT if the source file does not exist.
 */
static void test_link_noent(struct vt_env *vte)
{
	int fd = -1;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0700);
	vt_creat(path1, 0640, &fd);
	vt_link(path1, path2);
	vt_unlink(path1);
	vt_unlink(path2);
	vt_link_err(path1, path2, -ENOENT);
	vt_rmdir(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return EEXIST if a component of either path prefix is
 * not a directory.
 */
static void test_link_notdir(struct vt_env *vte)
{
	int fd1 = -1;
	int fd2 = -1;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path0);
	const char *path3 = vt_new_path_under(vte, path1);

	vt_mkdir(path0, 0755);
	vt_creat(path1, 0644, &fd1);
	vt_link_err(path3, path2, -ENOTDIR);
	vt_creat(path2, 0644, &fd2);
	vt_link_err(path2, path3, -ENOTDIR);
	vt_unlink(path1);
	vt_unlink(path2);
	vt_rmdir(path0);
	vt_close(fd1);
	vt_close(fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p)/unlink(3p) sequence to succeed for renamed links.
 */
static void test_link_rename_cnt(struct vt_env *vte, int cnt)
{
	int fd = -1;
	int nlink = 1;
	const int limit = cnt + 1;
	struct stat st;
	const char *name  = vt_new_name_unique(vte);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = NULL;
	const char *path3 = NULL;

	vt_mkdir(path0, 0700);
	vt_creat(path1, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_nlink, 1);
	nlink = (int)st.st_nlink;
	for (int i = nlink; i < limit; ++i) {
		path2 = vt_new_pathf(vte, path0, "%s-%d", name, i);
		path3 = vt_new_pathf(vte, path0, "%s-X-%d", name, i);
		vt_link(path1, path2);
		vt_rename(path2, path3);
		vt_unlink_noent(path2);
	}
	for (int i = limit - 1; i >= nlink; --i) {
		path3 = vt_new_pathf(vte, path0, "%s-X-%d", name, i);
		vt_unlink(path3);
	}
	vt_close(fd);
	vt_unlink(path1);
	vt_rmdir(path0);
}

static void test_link_rename(struct vt_env *vte)
{
	test_link_rename_cnt(vte, 1);
	test_link_rename_cnt(vte, 2);
	test_link_rename_cnt(vte, 300);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to succeed for link count less then LINK_MAX.
 */
static void test_link_max(struct vt_env *vte)
{
	int fd = -1;
	nlink_t nlink = 0;
	struct stat st;
	const char *name  = vt_new_name_unique(vte);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = NULL;
	const size_t link_max = get_link_max();

	vt_mkdir(path0, 0700);
	vt_creat(path1, 0600, &fd);
	vt_fstat(fd, &st);
	nlink = st.st_nlink;
	for (size_t i = nlink; i < link_max; ++i) {
		path2 = vt_new_pathf(vte, path0, "%s-%lu", name, i);
		vt_link(path1, path2);
	}
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_nlink, link_max);
	for (size_t j = nlink; j < link_max; ++j) {
		path2 = vt_new_pathf(vte, path0, "%s-%lu", name, j);
		vt_unlink(path2);
	}
	vt_close(fd);
	vt_unlink(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to not return EMLINK if the link count of the file is less
 * then LINK_MAX.
 */
static void test_link_limit(struct vt_env *vte)
{
	int fd = -1;
	nlink_t nlink = 0;
	struct stat st;
	const char *name = vt_new_name_unique(vte);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = NULL;
	const size_t link_max = get_link_max();

	vt_mkdir(path0, 0750);
	vt_creat(path1, 0640, &fd);
	vt_fstat(fd, &st);
	nlink = st.st_nlink;
	for (size_t i = nlink; i < link_max; ++i) {
		path2 = vt_new_pathf(vte, path0, "%d-%s", i, name);
		vt_link(path1, path2);
	}
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_nlink, link_max);
	for (size_t i = nlink; i < link_max; i += 2) {
		path2 = vt_new_pathf(vte, path0, "%d-%s", i, name);
		vt_unlink(path2);
	}
	for (size_t i = (nlink + 1); i < link_max; i += 2) {
		path2 = vt_new_pathf(vte, path0, "%d-%s", i, name);
		vt_unlink(path2);
	}
	vt_unlink(path1);
	vt_rmdir(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to succeed for names which may cause avalanche effect on
 * poor hash-based directories.
 */
static const char *make_name(struct vt_env *vte, char c, size_t len)
{
	size_t nlen;
	char name[SILOFS_NAME_MAX + 1] = "";

	nlen = (len < sizeof(name)) ? len : (sizeof(name) - 1);
	memset(name, c, nlen);
	return vt_strdup(vte, name);
}

static void test_link_similar_names(struct vt_env *vte)
{
	int fd = -1;
	struct stat st;
	const char *name = NULL;
	const char *lpath = NULL;
	const char *path0 = vt_new_path_unique(vte);
	const char *rpath = vt_new_path_under(vte, path0);
	const char *abc =
	        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const size_t abc_len = strlen(abc);
	const size_t name_max = SILOFS_NAME_MAX;

	vt_mkdir(path0, 0750);
	vt_creat(rpath, 0640, &fd);
	for (size_t i = 0; i < abc_len; ++i) {
		for (size_t j = 1; j <= name_max; ++j) {
			name = make_name(vte, abc[i], j);
			lpath = vt_new_path_nested(vte, path0, name);
			vt_link(rpath, lpath);
		}
	}
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_nlink, (name_max * abc_len) + 1);

	for (size_t i = 0; i < abc_len; ++i) {
		for (size_t j = 1; j <= name_max; ++j) {
			name = make_name(vte, abc[i], j);
			lpath = vt_new_path_nested(vte, path0, name);
			vt_unlink(lpath);
		}
	}
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_nlink, 1);
	vt_close(fd);
	vt_unlink(rpath);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_link_exists),
	VT_DEFTEST(test_link_noent),
	VT_DEFTEST(test_link_notdir),
	VT_DEFTEST(test_link_rename),
	VT_DEFTEST(test_link_max),
	VT_DEFTEST(test_link_limit),
	VT_DEFTEST(test_link_similar_names),
};

const struct vt_tests vt_test_link = VT_DEFTESTS(vt_local_tests);
