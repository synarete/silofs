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


/* Maximum hard-links per file */
static size_t get_link_max(void)
{
	long ret;
	const long lim = 2048;

	ret = sysconf(_PC_LINK_MAX);
	ft_expect_gt(ret, 0);
	ft_expect_lt(ret, FT_UGIGA);

	return (size_t)((ret < lim) ? ret : lim);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return EEXIST if the path2 argument resolves to an
 * existing file or refers to a symbolic link.
 */
static void test_link_exists(struct ft_env *fte)
{
	int fd0 = -1;
	int fd1 = -1;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_name(fte, "link-to-symlink-exist");

	ft_creat(path0, 0644, &fd0);
	ft_creat(path1, 0644, &fd1);

	ft_link_err(path0, path1, -EEXIST);
	ft_unlink(path1);

	ft_mkdir(path1, 0755);
	ft_link_err(path0, path1, -EEXIST);
	ft_rmdir(path1);

	ft_symlink(path1, path2);
	ft_link_err(path0, path2, -EEXIST);
	ft_unlink(path2);

	ft_mkfifo(path1, 0644);
	ft_link_err(path0, path1, -EEXIST);
	ft_unlink(path1);

	ft_unlink(path0);
	ft_close(fd0);
	ft_close(fd1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return ENOENT if the source file does not exist.
 */
static void test_link_noent(struct ft_env *fte)
{
	int fd = -1;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);

	ft_mkdir(path0, 0700);
	ft_creat(path1, 0640, &fd);
	ft_link(path1, path2);
	ft_unlink(path1);
	ft_unlink(path2);
	ft_link_err(path1, path2, -ENOENT);
	ft_rmdir(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return EEXIST if a component of either path prefix is
 * not a directory.
 */
static void test_link_notdir(struct ft_env *fte)
{
	int fd1 = -1;
	int fd2 = -1;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	const char *path3 = ft_new_path_under(fte, path1);

	ft_mkdir(path0, 0755);
	ft_creat(path1, 0644, &fd1);
	ft_link_err(path3, path2, -ENOTDIR);
	ft_creat(path2, 0644, &fd2);
	ft_link_err(path2, path3, -ENOTDIR);
	ft_unlink(path1);
	ft_unlink(path2);
	ft_rmdir(path0);
	ft_close(fd1);
	ft_close(fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p)/unlink(3p) sequence to succeed for renamed links.
 */
static void test_link_rename_cnt(struct ft_env *fte, int cnt)
{
	int fd = -1;
	int nlink = 1;
	const int limit = cnt + 1;
	struct stat st;
	const char *name  = ft_new_name_unique(fte);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = NULL;
	const char *path3 = NULL;

	ft_mkdir(path0, 0700);
	ft_creat(path1, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_nlink, 1);
	nlink = (int)st.st_nlink;
	for (int i = nlink; i < limit; ++i) {
		path2 = ft_new_pathf(fte, path0, "%s-%d", name, i);
		path3 = ft_new_pathf(fte, path0, "%s-X-%d", name, i);
		ft_link(path1, path2);
		ft_rename(path2, path3);
		ft_unlink_noent(path2);
	}
	for (int i = limit - 1; i >= nlink; --i) {
		path3 = ft_new_pathf(fte, path0, "%s-X-%d", name, i);
		ft_unlink(path3);
	}
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

static void test_link_rename(struct ft_env *fte)
{
	test_link_rename_cnt(fte, 1);
	test_link_rename_cnt(fte, 2);
	test_link_rename_cnt(fte, 300);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to succeed for link count less then LINK_MAX.
 */
static void test_link_max(struct ft_env *fte)
{
	int fd = -1;
	nlink_t nlink = 0;
	struct stat st;
	const char *name  = ft_new_name_unique(fte);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = NULL;
	const size_t link_max = get_link_max();

	ft_mkdir(path0, 0700);
	ft_creat(path1, 0600, &fd);
	ft_fstat(fd, &st);
	nlink = st.st_nlink;
	for (size_t i = nlink; i < link_max; ++i) {
		path2 = ft_new_pathf(fte, path0, "%s-%lu", name, i);
		ft_link(path1, path2);
	}
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_nlink, link_max);
	for (size_t j = nlink; j < link_max; ++j) {
		path2 = ft_new_pathf(fte, path0, "%s-%lu", name, j);
		ft_unlink(path2);
	}
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to not return EMLINK if the link count of the file is less
 * then LINK_MAX.
 */
static void test_link_limit(struct ft_env *fte)
{
	int fd = -1;
	nlink_t nlink = 0;
	struct stat st;
	const char *name = ft_new_name_unique(fte);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = NULL;
	const size_t link_max = get_link_max();

	ft_mkdir(path0, 0750);
	ft_creat(path1, 0640, &fd);
	ft_fstat(fd, &st);
	nlink = st.st_nlink;
	for (size_t i = nlink; i < link_max; ++i) {
		path2 = ft_new_pathf(fte, path0, "%d-%s", i, name);
		ft_link(path1, path2);
	}
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_nlink, link_max);
	for (size_t i = nlink; i < link_max; i += 2) {
		path2 = ft_new_pathf(fte, path0, "%d-%s", i, name);
		ft_unlink(path2);
	}
	for (size_t i = (nlink + 1); i < link_max; i += 2) {
		path2 = ft_new_pathf(fte, path0, "%d-%s", i, name);
		ft_unlink(path2);
	}
	ft_unlink(path1);
	ft_rmdir(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to succeed for names which may cause avalanche effect on
 * poor hash-based directories.
 */
static const char *make_name(struct ft_env *fte, char c, size_t len)
{
	size_t nlen;
	char name[SILOFS_NAME_MAX + 1] = "";

	nlen = (len < sizeof(name)) ? len : (sizeof(name) - 1);
	memset(name, c, nlen);
	return ft_strdup(fte, name);
}

static void test_link_similar_names(struct ft_env *fte)
{
	int fd = -1;
	struct stat st;
	const char *name = NULL;
	const char *lpath = NULL;
	const char *path0 = ft_new_path_unique(fte);
	const char *rpath = ft_new_path_under(fte, path0);
	const char *abc =
	        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const size_t abc_len = strlen(abc);
	const size_t name_max = SILOFS_NAME_MAX;

	ft_mkdir(path0, 0750);
	ft_creat(rpath, 0640, &fd);
	for (size_t i = 0; i < abc_len; ++i) {
		for (size_t j = 1; j <= name_max; ++j) {
			name = make_name(fte, abc[i], j);
			lpath = ft_new_path_nested(fte, path0, name);
			ft_link(rpath, lpath);
		}
	}
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_nlink, (name_max * abc_len) + 1);

	for (size_t i = 0; i < abc_len; ++i) {
		for (size_t j = 1; j <= name_max; ++j) {
			name = make_name(fte, abc[i], j);
			lpath = ft_new_path_nested(fte, path0, name);
			ft_unlink(lpath);
		}
	}
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_nlink, 1);
	ft_close(fd);
	ft_unlink(rpath);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_link_exists),
	FT_DEFTEST(test_link_noent),
	FT_DEFTEST(test_link_notdir),
	FT_DEFTEST(test_link_rename),
	FT_DEFTEST(test_link_max),
	FT_DEFTEST(test_link_limit),
	FT_DEFTEST(test_link_similar_names),
};

const struct ft_tests ft_test_link = FT_DEFTESTS(ft_local_tests);
