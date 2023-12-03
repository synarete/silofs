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
	const long lim = SILOFS_LINK_MAX;
	long ret;

	ret = sysconf(_PC_LINK_MAX);
	ft_expect_gt(ret, 0);
	ft_expect_lt(ret, FT_1G);

	return (size_t)((ret < lim) ? ret : lim);
}

static size_t link_count_chopped(size_t cnt)
{
	const size_t link_max = get_link_max();

	return ((cnt + 2) < link_max) ? cnt : link_max;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return EEXIST if the path2 argument resolves to an
 * existing file or refers to a symbolic link.
 */
static void test_link_exists(struct ft_env *fte)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_name(fte, "link-to-symlink-exist");
	int fd0 = -1;
	int fd1 = -1;

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
	ft_unlink2(path1, path0);
	ft_close2(fd0, fd1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to return ENOENT if the source file does not exist.
 */
static void test_link_noent(struct ft_env *fte)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	int fd = -1;

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
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	const char *path3 = ft_new_path_under(fte, path1);
	int fd1 = -1;
	int fd2 = -1;

	ft_mkdir(path0, 0755);
	ft_creat(path1, 0644, &fd1);
	ft_link_err(path3, path2, -ENOTDIR);
	ft_creat(path2, 0644, &fd2);
	ft_link_err(path2, path3, -ENOTDIR);
	ft_unlink2(path1, path2);
	ft_rmdir(path0);
	ft_close2(fd1, fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p)/unlink(3p) sequence to succeed for renamed links.
 */
static void test_link_rename_(struct ft_env *fte, int cnt)
{
	struct stat st = { .st_size = -1 };
	const char *name  = ft_new_name_unique(fte);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = NULL;
	const char *path3 = NULL;
	const int limit = cnt + 1;
	int nlink = 1;
	int fd = -1;

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
	const int cnt[] = { 1, 2, 300 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_link_rename_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to succeed for link count up to LINK_MAX.
 */
static void test_link_max(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const size_t link_max = get_link_max();
	const char *name  = ft_new_name_unique(fte);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = NULL;
	nlink_t nlink_base = 0;
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_creat(path1, 0600, &fd);
	ft_fstat(fd, &st);
	nlink_base = st.st_nlink;
	for (size_t i = nlink_base; i < link_max; ++i) {
		path2 = ft_new_pathf(fte, path0, "%s-%lu", name, i);
		ft_link(path1, path2);
	}
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_nlink, link_max);
	for (size_t j = nlink_base; j < link_max; ++j) {
		path2 = ft_new_pathf(fte, path0, "%s-%lu", name, j);
		ft_unlink(path2);
	}
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects link(3p) to succeed for names which may cause avalanche effect on
 * poor hash-based directories.
 */
static const char *make_name(struct ft_env *fte, char c, size_t len)
{
	char name[SILOFS_NAME_MAX + 1] = "";
	size_t nlen;

	nlen = (len < sizeof(name)) ? len : (sizeof(name) - 1);
	memset(name, c, nlen);
	return ft_strdup(fte, name);
}

static void test_link_similar_names(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *name = NULL;
	const char *lpath = NULL;
	const char *path0 = ft_new_path_unique(fte);
	const char *rpath = ft_new_path_under(fte, path0);
	const char *abc =
	        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const size_t abc_len = strlen(abc);
	const size_t name_max = SILOFS_NAME_MAX;
	int fd = -1;

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
/*
 * Expects linkat(2) to succeed for multiple links on same dir.
 */
static void test_linkat_same_dir_(struct ft_env *fte, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	const char *link = NULL;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);
	for (size_t i = 0; i < cnt; ++i) {
		ft_fstatat(dfd, name, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + i);
		link = ft_new_namef(fte, "%s-%lu", name, i);
		ft_linkat(dfd, name, dfd, link, 0);
	}
	for (size_t j = cnt; j > 0; --j) {
		ft_fstatat(dfd, name, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + j);
		link = ft_new_namef(fte, "%s-%lu", name, j - 1);
		ft_unlinkat(dfd, link, 0);
	}
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_linkat_same_dir(struct ft_env *fte)
{
	const size_t cnt[] = { 1, 10, 1000, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_linkat_same_dir_(fte, link_count_chopped(cnt[i]));
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects linkat(2) to succeed for multiple links between two distinct dirs.
 */
static void test_linkat_diff_dir_(struct ft_env *fte, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	const char *path1 = ft_new_path_unique(fte);
	const char *name1 = ft_new_name_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	const char *name2 = ft_new_name_unique(fte);
	const char *link = NULL;
	int dfd1 = -1;
	int dfd2 = -1;
	int fd = -1;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_openat(dfd1, name1, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);

	ft_mkdir(path2, 0700);
	ft_open(path2, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	ft_openat(dfd2, name2, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);

	for (size_t i = 0; i < cnt; ++i) {
		ft_fstatat(dfd1, name1, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + i);

		ft_fstatat(dfd2, name2, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + i);

		link = ft_new_namef(fte, "%s-%lu", name1, i);
		ft_linkat(dfd1, name1, dfd2, link, 0);

		link = ft_new_namef(fte, "%s-%lu", name2, i);
		ft_linkat(dfd2, name2, dfd1, link, 0);
	}
	for (size_t j = cnt; j > 0; --j) {
		ft_fstatat(dfd1, name1, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + j);

		ft_fstatat(dfd2, name2, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + j);

		link = ft_new_namef(fte, "%s-%lu", name2, j - 1);
		ft_unlinkat(dfd1, link, 0);

		link = ft_new_namef(fte, "%s-%lu", name1, j - 1);
		ft_unlinkat(dfd2, link, 0);
	}
	ft_unlinkat(dfd1, name1, 0);
	ft_unlinkat(dfd2, name2, 0);
	ft_close(dfd1);
	ft_close(dfd2);
	ft_rmdir(path1);
	ft_rmdir(path2);
}

static void test_linkat_diff_dir(struct ft_env *fte)
{
	const size_t cnt[] = { 1, 10, 1000, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_linkat_diff_dir_(fte, link_count_chopped(cnt[i]));
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects linkat(2) to succeed for multiple links on same dir plus I/O.
 */
static void test_linkat_with_io_(struct ft_env *fte, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	const char *link = NULL;
	loff_t off = -1;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		ft_fstatat(dfd, name, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + i);
		link = ft_new_namef(fte, "%s-%lu", name, i);
		ft_linkat(dfd, name, dfd, link, 0);
		off = (ssize_t)(i * FT_1M + i);
		ft_pwriten(fd, link, strlen(link), off);
	}
	for (size_t j = cnt; j > 0; --j) {
		ft_fstatat(dfd, name, &st, 0);
		ft_expect_eq(st.st_nlink, 1 + j);
		link = ft_new_namef(fte, "%s-%lu", name, j - 1);
		ft_unlinkat(dfd, link, 0);
		off = (ssize_t)(FT_1G + j);
		ft_pwriten(fd, link, strlen(link), off);
	}
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_linkat_with_io(struct ft_env *fte)
{
	const size_t cnt[] = { 1, 10, 1000, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_linkat_with_io_(fte, link_count_chopped(cnt[i]));
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_link_exists),
	FT_DEFTEST(test_link_noent),
	FT_DEFTEST(test_link_notdir),
	FT_DEFTEST(test_link_rename),
	FT_DEFTEST(test_link_max),
	FT_DEFTEST(test_link_similar_names),
	FT_DEFTEST(test_linkat_same_dir),
	FT_DEFTEST(test_linkat_diff_dir),
	FT_DEFTEST(test_linkat_with_io),
};

const struct ft_tests ft_test_link = FT_DEFTESTS(ft_local_tests);
