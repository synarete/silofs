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
 * Expects mkdir(3p) to create nested directories structure and allow rmdir(3p)
 * only to apply on last. Expects all other non-empty directories to return
 * -ENOTEMPTY upon rmdir(3p).
 */
static void
test_rmdir_notempty(struct ft_env *fte, char const **pathi, size_t count)
{
	for (size_t i = 0; i < count; ++i) {
		ft_rmdir_err(pathi[i], -ENOTEMPTY);
	}
	for (size_t j = count; j > 0; --j) {
		ft_rmdir_err(pathi[j - 1], -ENOTEMPTY);
	}
	silofs_unused(fte);
}

static void test_mkdir_rmdir(struct ft_env *fte)
{
	const char *pathi[32];
	const size_t nelems = FT_ARRAY_SIZE(pathi);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = path0;

	ft_mkdir(path0, 0700);
	for (size_t i = 0; i < nelems; ++i) {
		path1 = ft_new_pathf(fte, path1, "D%d", (int)i);
		ft_mkdir(path1, 0700);
		pathi[i] = path1;
	}
	for (size_t j = nelems; j > 0; --j) {
		test_rmdir_notempty(fte, pathi, j - 1);
		path1 = pathi[j - 1];
		ft_rmdir(path1);
	}
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to create a directory with a mode modified by the process'
 * umask.
 */
static void test_mkdir_umask(struct ft_env *fte)
{
	mode_t umsk;
	const mode_t ifmt = S_IFMT;
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);

	umsk = umask(0020);
	ft_mkdir(path0, 0755);
	ft_stat(path0, &st[0]);
	ft_expect_st_dir(&st[0]);

	ft_mkdir(path1, 0755);
	ft_stat(path1, &st[1]);
	ft_expect_st_dir(&st[1]);
	ft_expect_eq((st[1].st_mode & ~ifmt), 0755);
	ft_rmdir(path1);

	ft_mkdir(path1, 0153);
	ft_stat(path1, &st[1]);
	ft_expect_st_dir(&st[1]);
	ft_expect_eq((st[1].st_mode & ~ifmt), 0153);
	ft_rmdir(path1);

	umask(077);
	ft_mkdir(path1, 0151);
	ft_stat(path1, &st[1]);
	ft_expect_st_dir(&st[1]);
	ft_expect_eq((st[1].st_mode & ~ifmt), 0100);
	ft_rmdir(path1);

	umask(070);
	ft_mkdir(path1, 0345);
	ft_stat(path1, &st[1]);
	ft_expect_st_dir(&st[1]);
	ft_expect_eq((st[1].st_mode & ~ifmt), 0305);
	ft_rmdir(path1);

	umask(0501);
	ft_mkdir(path1, 0345);
	ft_stat(path1, &st[1]);
	ft_expect_st_dir(&st[1]);
	ft_expect_eq((st[1].st_mode & ~ifmt), 0244);

	ft_rmdir(path1);
	ft_rmdir(path0);
	ft_stat_noent(path0);
	ft_stat_noent(path1);
	umask(umsk);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to create a nested directory when parent directory is
 * writable or not.
 */
static void test_mkdir_chmod(struct ft_env *fte)
{
	struct stat st;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);

	ft_mkdir(path0, 0700);
	ft_stat(path0, &st);
	ft_expect_true(st.st_mode & S_IWUSR);
	ft_expect_true(st.st_mode & S_IXUSR);
	ft_mkdir(path1, st.st_mode);
	ft_stat(path1, &st);
	ft_expect_true(st.st_mode & S_IWUSR);
	ft_expect_true(st.st_mode & S_IXUSR);
	ft_chmod(path1, st.st_mode & ~((mode_t)S_IRUSR));
	ft_stat(path1, &st);
	ft_expect_false(st.st_mode & S_IRUSR);
	ft_mkdir(path2, st.st_mode);
	ft_stat(path2, &st);
	ft_expect_true(st.st_mode & S_IWUSR);
	ft_expect_true(st.st_mode & S_IXUSR);
	ft_expect_false(st.st_mode & S_IRUSR);
	ft_chmod(path2, st.st_mode & ~((mode_t)S_IXUSR));
	ft_stat(path2, &st);
	ft_expect_true(st.st_mode & S_IWUSR);
	ft_expect_false(st.st_mode & S_IXUSR);
	ft_rmdir(path2);
	ft_stat(path1, &st);
	ft_expect_true(st.st_mode & S_IWUSR);
	ft_chmod(path1, st.st_mode & ~((mode_t)S_IWUSR));
	ft_mkdir_err(path2, 0700, -EACCES);
	ft_rmdir(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to return ELOOP if too many symbolic links were
 * encountered in translating of the pathname.
 */
static void test_mkdir_loop(struct ft_env *fte)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_under(fte, path0);
	const char *path3 = ft_new_path_under(fte, path1);

	ft_symlink(path0, path1);
	ft_symlink(path1, path0);
	ft_mkdir_err(path2, 0755, -ELOOP);
	ft_mkdir_err(path3, 0750, -ELOOP);
	ft_unlink(path0);
	ft_unlink(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: rename test and move me from here */

/*
 * Verify creation & removal of many-many dir-entries.
 */
static void test_mkdir_many_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	int dfd = -1;
	struct stat st;
	const char *name = NULL;
	const char *path = ft_new_path_unique(fte);

	ft_mkdir(path, 0755);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);

	for (size_t i = 0; i < cnt; ++i) {
		name = ft_make_ulong_name(fte, i);
		ft_openat(dfd, name, O_CREAT | O_RDWR, 0644, &fd);
		ft_close(fd);
	}
	for (size_t j = 0; j < cnt; ++j) {
		name = ft_make_ulong_name(fte, j);
		ft_fstatat(dfd, name, &st, 0);
		ft_unlinkat(dfd, name, 0);
	}
	ft_stat(path, &st);
	ft_expect_eq(st.st_nlink, 2);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_mkdir_many(struct ft_env *fte)
{
	test_mkdir_many_(fte, 1000);
}

static void test_mkdir_many_more(struct ft_env *fte)
{
	test_mkdir_many_(fte, 30000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Create and remove deeply-nested directories structure
 */
static void test_mkdir_nested(struct ft_env *fte)
{
	char *pathi[64];
	char *path0 = ft_new_path_unique(fte);
	char *path1 = path0;

	ft_mkdir(path0, 0700);
	for (size_t i = 0; i < FT_ARRAY_SIZE(pathi); ++i) {
		path1 = ft_new_pathf(fte, path1, "D%d", (int)i);
		ft_mkdir(path1, 0700);
		pathi[i] = path1;
	}
	for (size_t i = FT_ARRAY_SIZE(pathi); i > 0; --i) {
		path1 = pathi[i - 1];
		ft_rmdir(path1);
	}
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Create recursively directory tree structure
 */
static const char *
makename(struct ft_env *fte, const char *prefix, size_t depth, size_t id)
{
	return ft_strfmt(fte, "%s%03x-%03x", prefix, (int)depth, (int)id);
}

static void test_walktree_recursive(struct ft_env *fte, const char *base)
{
	int fd = -1;
	loff_t pos = -1;
	loff_t off = 0;
	const char *path = NULL;
	struct dirent64 dent = { .d_ino = 0 };

	ft_open(base, O_DIRECTORY | O_RDONLY, 0, &fd);
	while (1) {
		ft_llseek(fd, off, SEEK_SET, &pos);
		ft_getdent(fd, &dent);
		off = dent.d_off;
		if (off <= 0) {
			break;
		}
		if (!strcmp(dent.d_name, ".") || !strcmp(dent.d_name, "..")) {
			continue;
		}
		if (dent.d_type == DT_DIR) {
			continue;
		}
		path = ft_new_path_nested(fte, base, dent.d_name);
		test_walktree_recursive(fte, path);
	}
	ft_close(fd);
}

static void
test_mktree_recursive(struct ft_env *fte, const char *parent, size_t id,
                      size_t nchilds, size_t depth, size_t depth_max)
{
	int fd = -1;
	const char *path = NULL;
	const char *name = NULL;

	if (depth < depth_max) {
		name = makename(fte, "d", depth, id);
		path = ft_new_path_nested(fte, parent, name);
		ft_mkdir(path, 0700);
		for (size_t i = 0; i < nchilds; ++i) {
			test_mktree_recursive(fte, path, i + 1, nchilds,
			                      depth + 1, depth_max);
		}
	} else {
		name = makename(fte, "f", depth, id);
		path = ft_new_path_nested(fte, parent, name);
		ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
		ft_close(fd);
	}
}

static void
test_rmtree_recursive(struct ft_env *fte, const char *parent, size_t id,
                      size_t nchilds, size_t depth, size_t depth_max)
{
	const char *path = NULL;
	const char *name = NULL;

	if (depth < depth_max) {
		name = makename(fte, "d", depth, id);
		path = ft_new_path_nested(fte, parent, name);
		for (size_t i = 0; i < nchilds; ++i) {
			test_rmtree_recursive(fte, path, i + 1, nchilds,
			                      depth + 1, depth_max);
		}
		ft_rmdir(path);
	} else {
		name = makename(fte, "f", depth, id);
		path = ft_new_path_nested(fte, parent, name);
		ft_unlink(path);
	}
}

static void
test_mkdir_tree_(struct ft_env *fte, size_t nchilds, size_t depth_max)
{
	const char *path = ft_new_path_unique(fte);

	ft_mkdir(path, 0700);
	for (size_t i = 0; i < nchilds; ++i) {
		test_mktree_recursive(fte, path, i + 1, nchilds, 1, depth_max);
	}
	test_walktree_recursive(fte, path);
	for (size_t j = 0; j < nchilds; ++j) {
		test_rmtree_recursive(fte, path, j + 1, nchilds, 1, depth_max);
	}
	ft_rmdir(path);
}

static void test_mkdir_tree_wide(struct ft_env *fte)
{
	test_mkdir_tree_(fte, 32, 2);
}

static void test_mkdir_tree_deep(struct ft_env *fte)
{
	test_mkdir_tree_(fte, 2, 8);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdir(3p) to preserve S_ISGID of parent directory
 */
static void test_mkdir_setgid(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_under(fte, path1);
	const char *path3 = ft_new_path_under(fte, path2);

	ft_mkdir(path1, 0700);
	ft_stat(path1, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_mkdir(path2, 0700);
	ft_stat(path2, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_chmod(path2, st.st_mode | S_ISGID);
	ft_stat(path2, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_mkdir(path3, 0700);
	ft_stat(path3, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_rmdir(path3);
	ft_rmdir(path2);
	ft_rmdir(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdirat(2) to work properly
 */
static void test_mkdirat_simple(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd1 = -1;
	int dfd2 = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_mkdirat(dfd1, name, 0700);
	ft_fstatat(dfd1, name, &st, 0);
	ft_expect_st_dir(&st);
	ft_openat(dfd1, name, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	ft_fstat(dfd2, &st);
	ft_expect_st_dir(&st);
	ft_close(dfd2);
	ft_unlinkat(dfd1, name, AT_REMOVEDIR);
	ft_fstatat_err(dfd1, name, 0, -ENOENT);
	ft_close(dfd1);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdirat(2) to work with nested dirs/files
 */
static void test_mkdirat_nested(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	const char *nested1 = "nested1";
	const char *nested2 = "nested1/nested2";
	int dfd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_mkdirat(dfd, nested1, 0755);
	ft_mkdirat(dfd, nested2, 0755);
	ft_unlinkat(dfd, nested2, AT_REMOVEDIR);
	ft_mknodat(dfd, nested2, 0755, 0);
	ft_unlinkat(dfd, nested2, 0);
	ft_unlinkat(dfd, nested1, AT_REMOVEDIR);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects mkdirat(2) to work with multiple nested dirs/files and I/O
 */
static void test_mkdirat_nested_io_(struct ft_env *fte, size_t cnt)
{
	const char *curr = ft_curr_test_name(fte);
	const char *path = ft_new_path_unique(fte);
	const char *name = NULL;
	const size_t len = FT_1M;
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	const size_t cnt_inner = (cnt > 10) ? 10 : cnt;
	loff_t off = -1;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		name = ft_new_namef(fte, "%s%lu", curr, i);
		ft_mkdirat(dfd, name, 0700);
		name = ft_new_namef(fte, "%s%lu/%lu", curr, i, i);
		ft_mkdirat(dfd, name, 0700);
		name = ft_new_namef(fte, "%s%lu/%lu/%lu", curr, i, i, i);
		ft_mkdirat(dfd, name, 0700);
		for (size_t j = 0; j < cnt_inner; ++j) {
			name = ft_new_namef(fte, "%s%lu/%lu/%lu/%s%lu", curr,
			                    i, i, i, curr, j);
			ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
			off = (ssize_t)(i * len + j);
			ft_pwriten(fd, buf1, len, off);
			ft_close(fd);
		}
	}
	ft_close(dfd);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		for (size_t j = 0; j < cnt_inner; ++j) {
			name = ft_new_namef(fte, "%s%lu/%lu/%lu/%s%lu", curr,
			                    i, i, i, curr, j);
			ft_openat(dfd, name, O_RDONLY, 0600, &fd);
			off = (ssize_t)(i * len + j);
			ft_preadn(fd, buf2, len, off);
			ft_expect_eqm(buf1, buf2, len);
			ft_close(fd);
			ft_unlinkat(dfd, name, 0);
		}
		name = ft_new_namef(fte, "%s%lu/%lu/%lu", curr, i, i, i);
		ft_unlinkat(dfd, name, AT_REMOVEDIR);
		name = ft_new_namef(fte, "%s%lu/%lu", curr, i, i);
		ft_unlinkat(dfd, name, AT_REMOVEDIR);
		name = ft_new_namef(fte, "%s%lu", curr, i);
		ft_unlinkat(dfd, name, AT_REMOVEDIR);
	}
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_mkdirat_nested_io(struct ft_env *fte)
{
	const size_t cnt[] = { 1, 10, 100 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_mkdirat_nested_io_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful rmdir(3p) to update the last data modification and last
 * file status change time-stamps of the parent directory
 */
static void test_rmdir_mctime(struct ft_env *fte)
{
	struct stat st[2];
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_under(fte, path1);

	ft_mkdir(path1, 0700);
	ft_mkdir(path2, 0700);
	ft_stat(path1, &st[0]);
	ft_expect_st_dir(&st[0]);
	ft_suspends(fte, 2);
	ft_rmdir(path2);
	ft_stat_err(path2, -ENOENT);
	ft_stat(path1, &st[1]);
	ft_expect_st_mtime_gt(&st[0], &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);
	ft_rmdir(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful rmdir(3p) on empty directory while still referenced by
 * open file-descriptor.
 */
static void test_rmdir_openat(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *name = ft_new_name_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_nested(fte, path1, name);
	int dfd1 = -1;
	int dfd2 = -1;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_mkdirat(dfd1, name, 0700);
	ft_openat(dfd1, name, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	ft_fstat(dfd1, &st);
	ft_expect_st_dir(&st);
	ft_fstat(dfd2, &st);
	ft_expect_st_dir(&st);
	ft_expect_eq(st.st_nlink, 2);
	ft_rmdir(path2);
	ft_fstat(dfd2, &st);
	ft_expect_st_dir(&st);
	ft_expect_le(st.st_nlink, 1); /* TODO: why not eq 1 ? */
	ft_rmdir(path1);
	ft_close(dfd1);
	ft_close(dfd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful getdents(2) after rmdir(3p) on empty directory while
 * still referenced by open file-descriptor.
 *
 * Note: current FUSE implementation does not allow readdir on dfd2 (although
 * you can do it on ext4 of xfs).
 */
static void test_rmdir_getdents(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	struct dirent64 dent = { .d_off = -1 };
	const char *name2 = ft_new_name_unique(fte);
	const char *name3 = ft_new_name_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_nested(fte, path1, name2);
	loff_t pos = -1;
	int dfd1 = -1;
	int dfd2 = -1;
	int fd3 = -1;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_mkdirat(dfd1, name2, 0700);
	ft_openat(dfd1, name2, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	ft_openat(dfd1, name3, O_CREAT | O_RDWR, 0600, &fd3);
	ft_fstat(dfd1, &st);
	ft_expect_st_dir(&st);
	ft_expect_eq(st.st_nlink, 3);
	ft_fstat(dfd2, &st);
	ft_expect_st_dir(&st);
	ft_expect_eq(st.st_nlink, 2);
	ft_rmdir(path2);
	ft_unlinkat(dfd1, name3, 0);
	ft_fstat(dfd2, &st);
	ft_expect_st_dir(&st);
	ft_fstat(dfd1, &st);
	ft_expect_st_dir(&st);
	ft_expect_eq(st.st_nlink, 2);
	ft_getdent(dfd1, &dent);
	ft_expect_true(ft_dirent_isdir(&dent));
	ft_expect_true(ft_dirent_isdot(&dent));
	ft_llseek(dfd1, dent.d_off, SEEK_SET, &pos);
	ft_expect_eq(dent.d_off, pos);
	ft_getdent(dfd1, &dent);
	ft_expect_true(ft_dirent_isdir(&dent));
	ft_expect_true(ft_dirent_isdotdot(&dent));
	ft_rmdir(path1);
	ft_close(dfd1);
	ft_close(dfd2);
	ft_close(fd3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_mkdir_rmdir),       //
	FT_DEFTEST(test_mkdir_umask),       //
	FT_DEFTEST(test_mkdir_chmod),       //
	FT_DEFTEST(test_mkdir_loop),        //
	FT_DEFTEST(test_mkdir_nested),      //
	FT_DEFTEST(test_mkdir_many),        //
	FT_DEFTEST(test_mkdir_many_more),   //
	FT_DEFTEST(test_mkdir_tree_wide),   //
	FT_DEFTEST(test_mkdir_tree_deep),   //
	FT_DEFTEST(test_mkdir_setgid),      //
	FT_DEFTEST(test_mkdirat_simple),    //
	FT_DEFTEST(test_mkdirat_nested),    //
	FT_DEFTEST(test_mkdirat_nested_io), //
	FT_DEFTEST(test_rmdir_mctime),      //
	FT_DEFTEST(test_rmdir_openat),      //
	FT_DEFTEST(test_rmdir_getdents),    //
};

const struct ft_tests ft_test_mkdir = FT_DEFTESTS(ft_local_tests);
