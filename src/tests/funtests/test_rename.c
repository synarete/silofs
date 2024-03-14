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
 * Expects rename(3p) to successfully change file's new-name and return ENOENT
 * on old-name.
 */
static void test_rename_simple(struct ft_env *fte)
{
	struct stat st[3];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	int fd = -1;

	ft_mkdir(path0, 0755);
	ft_creat(path1, 0644, &fd);
	ft_stat(path1, &st[0]);
	ft_expect_st_reg(&st[0]);
	ft_rename(path1, path2);
	ft_stat_err(path1, -ENOENT);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[1].st_ino, st[0].st_ino);
	ft_expect_eq(st[1].st_mode, st[0].st_mode);
	ft_expect_eq(st[1].st_nlink, st[0].st_nlink);
	ft_expect_eq(st[1].st_nlink, 1);
	ft_stat(path2, &st[2]);
	ft_expect_eq(st[2].st_ino, st[0].st_ino);
	ft_expect_eq(st[2].st_mode, st[0].st_mode);
	ft_expect_eq(st[2].st_nlink, st[0].st_nlink);
	ft_close(fd);
	ft_unlink(path2);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects renameat(2) to successfully change file's new-name and return ENOENT
 * on old-name.
 */
static void test_renameat_simple(struct ft_env *fte)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	const char *name1 = ft_new_name_unique(fte);
	const char *name2 = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name1, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st[0]);
	ft_expect_st_reg(&st[0]);
	ft_close(fd);
	ft_fstatat(dfd, name1, &st[1], 0);
	ft_expect_st_reg(&st[1]);
	ft_expect_eq(st[1].st_ino, st[0].st_ino);
	ft_renameat(dfd, name1, dfd, name2);
	ft_fstatat_err(dfd, name1, 0, -ENOENT);
	ft_fstatat(dfd, name2, &st[1], 0);
	ft_expect_eq(st[1].st_mode, st[0].st_mode);
	ft_expect_eq(st[1].st_ino, st[0].st_ino);
	ft_unlinkat(dfd, name2, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to successfully change file's new-name and return ENOENT
 * on old-name, plus preserve mode.
 */
static void test_rename_getattr(struct ft_env *fte)
{
	struct stat st[3];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	const mode_t ifmt = S_IFMT;
	int fd = -1;

	ft_mkdir(path0, 0755);
	ft_creat(path1, 0644, &fd);
	ft_stat(path1, &st[0]);
	ft_expect_st_reg(&st[0]);
	ft_expect_eq((st[0].st_mode & ~ifmt), 0644);
	ft_expect_eq(st[0].st_nlink, 1);
	ft_expect_eq(st[0].st_size, 0);
	ft_rename(path1, path2);
	ft_stat_err(path1, -ENOENT);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[1].st_ino, st[0].st_ino);
	ft_expect_eq(st[1].st_mode, st[0].st_mode);
	ft_stat(path2, &st[2]);
	ft_expect_st_reg(&st[2]);
	ft_expect_eq((st[2].st_mode & ~ifmt), 0644);
	ft_expect_eq(st[2].st_nlink, 1);
	ft_unlink(path2);
	ft_rmdir(path0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to update ctime only when successful.
 */
static void test_rename_ctime(struct ft_env *fte)
{
	int fd = -1;
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	const char *path3 = ft_new_path_under(fte, path2);

	ft_creat(path0, 0644, &fd);
	ft_close(fd);
	ft_stat(path0, &st[0]);
	ft_suspends(fte, 2);
	ft_rename(path0, path1);
	ft_stat(path1, &st[1]);
	ft_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	ft_unlink(path1);

	ft_mkdir(path0, 0700);
	ft_stat(path0, &st[0]);
	ft_suspends(fte, 2);
	ft_rename(path0, path1);
	ft_stat(path1, &st[1]);
	ft_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	ft_rmdir(path1);

	ft_mkfifo(path0, 0644);
	ft_stat(path0, &st[0]);
	ft_suspends(fte, 2);
	ft_rename(path0, path1);
	ft_stat(path1, &st[1]);
	ft_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	ft_unlink(path1);

	ft_symlink(path2, path0);
	ft_lstat(path0, &st[0]);
	ft_suspends(fte, 2);
	ft_rename(path0, path1);
	ft_lstat(path1, &st[1]);
	ft_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	ft_unlink(path1);

	ft_creat(path0, 0644, &fd);
	ft_close(fd);
	ft_stat(path0, &st[0]);
	ft_suspends(fte, 2);
	ft_rename_err(path0, path3, -ENOENT);
	ft_stat(path0, &st[1]);
	ft_expect_eq(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	ft_unlink(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to returns ENOTDIR when the 'from' argument is a
 * directory, but 'to' is not a directory.
 */
static void test_rename_notdirto(struct ft_env *fte)
{
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	int fd = -1;

	ft_mkdir(path0, 0750);
	ft_creat(path1, 0644, &fd);
	ft_close(fd);
	ft_rename_err(path0, path1, -ENOTDIR);
	ft_lstat(path0, &st[0]);
	ft_expect_st_dir(&st[0]);
	ft_unlink(path1);

	ft_symlink("test-rename-notdirto", path1);
	ft_rename_err(path0, path1, -ENOTDIR);
	ft_lstat(path0, &st[0]);
	ft_expect_st_dir(&st[0]);
	ft_lstat(path1, &st[1]);
	ft_expect_st_lnk(&st[1]);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to returns EISDIR when the 'to' argument is a
 * directory, but 'from' is not a directory.
 */
static void test_rename_isdirto(struct ft_env *fte)
{
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	int fd = -1;

	ft_mkdir(path0, 0750);
	ft_creat(path1, 0640, &fd);
	ft_close(fd);
	ft_rename_err(path1, path0, -EISDIR);
	ft_lstat(path0, &st[0]);
	ft_expect_st_dir(&st[0]);
	ft_unlink(path1);

	ft_mkfifo(path1, 0644);
	ft_rename_err(path1, path0, -EISDIR);
	ft_lstat(path0, &st[0]);
	ft_expect_st_dir(&st[0]);
	ft_lstat(path1, &st[1]);
	ft_expect_true(S_ISFIFO(st[1].st_mode));
	ft_unlink(path1);

	ft_symlink("test-rename-isdirto", path1);
	ft_rename_err(path1, path0, -EISDIR);
	ft_lstat(path0, &st[0]);
	ft_expect_st_dir(&st[0]);
	ft_lstat(path1, &st[1]);
	ft_expect_st_lnk(&st[1]);
	ft_unlink(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) with symlink(3p)
 */
static void test_rename_symlink_(struct ft_env *fte, size_t bsz)
{
	int fd = -1;
	void *buf = ft_new_buf_rands(fte, bsz);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	const char *path3 = ft_new_path_under(fte, path0);

	ft_mkdir(path0, 0755);
	ft_creat(path1, 0600, &fd);
	ft_pwriten(fd, buf, bsz, 0);
	ft_symlink(path1, path2);
	ft_rename(path2, path3);
	ft_close(fd);
	ft_unlink(path1);
	ft_unlink(path3);
	ft_rmdir(path0);
}

static void test_rename_symlink(struct ft_env *fte)
{
	test_rename_symlink_(fte, FT_1K);
	test_rename_symlink_(fte, FT_1M + FT_1K + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) to preserve proper nlink semantics
 */
static void test_rename_nlink(struct ft_env *fte)
{
	int fd = -1;
	struct stat st;
	const char *path_x = ft_new_path_unique(fte);
	const char *path_a = ft_new_path_under(fte, path_x);
	const char *path_b = ft_new_path_under(fte, path_x);
	const char *path_c = ft_new_path_under(fte, path_x);
	const char *path_d = ft_new_path_under(fte, path_x);
	const char *path_ab = ft_new_path_under(fte, path_a);
	const char *path_abc = ft_new_path_under(fte, path_ab);
	const char *path_abcd = ft_new_path_under(fte, path_abc);

	ft_mkdir(path_x, 0700);
	ft_stat(path_x, &st);
	ft_expect_eq(st.st_nlink, 2);
	ft_mkdir(path_a, 0700);
	ft_mkdir(path_b, 0700);
	ft_mkdir(path_c, 0700);
	ft_stat(path_x, &st);
	ft_expect_eq(st.st_nlink, 5);
	ft_creat(path_d, 0600, &fd);
	ft_close(fd);
	ft_stat(path_x, &st);
	ft_expect_eq(st.st_nlink, 5);
	ft_stat(path_d, &st);
	ft_expect_eq(st.st_nlink, 1);

	ft_rename(path_b, path_ab);
	ft_stat_noent(path_b);
	ft_stat(path_x, &st);
	ft_expect_eq(st.st_nlink, 4);
	ft_stat(path_a, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_ab, &st);
	ft_expect_eq(st.st_nlink, 2);

	ft_rename(path_c, path_abc);
	ft_stat_noent(path_c);
	ft_stat(path_x, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_a, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_ab, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_abc, &st);
	ft_expect_eq(st.st_nlink, 2);

	ft_rename(path_d, path_abcd);
	ft_stat_noent(path_d);
	ft_stat(path_x, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_a, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_ab, &st);
	ft_expect_eq(st.st_nlink, 3);
	ft_stat(path_abc, &st);
	ft_expect_eq(st.st_nlink, 2);
	ft_stat(path_abcd, &st);
	ft_expect_eq(st.st_nlink, 1);

	ft_unlink(path_abcd);
	ft_rmdir(path_abc);
	ft_rmdir(path_ab);
	ft_rmdir(path_a);
	ft_rmdir(path_x);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) within same directory without implicit unlink, where parent
 * directory is already populated with sibling links.
 */
static void test_rename_child_(struct ft_env *fte, size_t nsibs)
{
	int fd = -1;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path0);
	const char *path3 = NULL;

	ft_mkdir(path0, 0700);
	for (size_t i = 0; i < nsibs; ++i) {
		path3 = ft_new_pathf(fte, path0, "%08x", i);
		ft_creat(path3, 0600, &fd);
		ft_close(fd);
	}
	ft_creat(path1, 0600, &fd);
	ft_close(fd);
	ft_rename(path1, path2);
	ft_unlink(path2);
	for (size_t i = 0; i < nsibs; ++i) {
		path3 = ft_new_pathf(fte, path0, "%08x", i);
		ft_unlink(path3);
	}
	ft_rmdir(path0);
}

static void test_rename_child(struct ft_env *fte)
{
	test_rename_child_(fte, 16);
	test_rename_child_(fte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) within same directory with implicit unlink of target sibling
 * file.
 */
static void test_rename_replace_(struct ft_env *fte, size_t nsibs)
{
	int fd = -1;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = NULL;
	const char *path2 = ft_new_path_under(fte, path0);

	ft_mkdir(path0, 0700);
	for (size_t i = 0; i < nsibs; ++i) {
		path1 = ft_new_pathf(fte, path0, "%08x", i);
		ft_creat(path1, 0600, &fd);
		ft_close(fd);
	}
	ft_creat(path2, 0600, &fd);
	ft_close(fd);
	for (size_t i = 0; i < nsibs; ++i) {
		path1 = ft_new_pathf(fte, path0, "%08x", i);
		ft_rename(path2, path1);
		path2 = path1;
	}
	ft_unlink(path2);
	ft_rmdir(path0);
}

static void test_rename_replace(struct ft_env *fte)
{
	test_rename_replace_(fte, 1);
	test_rename_replace_(fte, 2);
	test_rename_replace_(fte, 3);
	test_rename_replace_(fte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) between two directories without implicit unlink of target.
 */
static void test_rename_move_(struct ft_env *fte, size_t cnt)
{
	int fd;
	const char *src_path1 = NULL;
	const char *tgt_path1 = NULL;
	const char *src_path0 = ft_new_path_unique(fte);
	const char *tgt_path0 = ft_new_path_unique(fte);

	ft_mkdir(src_path0, 0700);
	ft_mkdir(tgt_path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = ft_new_pathf(fte, src_path0, "s%08x", i);
		ft_creat(src_path1, 0600, &fd);
		ft_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = ft_new_pathf(fte, src_path0, "s%08x", i);
		tgt_path1 = ft_new_pathf(fte, tgt_path0, "t%08x", i);
		ft_rename(src_path1, tgt_path1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		tgt_path1 = ft_new_pathf(fte, tgt_path0, "t%08x", i);
		ft_unlink(tgt_path1);
	}
	ft_rmdir(src_path0);
	ft_rmdir(tgt_path0);
}

static void test_rename_move(struct ft_env *fte)
{
	test_rename_move_(fte, 1);
	test_rename_move_(fte, 2);
	test_rename_move_(fte, 3);
	test_rename_move_(fte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) between two directories with implicit truncate-unlink of
 * target.
 */
static void test_rename_override_(struct ft_env *fte, size_t cnt, size_t bsz)
{
	int fd = -1;
	char *src_path1 = NULL;
	char *tgt_path1 = NULL;
	const char *src_path0 = ft_new_path_unique(fte);
	const char *tgt_path0 = ft_new_path_unique(fte);
	void *buf = ft_new_buf_rands(fte, bsz);

	ft_mkdir(src_path0, 0700);
	ft_mkdir(tgt_path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = ft_new_pathf(fte, src_path0, "s%08x", i);
		tgt_path1 = ft_new_pathf(fte, tgt_path0, "t%08x", i);
		ft_creat(src_path1, 0600, &fd);
		ft_close(fd);
		ft_creat(tgt_path1, 0600, &fd);
		ft_pwriten(fd, buf, bsz, (loff_t)i);
		ft_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = ft_new_pathf(fte, src_path0, "s%08x", i);
		tgt_path1 = ft_new_pathf(fte, tgt_path0, "t%08x", i);
		ft_rename(src_path1, tgt_path1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		tgt_path1 = ft_new_pathf(fte, tgt_path0, "t%08x", i);
		ft_unlink(tgt_path1);
	}
	ft_rmdir(src_path0);
	ft_rmdir(tgt_path0);
}

static void test_rename_override(struct ft_env *fte)
{
	test_rename_override_(fte, 1, FT_BK_SIZE);
	test_rename_override_(fte, 3, FT_BK_SIZE);
	test_rename_override_(fte, 7, FT_1M);
	test_rename_override_(fte, 1024, FT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat(2) within same directory with different names length
 */
static const char *make_name(struct ft_env *fte, size_t len, char ch)
{
	size_t nn;
	char str[SILOFS_NAME_MAX + 1] = "";

	nn = (len < sizeof(str)) ? len : (sizeof(str) - 1);
	memset(str, ch, nn);
	str[nn] = '\0';

	return ft_strdup(fte, str);
}

static const char *dup_name(struct ft_env *fte, const char *str)
{
	return ft_strdup(fte, str);
}

static void test_renameat_inplace(struct ft_env *fte)
{
	int fd = -1;
	int dfd = -1;
	const char ch = 'A';
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char *path = ft_new_path_unique(fte);
	size_t count = SILOFS_NAME_MAX;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	name1 = make_name(fte, 1, ch);
	ft_openat(dfd, name1, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);
	for (size_t i = 2; i <= count; ++i) {
		name2 = make_name(fte, i, ch);
		ft_renameat(dfd, name1, dfd, name2);
		name1 = dup_name(fte, name2);
	}
	count = sizeof(name1) - 1;
	for (size_t i = count; i > 0; --i) {
		name2 = make_name(fte, i, ch);
		ft_renameat(dfd, name1, dfd, name2);
		name1 = dup_name(fte, name2);
	}
	ft_unlinkat(dfd, name1, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_renameat_inplace_rw_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	int dfd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char ch = 'B';
	const char *path = ft_new_path_unique(fte);
	const size_t bsz = cnt * FT_1K;
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);

	name1 = make_name(fte, 1, ch);
	ft_openat(dfd, name1, O_CREAT | O_RDWR, 0600, &fd);
	ft_write(fd, buf1, bsz, &nwr);
	ft_close(fd);

	cnt = sizeof(name1) - 1;
	for (size_t i = 2; i <= cnt; ++i) {
		name2 = make_name(fte, i, ch);
		ft_renameat(dfd, name1, dfd, name2);
		ft_openat(dfd, name2, O_RDONLY, 0600, &fd);
		ft_read(fd, buf2, bsz, &nrd);
		ft_close(fd);
		ft_expect_eqm(buf1, buf2, bsz);
		name1 = dup_name(fte, name2);
	}
	cnt = sizeof(name1) - 1;
	for (size_t i = cnt; i > 0; --i) {
		name2 = make_name(fte, i, ch);
		ft_renameat(dfd, name1, dfd, name2);
		ft_openat(dfd, name2, O_RDONLY, 0600, &fd);
		ft_read(fd, buf2, bsz, &nrd);
		ft_close(fd);
		ft_expect_eqm(buf1, buf2, bsz);
		name1 = dup_name(fte, name2);
	}
	ft_unlinkat(dfd, name1, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_renameat_inplace_rw(struct ft_env *fte)
{
	test_renameat_inplace_rw_(fte, 10);
	test_renameat_inplace_rw_(fte, SILOFS_NAME_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat(2) from one directory to other with different names length
 */
static void test_renameat_move_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	int dfd1 = -1;
	int dfd2 = -1;
	struct stat st;
	const char *name1;
	const char *name2;
	const char ch = 'C';
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);

	ft_mkdir(path1, 0700);
	ft_mkdir(path2, 0700);

	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_open(path2, O_DIRECTORY | O_RDONLY, 0, &dfd2);

	name1 = make_name(fte, 1, ch);
	ft_openat(dfd1, name1, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);

	for (size_t i = 2; i <= cnt; ++i) {
		ft_fstatat(dfd1, name1, &st, 0);
		name2 = make_name(fte, i, ch);
		ft_renameat(dfd1, name1, dfd2, name2);
		ft_fstatat_err(dfd1, name1, 0, -ENOENT);
		ft_fstatat(dfd2, name2, &st, 0);

		name1 = make_name(fte, i, ch);
		ft_renameat(dfd2, name2, dfd1, name1);
		ft_fstatat(dfd1, name1, &st, 0);
		ft_fstatat_err(dfd2, name2, 0, -ENOENT);
	}
	ft_unlinkat(dfd1, name1, 0);
	ft_close(dfd1);
	ft_close(dfd2);
	ft_rmdir(path1);
	ft_rmdir(path2);
}

static void test_renameat_move(struct ft_env *fte)
{
	test_renameat_move_(fte, 11);
	test_renameat_move_(fte, SILOFS_NAME_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat2(2) with RENAME_EXCHANGE flag
 */
static void test_renameat_exchange(struct ft_env *fte)
{
	int fd1 = -1;
	int fd2 = -1;
	int dfd1 = -1;
	int dfd2 = -1;
	ino_t ino1;
	ino_t ino2;
	struct stat dst1;
	struct stat dst2;
	struct stat st1;
	struct stat st2;
	const char *name1 = ft_new_name_unique(fte);
	const char *name2 = ft_new_name_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);

	ft_mkdir(path1, 0700);
	ft_mkdir(path2, 0700);

	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	ft_open(path2, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	ft_openat(dfd1, name1, O_CREAT | O_RDWR, 0600, &fd1);
	ft_openat(dfd2, name2, O_CREAT | O_RDWR, 0600, &fd2);
	ft_fstat(dfd1, &dst1);
	ft_fstat(dfd2, &dst2);
	ft_fstat(fd1, &st1);
	ft_fstat(fd2, &st2);
	ft_expect_eq(st1.st_nlink, 1);
	ft_expect_eq(st2.st_nlink, 1);
	ino1 = st1.st_ino;
	ino2 = st2.st_ino;

	ft_renameat2(dfd1, name1, dfd2, name2, RENAME_EXCHANGE);
	ft_fstat(dfd1, &dst1);
	ft_fstat(dfd2, &dst2);
	ft_openat_err(dfd1, name2, O_RDONLY, 0600, -ENOENT);
	ft_openat_err(dfd2, name1, O_RDONLY, 0600, -ENOENT);
	ft_close(fd1);
	ft_close(fd2);
	ft_openat(dfd1, name1, O_RDONLY, 0600, &fd2);
	ft_openat(dfd2, name2, O_RDONLY, 0600, &fd1);
	ft_fstat(fd1, &st1);
	ft_fstat(fd2, &st2);
	ft_expect_eq(st1.st_nlink, 1);
	ft_expect_eq(st2.st_nlink, 1);
	ft_expect_eq(st1.st_ino, ino1);
	ft_expect_eq(st2.st_ino, ino2);
	ft_unlinkat(dfd1, name1, 0);
	ft_unlinkat(dfd2, name2, 0);

	ft_close(fd1);
	ft_close(fd2);
	ft_close(dfd1);
	ft_close(dfd2);
	ft_rmdir(path1);
	ft_rmdir(path2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat2(2) back and forth within same dir
 */
static char *make_lname(struct ft_env *fte,
                        const char *prefix, size_t idx)
{
	char name[SILOFS_NAME_MAX + 1] = "";

	snprintf(name, sizeof(name) - 1, "%s-%08lu", prefix, idx);
	return ft_strdup(fte, name);
}

static void test_renameat_samedir(struct ft_env *fte)
{
	int dfd = -1;
	int fd = -1;
	ino_t ino = 0;
	char *lname1 = NULL;
	char *lname2 = NULL;
	char p1[] = "1";
	char p2[] = "2";
	const size_t cnt = SILOFS_LINK_MAX / 3;
	const char *path = ft_new_path_unique(fte);
	const char *fname = ft_new_name_unique(fte);
	struct stat st;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, fname, O_CREAT | O_RDWR, 060, &fd);
	ft_fstat(fd, &st);
	ino = st.st_ino;

	for (size_t i = 1; i <= cnt; ++i) {
		lname1 = make_lname(fte, p1, i);
		ft_linkat(dfd, fname, dfd, lname1, 0);
		ft_fstatat(dfd, lname1, &st, 0);
		ft_expect_eq(st.st_ino, ino);
	}
	for (size_t i = 1; i <= cnt; ++i) {
		lname1 = make_lname(fte, p1, i);
		lname2 = make_lname(fte, p2, i);
		ft_renameat2(dfd, lname1, dfd, lname2, 0);
		ft_fstatat(dfd, lname2, &st, 0);
		ft_expect_eq(st.st_ino, ino);
	}
	for (size_t i = 2; i <= cnt; i += 2) {
		lname1 = make_lname(fte, p1, i);
		lname2 = make_lname(fte, p2, i);
		ft_renameat2(dfd, lname2, dfd, lname1, 0);
		ft_fstatat(dfd, lname1, &st, 0);
		ft_expect_eq(st.st_ino, ino);
		ft_fstatat_err(dfd, lname2, 0, -ENOENT);
	}
	for (size_t i = 1; i <= cnt; i += 2) {
		lname1 = make_lname(fte, p1, i);
		lname2 = make_lname(fte, p2, i);
		ft_renameat2(dfd, lname2, dfd, lname1, 0);
		ft_fstatat(dfd, lname1, &st, 0);
		ft_expect_eq(st.st_ino, ino);
		ft_fstatat_err(dfd, lname2, 0, -ENOENT);
	}
	for (size_t i = 1; i <= cnt; ++i) {
		lname1 = make_lname(fte, p1, i);
		ft_unlinkat(dfd, lname1, 0);
		ft_fstatat_err(dfd, lname1, 0, -ENOENT);
	}

	ft_unlinkat(dfd, fname, 0);
	ft_close(fd);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_rename_simple),
	FT_DEFTEST(test_renameat_simple),
	FT_DEFTEST(test_rename_getattr),
	FT_DEFTEST(test_rename_ctime),
	FT_DEFTEST(test_rename_notdirto),
	FT_DEFTEST(test_rename_isdirto),
	FT_DEFTEST(test_rename_symlink),
	FT_DEFTEST(test_rename_nlink),
	FT_DEFTEST(test_rename_child),
	FT_DEFTEST(test_rename_replace),
	FT_DEFTEST(test_rename_move),
	FT_DEFTEST(test_rename_override),
	FT_DEFTEST(test_renameat_inplace),
	FT_DEFTEST(test_renameat_inplace_rw),
	FT_DEFTEST(test_renameat_move),
	FT_DEFTEST(test_renameat_exchange),
	FT_DEFTEST(test_renameat_samedir),
};

const struct ft_tests ft_test_rename = FT_DEFTESTS(ft_local_tests);
