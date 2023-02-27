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
 * Expects rename(3p) to successfully change file's new-name and return ENOENT
 * on old-name.
 */
static void test_rename_simple(struct vt_env *vte)
{
	int fd = -1;
	ino_t ino = 0;
	mode_t ifmt = S_IFMT;
	struct stat st[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0755);
	vt_creat(path1, 0644, &fd);
	vt_stat(path1, &st[0]);
	vt_expect_reg(st[0].st_mode);
	vt_expect_eq((st[0].st_mode & ~ifmt), 0644);
	vt_expect_eq(st[0].st_nlink, 1);

	ino = st[0].st_ino;
	vt_rename(path1, path2);
	vt_stat_err(path1, -ENOENT);
	vt_fstat(fd, &st[0]);
	vt_expect_eq(st[0].st_ino, ino);
	vt_stat(path2, &st[1]);
	vt_expect_reg(st[1].st_mode);
	vt_expect_eq((st[1].st_mode & ~ifmt), 0644);
	vt_expect_eq(st[1].st_nlink, 1);

	vt_unlink(path2);
	vt_rmdir(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to update ctime only when successful.
 */
static void test_rename_ctime(struct vt_env *vte)
{
	int fd = -1;
	struct stat st[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_unique(vte);
	const char *path3 = vt_new_path_under(vte, path2);

	vt_creat(path0, 0644, &fd);
	vt_close(fd);
	vt_stat(path0, &st[0]);
	vt_suspends(vte, 2);
	vt_rename(path0, path1);
	vt_stat(path1, &st[1]);
	vt_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	vt_unlink(path1);

	vt_mkdir(path0, 0700);
	vt_stat(path0, &st[0]);
	vt_suspends(vte, 2);
	vt_rename(path0, path1);
	vt_stat(path1, &st[1]);
	vt_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	vt_rmdir(path1);

	vt_mkfifo(path0, 0644);
	vt_stat(path0, &st[0]);
	vt_suspends(vte, 2);
	vt_rename(path0, path1);
	vt_stat(path1, &st[1]);
	vt_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	vt_unlink(path1);

	vt_symlink(path2, path0);
	vt_lstat(path0, &st[0]);
	vt_suspends(vte, 2);
	vt_rename(path0, path1);
	vt_lstat(path1, &st[1]);
	vt_expect_lt(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	vt_unlink(path1);

	vt_creat(path0, 0644, &fd);
	vt_close(fd);
	vt_stat(path0, &st[0]);
	vt_suspends(vte, 2);
	vt_rename_err(path0, path3, -ENOENT);
	vt_stat(path0, &st[1]);
	vt_expect_eq(st[0].st_ctim.tv_sec, st[1].st_ctim.tv_sec);
	vt_unlink(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to returns ENOTDIR when the 'from' argument is a
 * directory, but 'to' is not a directory.
 */
static void test_rename_notdirto(struct vt_env *vte)
{
	int fd = -1;
	struct stat st[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);

	vt_mkdir(path0, 0750);
	vt_creat(path1, 0644, &fd);
	vt_close(fd);
	vt_rename_err(path0, path1, -ENOTDIR);
	vt_lstat(path0, &st[0]);
	vt_expect_dir(st[0].st_mode);
	vt_unlink(path1);

	vt_symlink("test-rename-notdirto", path1);
	vt_rename_err(path0, path1, -ENOTDIR);
	vt_lstat(path0, &st[0]);
	vt_expect_dir(st[0].st_mode);
	vt_lstat(path1, &st[1]);
	vt_expect_lnk(st[1].st_mode);
	vt_unlink(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects rename(3p) to returns EISDIR when the 'to' argument is a
 * directory, but 'from' is not a directory.
 */
static void test_rename_isdirto(struct vt_env *vte)
{
	int fd = -1;
	struct stat st[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);

	vt_mkdir(path0, 0750);
	vt_creat(path1, 0640, &fd);
	vt_close(fd);
	vt_rename_err(path1, path0, -EISDIR);
	vt_lstat(path0, &st[0]);
	vt_expect_dir(st[0].st_mode);
	vt_unlink(path1);

	vt_mkfifo(path1, 0644);
	vt_rename_err(path1, path0, -EISDIR);
	vt_lstat(path0, &st[0]);
	vt_expect_dir(st[0].st_mode);
	vt_lstat(path1, &st[1]);
	vt_expect_true(S_ISFIFO(st[1].st_mode));
	vt_unlink(path1);

	vt_symlink("test-rename-isdirto", path1);
	vt_rename_err(path1, path0, -EISDIR);
	vt_lstat(path0, &st[0]);
	vt_expect_dir(st[0].st_mode);
	vt_lstat(path1, &st[1]);
	vt_expect_lnk(st[1].st_mode);
	vt_unlink(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) with symlink(3p)
 */
static void test_rename_symlink_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path0);
	const char *path3 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0755);
	vt_creat(path1, 0600, &fd);
	vt_pwriten(fd, buf, bsz, 0);
	vt_symlink(path1, path2);
	vt_rename(path2, path3);
	vt_close(fd);
	vt_unlink(path1);
	vt_unlink(path3);
	vt_rmdir(path0);
}

static void test_rename_symlink(struct vt_env *vte)
{
	test_rename_symlink_(vte, VT_KILO);
	test_rename_symlink_(vte, VT_MEGA + VT_KILO + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) to preserve proper nlink semantics
 */
static void test_rename_nlink(struct vt_env *vte)
{
	int fd = -1;
	struct stat st;
	const char *path_x = vt_new_path_unique(vte);
	const char *path_a = vt_new_path_under(vte, path_x);
	const char *path_b = vt_new_path_under(vte, path_x);
	const char *path_c = vt_new_path_under(vte, path_x);
	const char *path_d = vt_new_path_under(vte, path_x);
	const char *path_ab = vt_new_path_under(vte, path_a);
	const char *path_abc = vt_new_path_under(vte, path_ab);
	const char *path_abcd = vt_new_path_under(vte, path_abc);

	vt_mkdir(path_x, 0700);
	vt_stat(path_x, &st);
	vt_expect_eq(st.st_nlink, 2);
	vt_mkdir(path_a, 0700);
	vt_mkdir(path_b, 0700);
	vt_mkdir(path_c, 0700);
	vt_stat(path_x, &st);
	vt_expect_eq(st.st_nlink, 5);
	vt_creat(path_d, 0600, &fd);
	vt_close(fd);
	vt_stat(path_x, &st);
	vt_expect_eq(st.st_nlink, 5);
	vt_stat(path_d, &st);
	vt_expect_eq(st.st_nlink, 1);

	vt_rename(path_b, path_ab);
	vt_stat_noent(path_b);
	vt_stat(path_x, &st);
	vt_expect_eq(st.st_nlink, 4);
	vt_stat(path_a, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_ab, &st);
	vt_expect_eq(st.st_nlink, 2);

	vt_rename(path_c, path_abc);
	vt_stat_noent(path_c);
	vt_stat(path_x, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_a, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_ab, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_abc, &st);
	vt_expect_eq(st.st_nlink, 2);

	vt_rename(path_d, path_abcd);
	vt_stat_noent(path_d);
	vt_stat(path_x, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_a, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_ab, &st);
	vt_expect_eq(st.st_nlink, 3);
	vt_stat(path_abc, &st);
	vt_expect_eq(st.st_nlink, 2);
	vt_stat(path_abcd, &st);
	vt_expect_eq(st.st_nlink, 1);

	vt_unlink(path_abcd);
	vt_rmdir(path_abc);
	vt_rmdir(path_ab);
	vt_rmdir(path_a);
	vt_rmdir(path_x);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) within same directory without implicit unlink, where parent
 * directory is already populated with sibling links.
 */
static void test_rename_child_(struct vt_env *vte, size_t nsibs)
{
	int fd = -1;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path0);
	const char *path3 = NULL;

	vt_mkdir(path0, 0700);
	for (size_t i = 0; i < nsibs; ++i) {
		path3 = vt_new_pathf(vte, path0, "%08x", i);
		vt_creat(path3, 0600, &fd);
		vt_close(fd);
	}
	vt_creat(path1, 0600, &fd);
	vt_close(fd);
	vt_rename(path1, path2);
	vt_unlink(path2);
	for (size_t i = 0; i < nsibs; ++i) {
		path3 = vt_new_pathf(vte, path0, "%08x", i);
		vt_unlink(path3);
	}
	vt_rmdir(path0);
}

static void test_rename_child(struct vt_env *vte)
{
	test_rename_child_(vte, 16);
	test_rename_child_(vte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) within same directory with implicit unlink of target sibling
 * file.
 */
static void test_rename_replace_(struct vt_env *vte, size_t nsibs)
{
	int fd = -1;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = NULL;
	const char *path2 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0700);
	for (size_t i = 0; i < nsibs; ++i) {
		path1 = vt_new_pathf(vte, path0, "%08x", i);
		vt_creat(path1, 0600, &fd);
		vt_close(fd);
	}
	vt_creat(path2, 0600, &fd);
	vt_close(fd);
	for (size_t i = 0; i < nsibs; ++i) {
		path1 = vt_new_pathf(vte, path0, "%08x", i);
		vt_rename(path2, path1);
		path2 = path1;
	}
	vt_unlink(path2);
	vt_rmdir(path0);
}

static void test_rename_replace(struct vt_env *vte)
{
	test_rename_replace_(vte, 1);
	test_rename_replace_(vte, 2);
	test_rename_replace_(vte, 3);
	test_rename_replace_(vte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) between two directories without implicit unlink of target.
 */
static void test_rename_move_(struct vt_env *vte, size_t cnt)
{
	int fd;
	const char *src_path1 = NULL;
	const char *tgt_path1 = NULL;
	const char *src_path0 = vt_new_path_unique(vte);
	const char *tgt_path0 = vt_new_path_unique(vte);

	vt_mkdir(src_path0, 0700);
	vt_mkdir(tgt_path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = vt_new_pathf(vte, src_path0, "s%08x", i);
		vt_creat(src_path1, 0600, &fd);
		vt_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = vt_new_pathf(vte, src_path0, "s%08x", i);
		tgt_path1 = vt_new_pathf(vte, tgt_path0, "t%08x", i);
		vt_rename(src_path1, tgt_path1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		tgt_path1 = vt_new_pathf(vte, tgt_path0, "t%08x", i);
		vt_unlink(tgt_path1);
	}
	vt_rmdir(src_path0);
	vt_rmdir(tgt_path0);
}

static void test_rename_move(struct vt_env *vte)
{
	test_rename_move_(vte, 1);
	test_rename_move_(vte, 2);
	test_rename_move_(vte, 3);
	test_rename_move_(vte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test rename(3p) between two directories with implicit truncate-unlink of
 * target.
 */
static void test_rename_override_(struct vt_env *vte, size_t cnt, size_t bsz)
{
	int fd = -1;
	char *src_path1 = NULL;
	char *tgt_path1 = NULL;
	const char *src_path0 = vt_new_path_unique(vte);
	const char *tgt_path0 = vt_new_path_unique(vte);
	void *buf = vt_new_buf_rands(vte, bsz);

	vt_mkdir(src_path0, 0700);
	vt_mkdir(tgt_path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = vt_new_pathf(vte, src_path0, "s%08x", i);
		tgt_path1 = vt_new_pathf(vte, tgt_path0, "t%08x", i);
		vt_creat(src_path1, 0600, &fd);
		vt_close(fd);
		vt_creat(tgt_path1, 0600, &fd);
		vt_pwriten(fd, buf, bsz, (loff_t)i);
		vt_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		src_path1 = vt_new_pathf(vte, src_path0, "s%08x", i);
		tgt_path1 = vt_new_pathf(vte, tgt_path0, "t%08x", i);
		vt_rename(src_path1, tgt_path1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		tgt_path1 = vt_new_pathf(vte, tgt_path0, "t%08x", i);
		vt_unlink(tgt_path1);
	}
	vt_rmdir(src_path0);
	vt_rmdir(tgt_path0);
}

static void test_rename_override(struct vt_env *vte)
{
	test_rename_override_(vte, 1, VT_BK_SIZE);
	test_rename_override_(vte, 3, VT_BK_SIZE);
	test_rename_override_(vte, 7, VT_UMEGA);
	test_rename_override_(vte, 1024, VT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat(2) within same directory with different names length
 */
static const char *make_name(struct vt_env *vte, size_t len, char ch)
{
	size_t nn;
	char str[SILOFS_NAME_MAX + 1] = "";

	nn = (len < sizeof(str)) ? len : (sizeof(str) - 1);
	memset(str, ch, nn);
	str[nn] = '\0';

	return vt_strdup(vte, str);
}

static const char *dup_name(struct vt_env *vte, const char *str)
{
	return vt_strdup(vte, str);
}

static void test_renameat_inplace(struct vt_env *vte)
{
	int fd = -1;
	int dfd = -1;
	const char ch = 'A';
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char *path = vt_new_path_unique(vte);
	size_t count = SILOFS_NAME_MAX;

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	name1 = make_name(vte, 1, ch);
	vt_openat(dfd, name1, O_CREAT | O_RDWR, 0600, &fd);
	vt_close(fd);
	for (size_t i = 2; i <= count; ++i) {
		name2 = make_name(vte, i, ch);
		vt_renameat(dfd, name1, dfd, name2);
		name1 = dup_name(vte, name2);
	}
	count = sizeof(name1) - 1;
	for (size_t i = count; i > 0; --i) {
		name2 = make_name(vte, i, ch);
		vt_renameat(dfd, name1, dfd, name2);
		name1 = dup_name(vte, name2);
	}
	vt_unlinkat(dfd, name1, 0);
	vt_close(dfd);
	vt_rmdir(path);
}

static void test_renameat_inplace_rw_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	int dfd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	const char *name1 = NULL;
	const char *name2 = NULL;
	const char ch = 'B';
	const char *path = vt_new_path_unique(vte);
	const size_t bsz = cnt * VT_UKILO;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);

	name1 = make_name(vte, 1, ch);
	vt_openat(dfd, name1, O_CREAT | O_RDWR, 0600, &fd);
	vt_write(fd, buf1, bsz, &nwr);
	vt_close(fd);

	cnt = sizeof(name1) - 1;
	for (size_t i = 2; i <= cnt; ++i) {
		name2 = make_name(vte, i, ch);
		vt_renameat(dfd, name1, dfd, name2);
		vt_openat(dfd, name2, O_RDONLY, 0600, &fd);
		vt_read(fd, buf2, bsz, &nrd);
		vt_close(fd);
		vt_expect_eqm(buf1, buf2, bsz);
		name1 = dup_name(vte, name2);
	}
	cnt = sizeof(name1) - 1;
	for (size_t i = cnt; i > 0; --i) {
		name2 = make_name(vte, i, ch);
		vt_renameat(dfd, name1, dfd, name2);
		vt_openat(dfd, name2, O_RDONLY, 0600, &fd);
		vt_read(fd, buf2, bsz, &nrd);
		vt_close(fd);
		vt_expect_eqm(buf1, buf2, bsz);
		name1 = dup_name(vte, name2);
	}
	vt_unlinkat(dfd, name1, 0);
	vt_close(dfd);
	vt_rmdir(path);
}

static void test_renameat_inplace_rw(struct vt_env *vte)
{
	test_renameat_inplace_rw_(vte, 10);
	test_renameat_inplace_rw_(vte, SILOFS_NAME_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat(2) from one directory to other with different names length
 */
static void test_renameat_move_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	int dfd1 = -1;
	int dfd2 = -1;
	struct stat st;
	const char *name1;
	const char *name2;
	const char ch = 'C';
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_unique(vte);

	vt_mkdir(path1, 0700);
	vt_mkdir(path2, 0700);

	vt_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	vt_open(path2, O_DIRECTORY | O_RDONLY, 0, &dfd2);

	name1 = make_name(vte, 1, ch);
	vt_openat(dfd1, name1, O_CREAT | O_RDWR, 0600, &fd);
	vt_close(fd);

	for (size_t i = 2; i <= cnt; ++i) {
		vt_fstatat(dfd1, name1, &st, 0);
		name2 = make_name(vte, i, ch);
		vt_renameat(dfd1, name1, dfd2, name2);
		vt_fstatat_err(dfd1, name1, 0, -ENOENT);
		vt_fstatat(dfd2, name2, &st, 0);

		name1 = make_name(vte, i, ch);
		vt_renameat(dfd2, name2, dfd1, name1);
		vt_fstatat(dfd1, name1, &st, 0);
		vt_fstatat_err(dfd2, name2, 0, -ENOENT);
	}
	vt_unlinkat(dfd1, name1, 0);
	vt_close(dfd1);
	vt_close(dfd2);
	vt_rmdir(path1);
	vt_rmdir(path2);
}

static void test_renameat_move(struct vt_env *vte)
{
	test_renameat_move_(vte, 11);
	test_renameat_move_(vte, SILOFS_NAME_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat2(2) with RENAME_EXCHANGE flag
 */
static void test_renameat_exchange(struct vt_env *vte)
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
	const char *name1 = vt_new_name_unique(vte);
	const char *name2 = vt_new_name_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_unique(vte);

	vt_mkdir(path1, 0700);
	vt_mkdir(path2, 0700);

	vt_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd1);
	vt_open(path2, O_DIRECTORY | O_RDONLY, 0, &dfd2);
	vt_openat(dfd1, name1, O_CREAT | O_RDWR, 0600, &fd1);
	vt_openat(dfd2, name2, O_CREAT | O_RDWR, 0600, &fd2);
	vt_fstat(dfd1, &dst1);
	vt_fstat(dfd2, &dst2);
	vt_fstat(fd1, &st1);
	vt_fstat(fd2, &st2);
	vt_expect_eq(st1.st_nlink, 1);
	vt_expect_eq(st2.st_nlink, 1);
	ino1 = st1.st_ino;
	ino2 = st2.st_ino;

	vt_renameat2(dfd1, name1, dfd2, name2, RENAME_EXCHANGE);
	vt_fstat(dfd1, &dst1);
	vt_fstat(dfd2, &dst2);
	vt_openat_err(dfd1, name2, O_RDONLY, 0600, -ENOENT);
	vt_openat_err(dfd2, name1, O_RDONLY, 0600, -ENOENT);
	vt_close(fd1);
	vt_close(fd2);
	vt_openat(dfd1, name1, O_RDONLY, 0600, &fd2);
	vt_openat(dfd2, name2, O_RDONLY, 0600, &fd1);
	vt_fstat(fd1, &st1);
	vt_fstat(fd2, &st2);
	vt_expect_eq(st1.st_nlink, 1);
	vt_expect_eq(st2.st_nlink, 1);
	vt_expect_eq(st1.st_ino, ino1);
	vt_expect_eq(st2.st_ino, ino2);
	vt_unlinkat(dfd1, name1, 0);
	vt_unlinkat(dfd2, name2, 0);

	vt_close(fd1);
	vt_close(fd2);
	vt_close(dfd1);
	vt_close(dfd2);
	vt_rmdir(path1);
	vt_rmdir(path2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test renameat2(2) back and forth within same dir
 */
static char *make_lname(struct vt_env *vte,
                        const char *prefix, size_t idx)
{
	char name[SILOFS_NAME_MAX + 1] = "";

	snprintf(name, sizeof(name) - 1, "%s-%08lu", prefix, idx);
	return vt_strdup(vte, name);
}

static void test_renameat_samedir(struct vt_env *vte)
{
	int dfd = -1;
	int fd = -1;
	ino_t ino = 0;
	char *lname1 = NULL;
	char *lname2 = NULL;
	char p1[] = "1";
	char p2[] = "2";
	const size_t cnt = SILOFS_LINK_MAX / 3;
	const char *path = vt_new_path_unique(vte);
	const char *fname = vt_new_name_unique(vte);
	struct stat st;

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_openat(dfd, fname, O_CREAT | O_RDWR, 060, &fd);
	vt_fstat(fd, &st);
	ino = st.st_ino;

	for (size_t i = 1; i <= cnt; ++i) {
		lname1 = make_lname(vte, p1, i);
		vt_linkat(dfd, fname, dfd, lname1, 0);
		vt_fstatat(dfd, lname1, &st, 0);
		vt_expect_eq(st.st_ino, ino);
	}
	for (size_t i = 1; i <= cnt; ++i) {
		lname1 = make_lname(vte, p1, i);
		lname2 = make_lname(vte, p2, i);
		vt_renameat2(dfd, lname1, dfd, lname2, 0);
		vt_fstatat(dfd, lname2, &st, 0);
		vt_expect_eq(st.st_ino, ino);
	}
	for (size_t i = 2; i <= cnt; i += 2) {
		lname1 = make_lname(vte, p1, i);
		lname2 = make_lname(vte, p2, i);
		vt_renameat2(dfd, lname2, dfd, lname1, 0);
		vt_fstatat(dfd, lname1, &st, 0);
		vt_expect_eq(st.st_ino, ino);
		vt_fstatat_err(dfd, lname2, 0, -ENOENT);
	}
	for (size_t i = 1; i <= cnt; i += 2) {
		lname1 = make_lname(vte, p1, i);
		lname2 = make_lname(vte, p2, i);
		vt_renameat2(dfd, lname2, dfd, lname1, 0);
		vt_fstatat(dfd, lname1, &st, 0);
		vt_expect_eq(st.st_ino, ino);
		vt_fstatat_err(dfd, lname2, 0, -ENOENT);
	}
	for (size_t i = 1; i <= cnt; ++i) {
		lname1 = make_lname(vte, p1, i);
		vt_unlinkat(dfd, lname1, 0);
		vt_fstatat_err(dfd, lname1, 0, -ENOENT);
	}

	vt_unlinkat(dfd, fname, 0);
	vt_close(fd);
	vt_close(dfd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_rename_simple),
	VT_DEFTEST(test_rename_ctime),
	VT_DEFTEST(test_rename_notdirto),
	VT_DEFTEST(test_rename_isdirto),
	VT_DEFTEST(test_rename_symlink),
	VT_DEFTEST(test_rename_nlink),
	VT_DEFTEST(test_rename_child),
	VT_DEFTEST(test_rename_replace),
	VT_DEFTEST(test_rename_move),
	VT_DEFTEST(test_rename_override),
	VT_DEFTEST(test_renameat_inplace),
	VT_DEFTEST(test_renameat_inplace_rw),
	VT_DEFTEST(test_renameat_move),
	VT_DEFTEST(test_renameat_exchange),
	VT_DEFTEST(test_renameat_samedir),
};

const struct vt_tests vt_test_rename = VT_DEFTESTS(vt_local_tests);
