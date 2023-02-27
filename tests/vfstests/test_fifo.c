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
 * Expects successful mkfifo(3p)/mkfifoat(3p)
 */
static void test_mkfifo(struct vt_env *vte)
{
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_mkfifo(path, S_IFIFO | 0600);
	vt_stat(path, &st);
	vt_expect_true(S_ISFIFO(st.st_mode));
	vt_expect_eq(st.st_nlink, 1);
	vt_expect_eq(st.st_size, 0);
	vt_unlink(path);
}

static void test_mkfifoat_(struct vt_env *vte, size_t count)
{
	int dfd;
	struct stat st;
	const char *name;
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < count; ++i) {
		name = vt_make_ulong_name(vte, i + 1);
		vt_mkfifoat(dfd, name, S_IFIFO | 0600);
		vt_fstatat(dfd, name, &st, 0);
		vt_expect_true(S_ISFIFO(st.st_mode));
		vt_expect_eq(st.st_nlink, 1);
		vt_expect_eq(st.st_size, 0);
	}
	for (size_t i = 0; i < count; ++i) {
		name = vt_make_ulong_name(vte, i + 1);
		vt_unlinkat(dfd, name, 0);
	}
	vt_close(dfd);
	vt_rmdir(path);
}

static void test_mkfifoat(struct vt_env *vte)
{
	test_mkfifoat_(vte, 16);
	test_mkfifoat_(vte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful read/write over fifo
 */
static void test_fifo_read_write_(struct vt_env *vte, size_t bsz)
{
	int wfd = -1;
	int rfd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	struct stat st;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_mkfifo(path, S_IFIFO | 0600);
	vt_stat(path, &st);
	vt_expect_true(S_ISFIFO(st.st_mode));
	vt_open(path, O_RDWR, 0, &wfd);
	vt_write(wfd, buf1, bsz, &nwr);
	vt_expect_eq(bsz, nwr);
	vt_open(path, O_RDONLY, 0, &rfd);
	vt_read(rfd, buf2, bsz, &nrd);
	vt_expect_eq(bsz, nrd);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_close(wfd);
	vt_close(rfd);
	vt_unlink(path);
}

static void test_fifo_read_write(struct vt_env *vte)
{
	test_fifo_read_write_(vte, 1);
	test_fifo_read_write_(vte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write to fifo to change times
 */
static void test_fifo_write_mctime_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	struct stat st[2];
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);
	bool fuse_has_fifo_bug = true;

	vt_mkfifo(path, S_IFIFO | 0600);
	vt_open(path, O_RDWR, 0, &fd);
	vt_fstat(fd, &st[0]);
	vt_writen(fd, buf1, bsz);
	vt_readn(fd, buf2, bsz);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_suspends(vte, 1);
	vt_writen(fd, buf1, bsz);
	vt_readn(fd, buf2, bsz);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_suspends(vte, 1);
	vt_fstat(fd, &st[1]);
	if (!fuse_has_fifo_bug) { /* XXX */
		vt_expect_ctime_gt(&st[0], &st[1]);
		vt_expect_mtime_gt(&st[0], &st[1]);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_fifo_write_mctime(struct vt_env *vte)
{
	test_fifo_write_mctime_(vte, 512);
	test_fifo_write_mctime_(vte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects an unlinked fifo to be active while fd is open.
 */
static void test_fifo_unlinked_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	int dfd = -1;
	struct stat st[2];
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *dpath = vt_new_path_unique(vte);
	const char *path = vt_new_path_under(vte, dpath);

	vt_mkdir(dpath, 0700);
	vt_open(dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_mkfifo(path, S_IFIFO | 0600);
	vt_open(path, O_RDWR, 0, &fd);
	vt_fstat(fd, &st[0]);
	vt_expect_true(S_ISFIFO(st[0].st_mode));
	vt_unlink(path);
	vt_fstat(fd, &st[1]);
	vt_writen(fd, buf1, bsz);
	vt_readn(fd, buf2, bsz);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_suspends(vte, 1);
	vt_writen(fd, buf1, bsz);
	vt_readn(fd, buf2, bsz);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_fstat(fd, &st[1]);
	vt_expect_true(S_ISFIFO(st[1].st_mode));
	vt_close(fd);
	vt_stat_err(path, -ENOENT);
	vt_syncfs(dfd);
	vt_close(dfd);
	vt_suspends(vte, 1);
	vt_rmdir(dpath);
}

static void test_fifo_unlinked(struct vt_env *vte)
{
	test_fifo_unlinked_(vte, 512);
	test_fifo_unlinked_(vte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects a fifo to be alive as long as it is linked
 */
static void test_fifo_nlinks_(struct vt_env *vte, nlink_t nlink)
{
	int fd = -1;
	int dfd = -1;
	struct stat st;
	const size_t bsz = 1024;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *dpath = vt_new_path_unique(vte);
	const char *fname = vt_make_ulong_name(vte, nlink);
	const char *lname = NULL;

	vt_mkdir(dpath, 0700);
	vt_open(dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_mkfifoat(dfd, fname, S_IFIFO | 0600);
	vt_openat(dfd, fname, O_RDWR, 0, &fd);
	vt_fstat(fd, &st);
	vt_expect_true(S_ISFIFO(st.st_mode));
	for (nlink_t i = 0; i < nlink; ++i) {
		lname = vt_make_ulong_name(vte, i);
		vt_linkat(dfd, fname, dfd, lname, 0);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_nlink, i + 2);
		vt_writen(fd, buf1, bsz);
		vt_readn(fd, buf2, bsz);
		vt_expect_eqm(buf1, buf2, bsz);
	}
	vt_unlinkat(dfd, fname, 0);
	for (nlink_t i = nlink; i > 0; --i) {
		lname = vt_make_ulong_name(vte, i - 1);
		vt_unlinkat(dfd, lname, 0);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_nlink, i - 1);
		vt_writen(fd, buf1, bsz);
		vt_readn(fd, buf2, bsz);
		vt_expect_eqm(buf1, buf2, bsz);
	}
	vt_close(fd);
	vt_syncfs(dfd);
	vt_close(dfd);
	vt_suspends(vte, 1);
	vt_rmdir(dpath);
}

static void test_fifo_nlinks(struct vt_env *vte)
{
	test_fifo_nlinks_(vte, 16);
	test_fifo_nlinks_(vte, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_mkfifo),
	VT_DEFTEST(test_mkfifoat),
	VT_DEFTEST(test_fifo_read_write),
	VT_DEFTEST(test_fifo_write_mctime),
	VT_DEFTEST(test_fifo_unlinked),
	VT_DEFTEST(test_fifo_nlinks),
};

const struct vt_tests vt_test_mkfifo = VT_DEFTESTS(vt_local_tests);

