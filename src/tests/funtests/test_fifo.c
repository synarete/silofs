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
 * Expects successful mkfifo(3p)/mkfifoat(3p)
 */
static void test_mkfifo(struct ft_env *fte)
{
	struct stat st = { .st_mode = 0 };
	const char *path = ft_new_path_unique(fte);

	ft_mkfifo(path, S_IFIFO | 0600);
	ft_stat(path, &st);
	ft_expect_st_fifo(&st);
	ft_expect_eq(st.st_nlink, 1);
	ft_expect_eq(st.st_size, 0);
	ft_unlink(path);
}

static void test_mkfifoat_(struct ft_env *fte, size_t cnt)
{
	struct stat st = { .st_mode = 0 };
	const char *path = ft_new_path_unique(fte);
	const char *name = NULL;
	int dfd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		name = ft_make_ulong_name(fte, i + 1);
		ft_mkfifoat(dfd, name, S_IFIFO | 0600);
		ft_fstatat(dfd, name, &st, 0);
		ft_expect_st_fifo(&st);
		ft_expect_eq(st.st_nlink, 1);
		ft_expect_eq(st.st_size, 0);
	}
	for (size_t i = 0; i < cnt; ++i) {
		name = ft_make_ulong_name(fte, i + 1);
		ft_unlinkat(dfd, name, 0);
	}
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_mkfifoat(struct ft_env *fte)
{
	test_mkfifoat_(fte, 10);
	test_mkfifoat_(fte, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful read/write over fifo
 */
static void test_fifo_read_write_(struct ft_env *fte, size_t bsz)
{
	struct stat st = { .st_mode = 0 };
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);
	size_t nwr = 0;
	size_t nrd = 0;
	int wfd = -1;
	int rfd = -1;

	ft_mkfifo(path, S_IFIFO | 0600);
	ft_stat(path, &st);
	ft_expect_st_fifo(&st);
	ft_open(path, O_RDWR, 0, &wfd);
	ft_write(wfd, buf1, bsz, &nwr);
	ft_expect_eq(bsz, nwr);
	ft_open(path, O_RDONLY, 0, &rfd);
	ft_read(rfd, buf2, bsz, &nrd);
	ft_expect_eq(bsz, nrd);
	ft_expect_eqm(buf1, buf2, bsz);
	ft_close(wfd);
	ft_close(rfd);
	ft_unlink(path);
}

static void test_fifo_read_write(struct ft_env *fte)
{
	test_fifo_read_write_(fte, 10);
	test_fifo_read_write_(fte, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write to fifo to change times
 */
static void test_fifo_write_mctime_(struct ft_env *fte, size_t bsz)
{
	struct stat st[2];
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);
	int fd = -1;
	bool fuse_has_fifo_bug = true;

	ft_mkfifo(path, S_IFIFO | 0600);
	ft_open(path, O_RDWR, 0, &fd);
	ft_fstat(fd, &st[0]);
	ft_writen(fd, buf1, bsz);
	ft_readn(fd, buf2, bsz);
	ft_expect_eqm(buf1, buf2, bsz);
	ft_suspend1(fte);
	ft_writen(fd, buf1, bsz);
	ft_readn(fd, buf2, bsz);
	ft_expect_eqm(buf1, buf2, bsz);
	ft_suspend1(fte);
	ft_fstat(fd, &st[1]);
	if (!fuse_has_fifo_bug) { /* XXX */
		ft_expect_st_ctime_gt(&st[0], &st[1]);
		ft_expect_st_mtime_gt(&st[0], &st[1]);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_fifo_write_mctime(struct ft_env *fte)
{
	test_fifo_write_mctime_(fte, 100);
	test_fifo_write_mctime_(fte, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects an unlinked fifo to be active while fd is open.
 */
static void test_fifo_unlinked_(struct ft_env *fte, size_t bsz)
{
	struct stat st[2];
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *dpath = ft_new_path_unique(fte);
	const char *path = ft_new_path_under(fte, dpath);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(dpath, 0700);
	ft_open(dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_mkfifo(path, S_IFIFO | 0600);
	ft_open(path, O_RDWR, 0, &fd);
	ft_fstat(fd, &st[0]);
	ft_expect_st_fifo(&st[0]);
	ft_unlink(path);
	ft_fstat(fd, &st[1]);
	ft_writen(fd, buf1, bsz);
	ft_readn(fd, buf2, bsz);
	ft_expect_eqm(buf1, buf2, bsz);
	ft_suspend1(fte);
	ft_writen(fd, buf1, bsz);
	ft_readn(fd, buf2, bsz);
	ft_expect_eqm(buf1, buf2, bsz);
	ft_fstat(fd, &st[1]);
	ft_expect_st_fifo(&st[1]);
	ft_close(fd);
	ft_stat_err(path, -ENOENT);
	ft_syncfs(dfd);
	ft_close(dfd);
	ft_suspend1(fte);
	ft_rmdir(dpath);
}

static void test_fifo_unlinked(struct ft_env *fte)
{
	test_fifo_unlinked_(fte, 100);
	test_fifo_unlinked_(fte, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects a fifo to be alive as long as it is linked
 */
static void test_fifo_nlinks_(struct ft_env *fte, nlink_t nlink, size_t bsz)
{
	struct stat st = { .st_mode = 0 };
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *dpath = ft_new_path_unique(fte);
	const char *fname = ft_make_ulong_name(fte, nlink);
	const char *lname = NULL;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(dpath, 0700);
	ft_open(dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_mkfifoat(dfd, fname, S_IFIFO | 0600);
	ft_openat(dfd, fname, O_RDWR, 0, &fd);
	ft_fstat(fd, &st);
	ft_expect_st_fifo(&st);
	for (nlink_t i = 0; i < nlink; ++i) {
		lname = ft_make_ulong_name(fte, i);
		ft_linkat(dfd, fname, dfd, lname, 0);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_nlink, i + 2);
		ft_writen(fd, buf1, bsz);
		ft_readn(fd, buf2, bsz);
		ft_expect_eqm(buf1, buf2, bsz);
	}
	ft_unlinkat(dfd, fname, 0);
	for (nlink_t i = nlink; i > 0; --i) {
		lname = ft_make_ulong_name(fte, i - 1);
		ft_unlinkat(dfd, lname, 0);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_nlink, i - 1);
		ft_writen(fd, buf1, bsz);
		ft_readn(fd, buf2, bsz);
		ft_expect_eqm(buf1, buf2, bsz);
	}
	ft_close(fd);
	ft_syncfs(dfd);
	ft_close(dfd);
	ft_suspends(fte, 1);
	ft_rmdir(dpath);
}

static void test_fifo_nlinks(struct ft_env *fte)
{
	test_fifo_nlinks_(fte, 10, 1000);
	test_fifo_nlinks_(fte, 1000, 100);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_mkfifo),
	FT_DEFTEST(test_mkfifoat),
	FT_DEFTEST(test_fifo_read_write),
	FT_DEFTEST(test_fifo_write_mctime),
	FT_DEFTEST(test_fifo_unlinked),
	FT_DEFTEST(test_fifo_nlinks),
};

const struct ft_tests ft_test_mkfifo = FT_DEFTESTS(ft_local_tests);

