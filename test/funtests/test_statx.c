/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
 * Expects valid statx(2) results
 */
static void test_statx_simple_(struct ft_env *fte, size_t bsz)
{
	struct statx stx;
	void *buf = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_statx(dfd, "", AT_EMPTY_PATH, STATX_ALL, &stx);
	ft_expect_eq(stx.stx_mask & STATX_BASIC_STATS, STATX_BASIC_STATS);
	ft_expect_true(S_ISDIR(stx.stx_mode));
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_statx(dfd, name, 0, STATX_ALL, &stx);
	ft_expect_true(S_ISREG(stx.stx_mode));
	ft_statx(fd, "", AT_EMPTY_PATH, STATX_ALL, &stx);
	ft_expect_true(S_ISREG(stx.stx_mode));
	ft_writen(fd, buf, bsz);
	ft_statx(fd, "", AT_EMPTY_PATH | AT_STATX_FORCE_SYNC, STATX_ALL, &stx);
	ft_expect_eq(stx.stx_mask & STATX_SIZE, STATX_SIZE);
	ft_expect_eq(stx.stx_size, bsz);
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_statx_simple(struct ft_env *fte)
{
	test_statx_simple_(fte, FT_1K);
	test_statx_simple_(fte, FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statx(2) to return valid and constant birth time.
 */
static void test_statx_btime_(struct ft_env *fte, loff_t off, size_t len)
{
	struct statx stx[2];
	struct timespec ts[2];
	void *buf = ft_new_buf_rands(fte, len);
	const char *name = ft_new_name_unique(fte);
	const char *path = ft_new_path_unique(fte);
	const int flags = AT_STATX_FORCE_SYNC;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0750);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);

	ft_statx(dfd, name, flags, STATX_ALL, &stx[0]);
	if (!(stx[0].stx_mask & STATX_BTIME)) {
		goto out; /* FUSE does not support statx birth time */
	}
	ft_expect_eq(stx[0].stx_mask & STATX_ALL, STATX_ALL);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[0].stx_mtime);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[0].stx_ctime);
	ft_suspends(fte, 1);
	ft_pwriten(fd, buf, len, off);
	ft_statx(dfd, name, flags, STATX_ALL, &stx[1]);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[1].stx_btime);
	ft_expect_xts_gt(&stx[1].stx_btime, &stx[1].stx_mtime);
	ft_expect_xts_gt(&stx[1].stx_btime, &stx[1].stx_ctime);
	ts[0].tv_sec = 999;
	ts[0].tv_nsec = 9999;
	ts[1].tv_sec = 888;
	ts[1].tv_nsec = 8888;
	ft_utimensat(dfd, name, ts, 0);
	ft_statx(dfd, name, flags, STATX_ALL, &stx[1]);
	ft_expect_xts_eq(&stx[0].stx_btime, &stx[1].stx_btime);
out:
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_statx_btime(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_1G, FT_64K),
	};

	ft_exec_with_ranges(fte, test_statx_btime_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statx(2) to return valid attributes with ENCRYPTED
 */
static void test_statx_attributes_(struct ft_env *fte, loff_t off, size_t len)
{
	struct statx stx[2];
	void *buf = ft_new_buf_rands(fte, len);
	const char *name = ft_new_name_unique(fte);
	const char *path = ft_new_path_unique(fte);
	const int flags = AT_STATX_FORCE_SYNC;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0750);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	/*
	 * TODO-0058: Export STATX_ATTR_ENCRYPTED attribute via FUSE
	 *
	 * Send patch to upstream kernel to have statx.attribute returned to
	 * caller. See 'fuse_fillattr' in 'fs/fuse/dir.c' for details.
	 */
	ft_statx(dfd, name, flags, STATX_ALL, &stx[0]);
	if ((stx[0].stx_attributes_mask & STATX_ATTR_ENCRYPTED) == 0) {
		goto out; /* FUSE does not support statx attributes */
	}
	ft_expect_gt(stx[0].stx_attributes & STATX_ATTR_ENCRYPTED, 0);
	ft_pwriten(fd, buf, len, off);
	ft_statx(dfd, name, flags, STATX_ALL, &stx[1]);
	ft_expect_eq(stx[0].stx_attributes, stx[1].stx_attributes);
	ft_ftruncate(fd, 0);
	ft_expect_eq(stx[0].stx_attributes, stx[1].stx_attributes);
	ft_expect_eq(stx[1].stx_size, 0);
out:
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_statx_attributes(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_1G, FT_64K),
	};

	ft_exec_with_ranges(fte, test_statx_attributes_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statx(2) to return valid and ctime for unlinked fd.
 */
static void test_statx_ctime_unlinked_(struct ft_env *fte, size_t bsz)
{
	struct statx stx[2];
	void *buf = ft_new_buf_zeros(fte, bsz);
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	const int flags = AT_STATX_FORCE_SYNC;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0750);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_statx(dfd, name, flags, STATX_ALL, &stx[0]);
	ft_expect_eq(stx[0].stx_mask & STATX_BASIC_STATS, STATX_BASIC_STATS);
	ft_statx(fd, "", AT_EMPTY_PATH, STATX_ALL, &stx[0]);
	ft_expect_true(S_ISREG(stx[0].stx_mode));
	ft_writen(fd, buf, bsz);
	ft_fsync(fd);
	ft_suspend1(fte);
	ft_unlinkat(dfd, name, 0);
	ft_fsync(dfd);
	ft_statx(fd, "", AT_EMPTY_PATH, STATX_ALL, &stx[1]);
	ft_expect_xts_gt(&stx[0].stx_ctime, &stx[1].stx_ctime);
	ft_close(fd);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_statx_ctime_unlinked(struct ft_env *fte)
{
	test_statx_ctime_unlinked_(fte, 1);
	test_statx_ctime_unlinked_(fte, FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_statx_simple),
	FT_DEFTEST(test_statx_btime),
	FT_DEFTEST(test_statx_attributes),
	FT_DEFTEST(test_statx_ctime_unlinked),
};

const struct ft_tests ft_test_statx = FT_DEFTESTS(ft_local_tests);
