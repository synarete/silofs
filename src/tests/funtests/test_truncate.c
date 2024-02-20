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
 * Expects truncate(3p) on empty regular file to update size properly.
 */
static void test_truncate_simple(struct ft_env *fte)
{
	int fd = -1;
	loff_t off;
	struct stat st;
	const loff_t offs[] = {
		0, 1, FT_BK_SIZE,
		FT_1M, FT_1M + 1, FT_1G, FT_1G - 1,
		11 * FT_1G, 111 * FT_1G - 111,
		FT_1T, FT_1T - 11, FT_FILESIZE_MAX
	};
	const char *path = ft_new_path_unique(fte);

	ft_creat(path, 0600, &fd);
	for (size_t i = 0; i < FT_ARRAY_SIZE(offs); ++i) {
		off = offs[i];
		ft_truncate(path, off);
		ft_stat(path, &st);
		ft_expect_eq(st.st_size, off);
		ft_expect_eq(st.st_blocks, 0);
	}
	for (size_t j = 0; j < FT_ARRAY_SIZE(offs); ++j) {
		off = offs[j];
		ft_ftruncate(fd, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off);
		ft_expect_eq(st.st_blocks, 0);
	}
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) after write on unaligned offsets to update
 * size properly.
 */
static void test_truncate_unaligned(struct ft_env *fte)
{
	int fd = -1;
	loff_t off;
	struct stat st;
	const char *dat = "ABCDEFGHIJKLMNOPQ";
	const size_t len = strlen(dat);
	const loff_t offs[] = {
		17, 7177, 17 * FT_1M - 7, 17 * FT_1G - 7,
		3 * FT_1T - 7, FT_FILESIZE_MAX / 7,
	};
	const char *path = ft_new_path_unique(fte);

	ft_creat(path, 0600, &fd);
	for (size_t i = 0; i < FT_ARRAY_SIZE(offs); ++i) {
		off = offs[i];
		ft_pwriten(fd, dat, len, off - 1);
		ft_fsync(fd);
		ft_fstat(fd, &st);
		ft_expect_gt(st.st_blocks, 0);
		ft_truncate(path, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off);
		ft_expect_gt(st.st_blocks, 0);
	}
	for (size_t j = 0; j < FT_ARRAY_SIZE(offs); ++j) {
		off = offs[j];
		ft_pwriten(fd, dat, len, off - 3);
		ft_ftruncate(fd, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off);
	}
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects ftruncate(3p) to zero after write to clear file's block count.
 */
static void test_truncate_zero(struct ft_env *fte)
{
	int fd = -1;
	loff_t off = 0;
	size_t bsz = FT_BK_SIZE;
	struct stat st;
	const loff_t offs[] = {
		FT_1M, FT_1G, FT_1T,
		FT_1M - 1, FT_1G - 1, FT_1T - 1
	};
	const void *buf = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_creat(path, 0600, &fd);
	for (size_t i = 0; i < FT_ARRAY_SIZE(offs); ++i) {
		off = offs[i];
		ft_pwriten(fd, buf, bsz, off);
		ft_fstat(fd, &st);
		ft_expect_gt(st.st_blocks, 0);
		ft_ftruncate(fd, 0);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_blocks, 0);
		ft_ftruncate(fd, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off);
	}
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects ftruncate(3p) to change size successfully on file-size-limit
 */
static void test_truncate_filesize_max(struct ft_env *fte)
{
	int fd = -1;
	struct stat st;
	const loff_t off = FT_FILESIZE_MAX;
	const char *path = ft_new_path_unique(fte);

	ft_creat(path, 0600, &fd);
	ft_ftruncate(fd, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off);

	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects upon successful completion of ftruncate(3p) to update the last data
 * modification and last file status change time-stamps of the file, only if
 * file size changed.
 */
static void test_truncate_mctimes_(struct ft_env *fte, loff_t off)
{
	int fd = -1;
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);

	ft_fstat(fd, &st[0]);
	ft_suspend1(fte);
	ft_ftruncate(fd, off);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);

	ft_fstat(fd, &st[0]);
	ft_suspend1(fte);
	ft_ftruncate(fd, off);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_eq(&st[0], &st[1]);
	ft_expect_mtime_eq(&st[0], &st[1]);

	ft_fstat(fd, &st[0]);
	ft_suspend1(fte);
	ft_ftruncate(fd, 0);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);

	ft_close(fd);
	ft_unlink(path);
}

static void test_truncate_mctimes(struct ft_env *fte)
{
	test_truncate_mctimes_(fte, 1);
	test_truncate_mctimes_(fte, FT_1T - 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful ftruncate(3p) to clear SUID/SGID bits
 */
static void test_truncate_suid_sgid(struct ft_env *fte)
{
	int fd;
	loff_t off = FT_1M;
	struct stat st;
	const mode_t mode = 0770;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, mode, &fd);
	ft_fstat(fd, &st);
	ft_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_ftruncate(fd, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off);
	ft_expect_eq(st.st_mode & S_ISUID, 0);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_ftruncate(fd, 0);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_mode & S_ISUID, 0);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_truncate_simple),
	FT_DEFTEST(test_truncate_unaligned),
	FT_DEFTEST(test_truncate_zero),
	FT_DEFTEST(test_truncate_filesize_max),
	FT_DEFTEST(test_truncate_mctimes),
	FT_DEFTEST(test_truncate_suid_sgid),
};

const struct ft_tests ft_test_truncate = FT_DEFTESTS(ft_local_tests);
