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
#include <utime.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utime(3p) on regular file
 */
static void test_utime_file(struct ft_env *fte)
{
	struct stat st[3];
	struct utimbuf utm[2];
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_stat(path, &st[0]);
	utm[0].actime = 11111;
	utm[0].modtime = 111111;
	ft_utime(path, &utm[0]);
	ft_stat(path, &st[1]);
	ft_expect_eq(st[1].st_atim.tv_sec, utm[0].actime);
	ft_expect_eq(st[1].st_atim.tv_nsec, 0);
	ft_expect_eq(st[1].st_mtim.tv_sec, utm[0].modtime);
	ft_expect_eq(st[1].st_mtim.tv_nsec, 0);
	ft_expect_st_ctime_ge(&st[0], &st[1]);
	utm[1].actime = 2222222222;
	utm[1].modtime = 222;
	ft_utime(path, &utm[1]);
	ft_stat(path, &st[2]);
	ft_expect_eq(st[2].st_atim.tv_sec, utm[1].actime);
	ft_expect_eq(st[2].st_atim.tv_nsec, 0);
	ft_expect_eq(st[2].st_mtim.tv_sec, utm[1].modtime);
	ft_expect_eq(st[2].st_mtim.tv_nsec, 0);
	ft_expect_st_ctime_ge(&st[1], &st[2]);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utime(3p) with current time
 */
static void test_utime_now(struct ft_env *fte)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	size_t nwr = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_utime(path, NULL);
	ft_stat(path, &st[0]);
	ft_write(fd, path, ft_strlen(path), &nwr);
	ft_utime(path, NULL);
	ft_stat(path, &st[1]);
	ft_expect_st_ctime_ge(&st[0], &st[1]);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimes(3p) on regular file
 */
static void test_utimes_file(struct ft_env *fte)
{
	struct stat st[3];
	struct timeval tv1[2];
	struct timeval tv2[2];
	const char *path = ft_new_path_unique(fte);
	size_t nwr = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_stat(path, &st[0]);
	tv1[0].tv_sec = 3333333;
	tv1[0].tv_usec = 333;
	tv1[1].tv_sec = 4444;
	tv1[1].tv_usec = 444444;
	ft_utimes(path, tv1);
	ft_stat(path, &st[1]);
	ft_expect_st_ctime_ge(&st[0], &st[1]);
	ft_expect_eq(st[1].st_atim.tv_sec, tv1[0].tv_sec);
	ft_expect_eq(st[1].st_atim.tv_nsec / 1000, tv1[0].tv_usec);
	ft_expect_eq(st[1].st_mtim.tv_sec, tv1[1].tv_sec);
	ft_expect_eq(st[1].st_mtim.tv_nsec / 1000, tv1[1].tv_usec);
	ft_write(fd, path, ft_strlen(path), &nwr);
	tv2[0].tv_sec = 55555;
	tv2[0].tv_usec = 55;
	tv2[1].tv_sec = 666666;
	tv2[1].tv_usec = 6;
	ft_utimes(path, tv2);
	ft_stat(path, &st[2]);
	ft_expect_eq(st[2].st_atim.tv_sec, tv2[0].tv_sec);
	ft_expect_eq(st[2].st_atim.tv_nsec / 1000, tv2[0].tv_usec);
	ft_expect_eq(st[2].st_mtim.tv_sec, tv2[1].tv_sec);
	ft_expect_eq(st[2].st_mtim.tv_nsec / 1000, tv2[1].tv_usec);
	ft_expect_st_ctime_ge(&st[1], &st[2]);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimensat(3p) on regular file
 */
static void test_utimensat_file(struct ft_env *fte)
{
	struct stat st[4];
	struct timespec ts1[2];
	struct timespec ts2[2];
	struct timespec ts3[2];
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st[0]);

	ts1[0].tv_sec = 7;
	ts1[0].tv_nsec = 77777;
	ts1[1].tv_sec = 8;
	ts1[1].tv_nsec = 88888;
	ft_utimensat(dfd, name, ts1, 0);
	ft_fstat(fd, &st[1]);
	ft_expect_st_ctime_ge(&st[0], &st[1]);
	ft_expect_ts_eq(&st[1].st_atim, &ts1[0]);
	ft_expect_ts_eq(&st[1].st_mtim, &ts1[1]);
	ft_writen(fd, name, ft_strlen(name));

	ts2[0].tv_sec = 0;
	ts2[0].tv_nsec = 0;
	ts2[1].tv_sec = 0;
	ts2[1].tv_nsec = 0;
	ft_futimens(fd, ts2);
	ft_fstat(fd, &st[2]);
	ft_expect_st_ctime_ge(&st[1], &st[2]);
	ft_expect_ts_eq(&st[2].st_atim, &ts2[0]);
	ft_expect_ts_eq(&st[2].st_mtim, &ts2[1]);

	ts3[0].tv_sec = 0;
	ts3[0].tv_nsec = UTIME_NOW;
	ts3[1].tv_sec = 1;
	ts3[1].tv_nsec = UTIME_NOW;
	ft_futimens(fd, ts3);
	ft_fstat(fd, &st[3]);
	ft_expect_st_ctime_ge(&st[2], &st[3]);
	ft_expect_ts_gt(&ts3[0], &st[3].st_atim);
	ft_expect_ts_gt(&ts3[1], &st[3].st_mtim);

	/* TODO: TIME_OMIT */

	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

/* TODO: Test with utimes for dir */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful futimens(3p) to change CTIME
 */
static void test_futimens_ctime(struct ft_env *fte)
{
	struct stat st[2];
	struct timespec tm[2];
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_suspends(fte, 2);

	tm[0].tv_sec = 9999;
	tm[0].tv_nsec = 99;
	tm[1].tv_sec = 1111;
	tm[1].tv_nsec = 11;
	ft_fstat(fd, &st[0]);
	ft_futimens(fd, tm);
	ft_fstat(fd, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);
	ft_expect_ts_eq(&st[1].st_atim, &tm[0]);
	ft_expect_ts_eq(&st[1].st_mtim, &tm[1]);

	tm[0].tv_sec = 121212;
	tm[0].tv_nsec = 12;
	tm[1].tv_sec = 343434;
	tm[1].tv_nsec = 34;
	ft_fstat(dfd, &st[0]);
	ft_futimens(dfd, tm);
	ft_fstat(dfd, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);
	ft_expect_ts_eq(&st[1].st_atim, &tm[0]);
	ft_expect_ts_eq(&st[1].st_mtim, &tm[1]);

	ft_fstat(fd, &st[0]);
	ft_futimens(fd, NULL);
	ft_fstat(fd, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);

	ft_fstat(dfd, &st[0]);
	ft_futimens(dfd, NULL);
	ft_fstat(dfd, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);

	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimensat(3p) on regular file with I/O
 */
static void test_utimensat_io_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	struct timespec ts[2];
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	void *buf3 = ft_new_buf_rands(fte, len);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, len, off);
	ts[0].tv_sec = 9;
	ts[0].tv_nsec = 99999;
	ts[1].tv_sec = 10;
	ts[1].tv_nsec = 101010;
	ft_futimens(fd, ts);
	ft_fstat(fd, &st);
	ft_expect_ts_eq(&st.st_atim, &ts[0]);
	ft_expect_ts_eq(&st.st_mtim, &ts[1]);
	ft_preadn(fd, buf2, len, off);
	ft_expect_eqm(buf1, buf2, len);
	ts[0].tv_sec = 11;
	ts[0].tv_nsec = 11111;
	ts[1].tv_sec = 22;
	ts[1].tv_nsec = 222222;
	ft_futimens(fd, ts);
	ft_fstat(fd, &st);
	ft_expect_ts_eq(&st.st_atim, &ts[0]);
	ft_expect_ts_eq(&st.st_mtim, &ts[1]);
	ft_pwriten(fd, buf3, len, off);
	ts[0].tv_sec = 33;
	ts[0].tv_nsec = 33033030;
	ts[1].tv_sec = 44;
	ts[1].tv_nsec = 4040440;
	ft_futimens(fd, ts);
	ft_fstat(fd, &st);
	ft_expect_ts_eq(&st.st_atim, &ts[0]);
	ft_expect_ts_eq(&st.st_mtim, &ts[1]);
	ft_preadn(fd, buf1, len, off);
	ft_expect_eqm(buf1, buf3, len);
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_utimensat_io(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1K + 1, FT_4K - 7),
		FT_MKRANGE(FT_64K - 1, FT_4K + 7),
		FT_MKRANGE(FT_64K - 11, FT_1M + 17),
		FT_MKRANGE(FT_1M - 111, FT_1M + 1111),
		FT_MKRANGE(FT_1T - 1111, 111111),
	};

	ft_exec_with_ranges(fte, test_utimensat_io_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_utime_file),     FT_DEFTEST(test_utime_now),
	FT_DEFTEST(test_utimes_file),    FT_DEFTEST(test_utimensat_file),
	FT_DEFTEST(test_futimens_ctime), FT_DEFTEST(test_utimensat_io),
};

const struct ft_tests ft_test_utimes = FT_DEFTESTS(ft_local_tests);
