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
#include <utime.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utime(3p) on regular file
 */
static void test_utime_file(struct ft_env *fte)
{
	int fd = -1;
	struct stat st[3];
	struct utimbuf utm[2];
	const char *path = ft_new_path_unique(fte);

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
	ft_expect_ctime_ge(&st[0], &st[1]);
	utm[1].actime = 2222222222;
	utm[1].modtime = 222;
	ft_utime(path, &utm[1]);
	ft_stat(path, &st[2]);
	ft_expect_eq(st[2].st_atim.tv_sec, utm[1].actime);
	ft_expect_eq(st[2].st_atim.tv_nsec, 0);
	ft_expect_eq(st[2].st_mtim.tv_sec, utm[1].modtime);
	ft_expect_eq(st[2].st_mtim.tv_nsec, 0);
	ft_expect_ctime_ge(&st[1], &st[2]);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utime(3p) with current time
 */
static void test_utime_now(struct ft_env *fte)
{
	int fd = -1;
	size_t nwr = 0;
	struct stat st1;
	struct stat st2;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_utime(path, NULL);
	ft_stat(path, &st1);
	ft_write(fd, path, strlen(path), &nwr);
	ft_utime(path, NULL);
	ft_stat(path, &st2);
	ft_expect_ctime_ge(&st1, &st2);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimes(3p) on regular file
 */
static void test_utimes_file(struct ft_env *fte)
{
	int fd = -1;
	size_t nwr = 0;
	struct stat st[3];
	struct timeval tv1[2];
	struct timeval tv2[2];
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_stat(path, &st[0]);
	tv1[0].tv_sec = 3333333;
	tv1[0].tv_usec = 333;
	tv1[1].tv_sec = 4444;
	tv1[1].tv_usec = 444444;
	ft_utimes(path, tv1);
	ft_stat(path, &st[1]);
	ft_expect_ctime_ge(&st[0], &st[1]);
	ft_expect_eq(st[1].st_atim.tv_sec, tv1[0].tv_sec);
	ft_expect_eq(st[1].st_atim.tv_nsec / 1000, tv1[0].tv_usec);
	ft_expect_eq(st[1].st_mtim.tv_sec, tv1[1].tv_sec);
	ft_expect_eq(st[1].st_mtim.tv_nsec / 1000, tv1[1].tv_usec);
	ft_write(fd, path, strlen(path), &nwr);
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
	ft_expect_ctime_ge(&st[1], &st[2]);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimensat(3p) on regular file
 */
static void test_utimensat_file(struct ft_env *fte)
{
	int fd = -1;
	int dfd = -1;
	struct stat st[4];
	struct timespec ts1[2];
	struct timespec ts2[2];
	struct timespec ts3[2];
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);

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
	ft_expect_ctime_ge(&st[0], &st[1]);
	ft_expect_ts_eq(&st[1].st_atim, &ts1[0]);
	ft_expect_ts_eq(&st[1].st_mtim, &ts1[1]);
	ft_writen(fd, name, strlen(name));

	ts2[0].tv_sec = 0;
	ts2[0].tv_nsec = 0;
	ts2[1].tv_sec = 0;
	ts2[1].tv_nsec = 0;
	ft_futimens(fd, ts2);
	ft_fstat(fd, &st[2]);
	ft_expect_ctime_ge(&st[1], &st[2]);
	ft_expect_ts_eq(&st[2].st_atim, &ts2[0]);
	ft_expect_ts_eq(&st[2].st_mtim, &ts2[1]);

	ts3[0].tv_sec = 0;
	ts3[0].tv_nsec = UTIME_NOW;
	ts3[1].tv_sec = 1;
	ts3[1].tv_nsec = UTIME_NOW;
	ft_futimens(fd, ts3);
	ft_fstat(fd, &st[3]);
	ft_expect_ctime_ge(&st[2], &st[3]);
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
	int fd = -1;
	int dfd = -1;
	struct stat st[2];
	struct timespec tm[2];
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);

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
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_ts_eq(&st[1].st_atim, &tm[0]);
	ft_expect_ts_eq(&st[1].st_mtim, &tm[1]);

	tm[0].tv_sec = 121212;
	tm[0].tv_nsec = 12;
	tm[1].tv_sec = 343434;
	tm[1].tv_nsec = 34;
	ft_fstat(dfd, &st[0]);
	ft_futimens(dfd, tm);
	ft_fstat(dfd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_ts_eq(&st[1].st_atim, &tm[0]);
	ft_expect_ts_eq(&st[1].st_mtim, &tm[1]);

	ft_fstat(fd, &st[0]);
	ft_futimens(fd, NULL);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);

	ft_fstat(dfd, &st[0]);
	ft_futimens(dfd, NULL);
	ft_fstat(dfd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);

	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_utime_file),
	FT_DEFTEST(test_utime_now),
	FT_DEFTEST(test_utimes_file),
	FT_DEFTEST(test_utimensat_file),
	FT_DEFTEST(test_futimens_ctime),
};

const struct ft_tests ft_test_utimes = FT_DEFTESTS(ft_local_tests);

