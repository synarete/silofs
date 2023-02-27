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
#include <utime.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utime(3p) on regular file
 */
static void test_utime_file(struct vt_env *vte)
{
	int fd = -1;
	struct stat st[3];
	struct utimbuf utm[2];
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_stat(path, &st[0]);
	utm[0].actime = 11111;
	utm[0].modtime = 111111;
	vt_utime(path, &utm[0]);
	vt_stat(path, &st[1]);
	vt_expect_eq(st[1].st_atim.tv_sec, utm[0].actime);
	vt_expect_eq(st[1].st_atim.tv_nsec, 0);
	vt_expect_eq(st[1].st_mtim.tv_sec, utm[0].modtime);
	vt_expect_eq(st[1].st_mtim.tv_nsec, 0);
	vt_expect_ctime_ge(&st[0], &st[1]);
	utm[1].actime = 2222222222;
	utm[1].modtime = 222;
	vt_utime(path, &utm[1]);
	vt_stat(path, &st[2]);
	vt_expect_eq(st[2].st_atim.tv_sec, utm[1].actime);
	vt_expect_eq(st[2].st_atim.tv_nsec, 0);
	vt_expect_eq(st[2].st_mtim.tv_sec, utm[1].modtime);
	vt_expect_eq(st[2].st_mtim.tv_nsec, 0);
	vt_expect_ctime_ge(&st[1], &st[2]);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utime(3p) with current time
 */
static void test_utime_now(struct vt_env *vte)
{
	int fd = -1;
	size_t nwr = 0;
	struct stat st1;
	struct stat st2;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_utime(path, NULL);
	vt_stat(path, &st1);
	vt_write(fd, path, strlen(path), &nwr);
	vt_utime(path, NULL);
	vt_stat(path, &st2);
	vt_expect_ctime_ge(&st1, &st2);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimes(3p) on regular file
 */
static void test_utimes_file(struct vt_env *vte)
{
	int fd = -1;
	size_t nwr = 0;
	struct stat st[3];
	struct timeval tv1[2];
	struct timeval tv2[2];
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_stat(path, &st[0]);
	tv1[0].tv_sec = 3333333;
	tv1[0].tv_usec = 333;
	tv1[1].tv_sec = 4444;
	tv1[1].tv_usec = 444444;
	vt_utimes(path, tv1);
	vt_stat(path, &st[1]);
	vt_expect_ctime_ge(&st[0], &st[1]);
	vt_expect_eq(st[1].st_atim.tv_sec, tv1[0].tv_sec);
	vt_expect_eq(st[1].st_atim.tv_nsec / 1000, tv1[0].tv_usec);
	vt_expect_eq(st[1].st_mtim.tv_sec, tv1[1].tv_sec);
	vt_expect_eq(st[1].st_mtim.tv_nsec / 1000, tv1[1].tv_usec);
	vt_write(fd, path, strlen(path), &nwr);
	tv2[0].tv_sec = 55555;
	tv2[0].tv_usec = 55;
	tv2[1].tv_sec = 666666;
	tv2[1].tv_usec = 6;
	vt_utimes(path, tv2);
	vt_stat(path, &st[2]);
	vt_expect_eq(st[2].st_atim.tv_sec, tv2[0].tv_sec);
	vt_expect_eq(st[2].st_atim.tv_nsec / 1000, tv2[0].tv_usec);
	vt_expect_eq(st[2].st_mtim.tv_sec, tv2[1].tv_sec);
	vt_expect_eq(st[2].st_mtim.tv_nsec / 1000, tv2[1].tv_usec);
	vt_expect_ctime_ge(&st[1], &st[2]);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful utimensat(3p) on regular file
 */
static void test_utimensat_file(struct vt_env *vte)
{
	int fd = -1;
	int dfd = -1;
	struct stat st[4];
	struct timespec ts1[2];
	struct timespec ts2[2];
	struct timespec ts3[2];
	const char *path = vt_new_path_unique(vte);
	const char *name = vt_new_name_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st[0]);

	ts1[0].tv_sec = 7;
	ts1[0].tv_nsec = 77777;
	ts1[1].tv_sec = 8;
	ts1[1].tv_nsec = 88888;
	vt_utimensat(dfd, name, ts1, 0);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_ge(&st[0], &st[1]);
	vt_expect_ts_eq(&st[1].st_atim, &ts1[0]);
	vt_expect_ts_eq(&st[1].st_mtim, &ts1[1]);
	vt_writen(fd, name, strlen(name));

	ts2[0].tv_sec = 0;
	ts2[0].tv_nsec = 0;
	ts2[1].tv_sec = 0;
	ts2[1].tv_nsec = 0;
	vt_futimens(fd, ts2);
	vt_fstat(fd, &st[2]);
	vt_expect_ctime_ge(&st[1], &st[2]);
	vt_expect_ts_eq(&st[2].st_atim, &ts2[0]);
	vt_expect_ts_eq(&st[2].st_mtim, &ts2[1]);

	ts3[0].tv_sec = 0;
	ts3[0].tv_nsec = UTIME_NOW;
	ts3[1].tv_sec = 1;
	ts3[1].tv_nsec = UTIME_NOW;
	vt_futimens(fd, ts3);
	vt_fstat(fd, &st[3]);
	vt_expect_ctime_ge(&st[2], &st[3]);
	vt_expect_ts_gt(&ts3[0], &st[3].st_atim);
	vt_expect_ts_gt(&ts3[1], &st[3].st_mtim);

	/* TODO: TIME_OMIT */

	vt_close(fd);
	vt_unlinkat(dfd, name, 0);
	vt_close(dfd);
	vt_rmdir(path);
}

/* TODO: Test with utimes for dir */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful futimens(3p) to change CTIME
 */
static void test_futimens_ctime(struct vt_env *vte)
{
	int fd = -1;
	int dfd = -1;
	struct stat st[2];
	struct timespec tm[2];
	const char *path = vt_new_path_unique(vte);
	const char *name = vt_new_name_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	vt_suspends(vte, 2);

	tm[0].tv_sec = 9999;
	tm[0].tv_nsec = 99;
	tm[1].tv_sec = 1111;
	tm[1].tv_nsec = 11;
	vt_fstat(fd, &st[0]);
	vt_futimens(fd, tm);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_expect_ts_eq(&st[1].st_atim, &tm[0]);
	vt_expect_ts_eq(&st[1].st_mtim, &tm[1]);

	tm[0].tv_sec = 121212;
	tm[0].tv_nsec = 12;
	tm[1].tv_sec = 343434;
	tm[1].tv_nsec = 34;
	vt_fstat(dfd, &st[0]);
	vt_futimens(dfd, tm);
	vt_fstat(dfd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_expect_ts_eq(&st[1].st_atim, &tm[0]);
	vt_expect_ts_eq(&st[1].st_mtim, &tm[1]);

	vt_fstat(fd, &st[0]);
	vt_futimens(fd, NULL);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);

	vt_fstat(dfd, &st[0]);
	vt_futimens(dfd, NULL);
	vt_fstat(dfd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);

	vt_close(fd);
	vt_unlinkat(dfd, name, 0);
	vt_close(dfd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_utime_file),
	VT_DEFTEST(test_utime_now),
	VT_DEFTEST(test_utimes_file),
	VT_DEFTEST(test_utimensat_file),
	VT_DEFTEST(test_futimens_ctime),
};

const struct vt_tests vt_test_utimes = VT_DEFTESTS(vt_local_tests);

