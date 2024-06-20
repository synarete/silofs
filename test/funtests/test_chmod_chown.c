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
 * Expects chmod(3p) to do change permissions.
 */
static void test_chmod_basic(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const mode_t ifmt = S_IFMT;
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	int fd = -1;

	ft_creat(path0, 0644, &fd);
	ft_close(fd);
	ft_stat(path0, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0644);
	ft_chmod(path0, 0111);
	ft_stat(path0, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0111);
	ft_unlink(path0);

	ft_mkdir(path1, 0755);
	ft_stat(path1, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0755);
	ft_chmod(path1, 0753);
	ft_stat(path1, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0753);
	ft_rmdir(path1);

	ft_creat(path0, 0644, &fd);
	ft_close(fd);
	ft_symlink(path0, path2);
	ft_stat(path2, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0644);
	ft_chmod(path2, 0321);
	ft_stat(path2, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0321);
	ft_stat(path0, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0321);
	ft_unlink(path0);
	ft_unlink(path2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects chmod(3p) to updates ctime if successful.
 */
static void test_chmod_ctime(struct ft_env *fte)
{
	struct stat st[2];
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	int fd = -1;

	ft_creat(path0, 0644, &fd);
	ft_fstat(fd, &st[0]);
	ft_suspend(fte, 3, 2);
	ft_chmod(path0, 0111);
	ft_fstat(fd, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);
	ft_close(fd);
	ft_unlink(path0);

	ft_mkdir(path1, 0755);
	ft_stat(path1, &st[0]);
	ft_suspend(fte, 3, 2);
	ft_chmod(path1, 0753);
	ft_stat(path1, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);
	ft_rmdir(path1);

	ft_mkfifo(path2, 0640);
	ft_stat(path2, &st[0]);
	ft_suspend(fte, 3, 2);
	ft_chmod(path2, 0300);
	ft_stat(path2, &st[1]);
	ft_expect_st_ctime_gt(&st[0], &st[1]);
	ft_unlink(path2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fchmod(3p) to operate on regular files
 */
static void test_chmod_fchmod(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const mode_t ifmt = S_IFMT;
	int fd = -1;

	ft_creat(path, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0600);
	ft_fchmod(fd, 0755);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0755);
	ft_fchmod(fd, 0100);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0100);
	ft_fchmod(fd, 0600);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fchmod(3p) to operate on on unlinked regular files
 */
static void test_chmod_unlinked(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const mode_t ifmt = S_IFMT;
	int fd = -1;

	ft_creat(path, 0600, &fd);
	ft_unlink(path);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0600);
	ft_fchmod(fd, 0755);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0755);
	ft_fchmod(fd, 0100);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0100);
	ft_fchmod(fd, 0600);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0600);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fchmod(3p) to properly set/clear SUID/SGID
 */
static void test_chmod_suid_sgid(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const mode_t ifmt = S_IFMT;
	const mode_t isuid = S_ISUID;
	const mode_t isgid = S_ISGID;
	int fd = -1;

	ft_creat(path, 0755, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq((st.st_mode & ~ifmt), 0755);
	ft_fchmod(fd, st.st_mode | S_ISUID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_fchmod(fd, st.st_mode & ~isuid);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, 0);
	ft_fchmod(fd, st.st_mode | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_fchmod(fd, st.st_mode & ~isgid);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_unlink(path);

	ft_fchmod(fd, st.st_mode | S_ISUID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_fchmod(fd, st.st_mode & ~isuid);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, 0);
	ft_fchmod(fd, st.st_mode | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_fchmod(fd, st.st_mode & ~isgid);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects chown(3p) to update CTIME
 */
static void test_chown_ctime(struct ft_env *fte)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_creat(path, 0600, &fd);
	ft_stat(path, &st[0]);
	ft_suspend(fte, 2, 5);
	ft_chown(path, st[0].st_uid, st[0].st_gid);
	ft_stat(path, &st[1]);
	ft_expect_gt(st[1].st_ctim.tv_sec, st[0].st_ctim.tv_sec);
	ft_fstat(fd, &st[0]);
	ft_suspend(fte, 2, 5);
	ft_fchown(fd, st[0].st_uid, st[0].st_gid);
	ft_fstat(fd, &st[1]);
	ft_expect_gt(st[1].st_ctim.tv_sec, st[0].st_ctim.tv_sec);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects chown(3p) to work properly on unlinked file
 */
static void test_chown_unlinked(struct ft_env *fte)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_creat(path, 0600, &fd);
	ft_unlink(path);
	ft_stat_noent(path);
	ft_fstat(fd, &st[0]);
	ft_suspend(fte, 2, 5);
	ft_fchown(fd, st[0].st_uid, st[0].st_gid);
	ft_fstat(fd, &st[1]);
	ft_expect_gt(st[1].st_ctim.tv_sec, st[0].st_ctim.tv_sec);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fchown(3p) to properly sets/clear SUID/SGID
 */
static void test_chown_suid_sgid(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_creat(path, S_IFREG | S_IXUSR | S_IWUSR | S_IRUSR, &fd);
	ft_fstat(fd, &st);
	ft_fchmod(fd, st.st_mode | S_ISUID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_fchown(fd, st.st_uid, st.st_gid);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, 0);
	ft_fchmod(fd, st.st_mode | S_ISGID | S_IXGRP);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_fchown(fd, st.st_uid, st.st_gid);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: Check fchmodat */

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_chmod_basic),
	FT_DEFTEST(test_chmod_ctime),
	FT_DEFTEST(test_chmod_fchmod),
	FT_DEFTEST(test_chmod_unlinked),
	FT_DEFTEST(test_chmod_suid_sgid),
	FT_DEFTEST(test_chown_ctime),
	FT_DEFTEST(test_chown_unlinked),
	FT_DEFTEST(test_chown_suid_sgid),
};

const struct ft_tests ft_test_chmod = FT_DEFTESTS(ft_local_tests);

