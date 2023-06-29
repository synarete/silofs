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
#include <sys/xattr.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/getxattr/removexattr operations
 */
static void test_xattr_simple(struct ft_env *fte)
{
	int fd;
	size_t sz;
	const char *name = "user.digits";
	const char *value = "0123456789";
	const size_t valsz = strlen(value);
	char buf[80] = "";
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_close(fd);
	ft_setxattr(path, name, value, valsz, 0);
	ft_getxattr(path, name, NULL, 0, &sz);
	ft_expect_eq(sz, valsz);
	ft_getxattr(path, name, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz);
	ft_expect_eqm(value, buf, valsz);
	ft_removexattr(path, name);
	ft_getxattr_err(path, name, -ENODATA);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/getxattr operations on various inode types.
 */
static void test_xattr_inode(struct ft_env *fte)
{
	int fd;
	size_t sz;
	const char *name = "user.digits";
	const char *value = "0123456789";
	const size_t valsz = strlen(value);
	char buf[80] = "";
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_under(fte, path1);
	const char *path3 = ft_new_path_under(fte, path1);

	ft_mkdir(path1, 0700);
	ft_open(path2, O_CREAT | O_RDWR, 0600, &fd);
	ft_symlink(path1, path3);

	ft_setxattr(path1, name, value, valsz, 0);
	ft_getxattr(path1, name, NULL, 0, &sz);
	ft_expect_eq(sz, valsz);
	ft_getxattr(path1, name, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz);
	ft_expect_eqm(value, buf, valsz);

	ft_setxattr(path2, name, value, valsz, 0);
	ft_getxattr(path2, name, NULL, 0, &sz);
	ft_expect_eq(sz, valsz);
	ft_getxattr(path2, name, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz);
	ft_expect_eqm(value, buf, valsz);

	ft_setxattr(path3, name, value, valsz, 0);
	ft_getxattr(path3, name, NULL, 0, &sz);
	ft_expect_eq(sz, valsz);
	ft_getxattr(path3, name, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz);
	ft_expect_eqm(value, buf, valsz);

	ft_close(fd);
	ft_unlink(path3);
	ft_unlink(path2);
	ft_rmdir(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/removexattr operations to change CTIME only
 */
static void test_xattr_ctime(struct ft_env *fte)
{
	int fd;
	size_t sz;
	struct stat st1;
	struct stat st2;
	const char *name = "user.xattr_ctime";
	const char *value = "ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF";
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_fstat(fd, &st1);
	ft_fsetxattr(fd, name, value, strlen(value), 0);
	ft_fstat(fd, &st2);
	ft_expect_mtime_eq(&st1, &st2);
	ft_expect_ctime_ge(&st1, &st2);

	ft_fstat(fd, &st1);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_fstat(fd, &st2);
	ft_expect_mtime_eq(&st1, &st2);
	ft_expect_ctime_eq(&st1, &st2);

	ft_fstat(fd, &st1);
	ft_fremovexattr(fd, name);
	ft_fstat(fd, &st2);
	ft_expect_mtime_eq(&st1, &st2);
	ft_expect_ctime_ge(&st1, &st2);

	ft_fstat(fd, &st1);
	ft_fremovexattr_err(fd, name, -ENODATA);
	ft_fstat(fd, &st2);
	ft_expect_mtime_eq(&st1, &st2);
	ft_expect_ctime_eq(&st1, &st2);

	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr operations with implicit/explicit rename
 */
static void test_xattr_replace(struct ft_env *fte)
{
	int fd;
	size_t sz;
	const char *name = "user.xattr_replace";
	const char *val1 = "0123456789";
	const char *val2 = "ABCDEFGHIJKLMNOPQRSTUVXYZ";
	const char *val3 = "abcdefghijklmnopqrstuvwxyz0123456789";
	const char *path = ft_new_path_unique(fte);
	char buf[256] = "";

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_fsetxattr(fd, name, val1, strlen(val1), 0);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_expect_eq(sz, strlen(val1));
	ft_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	ft_expect_eq(sz, strlen(val1));
	ft_expect_eqm(buf, val1, sz);

	ft_fsetxattr(fd, name, val2, strlen(val2), 0);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_expect_eq(sz, strlen(val2));
	ft_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	ft_expect_eq(sz, strlen(val2));
	ft_expect_eqm(buf, val2, sz);

	ft_fsetxattr(fd, name, val3, strlen(val3), XATTR_REPLACE);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_expect_eq(sz, strlen(val3));
	ft_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	ft_expect_eq(sz, strlen(val3));
	ft_expect_eqm(buf, val3, sz);

	ft_fremovexattr(fd, name);
	ft_fremovexattr_err(fd, name, -ENODATA);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful listxattr operations
 */
static void test_xattr_list(struct ft_env *fte)
{
	int fd;
	size_t sz;
	const char *name1 = "user.xattr_list1";
	const char *name2 = "user.xattr_xxxxx_list2";
	const char *value = "0123456789ABCDEF";
	const size_t nlen1 = strlen(name1);
	const size_t nlen2 = strlen(name2);
	const char *path = ft_new_path_unique(fte);
	char list[256] = "";

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, 0);
	ft_fsetxattr(fd, name1, value, strlen(value), 0);
	ft_flistxattr(fd, NULL, 0, &sz);
	ft_expect_eq(sz, nlen1 + 1);
	ft_expect_lt(sz, sizeof(list));
	ft_flistxattr_err(fd, list, 1, -ERANGE);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, nlen1 + 1);
	ft_flistxattr(fd, list, sz, &sz);
	ft_expect_eq(sz, nlen1 + 1);
	ft_fsetxattr(fd, name2, value, strlen(value), 0);
	ft_flistxattr(fd, NULL, 0, &sz);
	ft_expect_eq(sz, nlen1 + nlen2 + 2);
	ft_flistxattr_err(fd, list, 1, -ERANGE);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, nlen1 + nlen2 + 2);
	ft_expect_eqm(list, name1, nlen1);
	ft_expect_eqm(list + nlen1 + 1, name2, nlen2);
	ft_fremovexattr(fd, name1);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, nlen2 + 1);
	ft_expect_eqm(list, name2, nlen2);
	ft_fremovexattr(fd, name2);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, 0);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful xattr operation with any name length
 */
static void test_xattr_any_(struct ft_env *fte, size_t value_size)
{
	char buf[SILOFS_NAME_MAX + 1] = "";
	const char *name = NULL;
	void *vbuf = ft_new_buf_rands(fte, value_size + 1);
	const void *value = ft_new_buf_rands(fte, value_size);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	size_t cnt = 0;
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t nlen = 1; nlen < sizeof(buf); ++nlen) {
		name = ft_make_xname_unique(fte, nlen, buf, sizeof(buf));
		ft_fsetxattr(fd, name, value, value_size, 0);
		ft_fgetxattr(fd, name, vbuf, 0, &cnt);
		ft_expect_eq(cnt, value_size);
		ft_fgetxattr(fd, name, vbuf, value_size + 1, &cnt);
		ft_expect_eq(cnt, value_size);
		ft_fremovexattr(fd, name);
		ft_flistxattr(fd, NULL, 0, &cnt);
		ft_expect_eq(cnt, 0);
	}
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

static void test_xattr_any_small(struct ft_env *fte)
{
	size_t value_size = 1;
	const size_t value_size_max = 1023;

	while (value_size <= value_size_max) {
		test_xattr_any_(fte, value_size);
		value_size += 13;
	}
}

static void test_xattr_any_large(struct ft_env *fte)
{
	size_t value_size = 1024;

	while (value_size <= SILOFS_XATTR_VALUE_MAX) {
		test_xattr_any_(fte, value_size);
		value_size += 23;
	}
}

static void test_xattr_any_edges(struct ft_env *fte)
{
	test_xattr_any_(fte, 1);
	test_xattr_any_(fte, 2);
	test_xattr_any_(fte, 247);
	test_xattr_any_(fte, 248);
	test_xattr_any_(fte, 249);
	test_xattr_any_(fte, SILOFS_XATTR_VALUE_MAX - 1);
	test_xattr_any_(fte, SILOFS_XATTR_VALUE_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_xattr_simple),
	FT_DEFTEST(test_xattr_inode),
	FT_DEFTEST(test_xattr_ctime),
	FT_DEFTEST(test_xattr_replace),
	FT_DEFTEST(test_xattr_list),
	FT_DEFTEST(test_xattr_any_small),
	FT_DEFTEST(test_xattr_any_large),
	FT_DEFTEST(test_xattr_any_edges),
};

const struct ft_tests ft_test_xattr = FT_DEFTESTS(ft_local_tests);

