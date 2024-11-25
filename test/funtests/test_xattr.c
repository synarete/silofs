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
 * Expects successful setxattr/getxattr/removexattr operations
 */
static void test_xattr_simple(struct ft_env *fte)
{
	char buf[80] = "";
	const char *path = ft_new_path_unique(fte);
	const char *name = "user.digits";
	const char *value = "0123456789";
	const size_t valsz = ft_strlen(value);
	size_t sz = 0;
	int fd = -1;

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
 * Expects successful fsetxattr/fgetxattr/fremovexattr operations on directory
 * and regular file.
 */
static void test_xattr_by_fd(struct ft_env *fte)
{
	char buf[80] = "";
	const char *dpath = ft_new_path_unique(fte);
	const char *fpath = ft_new_path_under(fte, dpath);
	const char *name1 = "user.ascii_lowercase";
	const char *value1 = "abcdefghijklmnopqrstuvwxyz";
	const size_t valsz1 = ft_strlen(value1);
	const char *name2 = "user.ascii_letters";
	const char *value2 =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	const size_t valsz2 = ft_strlen(value2);
	size_t sz = 0;
	int dfd = -1;
	int fd = -1;

	ft_mkdir(dpath, 0700);
	ft_open(dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_fsetxattr(dfd, name1, value1, valsz1, 0);
	ft_fgetxattr(dfd, name1, NULL, 0, &sz);
	ft_expect_eq(sz, valsz1);
	ft_fgetxattr(dfd, name1, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz1);
	ft_expect_eqm(value1, buf, valsz1);
	ft_fremovexattr(dfd, name1);
	ft_fgetxattr_err(dfd, name1, -ENODATA);
	ft_open(fpath, O_CREAT | O_RDWR, 0700, &fd);
	ft_fsetxattr(fd, name1, value1, valsz1, 0);
	ft_fgetxattr(fd, name1, NULL, 0, &sz);
	ft_expect_eq(sz, valsz1);
	ft_fgetxattr(fd, name1, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz1);
	ft_expect_eqm(value1, buf, valsz1);
	ft_fsetxattr(fd, name2, value2, valsz2, 0);
	ft_fgetxattr(fd, name2, NULL, 0, &sz);
	ft_expect_eq(sz, valsz2);
	ft_fgetxattr(fd, name2, buf, sizeof(buf), &sz);
	ft_expect_eq(sz, valsz2);
	ft_expect_eqm(value2, buf, valsz2);
	ft_fremovexattr(fd, name1);
	ft_fgetxattr_err(fd, name1, -ENODATA);
	ft_fremovexattr(fd, name2);
	ft_fgetxattr_err(fd, name2, -ENODATA);
	ft_close(fd);
	ft_close(dfd);
	ft_unlink(fpath);
	ft_rmdir(dpath);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/getxattr operations on various inode types.
 */
static void test_xattr_inode(struct ft_env *fte)
{
	char buf[80] = "";
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_under(fte, path1);
	const char *path3 = ft_new_path_under(fte, path1);
	const char *name = "user.digits";
	const char *value = "0123456789";
	const size_t valsz = ft_strlen(value);
	size_t sz = 0;
	int fd = -1;

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
	struct stat st[2];
	const char *name = "user.xattr_ctime";
	const char *value = "ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF";
	const char *path = ft_new_path_unique(fte);
	size_t sz = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_fstat(fd, &st[0]);
	ft_fsetxattr(fd, name, value, ft_strlen(value), 0);
	ft_fstat(fd, &st[1]);
	ft_expect_st_mtime_eq(&st[0], &st[1]);
	ft_expect_st_ctime_ge(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_fstat(fd, &st[1]);
	ft_expect_st_mtime_eq(&st[0], &st[1]);
	ft_expect_st_ctime_eq(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_fremovexattr(fd, name);
	ft_fstat(fd, &st[1]);
	ft_expect_st_mtime_eq(&st[0], &st[1]);
	ft_expect_st_ctime_ge(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_fremovexattr_err(fd, name, -ENODATA);
	ft_fstat(fd, &st[1]);
	ft_expect_st_mtime_eq(&st[0], &st[1]);
	ft_expect_st_ctime_eq(&st[0], &st[1]);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr operations with implicit/explicit rename
 */
static void test_xattr_replace(struct ft_env *fte)
{
	char buf[256] = "";
	const char *name = "user.xattr_replace";
	const char *val1 = "0123456789";
	const char *val2 = "ABCDEFGHIJKLMNOPQRSTUVXYZ";
	const char *val3 = "abcdefghijklmnopqrstuvwxyz0123456789";
	const char *path = ft_new_path_unique(fte);
	size_t sz = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_fsetxattr(fd, name, val1, ft_strlen(val1), 0);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_expect_eq(sz, ft_strlen(val1));
	ft_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	ft_expect_eq(sz, ft_strlen(val1));
	ft_expect_eqm(buf, val1, sz);
	ft_fsetxattr(fd, name, val2, ft_strlen(val2), 0);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_expect_eq(sz, ft_strlen(val2));
	ft_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	ft_expect_eq(sz, ft_strlen(val2));
	ft_expect_eqm(buf, val2, sz);
	ft_fsetxattr(fd, name, val3, ft_strlen(val3), XATTR_REPLACE);
	ft_fgetxattr(fd, name, NULL, 0, &sz);
	ft_expect_eq(sz, ft_strlen(val3));
	ft_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	ft_expect_eq(sz, ft_strlen(val3));
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
	char list[256] = "";
	const char *path = ft_new_path_unique(fte);
	const char *name1 = "user.xattr_list1";
	const char *name2 = "user.xattr_xxxxx_list2";
	const char *value = "0123456789ABCDEF";
	const size_t nlen1 = ft_strlen(name1);
	const size_t nlen2 = ft_strlen(name2);
	size_t sz = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, 0);
	ft_fsetxattr(fd, name1, value, ft_strlen(value), 0);
	ft_flistxattr(fd, NULL, 0, &sz);
	ft_expect_eq(sz, nlen1 + 1);
	ft_expect_lt(sz, sizeof(list));
	ft_flistxattr_err(fd, list, 1, -ERANGE);
	ft_flistxattr(fd, list, sizeof(list), &sz);
	ft_expect_eq(sz, nlen1 + 1);
	ft_flistxattr(fd, list, sz, &sz);
	ft_expect_eq(sz, nlen1 + 1);
	ft_fsetxattr(fd, name2, value, ft_strlen(value), 0);
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
static void test_xattr_any_(struct ft_env *fte, size_t valsz)
{
	char buf[SILOFS_NAME_MAX + 1] = "";
	void *vbuf = ft_new_buf_rands(fte, valsz + 1);
	const void *value = ft_new_buf_rands(fte, valsz);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *name = NULL;
	size_t cnt = 0;
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t nlen = 1; nlen < sizeof(buf); ++nlen) {
		name = ft_make_xname_unique(fte, nlen, buf, sizeof(buf));
		ft_fsetxattr(fd, name, value, valsz, 0);
		ft_fgetxattr(fd, name, vbuf, 0, &cnt);
		ft_expect_eq(cnt, valsz);
		ft_fgetxattr(fd, name, vbuf, valsz + 1, &cnt);
		ft_expect_eq(cnt, valsz);
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
	size_t valsz = 0;

	while (valsz <= 1023) {
		ft_relax_mem(fte);
		valsz += 13;
		test_xattr_any_(fte, valsz);
	}
}

static void test_xattr_any_large(struct ft_env *fte)
{
	size_t valsz = 1024;

	while (valsz <= SILOFS_XATTR_VALUE_MAX) {
		ft_relax_mem(fte);
		test_xattr_any_(fte, valsz);
		valsz += 64;
	}
}

static void test_xattr_any_edges(struct ft_env *fte)
{
	const size_t valsz[] = {
		1,
		2,
		80,
		247,
		248,
		249,
		SILOFS_XATTR_VALUE_MAX - 1,
		SILOFS_XATTR_VALUE_MAX,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(valsz); ++i) {
		test_xattr_any_(fte, valsz[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_xattr_simple),    //
	FT_DEFTEST(test_xattr_by_fd),     //
	FT_DEFTEST(test_xattr_inode),     //
	FT_DEFTEST(test_xattr_ctime),     //
	FT_DEFTEST(test_xattr_replace),   //
	FT_DEFTEST(test_xattr_list),      //
	FT_DEFTEST(test_xattr_any_small), //
	FT_DEFTEST(test_xattr_any_large), //
	FT_DEFTEST(test_xattr_any_edges), //
};

const struct ft_tests ft_test_xattr = FT_DEFTESTS(ft_local_tests);
