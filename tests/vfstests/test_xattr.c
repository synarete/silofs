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
#include <sys/xattr.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/getxattr/removexattr operations
 */
static void test_xattr_simple(struct vt_env *vte)
{
	int fd;
	size_t sz;
	const char *name = "user.digits";
	const char *value = "0123456789";
	const size_t valsz = strlen(value);
	char buf[80] = "";
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0700, &fd);
	vt_close(fd);
	vt_setxattr(path, name, value, valsz, 0);
	vt_getxattr(path, name, NULL, 0, &sz);
	vt_expect_eq(sz, valsz);
	vt_getxattr(path, name, buf, sizeof(buf), &sz);
	vt_expect_eq(sz, valsz);
	vt_expect_eqm(value, buf, valsz);
	vt_removexattr(path, name);
	vt_getxattr_err(path, name, -ENODATA);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/getxattr operations on various inode types.
 */
static void test_xattr_inode(struct vt_env *vte)
{
	int fd;
	size_t sz;
	const char *name = "user.digits";
	const char *value = "0123456789";
	const size_t valsz = strlen(value);
	char buf[80] = "";
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_under(vte, path1);
	const char *path3 = vt_new_path_under(vte, path1);

	vt_mkdir(path1, 0700);
	vt_open(path2, O_CREAT | O_RDWR, 0600, &fd);
	vt_symlink(path1, path3);

	vt_setxattr(path1, name, value, valsz, 0);
	vt_getxattr(path1, name, NULL, 0, &sz);
	vt_expect_eq(sz, valsz);
	vt_getxattr(path1, name, buf, sizeof(buf), &sz);
	vt_expect_eq(sz, valsz);
	vt_expect_eqm(value, buf, valsz);

	vt_setxattr(path2, name, value, valsz, 0);
	vt_getxattr(path2, name, NULL, 0, &sz);
	vt_expect_eq(sz, valsz);
	vt_getxattr(path2, name, buf, sizeof(buf), &sz);
	vt_expect_eq(sz, valsz);
	vt_expect_eqm(value, buf, valsz);

	vt_setxattr(path3, name, value, valsz, 0);
	vt_getxattr(path3, name, NULL, 0, &sz);
	vt_expect_eq(sz, valsz);
	vt_getxattr(path3, name, buf, sizeof(buf), &sz);
	vt_expect_eq(sz, valsz);
	vt_expect_eqm(value, buf, valsz);

	vt_close(fd);
	vt_unlink(path3);
	vt_unlink(path2);
	vt_rmdir(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr/removexattr operations to change CTIME only
 */
static void test_xattr_ctime(struct vt_env *vte)
{
	int fd;
	size_t sz;
	struct stat st1;
	struct stat st2;
	const char *name = "user.xattr_ctime";
	const char *value = "ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF";
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0700, &fd);
	vt_fstat(fd, &st1);
	vt_fsetxattr(fd, name, value, strlen(value), 0);
	vt_fstat(fd, &st2);
	vt_expect_mtime_eq(&st1, &st2);
	vt_expect_ctime_ge(&st1, &st2);

	vt_fstat(fd, &st1);
	vt_fgetxattr(fd, name, NULL, 0, &sz);
	vt_fstat(fd, &st2);
	vt_expect_mtime_eq(&st1, &st2);
	vt_expect_ctime_eq(&st1, &st2);

	vt_fstat(fd, &st1);
	vt_fremovexattr(fd, name);
	vt_fstat(fd, &st2);
	vt_expect_mtime_eq(&st1, &st2);
	vt_expect_ctime_ge(&st1, &st2);

	vt_fstat(fd, &st1);
	vt_fremovexattr_err(fd, name, -ENODATA);
	vt_fstat(fd, &st2);
	vt_expect_mtime_eq(&st1, &st2);
	vt_expect_ctime_eq(&st1, &st2);

	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful setxattr operations with implicit/explicit rename
 */
static void test_xattr_replace(struct vt_env *vte)
{
	int fd;
	size_t sz;
	const char *name = "user.xattr_replace";
	const char *val1 = "0123456789";
	const char *val2 = "ABCDEFGHIJKLMNOPQRSTUVXYZ";
	const char *val3 = "abcdefghijklmnopqrstuvwxyz0123456789";
	const char *path = vt_new_path_unique(vte);
	char buf[256] = "";

	vt_open(path, O_CREAT | O_RDWR, 0700, &fd);
	vt_fsetxattr(fd, name, val1, strlen(val1), 0);
	vt_fgetxattr(fd, name, NULL, 0, &sz);
	vt_expect_eq(sz, strlen(val1));
	vt_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	vt_expect_eq(sz, strlen(val1));
	vt_expect_eqm(buf, val1, sz);

	vt_fsetxattr(fd, name, val2, strlen(val2), 0);
	vt_fgetxattr(fd, name, NULL, 0, &sz);
	vt_expect_eq(sz, strlen(val2));
	vt_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	vt_expect_eq(sz, strlen(val2));
	vt_expect_eqm(buf, val2, sz);

	vt_fsetxattr(fd, name, val3, strlen(val3), XATTR_REPLACE);
	vt_fgetxattr(fd, name, NULL, 0, &sz);
	vt_expect_eq(sz, strlen(val3));
	vt_fgetxattr(fd, name, buf, sizeof(buf) - 1, &sz);
	vt_expect_eq(sz, strlen(val3));
	vt_expect_eqm(buf, val3, sz);

	vt_fremovexattr(fd, name);
	vt_fremovexattr_err(fd, name, -ENODATA);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful listxattr operations
 */
static void test_xattr_list(struct vt_env *vte)
{
	int fd;
	size_t sz;
	const char *name1 = "user.xattr_list1";
	const char *name2 = "user.xattr_xxxxx_list2";
	const char *value = "0123456789ABCDEF";
	const size_t nlen1 = strlen(name1);
	const size_t nlen2 = strlen(name2);
	const char *path = vt_new_path_unique(vte);
	char list[256] = "";

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_flistxattr(fd, list, sizeof(list), &sz);
	vt_expect_eq(sz, 0);
	vt_fsetxattr(fd, name1, value, strlen(value), 0);
	vt_flistxattr(fd, NULL, 0, &sz);
	vt_expect_eq(sz, nlen1 + 1);
	vt_expect_lt(sz, sizeof(list));
	vt_flistxattr_err(fd, list, 1, -ERANGE);
	vt_flistxattr(fd, list, sizeof(list), &sz);
	vt_expect_eq(sz, nlen1 + 1);
	vt_flistxattr(fd, list, sz, &sz);
	vt_expect_eq(sz, nlen1 + 1);
	vt_fsetxattr(fd, name2, value, strlen(value), 0);
	vt_flistxattr(fd, NULL, 0, &sz);
	vt_expect_eq(sz, nlen1 + nlen2 + 2);
	vt_flistxattr_err(fd, list, 1, -ERANGE);
	vt_flistxattr(fd, list, sizeof(list), &sz);
	vt_expect_eq(sz, nlen1 + nlen2 + 2);
	vt_expect_eqm(list, name1, nlen1);
	vt_expect_eqm(list + nlen1 + 1, name2, nlen2);
	vt_fremovexattr(fd, name1);
	vt_flistxattr(fd, list, sizeof(list), &sz);
	vt_expect_eq(sz, nlen2 + 1);
	vt_expect_eqm(list, name2, nlen2);
	vt_fremovexattr(fd, name2);
	vt_flistxattr(fd, list, sizeof(list), &sz);
	vt_expect_eq(sz, 0);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful xattr operation with any name length
 */
static void test_xattr_any_(struct vt_env *vte, size_t value_size)
{
	char buf[SILOFS_NAME_MAX + 1] = "";
	const char *name = NULL;
	void *vbuf = vt_new_buf_rands(vte, value_size + 1);
	const void *value = vt_new_buf_rands(vte, value_size);
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	size_t cnt = 0;
	int fd = -1;

	vt_mkdir(path0, 0700);
	vt_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t nlen = 1; nlen < sizeof(buf); ++nlen) {
		name = vt_make_xname_unique(vte, nlen, buf, sizeof(buf));
		vt_fsetxattr(fd, name, value, value_size, 0);
		vt_fgetxattr(fd, name, vbuf, 0, &cnt);
		vt_expect_eq(cnt, value_size);
		vt_fgetxattr(fd, name, vbuf, value_size + 1, &cnt);
		vt_expect_eq(cnt, value_size);
		vt_fremovexattr(fd, name);
		vt_flistxattr(fd, NULL, 0, &cnt);
		vt_expect_eq(cnt, 0);
	}
	vt_close(fd);
	vt_unlink(path1);
	vt_rmdir(path0);
}

static void test_xattr_any_small(struct vt_env *vte)
{
	size_t value_size = 1;
	const size_t value_size_max = 1023;

	while (value_size <= value_size_max) {
		test_xattr_any_(vte, value_size);
		value_size += 13;
	}
}

static void test_xattr_any_large(struct vt_env *vte)
{
	size_t value_size = 1024;

	while (value_size <= SILOFS_XATTR_VALUE_MAX) {
		test_xattr_any_(vte, value_size);
		value_size += 23;
	}
}

static void test_xattr_any_edges(struct vt_env *vte)
{
	test_xattr_any_(vte, 1);
	test_xattr_any_(vte, 2);
	test_xattr_any_(vte, 247);
	test_xattr_any_(vte, 248);
	test_xattr_any_(vte, 249);
	test_xattr_any_(vte, SILOFS_XATTR_VALUE_MAX - 1);
	test_xattr_any_(vte, SILOFS_XATTR_VALUE_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_xattr_simple),
	VT_DEFTEST(test_xattr_inode),
	VT_DEFTEST(test_xattr_ctime),
	VT_DEFTEST(test_xattr_replace),
	VT_DEFTEST(test_xattr_list),
	VT_DEFTEST(test_xattr_any_small),
	VT_DEFTEST(test_xattr_any_large),
	VT_DEFTEST(test_xattr_any_edges),
};

const struct vt_tests vt_test_xattr = VT_DEFTESTS(vt_local_tests);

