/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) on empty regular file to update size properly.
 */
static void test_truncate_simple(struct vt_env *vte)
{
	int fd = -1;
	loff_t off;
	struct stat st;
	const loff_t offs[] = {
		0, 1, VT_BK_SIZE,
		VT_MEGA, VT_MEGA + 1, VT_GIGA, VT_GIGA - 1,
		11 * VT_GIGA, 111 * VT_GIGA - 111,
		VT_TERA, VT_TERA - 11, VT_FILESIZE_MAX
	};
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	for (size_t i = 0; i < VT_ARRAY_SIZE(offs); ++i) {
		off = offs[i];
		vt_truncate(path, off);
		vt_stat(path, &st);
		vt_expect_eq(st.st_size, off);
		vt_expect_eq(st.st_blocks, 0);
	}
	for (size_t j = 0; j < VT_ARRAY_SIZE(offs); ++j) {
		off = offs[j];
		vt_ftruncate(fd, off);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off);
		vt_expect_eq(st.st_blocks, 0);
	}
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) after write on unaligned offsets to update
 * size properly.
 */
static void test_truncate_unaligned(struct vt_env *vte)
{
	int fd = -1;
	loff_t off;
	struct stat st;
	const char *dat = "ABCDEFGHIJKLMNOPQ";
	const size_t len = strlen(dat);
	const loff_t offs[] = {
		17, 7177, 17 * VT_MEGA - 7, 17 * VT_GIGA - 7,
		3 * VT_TERA - 7, VT_FILESIZE_MAX / 7,
	};
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	for (size_t i = 0; i < VT_ARRAY_SIZE(offs); ++i) {
		off = offs[i];
		vt_pwriten(fd, dat, len, off - 1);
		vt_fsync(fd);
		vt_fstat(fd, &st);
		vt_expect_gt(st.st_blocks, 0);
		vt_truncate(path, off);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off);
		vt_expect_gt(st.st_blocks, 0);
	}
	for (size_t j = 0; j < VT_ARRAY_SIZE(offs); ++j) {
		off = offs[j];
		vt_pwriten(fd, dat, len, off - 3);
		vt_ftruncate(fd, off);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off);
	}
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects ftruncate(3p) to zero after write to clear file's block count.
 */
static void test_truncate_zero(struct vt_env *vte)
{
	int fd = -1;
	loff_t off = 0;
	size_t bsz = VT_BK_SIZE;
	struct stat st;
	const loff_t offs[] = {
		VT_UMEGA, VT_UGIGA, VT_UTERA,
		VT_UMEGA - 1, VT_UGIGA - 1, VT_UTERA - 1
	};
	const void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	for (size_t i = 0; i < VT_ARRAY_SIZE(offs); ++i) {
		off = offs[i];
		vt_pwriten(fd, buf, bsz, off);
		vt_fstat(fd, &st);
		vt_expect_gt(st.st_blocks, 0);
		vt_ftruncate(fd, 0);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_blocks, 0);
		vt_ftruncate(fd, off);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off);
	}
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects ftruncate(3p) to change size successfully on file-size-limit
 */
static void test_truncate_filesize_max(struct vt_env *vte)
{
	int fd = -1;
	struct stat st;
	const loff_t off = VT_FILESIZE_MAX;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	vt_ftruncate(fd, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off);

	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects upon successful completion of ftruncate(3p) to update the last data
 * modification and last file status change time-stamps of the file, only if
 * file size changed.
 */
static void test_truncate_mctimes_(struct vt_env *vte, loff_t off)
{
	int fd = -1;
	struct stat st[2];
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);

	vt_fstat(fd, &st[0]);
	vt_suspends(vte, 1);
	vt_ftruncate(fd, off);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_expect_mtime_gt(&st[0], &st[1]);

	vt_fstat(fd, &st[0]);
	vt_suspends(vte, 1);
	vt_ftruncate(fd, off);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_eq(&st[0], &st[1]);
	vt_expect_mtime_eq(&st[0], &st[1]);

	vt_fstat(fd, &st[0]);
	vt_suspends(vte, 1);
	vt_ftruncate(fd, 0);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_expect_mtime_gt(&st[0], &st[1]);

	vt_close(fd);
	vt_unlink(path);
}

static void test_truncate_mctimes(struct vt_env *vte)
{
	test_truncate_mctimes_(vte, 1);
	test_truncate_mctimes_(vte, VT_TERA - 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful ftruncate(3p) to clear SUID/SGID bits
 */
static void test_truncate_suid_sgid(struct vt_env *vte)
{
	int fd;
	loff_t off = VT_UMEGA;
	struct stat st;
	const mode_t mode = 0770;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, mode, &fd);
	vt_fstat(fd, &st);
	vt_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	vt_ftruncate(fd, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off);
	vt_expect_eq(st.st_mode & S_ISUID, 0);
	vt_expect_eq(st.st_mode & S_ISGID, 0);
	vt_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	vt_ftruncate(fd, 0);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_mode & S_ISUID, 0);
	vt_expect_eq(st.st_mode & S_ISGID, 0);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_truncate_simple),
	VT_DEFTEST(test_truncate_unaligned),
	VT_DEFTEST(test_truncate_zero),
	VT_DEFTEST(test_truncate_filesize_max),
	VT_DEFTEST(test_truncate_mctimes),
	VT_DEFTEST(test_truncate_suid_sgid),
};

const struct vt_tests vt_test_truncate = VT_DEFTESTS(vt_local_tests);
