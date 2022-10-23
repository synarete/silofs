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
 * Expects successful open(3p) with O_CREAT to set the file's access time
 */
static void test_open_atime(struct vt_env *vte)
{
	int fd = -1;
	struct stat st0;
	struct stat st1;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0755);
	vt_stat(path0, &st0);
	vt_suspend(vte, 3, 1);
	vt_open(path1, O_CREAT | O_WRONLY, 0644, &fd);
	vt_fstat(fd, &st1);
	vt_expect_true(st0.st_atim.tv_sec < st1.st_atim.tv_sec);
	vt_unlink(path1);
	vt_rmdir(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful open(3p) with O_CREAT to update parent's ctime and mtime
 * only if file did *not* exist.
 */
static void test_open_mctime(struct vt_env *vte)
{
	int fd1 = -1;
	int fd2 = -1;
	struct stat st0;
	struct stat st1;
	struct stat st2;
	struct stat st3;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0755);
	vt_stat(path0, &st0);
	vt_suspend(vte, 3, 2);
	vt_open(path1, O_CREAT | O_WRONLY, 0644, &fd1);
	vt_fstat(fd1, &st1);
	vt_expect_lt(st0.st_mtim.tv_sec, st1.st_mtim.tv_sec);
	vt_expect_lt(st0.st_ctim.tv_sec, st1.st_ctim.tv_sec);
	vt_stat(path0, &st2);
	vt_expect_lt(st0.st_mtim.tv_sec, st2.st_mtim.tv_sec);
	vt_expect_lt(st0.st_ctim.tv_sec, st2.st_ctim.tv_sec);
	vt_unlink(path1);
	vt_close(fd1);

	vt_creat(path1, 0644, &fd1);
	vt_fstat(fd1, &st1);
	vt_stat(path0, &st0);
	vt_suspend(vte, 3, 2);
	vt_open(path1, O_CREAT | O_RDONLY, 0644, &fd2);
	vt_fstat(fd2, &st2);
	vt_stat(path0, &st3);
	vt_expect_eq(st1.st_mtim.tv_sec, st2.st_mtim.tv_sec);
	vt_expect_eq(st1.st_ctim.tv_sec, st2.st_ctim.tv_sec);
	vt_expect_eq(st0.st_mtim.tv_sec, st3.st_mtim.tv_sec);
	vt_expect_eq(st0.st_ctim.tv_sec, st3.st_ctim.tv_sec);

	vt_unlink(path1);
	vt_rmdir(path0);
	vt_close(fd1);
	vt_close(fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) to return ELOOP if too many symbolic links are encountered
 * while resolving pathname, or O_NOFOLLOW was specified but pathname was a
 * symbolic link.
 */
static void test_open_loop(struct vt_env *vte)
{
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_under(vte, path0);
	const char *path3 = vt_new_path_under(vte, path1);

	vt_symlink(path0, path1);
	vt_symlink(path1, path0);
	vt_open_err(path2, O_RDONLY, 0, -ELOOP);
	vt_open_err(path3, O_RDONLY, 0, -ELOOP);
	vt_unlink(path0);
	vt_unlink(path1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) to return EISDIR if the named file is a directory and
 * oflag includes O_WRONLY or O_RDWR.
 */
static void test_open_isdir(struct vt_env *vte)
{
	int fd = -1;
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0755);
	vt_open(path, O_RDONLY, 0, &fd);
	vt_open_err(path, O_WRONLY, 0, -EISDIR);
	vt_open_err(path, O_RDWR, 0, -EISDIR);
	vt_open_err(path, O_RDONLY | O_TRUNC, 0, -EISDIR);
	vt_open_err(path, O_WRONLY | O_TRUNC, 0, -EISDIR);
	vt_open_err(path, O_RDWR | O_TRUNC, 0, -EISDIR);
	vt_close(fd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_TRUNC to reduce file-size to zero.
 */
static void test_open_trunc_(struct vt_env *vte, loff_t off, size_t bsz)
{
	int fd = -1;
	int fd2 = -1;
	struct stat st;
	void *buf = vt_new_buf_zeros(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (long)bsz);
	vt_expect_gt(st.st_blocks, 0);
	vt_close(fd);
	vt_open(path, O_RDWR | O_TRUNC, 0, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (long)bsz);
	vt_expect_gt(st.st_blocks, 0);
	vt_open(path, O_RDWR | O_TRUNC, 0, &fd2);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);
	vt_close(fd);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_open_trunc(struct vt_env *vte)
{
	test_open_trunc_(vte, 0, VT_1K);
	test_open_trunc_(vte, VT_1K, VT_4K);
	test_open_trunc_(vte, VT_MEGA, VT_64K);
	test_open_trunc_(vte, VT_GIGA - 7, 7 * VT_1K);
	test_open_trunc_(vte, VT_TERA - 11, VT_MEGA + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_open_atime),
	VT_DEFTEST(test_open_mctime),
	VT_DEFTEST(test_open_loop),
	VT_DEFTEST(test_open_isdir),
	VT_DEFTEST(test_open_trunc),
};

const struct vt_tests vt_test_open = VT_DEFTESTS(vt_local_tests);
