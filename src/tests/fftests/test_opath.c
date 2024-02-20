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
#include "fftests.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_PATH on regular file to have valid semantics.
 */
static void test_opath_reg(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	struct statvfs stv = { .f_blocks = 0 };
	uint8_t buf[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const char *path = ft_new_path_unique(fte);
	const mode_t ifmt = S_IFMT;
	int fd = -1;

	ft_open_err(path, O_CREAT | O_RDWR | O_PATH, 0666, -ENOENT);
	ft_open(path, O_CREAT | O_RDWR, 0666, &fd);
	ft_close(fd);
	ft_open(path, O_CREAT | O_RDWR | O_PATH, 0666, &fd);
	ft_read_err(fd, buf, sizeof(buf), -EBADF);
	ft_write_err(fd, buf, sizeof(buf), -EBADF);
	ft_fchmod_err(fd, 0600, -EBADF);
	ft_fsync_err(fd, -EBADF);
	ft_fstat(fd, &st);
	ft_expect_reg(st.st_mode);
	ft_expect_eq(st.st_size, 0);
	ft_fstatvfs(fd, &stv);
	ft_expect_gt(stv.f_blocks, 0);
	ft_close(fd);
	ft_chmod(path, 0444);
	ft_open(path, O_PATH, 0, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & ~ifmt, 0444);
	ft_close(fd);
	ft_chmod(path, 0600);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_PATH on symbolic-link to have valid semantics.
 */
static void test_opath_symlnk(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_unique(fte);
	const size_t len = strlen(path0);
	char *symval = ft_new_buf_zeros(fte, len + 1);
	size_t nch = 0;
	int fd = -1;

	ft_creat(path0, 0600, &fd);
	ft_close(fd);
	ft_symlink(path0, path1);
	ft_open(path1, O_PATH | O_NOFOLLOW, 0, &fd);
	ft_fstat(fd, &st);
	ft_expect_lnk(st.st_mode);
	ft_readlinkat(fd, "", symval, len, &nch);
	ft_expect_eq(nch, len);
	ft_expect_eqm(symval, path0, len);
	ft_close(fd);
	ft_unlink(path1);
	ft_unlink(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_PATH on directory to have valid semantics.
 */
static void test_opath_dir(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	const size_t dlen = FT_1M - 1;
	const void *data = ft_new_buf_rands(fte, dlen);
	int dfd1 = -1;
	int dfd2 = -1;
	int dfd3 = -1;
	int fd1 = -1;
	int fd2 = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_PATH, 0, &dfd1);
	ft_fstat(dfd1, &st);
	ft_expect_dir(st.st_mode);
	ft_mkdirat(dfd1, name, 0700);
	ft_openat(dfd1, name, O_DIRECTORY | O_PATH, 0, &dfd2);
	ft_fstat(dfd2, &st);
	ft_expect_dir(st.st_mode);
	ft_mkdirat(dfd2, name, 0750);
	ft_openat(dfd2, name, O_DIRECTORY | O_PATH, 0, &dfd3);
	ft_fstat(dfd3, &st);
	ft_expect_dir(st.st_mode);
	ft_openat(dfd3, name, O_CREAT | O_WRONLY | O_TRUNC, 0600, &fd1);
	ft_openat(dfd3, name, O_PATH | O_CLOEXEC, 0, &fd2);
	ft_fstat(fd2, &st);
	ft_expect_reg(st.st_mode);
	ft_expect_eq(st.st_size, 0);
	ft_writen(fd1, data, dlen);
	ft_close(fd1);
	ft_fstat(fd2, &st);
	ft_expect_eq(st.st_size, dlen);
	ft_close(fd2);
	ft_unlinkat(dfd3, name, 0);
	ft_close(dfd3);
	ft_unlinkat(dfd2, name, AT_REMOVEDIR);
	ft_close(dfd2);
	ft_unlinkat(dfd1, name, AT_REMOVEDIR);
	ft_close(dfd1);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_PATH on directory to work correctly with renameat(2)
 */
static void test_opath_renameat(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const size_t len1 = FT_1K;
	const size_t len2 = FT_64K;
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	const char *name1 = ft_new_name_unique(fte);
	const char *name2 = ft_new_name_unique(fte);
	const void *data1 = ft_new_buf_rands(fte, len1);
	const void *data2 = ft_new_buf_rands(fte, len2);
	int dfd1 = -1;
	int dfd2 = -1;
	int fd1 = -1;
	int fd2 = -1;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY, 0, &dfd1);
	ft_openat(dfd1, name1, O_CREAT | O_WRONLY | O_TRUNC, 0600, &fd1);
	ft_writen(fd1, data1, len1);
	ft_close(fd1);
	ft_close(dfd1);

	ft_mkdir(path2, 0700);
	ft_open(path2, O_DIRECTORY, 0, &dfd2);
	ft_openat(dfd2, name2, O_CREAT | O_WRONLY | O_TRUNC, 0600, &fd2);
	ft_writen(fd2, data2, len2);
	ft_close(fd2);
	ft_close(dfd2);

	ft_open(path1, O_DIRECTORY | O_PATH, 0, &dfd1);
	ft_open(path2, O_DIRECTORY | O_PATH, 0, &dfd2);
	ft_renameat(dfd1, name1, dfd2, name1);
	ft_fstatat_err(dfd1, name1, 0, -ENOENT);
	ft_fstatat(dfd2, name1, &st, 0);
	ft_expect_eq(st.st_size, len1);
	ft_renameat(dfd2, name2, dfd1, name2);
	ft_fstatat_err(dfd2, name2, 0, -ENOENT);
	ft_fstatat(dfd1, name2, &st, 0);
	ft_expect_eq(st.st_size, len2);

	ft_renameat2(dfd1, name2, dfd2, name1, RENAME_EXCHANGE);
	ft_fstatat(dfd1, name2, &st, 0);
	ft_expect_eq(st.st_size, len1);
	ft_fstatat_err(dfd1, name1, 0, -ENOENT);
	ft_fstatat(dfd2, name1, &st, 0);
	ft_expect_eq(st.st_size, len2);
	ft_fstatat_err(dfd2, name2, 0, -ENOENT);
	ft_renameat2(dfd1, name2, dfd2, name1, RENAME_EXCHANGE);

	ft_renameat(dfd1, name2, dfd2, name1);
	ft_fstatat_err(dfd1, name2, 0, -ENOENT);
	ft_fstatat(dfd2, name1, &st, 0);
	ft_expect_eq(st.st_size, len2);
	ft_unlinkat(dfd2, name1, 0);

	ft_close2(dfd1, dfd2);
	ft_rmdir(path1);
	ft_rmdir(path2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fstatat(2) to successfully probe sub-directory components when used
 * with O_PATH.
 */
static void test_opath_fstatat(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd = -1;
	int fd = -1;

	ft_mkdir(path, 0700);
	ft_openat(AT_FDCWD, path, O_DIRECTORY | O_RDONLY | O_PATH, 0, &dfd);
	ft_fstatat(dfd, "", &st, AT_EMPTY_PATH);
	ft_expect_dir(st.st_mode);
	ft_openat(dfd, name, O_CREAT | O_TRUNC | O_RDWR, 0644, &fd);
	ft_fstatat(dfd, "", &st, AT_EMPTY_PATH);
	ft_expect_dir(st.st_mode);
	ft_fstatat(dfd, name, &st, 0);
	ft_expect_reg(st.st_mode);
	ft_unlinkat(dfd, name, 0);
	ft_close(fd);
	ft_unlinkat_noent(dfd, name);
	ft_close(dfd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects open(3p) with O_PATH on regular file to have valid semantics when
 * file is unlinked but still referenced by an open file-descriptor.
 */
static void test_opath_unlinked(struct ft_env *fte)
{
	struct stat st = { .st_size = -1 };
	struct timespec ts[2] = { { 1, 22 }, { 333, 4444 } };
	uint8_t buf[] = { 7, 6, 5, 4, 3, 2, 1 };
	const char *path = ft_new_path_unique(fte);
	const char *name = ft_new_name_unique(fte);
	int dfd = -1;
	int fd1 = -1;
	int fd2 = -1;   /* need 2nd fd due to issue with FUSE+O_PATH */

	ft_mkdir(path, 0700);
	ft_openat(AT_FDCWD, path, O_DIRECTORY | O_RDONLY | O_PATH, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd1);
	ft_writen(fd1, buf, sizeof(buf));
	ft_fstat(fd1, &st);
	ft_expect_reg(st.st_mode);
	ft_expect_eq(st.st_size, sizeof(buf));
	ft_close(fd1);
	ft_openat(dfd, name, O_RDONLY | O_PATH, 0, &fd1);
	ft_openat(dfd, name, O_RDWR, 0, &fd2);
	ft_fstat(fd1, &st);
	ft_expect_reg(st.st_mode);
	ft_expect_eq(st.st_size, sizeof(buf));
	ft_utimensat(dfd, name, ts, 0);
	ft_fstat(fd1, &st);
	ft_expect_ts_eq(&st.st_atim, &ts[0]);
	ft_expect_ts_eq(&st.st_mtim, &ts[1]);
	ft_unlinkat(dfd, name, 0);
	ft_fstatat_err(dfd, name, 0, -ENOENT);
	ft_fstat(fd1, &st);
	ft_expect_ts_eq(&st.st_atim, &ts[0]);
	ft_expect_ts_eq(&st.st_mtim, &ts[1]);
	ft_close2(fd1, fd2);
	ft_close(dfd);
	ft_rmdir(path);
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_opath_reg),
	FT_DEFTEST(test_opath_symlnk),
	FT_DEFTEST(test_opath_dir),
	FT_DEFTEST(test_opath_renameat),
	FT_DEFTEST(test_opath_fstatat),
	FT_DEFTEST(test_opath_unlinked),
};

const struct ft_tests ft_test_opath = FT_DEFTESTS(ft_local_tests);
