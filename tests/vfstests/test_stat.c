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
 * Expects stat(3p) to successfully probe directory and return ENOENT if a
 * component of path does not name an existing file or path is an empty string.
 */
static void test_stat_simple(struct vt_env *vte)
{
	struct stat st;
	const mode_t ifmt = S_IFMT;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_unique(vte);

	vt_mkdir(path0, 0700);
	vt_stat(path0, &st);
	vt_expect_dir(st.st_mode);
	vt_expect_eq((int)(st.st_mode & ~ifmt), 0700);
	vt_expect_eq((long)st.st_nlink, 2);
	vt_stat_noent(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects stat(3p) to return ENOTDIR if a component of the path prefix is not
 * a directory.
 */
static void test_stat_notdir(struct vt_env *vte)
{
	int fd = -1;
	struct stat st;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);

	vt_mkdir(path0, 0700);
	vt_stat(path0, &st);
	vt_expect_dir(st.st_mode);
	vt_open(path1, O_CREAT | O_RDWR, 0644, &fd);
	vt_stat(path1, &st);
	vt_expect_reg(st.st_mode);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);
	vt_stat_err(path2, -ENOTDIR);
	vt_unlink(path1);
	vt_rmdir(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to return valid result for dir-path, reg-path or rd-open
 * file-descriptor.
 */
static void test_stat_statvfs(struct vt_env *vte)
{
	int fd = -1;
	struct statvfs stv[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);
	const char *path3 = vt_new_path_under(vte, path0);

	vt_mkdir(path0, 0750);
	vt_creat(path1, 0644, &fd);
	vt_statvfs(path0, &stv[0]);
	vt_statvfs(path1, &stv[1]);
	vt_expect_true((stv[0].f_bavail > 0));
	vt_expect_eq(stv[0].f_fsid, stv[1].f_fsid);
	vt_fstatvfs(fd, &stv[1]);
	vt_expect_eq(stv[0].f_fsid, stv[1].f_fsid);
	vt_statvfs_err(path2, -ENOTDIR);
	vt_statvfs_err(path3, -ENOENT);
	vt_close(fd);
	vt_unlink(path1);
	vt_rmdir(path0);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statx(2) to return valid and constant birth time.
 */
static void test_statx_btime(struct vt_env *vte)
{
	int fd = -1;
	int dfd = -1;
	struct statx stx[2];
	const char *name = vt_new_name_unique(vte);
	const char *path = vt_new_path_unique(vte);
	const int flags = AT_STATX_FORCE_SYNC;

	vt_mkdir(path, 0750);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);

	vt_statx(dfd, name, flags, STATX_ALL, &stx[0]);
	if (!(stx[0].stx_mask & STATX_BTIME)) {
		goto out; /* no FUSE statx */
	}
	vt_expect_eq(stx[0].stx_mask & STATX_ALL, STATX_ALL);
	vt_expect_xts_eq(&stx[0].stx_btime, &stx[0].stx_mtime);
	vt_expect_xts_eq(&stx[0].stx_btime, &stx[0].stx_ctime);
	vt_suspends(vte, 1);
	vt_writen(fd, name, strlen(name));
	vt_statx(dfd, name, flags, STATX_ALL, &stx[1]);
	vt_expect_xts_eq(&stx[0].stx_btime, &stx[1].stx_btime);
	vt_expect_xts_gt(&stx[1].stx_btime, &stx[1].stx_mtime);
	vt_expect_xts_gt(&stx[1].stx_btime, &stx[1].stx_ctime);
out:
	vt_close(fd);
	vt_unlinkat(dfd, name, 0);
	vt_close(dfd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_stat_simple),
	VT_DEFTEST(test_stat_notdir),
	VT_DEFTEST(test_stat_statvfs),
	VT_DEFTEST(test_statx_btime),
};

const struct vt_tests vt_test_stat = VT_DEFTESTS(vt_local_tests);
