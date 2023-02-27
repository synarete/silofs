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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to successfully obtain information about the file system
 * containing base-dir, and return ENOENT if a component of path does not name
 * an existing file.
 */
static void test_statvfs_simple(struct vt_env *vte)
{
	struct statvfs stv;
	const char *name = vt_new_name_unique(vte);
	const char *path = vt_new_path_name(vte, name);

	vt_statvfs(vte->params.workdir, &stv);
	vt_expect_gt(stv.f_bsize, 0);
	vt_expect_eq((stv.f_bsize % VT_FRGSIZE), 0);
	vt_expect_gt(stv.f_frsize, 0);
	vt_expect_eq(stv.f_frsize % VT_FRGSIZE, 0);
	vt_expect_gt(stv.f_namemax, strlen(name));
	vt_statvfs_err(path, -ENOENT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to successfully obtain information about the file system
 * via open file-descriptor to regular-file.
 */
static void test_statvfs_reg(struct vt_env *vte)
{
	int fd = -1;
	struct statvfs stv;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0644, &fd);
	vt_fstatvfs(fd, &stv);
	vt_expect_gt(stv.f_bsize, 0);
	vt_expect_eq((stv.f_bsize % VT_FRGSIZE), 0);
	vt_expect_gt(stv.f_frsize, 0);
	vt_expect_eq((stv.f_frsize % VT_FRGSIZE), 0);
	vt_expect_lt(stv.f_bfree, stv.f_blocks);
	vt_expect_lt(stv.f_bavail, stv.f_blocks);
	vt_expect_lt(stv.f_ffree, stv.f_files);
	vt_expect_lt(stv.f_favail, stv.f_files);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to successfully obtain information about the file system
 * via open file-descriptor to directory
 */
static void test_statvfs_dir(struct vt_env *vte)
{
	int dfd = -1;
	struct statvfs stv;
	const char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_fstatvfs(dfd, &stv);
	vt_expect_gt(stv.f_bsize, 0);
	vt_expect_eq((stv.f_bsize % VT_FRGSIZE), 0);
	vt_expect_gt(stv.f_frsize, 0);
	vt_expect_eq((stv.f_frsize % VT_FRGSIZE), 0);
	vt_expect_lt(stv.f_bfree, stv.f_blocks);
	vt_expect_lt(stv.f_bavail, stv.f_blocks);
	vt_expect_lt(stv.f_ffree, stv.f_files);
	vt_expect_lt(stv.f_favail, stv.f_files);
	vt_close(dfd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to return ENOTDIR if a component of the path prefix of
 * path is not a directory.
 */
static void test_statvfs_notdir(struct vt_env *vte)
{
	int fd = -1;
	struct statvfs stv[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);

	vt_mkdir(path0, 0700);
	vt_statvfs(path0, &stv[0]);
	vt_creat(path1, 0644, &fd);
	vt_fstatvfs(fd, &stv[1]);
	vt_statvfs_err(path2, -ENOTDIR);
	vt_unlink(path1);
	vt_rmdir(path0);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to change statvfs.f_ffree upon objects create/unlink
 */
static void test_statvfs_ffree(struct vt_env *vte)
{
	int fd = -1;
	struct statvfs stv[2];
	char *dpath = vt_new_path_unique(vte);
	char *path0 = vt_new_path_under(vte, dpath);
	char *path1 = vt_new_path_under(vte, dpath);
	char *path2 = vt_new_path_under(vte, dpath);
	char *path3 = vt_new_path_under(vte, dpath);

	vt_mkdir(dpath, 0700);
	vt_statvfs(dpath, &stv[0]);
	vt_mkdir(path0, 0700);
	vt_statvfs(path0, &stv[1]);
	vt_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	vt_rmdir(path0);
	vt_statvfs(dpath, &stv[1]);
	vt_expect_eq(stv[0].f_ffree, stv[1].f_ffree);

	vt_statvfs(dpath, &stv[0]);
	vt_symlink(dpath, path1);
	vt_statvfs(path1, &stv[1]);
	vt_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	vt_unlink(path1);
	vt_statvfs(dpath, &stv[1]);
	vt_expect_eq(stv[0].f_ffree, stv[1].f_ffree);

	vt_statvfs(dpath, &stv[0]);
	vt_creat(path2, 0600, &fd);
	vt_close(fd);
	vt_statvfs(path2, &stv[1]);
	vt_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	vt_unlink(path2);
	vt_statvfs(dpath, &stv[1]);
	vt_expect_eq(stv[1].f_ffree, stv[0].f_ffree);

	vt_statvfs(dpath, &stv[0]);
	vt_creat(path3, 0600, &fd);
	vt_fstatvfs(fd, &stv[1]);
	vt_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	vt_unlink(path3);
	vt_statvfs(dpath, &stv[1]);
	vt_expect_eq(stv[1].f_ffree, (stv[0].f_ffree - 1));
	vt_close(fd);
	vt_statvfs(dpath, &stv[1]);
	vt_expect_eq(stv[0].f_ffree, stv[1].f_ffree);

	vt_rmdir(dpath);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to change statvfs.f_ffree upon sequence of creates
 * following sequence of unlinks.
 */
static void test_statvfs_ffree_nseq(struct vt_env *vte, size_t n)
{
	int fd = -1;
	struct statvfs stv[2];
	const char *fpath = NULL;
	const char *dpath = vt_new_path_unique(vte);

	vt_mkdir(dpath, 0700);
	vt_statvfs(dpath, &stv[0]);
	vt_statvfs(dpath, &stv[1]);

	for (size_t i = 0; i < n; ++i) {
		fpath = vt_new_pathf(vte, dpath, "%lu", i);
		vt_statvfs_err(fpath, -ENOENT);
		vt_creat(fpath, 0600, &fd);
		vt_close(fd);
		vt_statvfs(fpath, &stv[1]);
		vt_expect_eq((stv[0].f_ffree - (i + 1)), stv[1].f_ffree);
	}
	for (size_t j = n; j > 0; --j) {
		fpath = vt_new_pathf(vte, dpath, "%lu", (j - 1));
		vt_statvfs(fpath, &stv[1]);
		vt_expect_eq((stv[0].f_ffree - j), stv[1].f_ffree);
		vt_unlink(fpath);
	}

	vt_statvfs(dpath, &stv[1]);
	vt_expect_eq(stv[0].f_ffree, stv[1].f_ffree);
	vt_rmdir(dpath);
}

static void test_statvfs_ffree_seq(struct vt_env *vte)
{
	test_statvfs_ffree_nseq(vte, 16);
	test_statvfs_ffree_nseq(vte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects statvfs(3p) to change statvfs.f_bfree upon write/trim.
 */
static void test_statvfs_bfree_(struct vt_env *vte, loff_t off, size_t bsz)
{
	struct stat st[2];
	struct statvfs stv[2];
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	int fd = -1;

	vt_mkdir(path0, 0700);
	vt_open(path1, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st[0]);
	vt_fstatvfs(fd, &stv[0]);
	for (size_t i = 0; i < 2; ++i) {
		vt_pwriten(fd, buf1, bsz, off);
		vt_preadn(fd, buf2, bsz, off);
		vt_expect_eqm(buf1, buf2, bsz);
		vt_fstat(fd, &st[1]);
		vt_fstatvfs(fd, &stv[1]);
		vt_expect_gt(st[1].st_blocks, st[0].st_blocks);
		vt_expect_gt(stv[0].f_bfree, stv[1].f_bfree);
		vt_ftruncate(fd, 0);
		vt_fstat(fd, &st[1]);
		vt_fstatvfs(fd, &stv[1]);
		vt_expect_eq(st[1].st_blocks, st[0].st_blocks);
		vt_expect_eq(stv[1].f_bfree, stv[0].f_bfree);
	}
	vt_close(fd);
	vt_unlink(path1);
	vt_rmdir(path0);
}

static void test_statvfs_bfree(struct vt_env *vte)
{
	test_statvfs_bfree_(vte, 0, VT_UMEGA);
	test_statvfs_bfree_(vte, VT_KILO, VT_UMEGA - 1);
	test_statvfs_bfree_(vte, VT_BK_SIZE, 2 * VT_BK_SIZE);
	test_statvfs_bfree_(vte, VT_MEGA, VT_UMEGA);
	test_statvfs_bfree_(vte, VT_MEGA + 1, VT_UMEGA);
	test_statvfs_bfree_(vte, VT_TERA - 11, VT_UMEGA + 111);
	test_statvfs_bfree_(vte, VT_FILESIZE_MAX - VT_UMEGA, VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTESTF(test_statvfs_simple, VT_F_STAVFS),
	VT_DEFTESTF(test_statvfs_reg, VT_F_STAVFS),
	VT_DEFTESTF(test_statvfs_dir, VT_F_STAVFS),
	VT_DEFTESTF(test_statvfs_notdir, VT_F_STAVFS),
	VT_DEFTESTF(test_statvfs_ffree, VT_F_STAVFS),
	VT_DEFTESTF(test_statvfs_ffree_seq, VT_F_STAVFS),
	VT_DEFTESTF(test_statvfs_bfree, VT_F_STAVFS),
};

const struct vt_tests vt_test_statvfs = VT_DEFTESTS(vt_local_tests);
