/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "utests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_empty(struct ut_env *ute)
{
	struct statvfs stv = {};
	size_t fs_size     = 0;
	size_t used_bytes  = 0;
	size_t used_files  = 0;

	ut_statfs(ute, UT_ROOT_INO, &stv);
	ut_expect_eq(stv.f_bsize, UT_4K);
	ut_expect_eq(stv.f_frsize, UT_4K);
	ut_expect_gt(stv.f_blocks, 0);
	ut_expect_gt(stv.f_blocks, stv.f_bfree);
	ut_expect_gt(stv.f_files, stv.f_ffree);

	fs_size = stv.f_frsize * stv.f_blocks;
	ut_expect_eq(fs_size, ute->fs_capacity);

	used_bytes = (stv.f_blocks - stv.f_bfree) * stv.f_frsize;
	ut_expect_gt(used_bytes, SILOFS_INODE_SIZE);
	ut_expect_lt(used_bytes, ute->fs_capacity);

	used_files = stv.f_files - stv.f_ffree;
	ut_expect_eq(used_files, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_files_(struct ut_env *ute, size_t cnt)
{
	struct statvfs stv = {};
	const char *name   = UT_NAME;
	const char *fname  = nullptr;
	fsfilcnt_t ffree, files[2];
	ino_t dino, ino;

	ut_statfs_rootd(ute, &stv);
	files[0] = stv.f_files;
	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_create_only(ute, dino, fname, &ino);
		ut_statfs(ute, dino, &stv);
		ut_expect_eq(ffree, stv.f_ffree + 1);
		ffree = stv.f_ffree;
	}
	ut_statfs(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, 0);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_unlink_file(ute, dino, fname);
		ut_statfs(ute, dino, &stv);
		ut_expect_eq(ffree + 1, stv.f_ffree);
		ffree = stv.f_ffree;
	}
	ut_rmdir_at_root(ute, name);
	ut_statfs_rootd(ute, &stv);
	files[1] = stv.f_files;
	silofs_assert_eq(files[0], files[1]);
}

static void ut_statfs_files(struct ut_env *ute)
{
	ut_statfs_files_(ute, 1);
	ut_statfs_files_(ute, 10);
	ut_statfs_files_(ute, 100);
	ut_statfs_files_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_dirs_(struct ut_env *ute, size_t cnt)
{
	struct statvfs stv = {};
	const char *name   = UT_NAME;
	const char *dname  = nullptr;
	fsfilcnt_t ffree, files[2];
	ino_t dino, ino;

	ut_statfs_rootd(ute, &stv);
	files[0] = stv.f_files;
	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dname = ut_make_name(ute, name, i);
		ut_mkdir2(ute, dino, dname, &ino);
		ut_statfs(ute, ino, &stv);
		ut_expect_eq(ffree, stv.f_ffree + 1);
		ffree = stv.f_ffree;
	}
	ut_sync_drop_all(ute);
	ut_statfs(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, 0);
	for (size_t i = 0; i < cnt; ++i) {
		dname = ut_make_name(ute, name, i);
		ut_rmdir(ute, dino, dname);
		ut_statfs(ute, dino, &stv);
		ut_expect_eq(ffree + 1, stv.f_ffree);
		ffree = stv.f_ffree;
	}
	ut_rmdir_at_root(ute, name);
	ut_sync_drop_all(ute);
	ut_statfs_rootd(ute, &stv);
	files[1] = stv.f_files;
	silofs_assert_eq(files[0], files[1]);
}

static void ut_statfs_dirs(struct ut_env *ute)
{
	ut_statfs_dirs_(ute, 1);
	ut_statfs_dirs_(ute, 10);
	ut_statfs_dirs_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_bfree_(struct ut_env *ute, off_t off, size_t bsz)
{
	struct stat st[2];
	struct statvfs stv[2];
	const char *name = UT_NAME;
	const void *buf  = ut_randbuf(ute, bsz);
	ino_t dino, ino;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_getattr(ute, ino, &st[0]);
	ut_statfs(ute, ino, &stv[0]);
	for (size_t i = 0; i < 2; ++i) {
		ut_write_read(ute, ino, buf, bsz, off);
		ut_getattr(ute, ino, &st[1]);
		ut_statfs(ute, ino, &stv[1]);
		ut_expect_gt(st[1].st_blocks, st[0].st_blocks);
		ut_expect_gt(stv[0].f_bfree, stv[1].f_bfree);
		ut_trunacate_zero(ute, ino);
		ut_getattr(ute, ino, &st[1]);
		ut_statfs(ute, ino, &stv[1]);
		ut_expect_eq(st[1].st_blocks, st[0].st_blocks);
		ut_expect_eq(stv[1].f_bfree, stv[0].f_bfree);
	}
	ut_release_flush(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_statfs_bfree(struct ut_env *ute)
{
	ut_statfs_bfree_(ute, 0, UT_1M);
	ut_statfs_bfree_(ute, UT_1K, UT_1M - 1);
	ut_statfs_bfree_(ute, 8 * UT_1K, UT_64K - 1);
	ut_statfs_bfree_(ute, UT_64K, 2 * UT_64K);
	ut_statfs_bfree_(ute, UT_1M, UT_1M);
	ut_statfs_bfree_(ute, UT_1M + 1, UT_1M);
	ut_statfs_bfree_(ute, UT_1T - 11, UT_1M + 111);
	ut_statfs_bfree_(ute, UT_FILESIZE_MAX / 2, UT_1M / 2);
	ut_statfs_bfree_(ute, UT_FILESIZE_MAX - UT_1M, UT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_symlnk(struct ut_env *ute)
{
	struct statvfs stv1, stv2;
	const char *name   = UT_NAME;
	const char *symval = UT_NAME;
	ino_t dino = 0, sino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs(ute, dino, &stv1);
	ut_symlink(ute, dino, name, symval, &sino);
	ut_lookup_exists(ute, dino, name, sino, S_IFLNK);
	ut_statfs(ute, sino, &stv2);
	ut_expect_gt(stv1.f_bfree, stv2.f_bfree);
	ut_expect_gt(stv1.f_ffree, stv2.f_ffree);
	ut_unlink(ute, dino, name);
	ut_statfs(ute, dino, &stv2);
	ut_expect_eq(stv1.f_bfree, stv2.f_bfree);
	ut_expect_eq(stv1.f_ffree, stv2.f_ffree);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_statfs_empty), //
	UT_DEFTEST(ut_statfs_files),  //
	UT_DEFTEST(ut_statfs_dirs),   //
	UT_DEFTEST(ut_statfs_bfree),  //
	UT_DEFTEST(ut_statfs_symlnk), //
};

const struct ut_testdefs ut_tdefs_statfs = UT_MKTESTS(ut_local_tests);
