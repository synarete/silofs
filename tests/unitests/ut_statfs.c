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
#include "unitests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_empty(struct ut_env *ute)
{
	size_t capacity = 0;
	size_t fs_size = 0;
	size_t used_bytes = 0;
	size_t used_files = 0;
	struct statvfs stv = { .f_bsize = 0 };

	ut_statfs_ok(ute, UT_ROOT_INO, &stv);
	ut_expect_le(stv.f_bsize, UT_64K); /* TODO: needs to be eq one day */
	ut_expect_ge(stv.f_frsize, UT_1K); /* TODO: needs to be eq one day */
	ut_expect_gt(stv.f_blocks, 0);
	ut_expect_gt(stv.f_blocks, stv.f_bfree);
	ut_expect_gt(stv.f_files, stv.f_ffree);

	fs_size = stv.f_frsize * stv.f_blocks;
	capacity = ute->args->fs_args.capacity;
	ut_expect_eq(fs_size, capacity);

	used_bytes = (stv.f_blocks - stv.f_bfree) * stv.f_frsize;
	ut_expect_gt(used_bytes, SILOFS_SB_SIZE);
	ut_expect_lt(used_bytes, capacity);

	/* 2 used inodes: anon-allocation at voff=0 and root-dir */
	used_files = stv.f_files - stv.f_ffree;
	ut_expect_eq(used_files, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_files_(struct ut_env *ute, size_t cnt)
{
	ino_t ino = 0;
	ino_t dino = 0;
	fsfilcnt_t ffree = 0;
	const char *name = UT_NAME;
	const char *fname = NULL;
	struct statvfs stv = { .f_bsize = 0 };

	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs_ok(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_create_only(ute, dino, fname, &ino);
		ut_statfs_ok(ute, dino, &stv);
		ut_expect_eq(ffree, stv.f_ffree + 1);
		ffree = stv.f_ffree;
	}
	ut_statfs_ok(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, 0);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_unlink_file(ute, dino, fname);
		ut_statfs_ok(ute, dino, &stv);
		ut_expect_eq(ffree + 1, stv.f_ffree);
		ffree = stv.f_ffree;
	}
	ut_rmdir_at_root(ute, name);
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
	ino_t ino = 0;
	ino_t dino = 0;
	fsfilcnt_t ffree = 0;
	const char *name = UT_NAME;
	const char *dname = NULL;
	struct statvfs stv = { .f_bsize = 0 };

	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs_ok(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		dname = ut_make_name(ute, name, i);
		ut_mkdir_oki(ute, dino, dname, &ino);
		ut_statfs_ok(ute, ino, &stv);
		ut_expect_eq(ffree, stv.f_ffree + 1);
		ffree = stv.f_ffree;
	}
	ut_drop_caches_fully(ute);
	ut_statfs_ok(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, 0);
	for (size_t i = 0; i < cnt; ++i) {
		dname = ut_make_name(ute, name, i);
		ut_rmdir_ok(ute, dino, dname);
		ut_statfs_ok(ute, dino, &stv);
		ut_expect_eq(ffree + 1, stv.f_ffree);
		ffree = stv.f_ffree;
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_statfs_dirs(struct ut_env *ute)
{
	ut_statfs_dirs_(ute, 1);
	ut_statfs_dirs_(ute, 10);
	ut_statfs_dirs_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_bfree_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino = 0;
	ino_t dino = 0;
	struct stat st[2];
	struct statvfs stv[2];
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_statfs_ok(ute, ino, &stv[0]);
	for (size_t i = 0; i < 2; ++i) {
		ut_write_read(ute, ino, buf, bsz, off);
		ut_getattr_ok(ute, ino, &st[1]);
		ut_statfs_ok(ute, ino, &stv[1]);
		ut_expect_gt(st[1].st_blocks, st[0].st_blocks);
		ut_expect_gt(stv[0].f_bfree, stv[1].f_bfree);
		ut_trunacate_zero(ute, ino);
		ut_getattr_ok(ute, ino, &st[1]);
		ut_statfs_ok(ute, ino, &stv[1]);
		ut_expect_eq(st[1].st_blocks, st[0].st_blocks);
		ut_expect_eq(stv[1].f_bfree, stv[0].f_bfree);
	}
	ut_release_flush_ok(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_statfs_bfree(struct ut_env *ute)
{
	ut_statfs_bfree_(ute, 0, UT_1M);
	ut_statfs_bfree_(ute, UT_1K, UT_1M - 1);
	ut_statfs_bfree_(ute, 8 * UT_1K, UT_BK_SIZE - 1);
	ut_statfs_bfree_(ute, UT_BK_SIZE, 2 * UT_BK_SIZE);
	ut_statfs_bfree_(ute, UT_1M, UT_1M);
	ut_statfs_bfree_(ute, UT_1M + 1, UT_1M);
	ut_statfs_bfree_(ute, UT_1T - 11, UT_1M + 111);
	ut_statfs_bfree_(ute, UT_FILESIZE_MAX - UT_1M, UT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_statfs_empty),
	UT_DEFTEST(ut_statfs_files),
	UT_DEFTEST(ut_statfs_dirs),
	UT_DEFTEST(ut_statfs_bfree),
};

const struct ut_testdefs ut_tdefs_statfs = UT_MKTESTS(ut_local_tests);
