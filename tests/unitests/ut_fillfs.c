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

static size_t calc_wr_size(const struct statvfs *stv, size_t limit)
{
	size_t wr_size = UT_BK_SIZE;
	const size_t nbytes_free = stv->f_bfree * stv->f_frsize;

	if (nbytes_free > wr_size) {
		wr_size = nbytes_free;
	}
	if (wr_size > limit) {
		wr_size = limit;
	}
	return wr_size;
}

static void ut_fillfs_simple(struct ut_env *ute)
{
	void *buf = NULL;
	ino_t ino;
	ino_t dino;
	size_t len;
	size_t nwr;
	loff_t off;
	struct stat st;
	struct statvfs stv[2];
	struct statvfs stv2;
	const char *name = UT_NAME;
	const size_t bsz = UT_1M;

	ut_statfs_rootd_ok(ute, &stv[0]);
	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs_ok(ute, dino, &stv2);
	ut_expect_gt(stv2.f_bfree, 0);
	ut_create_file(ute, dino, name, &ino);

	ut_statfs_ok(ute, dino, &stv2);
	len = calc_wr_size(&stv2, bsz);
	nwr = len;
	buf = ut_randbuf(ute, bsz);
	while (nwr == len) {
		ut_getattr_reg(ute, ino, &st);
		ut_statfs_ok(ute, dino, &stv2);
		len = calc_wr_size(&stv2, bsz);
		nwr = 0;
		off = st.st_size;
		ut_write_nospc(ute, ino, buf, len, off, &nwr);
		ut_flush_ok(ute, ino, false);
		ut_timedout_ok(ute);
	}
	for (size_t i = 0; i < 10; ++i) {
		ut_getattr_reg(ute, ino, &st);
		ut_statfs_ok(ute, dino, &stv2);
		len = calc_wr_size(&stv2, bsz);
		off = st.st_size;
		ut_write_nospc(ute, ino, buf, len, off, &nwr);
		ut_timedout_ok(ute);
	}
	ut_release_file(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_rmdir_at_root(ute, name);
	ut_statfs_rootd_ok(ute, &stv[1]);
	ut_expect_statvfs(&stv[0], &stv[1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_fillfs_mixed(struct ut_env *ute)
{
	size_t idx = 0;
	size_t idx_end = 0;
	loff_t off;
	ino_t ino;
	ino_t dino;
	size_t len = 0;
	size_t nwr = 0;
	struct statvfs stv;
	const char *name;
	const char *dname = UT_NAME;
	size_t bsz = UT_IOSIZE_MAX;
	const void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_statfs_ok(ute, dino, &stv);
	while ((nwr == len) && (stv.f_bfree > 2) && bsz) {
		name = ut_make_name(ute, dname, idx++);
		ut_mkdir_oki(ute, dino, name, &ino);
		ut_create_file(ute, ino, name, &ino);
		len = calc_wr_size(&stv, bsz--);
		off = (loff_t)idx;
		nwr = 0;
		ut_write_nospc(ute, ino, buf, len, off, &nwr);
		ut_release_file(ute, ino);
		ut_statfs_ok(ute, dino, &stv);
		idx_end = idx;
		ut_timedout_ok(ute);
	}
	idx = 0;
	while (idx < idx_end) {
		name = ut_make_name(ute, dname, idx++);
		ut_lookup_ino(ute, dino, name, &ino);
		ut_unlink_file(ute, ino, name);
		ut_rmdir_ok(ute, dino, name);
	}
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_fillfs_append_(struct ut_env *ute, ino_t ino, size_t bsz)
{
	size_t nwr = bsz;
	size_t fs_size_bytes;
	size_t fs_free_bytes;
	struct stat st;
	struct statvfs stv;
	const void *buf = ut_randbuf(ute, bsz);

	ut_statfs_ok(ute, ino, &stv);
	fs_size_bytes = stv.f_blocks * stv.f_frsize;
	fs_free_bytes = stv.f_bfree * stv.f_bsize;
	ut_expect_le(fs_free_bytes, fs_size_bytes);
	ut_expect_lt(bsz, fs_free_bytes);

	while ((nwr == bsz) && stv.f_bfree) {
		ut_getattr_reg(ute, ino, &st);
		nwr = 0;
		ut_write_nospc(ute, ino, buf, bsz, st.st_size, &nwr);
		ut_statfs_ok(ute, ino, &stv);
		ut_timedout_ok(ute);
	}
	ut_statfs_ok(ute, ino, &stv);
	fs_size_bytes = stv.f_blocks * stv.f_frsize;
	fs_free_bytes = stv.f_bfree * stv.f_bsize;
	ut_expect_le(fs_free_bytes, fs_size_bytes);
	ut_expect_le(bsz, fs_free_bytes);
}

static void ut_fillfs_data_(struct ut_env *ute, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	struct statvfs stv[2];
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs_ok(ute, dino, &stv[0]);
	ut_create_file(ute, dino, name, &ino);
	ut_fillfs_append_(ute, ino, bsz);
	ut_release_file(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_statfs_ok(ute, dino, &stv[1]);
	ut_expect_statvfs(&stv[0], &stv[1]);
	ut_rmdir_at_root(ute, name);
}

static void ut_fillfs_data(struct ut_env *ute)
{
	ut_fillfs_data_(ute, UT_1M);
	ut_fillfs_data_(ute, 1111111);
}

static void ut_fillfs_reload_(struct ut_env *ute, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	struct statvfs stv[2];
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs_ok(ute, dino, &stv[0]);
	ut_create_file(ute, dino, name, &ino);
	ut_fillfs_append_(ute, ino, bsz);
	ut_release_file(ute, ino);
	ut_reload_fs_ok_at(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_statfs_ok(ute, dino, &stv[1]);
	ut_expect_statvfs(&stv[0], &stv[1]);
	ut_rmdir_at_root(ute, name);
}

static void ut_fillfs_reload(struct ut_env *ute)
{
	ut_fillfs_reload_(ute, 1234567);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_fillfs_simple),
	UT_DEFTEST(ut_fillfs_mixed),
	UT_DEFTEST(ut_fillfs_data),
	UT_DEFTEST(ut_fillfs_reload),
};

const struct ut_testdefs ut_tdefs_fillfs = UT_MKTESTS(ut_local_tests);

