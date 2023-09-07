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

static void ut_snap_write_sparse_(struct ut_env *ute,
                                  const loff_t *offs, size_t cnt, size_t bsz)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		ut_write_read(ute, ino, buf, bsz, offs[i]);
	}
	ut_release_ok(ute, ino);
	ut_snap_ok(ute, dino);
	ut_open_rdwr(ute, ino);
	for (size_t i = 0; i < cnt; ++i) {
		ut_read_verify(ute, ino, buf, bsz, offs[i]);
	}
	for (size_t i = cnt; i > 0; --i) {
		ut_write_read(ute, ino, buf, bsz, offs[i - 1]);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_snap_write_sparse(struct ut_env *ute)
{
	const loff_t offs[] = {
		1,
		2 * UT_1K - 1,
		8 * UT_1K - 1,
		UT_BK_SIZE - 1,
		UT_1M - 1,
		UT_1G - 1,
		UT_1T - 1
	};

	ut_snap_write_sparse_(ute, offs, UT_ARRAY_SIZE(offs), UT_1K);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_copy_range_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino = 0;
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	const loff_t end = off + (long)len;
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf = ut_randbuf(ute, len);
	void *buf2 = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end);
	ut_snap_ok(ute, dino);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end - 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len - 1, off);
	ut_read_zero(ute, ino_dst, end - 1);
	ut_snap_ok(ute, dino);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_trunacate_file(ute, ino_dst, off + 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, 1, off);
	ut_read_zeros(ute, ino_dst, off + 1, len - 1);
	ut_write_read(ute, ino_dst, buf2, len, off);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_snap_ok(ute, dino);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_snap_copy_range(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_1K),
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(UT_4K, UT_4K),
		UT_MKRANGE1(2 * UT_4K, 2 * UT_4K),
		UT_MKRANGE1(UT_64K, UT_64K),
		UT_MKRANGE1(4 * UT_4K, 4 * UT_64K),
		UT_MKRANGE1(UT_1M, UT_1M),
		UT_MKRANGE1(2 * UT_1M, UT_1M / 2),
		UT_MKRANGE1(UT_1G, 2 * UT_64K),
		UT_MKRANGE1(1, UT_1M),
		UT_MKRANGE1(UT_1G - 1, (3 * UT_64K) + 3),
		UT_MKRANGE1(UT_1T - 7, UT_1M + 11),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_snap_copy_range_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_rename_io_(struct ut_env *ute, loff_t off, size_t bsz)
{
	const char *dname = UT_NAME;
	const char *name1 = UT_NAME_AT;
	const char *name2 = UT_NAME_AT;
	void *buf1 = ut_randbuf(ute, bsz);
	void *buf2 = ut_randbuf(ute, bsz);
	ino_t dino = 0;
	ino_t ino1 = 0;
	ino_t ino2 = 0;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < 4; ++i) {
		ut_create_file(ute, dino, name1, &ino1);
		ut_create_file(ute, dino, name2, &ino2);
		ut_write_read(ute, ino1, buf1, bsz, off);
		ut_write_read(ute, ino2, buf2, bsz, off);
		ut_snap_ok(ute, dino);
		ut_read_verify(ute, ino1, buf1, bsz, off);
		ut_read_verify(ute, ino2, buf2, bsz, off);
		ut_release_file(ute, ino1);
		ut_rename_replace(ute, dino, name1, dino, name2);
		ut_release_file(ute, ino2);
		ut_getattr_noent(ute, ino2);
		ut_open_rdonly(ute, ino1);
		ut_read_verify(ute, ino1, buf1, bsz, off);
		ut_release_file(ute, ino1);
		ut_unlink_ok(ute, dino, name2);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_snap_rename_io(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_1K - 1),
		UT_MKRANGE1(UT_1K - 1, UT_1K + 3),
		UT_MKRANGE1(2 * UT_4K, 2 * UT_4K),
		UT_MKRANGE1(UT_64K, UT_64K),
		UT_MKRANGE1(UT_1M, UT_1M),
		UT_MKRANGE1(UT_1T - 7, UT_1M + 11),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_snap_rename_io_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_snap_write_sparse),
	UT_DEFTEST(ut_snap_copy_range),
	UT_DEFTEST(ut_snap_rename_io),
};

const struct ut_testdefs ut_tdefs_snap_io = UT_MKTESTS(ut_local_tests);
