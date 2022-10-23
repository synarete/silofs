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
#include "unitests.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_write_sparse_(struct ut_env *ute,
                                  const loff_t *offs, size_t cnt, size_t bsz)
{
	ino_t ino;
	ino_t dino;
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
		2 * UT_KILO - 1,
		8 * UT_KILO - 1,
		UT_BK_SIZE - 1,
		UT_MEGA - 1,
		UT_GIGA - 1,
		UT_TERA - 1
	};

	ut_snap_write_sparse_(ute, offs, UT_ARRAY_SIZE(offs), UT_KILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_copy_range_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
	const loff_t end = off + (long)len;
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	uint8_t *buf = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end);
	ut_snap_ok(ute, dino);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end - 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len - 1, off);
	ut_read_zero(ute, ino_dst, end - 1);
	ut_snap_ok(ute, dino);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_trunacate_file(ute, ino_dst, off + 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, 1, off);
	ut_read_zeros(ute, ino_dst, off + 1, len - 1);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_snap_copy_range(struct ut_env *ute)
{
	ut_snap_copy_range_(ute, 0, UT_1K);
	ut_snap_copy_range_(ute, 0, UT_4K);
	ut_snap_copy_range_(ute, UT_64K, UT_64K);
	ut_snap_copy_range_(ute, UT_MEGA, UT_MEGA);
	ut_snap_copy_range_(ute, UT_GIGA, 2 * UT_64K);
	ut_snap_copy_range_(ute, 1, UT_MEGA);
	ut_snap_copy_range_(ute, UT_GIGA - 1, (3 * UT_64K) + 3);
	ut_snap_copy_range_(ute, UT_TERA - 7, UT_MEGA + 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_snap_write_sparse),
	UT_DEFTEST(ut_snap_copy_range),
};

const struct ut_testdefs ut_tdefs_snap_io = UT_MKTESTS(ut_local_tests);
