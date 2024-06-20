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
#include "unitests.h"

static void ut_pack_simple(struct ut_env *ute)
{
	const char *name = UT_NAME;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_data(struct ut_env *ute)
{
	struct stat st = {.st_ino = 0};
	const char *name = UT_NAME;
	const size_t len = UT_1M;
	const loff_t off = 1;
	void *buf = ut_randbuf(ute, len);
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, len, off);
	ut_release_flush_ok(ute, ino);
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	/*ut_unref_fs_ok(ute);*/
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
	ut_getattr_reg(ute, ino, &st);
	ut_open_rdwr(ute, ino);
	ut_read_verify(ute, ino, buf, len, off);
	ut_release_file(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_pack_simple),
	UT_DEFTEST1(ut_pack_data),
};

const struct ut_testdefs ut_tdefs_pack = UT_MKTESTS(ut_local_tests);
