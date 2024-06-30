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
	ut_reload_fs_ok(ute);
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	ut_unref_fs_ok(ute);
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

static void ut_pack_nfiles(struct ut_env *ute)
{
	struct stat st = {.st_ino = 0};
	const ino_t root_ino = SILOFS_INO_ROOT;
	const char *pref = UT_NAME;
	const char *name = NULL;
	const size_t cnt = 100;
	const size_t len = UT_1M;
	loff_t off = -1;
	void *buf = ut_randbuf(ute, len);
	ino_t dino = 0;
	ino_t ino = 0;

	for (size_t i = 0; i < cnt; ++i) {
		off = (loff_t)((i * len) + (i * UT_1G) + i);
		name = ut_make_name(ute, pref, i);
		ut_mkdir_oki(ute, root_ino, name, &dino);
		ut_create_file(ute, dino, name, &ino);
		ut_write_read(ute, ino, buf, len, off);
		ut_release_flush_ok(ute, ino);
	}
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	ut_unref_fs_ok(ute);
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
	for (size_t i = 0; i < cnt; ++i) {
		off = (loff_t)((i * len) + (i * UT_1G) + i);
		name = ut_make_name(ute, pref, i);
		ut_lookup_ino(ute, root_ino, name, &dino);
		ut_lookup_ino(ute, dino, name, &ino);
		ut_getattr_reg(ute, ino, &st);
		ut_open_rdwr(ute, ino);
		ut_read_verify(ute, ino, buf, len, off);
		ut_release_file(ute, ino);
		ut_unlink_file(ute, dino, name);
		ut_rmdir_ok(ute, root_ino, name);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_twice(struct ut_env *ute)
{
	const char *dname = UT_NAME;
	const char *name1 = "file1";
	const char *name2 = "file2";
	const size_t len = UT_1M;
	const loff_t off1 = UT_1G - 1;
	const loff_t off2 = UT_1T - UT_1M - 2;
	void *buf1 = ut_randbuf(ute, len);
	void *buf2 = ut_randbuf(ute, len);
	ino_t dino = 0;
	ino_t ino1 = 0;
	ino_t ino2 = 0;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_file(ute, dino, name1, &ino1);
	ut_write_read(ute, ino1, buf1, len, off1);
	ut_release_flush_ok(ute, ino1);
	ut_create_file(ute, dino, name2, &ino2);
	ut_write_read(ute, ino2, buf2, len, off2);
	ut_release_flush_ok(ute, ino2);
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	ut_unref_fs_ok(ute);
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
	ut_open_rdonly(ute, ino1);
	ut_read_verify(ute, ino1, buf1, len, off1);
	ut_release_file(ute, ino1);
	ut_open_rdonly(ute, ino2);
	ut_read_verify(ute, ino2, buf2, len, off2);
	ut_release_file(ute, ino2);
	ut_rename_exchange(ute, dino, name1, dino, name2);
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	ut_unref_fs_ok(ute);
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
	ut_open_rdonly(ute, ino1);
	ut_read_verify(ute, ino1, buf1, len, off1);
	ut_release_file(ute, ino1);
	ut_unlink_file(ute, dino, name2);
	ut_open_rdonly(ute, ino2);
	ut_read_verify(ute, ino2, buf2, len, off2);
	ut_release_file(ute, ino2);
	ut_unlink_file(ute, dino, name1);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_pack_simple),
	UT_DEFTEST(ut_pack_data),
	UT_DEFTEST(ut_pack_nfiles),
	UT_DEFTEST(ut_pack_twice),
};

const struct ut_testdefs ut_tdefs_pack = UT_MKTESTS(ut_local_tests);