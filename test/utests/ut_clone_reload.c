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

static void ut_clone_reload(struct ut_env *ute)
{
	const char *name = UT_NAME;
	ino_t dino       = 0;
	ino_t ino        = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_str(ute, ino, name, UT_1K);
	ut_write_read_str(ute, ino, name, UT_1T);
	ut_write_read_str(ute, ino, name, UT_1M);
	ut_release(ute, ino);
	ut_clone(ute, dino);
	ut_unload_reload_fs(ute);
	ut_inspect_fs(ute);
	ut_open_rdonly(ute, ino);
	ut_read_verify_str(ute, ino, name, UT_1M);
	ut_read_verify_str(ute, ino, name, UT_1K);
	ut_read_verify_str(ute, ino, name, UT_1T);
	ut_read_zeros(ute, ino, UT_1G, 1);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_reload_other(struct ut_env *ute)
{
	const off_t off1[] = { 0, UT_1G };
	const off_t off2[] = { UT_1M, UT_1K };
	const char *name   = UT_NAME;
	const char *str1   = ut_randstr(ute, UT_1K);
	const char *str2   = ut_randstr(ute, UT_4K);
	ino_t dino         = 0;
	ino_t ino1         = 0;
	ino_t ino2         = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino1);
	ut_write_read_str(ute, ino1, str1, off1[0]);
	ut_write_read_str(ute, ino1, str1, off1[1]);
	ut_release(ute, ino1);
	ut_clone(ute, dino);
	ut_unload_fs(ute);
	ut_reload_forked_fs(ute);
	ut_open_rdonly(ute, ino1);
	ut_read_verify_str(ute, ino1, str1, off1[0]);
	ut_read_verify_str(ute, ino1, str1, off1[1]);
	ut_release(ute, ino1);
	ut_unlink(ute, dino, name);
	ut_create_file(ute, dino, name, &ino2);
	ut_write_read_str(ute, ino2, str2, off2[0]);
	ut_write_read_str(ute, ino2, str2, off2[1]);
	ut_release(ute, ino2);
	ut_unload_fs(ute);
	ut_remove_fs2(ute);
	ut_reload_fs(ute);
	ut_open_rdonly(ute, ino1);
	ut_read_verify_str(ute, ino1, str1, off1[0]);
	ut_read_verify_str(ute, ino1, str1, off1[1]);
	ut_remove_file(ute, dino, name, ino1);
	ut_inspect_fs(ute);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_clone_reload),       //
	UT_DEFTEST(ut_clone_reload_other), //
};

const struct ut_testdefs ut_tdefs_clone_reload = UT_MKTESTS(ut_local_tests);
