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

static void ut_clone_mkdir_rmdir(struct ut_env *ute)
{
	struct statvfs stvfs[2];
	struct silofs_space_stats1k spst[2];
	const ino_t rootd_ino = SILOFS_INO_ROOT;
	ino_t dino            = 0;
	const char *name      = UT_NAME;

	ut_statfs(ute, rootd_ino, &stvfs[0]);
	ut_statsp(ute, rootd_ino, &spst[0]);
	ut_mkdir_at_root(ute, name, &dino);
	ut_clone(ute, dino);
	ut_inspect_fs(ute);
	ut_rmdir_at_root(ute, name);
	ut_statfs(ute, rootd_ino, &stvfs[1]);
	ut_statsp(ute, rootd_ino, &spst[1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_create_remove(struct ut_env *ute)
{
	const char *name = UT_NAME;
	ino_t dino       = 0;
	ino_t ino        = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_clone(ute, dino);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_write_read(struct ut_env *ute)
{
	time_t val       = silofs_time_real_now();
	const char *name = UT_NAME;
	const off_t off  = (off_t)(val & 0xFFFFFF);
	ino_t dino       = 0;
	ino_t ino        = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, &val, sizeof(val), off);
	ut_clone(ute, dino);
	ut_read_verify(ute, ino, &val, sizeof(val), off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_write_post(struct ut_env *ute)
{
	const char *name = UT_NAME;
	const off_t off  = UT_1M;
	ino_t dino       = 0;
	ino_t ino        = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_clone(ute, dino);
	ut_write_read_str(ute, ino, name, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_overwrite(struct ut_env *ute)
{
	uint64_t val1    = (uint64_t)silofs_time_real_now();
	uint64_t val2    = ~val1;
	const char *name = UT_NAME;
	const off_t off  = UT_1G;
	ino_t dino       = 0;
	ino_t ino        = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, &val1, sizeof(val1), off);
	ut_clone(ute, dino);
	ut_read_verify(ute, ino, &val1, sizeof(val1), off);
	ut_read_zero(ute, ino, off - 1);
	ut_write_read(ute, ino, &val2, sizeof(val2), off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_clone_mkdir_rmdir),   //
	UT_DEFTEST(ut_clone_create_remove), //
	UT_DEFTEST(ut_clone_write_read),    //
	UT_DEFTEST(ut_clone_write_post),    //
	UT_DEFTEST(ut_clone_overwrite),     //
};

const struct ut_testdefs ut_tdefs_clone_basic = UT_MKTESTS(ut_local_tests);
