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

static void ut_pack_simple(struct ut_env *ute)
{
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_pack_ok(ute, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_data_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_pack_ok(ute, name);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_data(struct ut_env *ute)
{
	ut_pack_data_(ute, 0, UT_MEGA);
	ut_pack_data_(ute, UT_KILO - 1, 2 * UT_BK_SIZE);
	ut_pack_data_(ute, UT_GIGA, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_pack_simple),
	UT_DEFTEST(ut_pack_data),
};

const struct ut_testdefs ut_tdefs_pack_basic = UT_MKTESTS(ut_local_tests);
