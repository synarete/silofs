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
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_pack_fs_ok(ute);
	ut_close_fs_ok(ute);
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_pack_simple),
};

const struct ut_testdefs ut_tdefs_pack = UT_MKTESTS(ut_local_tests);
