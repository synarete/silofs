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


static void ut_rootd_getattr(struct ut_env *ute)
{
	struct stat st = { .st_size = -1 };

	ut_getattr(ute, UT_ROOT_INO, &st);
	ut_expect(S_ISDIR(st.st_mode));
	ut_expect_eq(st.st_size, SILOFS_DIR_EMPTY_SIZE);
	ut_expect_eq(st.st_nlink, 2);
}

static void ut_rootd_access(struct ut_env *ute)
{
	ut_access(ute, UT_ROOT_INO, R_OK);
	ut_access(ute, UT_ROOT_INO, X_OK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_rootd_getattr),
	UT_DEFTEST1(ut_rootd_access),
};

const struct ut_testdefs ut_tdefs_super = UT_MKTESTS(ut_local_tests);
