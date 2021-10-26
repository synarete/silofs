/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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


static void ut_ioctl_query(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	struct silofs_ioc_query query = {
		.qtype = SILOFS_QUERY_VERSION
	};

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_ok(ute, dino, &query);
	ut_expect_eq(query.u.version.major, silofs_version.major);
	ut_create_file(ute, dino, name, &ino);
	ut_query_ok(ute, ino, &query);
	ut_expect_eq(query.u.version.minor, silofs_version.minor);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_ioctl_query),
};

const struct ut_tests ut_test_ioctl = UT_MKTESTS(ut_local_tests);
