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
	ut_snap_ok(ute, dino, name);
	ut_open_rdwr(ute, ino);
	for (size_t i = 0; i < cnt; ++i) {
		ut_read_verify(ute, ino, buf, bsz, offs[i]);
	}
	for (size_t i = cnt; i > 0; --i) {
		ut_write_read(ute, ino, buf, bsz, offs[i - 1]);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_snap_write_sparse(struct ut_env *ute)
{
	const loff_t offs[] = {
		1, 2 * UT_KILO - 1, 8 * UT_KILO - 1,
		UT_BK_SIZE - 1, UT_MEGA - 1, UT_GIGA - 1, UT_TERA - 1
	};

	ut_snap_write_sparse_(ute, offs, UT_ARRAY_SIZE(offs), UT_KILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_snap_write_sparse),

};

const struct ut_testdefs ut_tdefs_snap_io = UT_MKTESTS(ut_local_tests);
