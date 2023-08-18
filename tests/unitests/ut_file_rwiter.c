/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

static void ut_file_write_iter_(struct ut_env *ute, loff_t off, size_t len)
{
	void *buf = ut_randbuf(ute, len);
	const char *name = UT_NAME;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_iter_ok(ute, ino, buf, len, off);
	ut_read_verify(ute, ino, buf, len, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_write_iter_simple(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_64K),
		UT_MKRANGE1(UT_64K, 2 * UT_64K),
		UT_MKRANGE1(2 * UT_64K, 4 * UT_64K),
		UT_MKRANGE1(0, UT_MEGA),
		UT_MKRANGE1(UT_GIGA, UT_MEGA),
		UT_MKRANGE1(UT_TERA, UT_MEGA),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_write_iter_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

static void ut_file_write_iter_aligned(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(0, UT_64K),
		UT_MKRANGE1(UT_4K, UT_64K),
		UT_MKRANGE1(UT_64K, 2 * UT_64K),
		UT_MKRANGE1(2 * UT_64K, 4 * UT_64K),
		UT_MKRANGE1(UT_MEGA / 2, UT_MEGA / 2),
		UT_MKRANGE1(UT_GIGA / 2, UT_MEGA / 2),
		UT_MKRANGE1(UT_TERA / 2, UT_MEGA / 2),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_write_iter_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

static void ut_file_write_iter_unaligned(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(1, UT_4K),
		UT_MKRANGE1(3, 3 * UT_BK_SIZE),
		UT_MKRANGE1(UT_4K - 5, UT_64K + 7),
		UT_MKRANGE1(UT_4K + 5, 3 * UT_64K - 7),
		UT_MKRANGE1(UT_BK_SIZE - 1, UT_BK_SIZE + 3),
		UT_MKRANGE1(UT_MEGA - 3, UT_BK_SIZE / 5),
		UT_MKRANGE1(UT_GIGA - 5, UT_MEGA / 1),
		UT_MKRANGE1(UT_TERA - 7, UT_MEGA / 7),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_write_iter_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_write_iter_sparse_(struct ut_env *ute,
                                       const loff_t *offs, size_t cnt)
{
	ino_t ino = 0;
	ino_t dino = 0;
	loff_t off = -1;
	loff_t val = -1;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = offs[i];
		val = off;
		ut_write_iter_ok(ute, ino, &val, sizeof(val), off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = offs[i];
		val = off;
		ut_read_verify(ute, ino, &val, sizeof(val), off);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_write_iter_sparse(struct ut_env *ute)
{
	const loff_t offs[] = {
		8 * UT_BK_SIZE, UT_GIGA / 5 - 5, UT_BK_SIZE - 1,
		UT_TERA / 7 - 7, 0, UT_MEGA / 3 - 3, 4 * UT_MEGA, UT_KILO - 1,
	};

	ut_file_write_iter_sparse_(ute, offs, UT_ARRAY_SIZE(offs));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_file_write_iter_simple),
	UT_DEFTEST(ut_file_write_iter_aligned),
	UT_DEFTEST(ut_file_write_iter_unaligned),
	UT_DEFTEST(ut_file_write_iter_sparse),
};

const struct ut_testdefs ut_tdefs_file_rwiter = UT_MKTESTS(ut_local_tests);
