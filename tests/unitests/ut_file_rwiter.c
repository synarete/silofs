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
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_64K),
		UT_MKRANGE1(UT_64K, 2 * UT_64K),
		UT_MKRANGE1(2 * UT_64K, 4 * UT_64K),
		UT_MKRANGE1(0, UT_1M),
		UT_MKRANGE1(UT_1G, UT_1M),
		UT_MKRANGE1(UT_1T, UT_1M),
	};

	ut_exec_with_ranges(ute, ut_file_write_iter_, ranges);
}

static void ut_file_write_iter_aligned(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(0, UT_64K),
		UT_MKRANGE1(UT_4K, UT_64K),
		UT_MKRANGE1(UT_64K, 2 * UT_64K),
		UT_MKRANGE1(2 * UT_64K, 4 * UT_64K),
		UT_MKRANGE1(UT_1M / 2, UT_1M / 2),
		UT_MKRANGE1(UT_1G / 2, UT_1M / 2),
		UT_MKRANGE1(UT_1T / 2, UT_1M / 2),
	};

	ut_exec_with_ranges(ute, ut_file_write_iter_, ranges);
}

static void ut_file_write_iter_unaligned(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(1, UT_4K),
		UT_MKRANGE1(3, 3 * UT_BK_SIZE),
		UT_MKRANGE1(UT_4K - 5, UT_64K + 7),
		UT_MKRANGE1(UT_4K + 5, 3 * UT_64K - 7),
		UT_MKRANGE1(UT_BK_SIZE - 1, UT_BK_SIZE + 3),
		UT_MKRANGE1(UT_1M - 3, UT_BK_SIZE / 5),
		UT_MKRANGE1(UT_1G - 5, UT_1M / 1),
		UT_MKRANGE1(UT_1T - 7, UT_1M / 7),
	};

	ut_exec_with_ranges(ute, ut_file_write_iter_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_write_iter_sparse_(struct ut_env *ute,
                                       const loff_t *offs, size_t cnt)
{
	const char *name = UT_NAME;
	uint64_t val = 0;
	loff_t off = -1;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = offs[i];
		val = (uint64_t)off;
		ut_write_iter_ok(ute, ino, &val, sizeof(val), off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = offs[i];
		val = (uint64_t)off;
		ut_read_verify(ute, ino, &val, sizeof(val), off);
	}
	for (size_t i = cnt; i > 0; --i) {
		off = offs[i - 1];
		val = (uint64_t)off + i;
		ut_write_iter_ok(ute, ino, &val, sizeof(val), off);
	}
	for (size_t i = cnt; i > 0; --i) {
		off = offs[i - 1];
		val = (uint64_t)off + i;
		ut_read_verify(ute, ino, &val, sizeof(val), off);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_write_iter_sparse(struct ut_env *ute)
{
	const loff_t offs[] = {
		8 * UT_BK_SIZE, UT_1G / 5 - 5, UT_BK_SIZE - 1,
		UT_1T / 7 - 7, 0, UT_1M / 3 - 3, 4 * UT_1M, UT_1K - 1,
	};

	ut_file_write_iter_sparse_(ute, offs, UT_ARRAY_SIZE(offs));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST3(ut_file_write_iter_simple),
	UT_DEFTEST2(ut_file_write_iter_aligned),
	UT_DEFTEST2(ut_file_write_iter_unaligned),
	UT_DEFTEST2(ut_file_write_iter_sparse),
};

const struct ut_testdefs ut_tdefs_file_rwiter = UT_MKTESTS(ut_local_tests);
