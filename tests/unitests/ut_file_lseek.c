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


static void ut_file_lseek_simple_(struct ut_env *ute, loff_t off)
{
	struct stat st = { .st_size = -1 };
	const char *name = UT_NAME;
	const loff_t step = 2 * UT_64K;
	loff_t off_data = -1;
	loff_t off_hole = -1;
	ino_t dino = 0;
	ino_t ino = 0;
	char d = 'd';

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off + step + 1);
	ut_getattr_reg(ute, ino, &st);
	ut_lseek_nodata(ute, ino, 0);
	ut_write_read(ute, ino, &d, 1, off);
	ut_lseek_data(ute, ino, 0, &off_data);
	ut_expect_eq(off_data, ut_off_baligned(off));
	ut_lseek_data(ute, ino, off ? (off - 1) : 0, &off_data);
	ut_expect_eq(ut_off_baligned(off_data), ut_off_baligned(off));
	ut_lseek_nodata(ute, ino, off + step);
	ut_trunacate_file(ute, ino, off + 2);
	ut_lseek_hole(ute, ino, off, &off_hole);
	ut_expect_eq(off_hole, off + 2);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_lseek_simple(struct ut_env *ute)
{
	const loff_t off[] = {
		0, UT_64K, UT_1M, UT_1G, UT_1T, 1,
		UT_64K + 1, UT_1M + 111, UT_1G - 1111, UT_1T + 11111,
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(off); ++i) {
		ut_file_lseek_simple_(ute, off[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_lseek_holes_(struct ut_env *ute, loff_t off)
{
	struct stat st = { .st_size = -1 };
	const char *name = UT_NAME;
	const size_t len = UT_64K;
	const size_t cnt = 1000;
	void *buf = ut_randbuf(ute, len);
	loff_t pos_data = -1;
	loff_t pos_hole = -1;
	loff_t pos = -1;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		pos = off + (loff_t)(2 * len * (i + 1));
		ut_write_read(ute, ino, buf, len, pos);
		ut_getattr_reg(ute, ino, &st);
		ut_lseek_hole(ute, ino, pos, &pos_hole);
		ut_expect_eq(pos_hole, st.st_size);
	}
	for (size_t i = 0; i < cnt; ++i) {
		pos = off + (loff_t)(2 * len * (i + 1));
		ut_lseek_data(ute, ino, pos, &pos_data);
		ut_expect_eq(pos_data, pos);
		ut_lseek_hole(ute, ino, pos, &pos_hole);
		ut_expect_eq(pos_hole, pos + (loff_t)len);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}


static void ut_file_lseek_holes(struct ut_env *ute)
{
	const loff_t off[] = { 0, UT_64K, UT_1M, UT_1G, UT_1T };

	for (size_t i = 0; i < UT_ARRAY_SIZE(off); ++i) {
		ut_file_lseek_holes_(ute, off[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_lseek_sparse_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	const size_t nsteps = (len < UT_1M) ? 1000 : 100;
	const loff_t head1_lsize = SILOFS_FILE_HEAD1_LEAF_SIZE;
	const loff_t head2_lsize = SILOFS_FILE_HEAD2_LEAF_SIZE;
	const loff_t tree_lsize = SILOFS_FILE_TREE_LEAF_SIZE;
	loff_t pos_data = -1;
	loff_t pos_hole = -1;
	loff_t pos_next = -1;
	loff_t pos = -1;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < nsteps; ++i) {
		pos = off + (ssize_t)(i * len);
		ut_write_read1(ute, ino, pos);
		ut_lseek_data(ute, ino, pos, &pos_data);
		ut_expect_eq(pos_data, pos);
		ut_trunacate_file(ute, ino, pos + tree_lsize);
	}
	for (size_t i = 0; i < (nsteps - 1); ++i) {
		pos = off + (ssize_t)(i * len);
		ut_lseek_data(ute, ino, pos, &pos_data);
		ut_expect_eq(pos_data, pos);
		ut_lseek_hole(ute, ino, pos, &pos_hole);

		if (pos_data < head2_lsize) {
			pos_next = pos_data + head1_lsize;
		} else if (pos_data < tree_lsize) {
			pos_next = pos_data + head2_lsize;
		} else {
			pos_next = pos_data + tree_lsize;
		}
		ut_expect_le(pos_hole, pos_next); /* FIXME  calc exact value */

		pos_next = pos + (ssize_t)len;
		pos = (pos + pos_next) / 2;
		ut_lseek_data(ute, ino, pos, &pos_data);
		ut_expect_le(pos_data, pos_next);
		ut_expect_gt(pos_data + (ssize_t)len, pos_next);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_lseek_sparse(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, 10 * UT_64K),
		UT_MKRANGE1(UT_4K, 10 * UT_64K),
		UT_MKRANGE1(UT_8K, 10 * UT_64K),
		UT_MKRANGE1(UT_1M, UT_1G),
		UT_MKRANGE1(UT_1G, UT_1M),
		UT_MKRANGE1(UT_1T, 10 * UT_64K),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_lseek_sparse_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST2(ut_file_lseek_simple),
	UT_DEFTEST2(ut_file_lseek_holes),
	UT_DEFTEST(ut_file_lseek_sparse),
};

const struct ut_testdefs ut_tdefs_file_lseek = UT_MKTESTS(ut_local_tests);
