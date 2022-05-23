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


static void ut_file_lseek_simple_(struct ut_env *ute, loff_t off)
{
	ino_t ino;
	ino_t dino;
	loff_t off_data;
	loff_t off_hole;
	char d = 'd';
	struct stat st;
	const char *name = UT_NAME;
	const loff_t step = 2 * UT_BK_SIZE;

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
	ut_file_lseek_simple_(ute, 0);
	ut_file_lseek_simple_(ute, 1);
	ut_file_lseek_simple_(ute, UT_MEGA + 1);
	ut_file_lseek_simple_(ute, UT_GIGA - 3);
	ut_file_lseek_simple_(ute, UT_TERA + 5);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_lseek_holes_(struct ut_env *ute,
                                 loff_t base_off, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	loff_t off;
	loff_t off_data;
	loff_t off_hole;
	struct stat st;
	const char *name = UT_NAME;
	const size_t bsz = UT_BK_SIZE;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = base_off + (loff_t)(2 * bsz * (i + 1));
		ut_write_read(ute, ino, buf, bsz, off);
		ut_getattr_reg(ute, ino, &st);
		ut_lseek_hole(ute, ino, off, &off_hole);
		ut_expect_eq(off_hole, st.st_size);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = base_off + (loff_t)(2 * bsz * (i + 1));
		ut_lseek_data(ute, ino, off, &off_data);
		ut_expect_eq(off_data, off);
		ut_lseek_hole(ute, ino, off, &off_hole);
		ut_expect_eq(off_hole, off + (loff_t)bsz);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}


static void ut_file_lseek_holes(struct ut_env *ute)
{
	ut_file_lseek_holes_(ute, 0, 10);
	ut_file_lseek_holes_(ute, UT_MEGA, 100);
	ut_file_lseek_holes_(ute, UT_GIGA, 1000);
	ut_file_lseek_holes_(ute, UT_TERA, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_lseek_sparse_(struct ut_env *ute,
                                  loff_t off_base, loff_t step, size_t nsteps)
{
	ino_t ino;
	ino_t dino;
	loff_t off;
	loff_t off_data;
	loff_t off_hole;
	loff_t off_next;
	const loff_t head1_lsize = SILOFS_FILE_HEAD1_LEAF_SIZE;
	const loff_t head2_lsize = SILOFS_FILE_HEAD2_LEAF_SIZE;
	const loff_t tree_lsize = SILOFS_FILE_TREE_LEAF_SIZE;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < nsteps; ++i) {
		off = off_base + ((loff_t)i * step);
		ut_write_read1(ute, ino, off);
		ut_lseek_data(ute, ino, off, &off_data);
		ut_expect_eq(off_data, off);
		ut_trunacate_file(ute, ino, off + tree_lsize);
	}
	for (size_t i = 0; i < (nsteps - 1); ++i) {
		off = off_base + ((loff_t)i * step);
		ut_lseek_data(ute, ino, off, &off_data);
		ut_expect_eq(off_data, off);
		ut_lseek_hole(ute, ino, off, &off_hole);

		if (off_data < head2_lsize) {
			off_next = off_data + head1_lsize;
		} else if (off_data < tree_lsize) {
			off_next = off_data + head2_lsize;
		} else {
			off_next = off_data + tree_lsize;
		}
		ut_expect_le(off_hole, off_next); /* FIXME  calc exact value */

		off_next = off + step;
		off = (off + off_next) / 2;
		ut_lseek_data(ute, ino, off, &off_data);
		ut_expect_le(off_data, off_next);
		ut_expect_gt(off_data + step, off_next);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_lseek_sparse(struct ut_env *ute)
{
	ut_file_lseek_sparse_(ute, 0, 10 * UT_BK_SIZE, 10);
	ut_file_lseek_sparse_(ute, UT_4K, 10 * UT_BK_SIZE, 10);
	ut_file_lseek_sparse_(ute, UT_8K, 10 * UT_BK_SIZE, 10);
	ut_file_lseek_sparse_(ute, UT_MEGA, UT_GIGA, 100);
	ut_file_lseek_sparse_(ute, UT_GIGA, UT_MEGA, 1000);
	ut_file_lseek_sparse_(ute, UT_TERA, 10 * UT_BK_SIZE, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_lseek_simple),
	UT_DEFTEST(ut_file_lseek_holes),
	UT_DEFTEST(ut_file_lseek_sparse),
};

const struct ut_testdefs ut_tdefs_file_lseek = UT_MKTESTS(ut_local_tests);
