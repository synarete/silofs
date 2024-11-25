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

static blkcnt_t datasize_to_nbytes(size_t dsz, blkcnt_t blksize)
{
	return (((blkcnt_t)dsz + blksize - 1) / blksize) * blksize;
}

static blkcnt_t datasize_to_nfrgs_min(size_t dsz)
{
	return datasize_to_nbytes(dsz, SILOFS_FILE_HEAD1_LEAF_SIZE) / 512;
}

static blkcnt_t datasize_to_nfrgs_max(size_t dsz)
{
	return datasize_to_nbytes(dsz, SILOFS_LBK_SIZE) / 512;
}

static void ut_getattr_blocks(struct ut_env *ute, ino_t ino, size_t dsz)
{
	struct stat st;
	blkcnt_t blocks;
	blkcnt_t blocks_min;
	blkcnt_t blocks_max;

	ut_getattr(ute, ino, &st);
	if (st.st_size < SILOFS_LBK_SIZE) {
		ut_expect_eq(st.st_blksize, SILOFS_FILE_HEAD2_LEAF_SIZE);
	} else {
		ut_expect_eq(st.st_blksize, SILOFS_LBK_SIZE);
	}
	blocks = st.st_blocks;
	blocks_min = datasize_to_nfrgs_min(dsz);
	blocks_max = datasize_to_nfrgs_max(dsz);
	ut_expect_ge(blocks, blocks_min);
	ut_expect_le(blocks, blocks_max);
}

static void ut_file_stat_blocks_at_(struct ut_env *ute, size_t bsz, loff_t off)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_getattr_blocks(ute, ino, bsz);
	ut_trunacate_file(ute, ino, off);
	ut_getattr_blocks(ute, ino, 0);
	ut_trunacate_file(ute, ino, off);
	ut_getattr_blocks(ute, ino, 0);
	ut_trunacate_file(ute, ino, off + (loff_t)bsz);
	ut_getattr_blocks(ute, ino, 0);
	ut_trunacate_file(ute, ino, off / 2);
	ut_getattr_blocks(ute, ino, 0);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_getattr_blocks(ute, ino, bsz);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_stat_blocks_(struct ut_env *ute, loff_t off)
{
	ut_file_stat_blocks_at_(ute, 1, off);
	ut_file_stat_blocks_at_(ute, UT_BK_SIZE, off);
	ut_file_stat_blocks_at_(ute, 2 * UT_BK_SIZE, off);
	ut_file_stat_blocks_at_(ute, UT_1M, off);
	ut_file_stat_blocks_at_(ute, UT_IOSIZE_MAX, off);
	ut_file_stat_blocks_at_(ute, SILOFS_IO_SIZE_MAX, off);
}

static void ut_file_stat_blocks(struct ut_env *ute)
{
	const loff_t off[] = { 0, UT_1M, UT_1G, UT_1T };

	for (size_t i = 0; i < UT_ARRAY_SIZE(off); ++i) {
		ut_file_stat_blocks_(ute, off[i]);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_statvfs_(struct ut_env *ute, loff_t off, size_t len)
{
	struct statvfs stv[2];
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, len);
	fsblkcnt_t bcnt = 0;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_statfs(ute, dino, &stv[0]);
	bcnt = len / stv[0].f_frsize;

	ut_create_file(ute, dino, name, &ino);
	ut_statfs(ute, ino, &stv[0]);
	ut_write_read(ute, ino, buf, len, off);
	ut_statfs(ute, ino, &stv[1]);
	ut_expect_lt(stv[1].f_bfree, stv[0].f_bfree);
	ut_expect_le(stv[1].f_bfree + bcnt, stv[0].f_bfree);

	ut_statfs(ute, ino, &stv[0]);
	ut_write_read(ute, ino, buf, len, off);
	ut_statfs(ute, ino, &stv[1]);
	ut_expect_eq(stv[1].f_bfree, stv[0].f_bfree);

	ut_trunacate_file(ute, ino, off);
	ut_statfs(ute, ino, &stv[0]);
	ut_trunacate_file(ute, ino, off + (loff_t)len);
	ut_statfs(ute, ino, &stv[1]);
	ut_expect_eq(stv[0].f_bfree, stv[1].f_bfree);

	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_statvfs(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_64K),
		UT_MKRANGE1(0, UT_1M),
		UT_MKRANGE1(UT_64K - 1, UT_1M + 3),
		UT_MKRANGE1(UT_IOSIZE_MAX - UT_1M - 1, UT_1M + 1),
	};

	ut_exec_with_ranges(ute, ut_file_statvfs_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_stat_blocks),
	UT_DEFTEST1(ut_file_statvfs),
};

const struct ut_testdefs ut_tdefs_file_stat = UT_MKTESTS(ut_local_tests);
