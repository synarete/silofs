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

#define FIMAP_SZ     (UT_FILEMAP_NCHILDS * UT_BK_SIZE)
#define FIMAP_SZ2    (FIMAP_SZ * UT_FILEMAP_NCHILDS)
#define FIMAP_SZ_MAX (UT_FILESIZE_MAX)

static uint8_t dvec_first_byte(const struct ut_dvec *dvec)
{
	return dvec->dat[0];
}

static uint8_t dvec_last_byte(const struct ut_dvec *dvec)
{
	return dvec->dat[dvec->len - 1];
}

static loff_t dvec_last_off(const struct ut_dvec *dvec)
{
	return dvec->off + (loff_t)dvec->len - 1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_rw_plus_minus_1_(struct ut_env *ute, ino_t ino, loff_t off, size_t len)
{
	uint8_t byte;
	struct ut_dvec *dv1;
	struct ut_dvec *dv2;
	struct ut_dvec *dv3;
	struct ut_dvec *dv4;

	dv1 = ut_new_dvec(ute, off, len);
	ut_write_dvec(ute, ino, dv1);
	dv2 = ut_new_dvec(ute, off + 1, len);
	ut_write_dvec(ute, ino, dv2);
	byte = dvec_first_byte(dv1);
	ut_read(ute, ino, &byte, 1, dv1->off);
	dv3 = ut_new_dvec(ute, off - 1, len);
	ut_write_dvec(ute, ino, dv3);
	byte = dvec_last_byte(dv2);
	ut_read(ute, ino, &byte, 1, dvec_last_off(dv2));
	ut_fallocate_punch_hole(ute, ino, off, (loff_t)len);
	ut_read_zeros(ute, ino, off, len);
	byte = dvec_first_byte(dv3);
	ut_read(ute, ino, &byte, 1, dv3->off);
	dv4 = ut_new_dvec(ute, off, len);
	ut_write_dvec(ute, ino, dv4);
	ut_fallocate_punch_hole(ute, ino, off - 1, (loff_t)len + 2);
	ut_read_zeros(ute, ino, off - 1, len + 2);
}

static void ut_file_edges_1_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_rw_plus_minus_1_(ute, ino, off, len);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_edges_aligned(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(UT_4K, UT_4K),
		UT_MKRANGE1(2 * UT_4K, UT_4K),
		UT_MKRANGE1(UT_8K, UT_8K),
		UT_MKRANGE1(UT_8K, UT_64K),
		UT_MKRANGE1(UT_64K, UT_64K),
		UT_MKRANGE1(UT_1M, 4 * UT_64K),
		UT_MKRANGE1(UT_1G, 8 * UT_64K),
		UT_MKRANGE1(UT_1T, 16 * UT_64K),
	};

	ut_exec_with_ranges(ute, ut_file_edges_1_, ranges);
}

static void ut_file_edges_unaligned(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(UT_8K - 1, UT_64K + 11),
		UT_MKRANGE1(UT_64K + 11, UT_64K - 1),
		UT_MKRANGE1(UT_1M - 1111, 4 * UT_64K + 1),
		UT_MKRANGE1(UT_1G - 11111, 8 * UT_64K + 11),
		UT_MKRANGE1(UT_1T - 111111, 16 * UT_64K + 111),
	};

	ut_exec_with_ranges(ute, ut_file_edges_1_, ranges);
}

static void ut_file_edges_special(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(FIMAP_SZ, UT_64K),
		UT_MKRANGE1(FIMAP_SZ, 2 * UT_64K),
		UT_MKRANGE1(FIMAP_SZ - 11, UT_64K + 111),
		UT_MKRANGE1(FIMAP_SZ - 111, 2 * UT_64K + 1111),
		UT_MKRANGE1(2 * FIMAP_SZ, 2 * UT_64K),
		UT_MKRANGE1(2 * FIMAP_SZ - 1, UT_64K + 2),
		UT_MKRANGE1(FIMAP_SZ + FIMAP_SZ2, 2 * UT_64K),
		UT_MKRANGE1(FIMAP_SZ + FIMAP_SZ2 - 2, UT_64K + 3),
		UT_MKRANGE1(FIMAP_SZ2 - 2, UT_64K + 3),
		UT_MKRANGE1(FIMAP_SZ_MAX / 2, UT_64K),
		UT_MKRANGE1(FIMAP_SZ_MAX - (2 * UT_64K), UT_64K),
		UT_MKRANGE1(FIMAP_SZ_MAX - UT_64K - 1, UT_64K),
	};

	ut_exec_with_ranges(ute, ut_file_edges_1_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Test I/O on file-mapping boundaries, where each operation falls on two
 * distinguished file mappings */
static void
ut_file_edges_fmapping_(struct ut_env *ute, const loff_t *off_arr, size_t cnt)
{
	const size_t bsz = 512;
	uint8_t *buf = ut_randbuf(ute, bsz);
	const char *name = UT_NAME;
	loff_t off = -1;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		buf[0] ^= (uint8_t)i;
		ut_write_read(ute, ino, buf, bsz, off - 1);
		buf[0] ^= (uint8_t)i;
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		buf[0] ^= (uint8_t)i;
		ut_read_verify(ute, ino, buf, bsz, off - 1);
		buf[0] ^= (uint8_t)i;
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		ut_fallocate_punch_hole(ute, ino, off, UT_1K / 2);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		buf[0] ^= (uint8_t)i;
		ut_read_verify(ute, ino, buf, 1, off - 1);
		buf[0] ^= (uint8_t)i;
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_edges_fmapping(struct ut_env *ute)
{
	long off_arr[] = { UT_1K,
			   2 * UT_1K,
			   UT_4K,
			   UT_8K,
			   2 * UT_8K,
			   4 * UT_8K,
			   UT_BK_SIZE,
			   2 * UT_BK_SIZE,
			   UT_BK_SIZE * UT_FILEMAP_NCHILDS,
			   UT_BK_SIZE * (UT_FILEMAP_NCHILDS + 1),
			   UT_BK_SIZE * 2 * UT_FILEMAP_NCHILDS,
			   UT_BK_SIZE * ((2 * UT_FILEMAP_NCHILDS) + 1),
			   UT_BK_SIZE * UT_FILEMAP_NCHILDS *
				   UT_FILEMAP_NCHILDS,
			   UT_FILESIZE_MAX / 2,
			   UT_FILESIZE_MAX - UT_BK_SIZE };
	const size_t off_arr_len = UT_ARRAY_SIZE(off_arr);

	for (size_t i = 0; i < 8; ++i) {
		ut_file_edges_fmapping_(ute, off_arr, off_arr_len);
		ut_reverse_inplace(off_arr, off_arr_len);
		ut_file_edges_fmapping_(ute, off_arr, off_arr_len);
		ut_prandom_shuffle(ute, off_arr, off_arr_len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST2(ut_file_edges_aligned),
	UT_DEFTEST2(ut_file_edges_unaligned),
	UT_DEFTEST2(ut_file_edges_special),
	UT_DEFTEST2(ut_file_edges_fmapping),
};

const struct ut_testdefs ut_tdefs_file_edges = UT_MKTESTS(ut_local_tests);
