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

static void ut_rw_plus_minus_1_(struct ut_env *ute,
                                ino_t ino, loff_t off, size_t len)
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
	ut_read_ok(ute, ino, &byte, 1, dv1->off);
	dv3 = ut_new_dvec(ute, off - 1, len);
	ut_write_dvec(ute, ino, dv3);
	byte = dvec_last_byte(dv2);
	ut_read_ok(ute, ino, &byte, 1, dvec_last_off(dv2));
	ut_fallocate_punch_hole(ute, ino, off, (loff_t)len);
	ut_read_zeros(ute, ino, off, len);
	byte = dvec_first_byte(dv3);
	ut_read_ok(ute, ino, &byte, 1, dv3->off);
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
	ut_file_edges_1_(ute, UT_4K, UT_4K);
	ut_file_edges_1_(ute, 2 * UT_4K, UT_4K);
	ut_file_edges_1_(ute, UT_8K, UT_8K);
	ut_file_edges_1_(ute, UT_8K, UT_BK_SIZE);
	ut_file_edges_1_(ute, UT_BK_SIZE, UT_BK_SIZE);
	ut_file_edges_1_(ute, UT_MEGA, 4 * UT_BK_SIZE);
	ut_file_edges_1_(ute, UT_GIGA, 8 * UT_BK_SIZE);
	ut_file_edges_1_(ute, UT_TERA, 16 * UT_BK_SIZE);
}

static void ut_file_edges_unaligned(struct ut_env *ute)
{
	ut_file_edges_1_(ute, UT_8K - 1, UT_BK_SIZE + 11);
	ut_file_edges_1_(ute, UT_BK_SIZE + 11, UT_BK_SIZE - 1);
	ut_file_edges_1_(ute, UT_MEGA - 1111, 4 * UT_BK_SIZE + 1);
	ut_file_edges_1_(ute, UT_GIGA - 11111, 8 * UT_BK_SIZE + 11);
	ut_file_edges_1_(ute, UT_TERA - 111111, 16 * UT_BK_SIZE + 111);
}

static void ut_file_edges_special(struct ut_env *ute)
{
	const size_t bksz = UT_BK_SIZE;
	const loff_t bkssz = (loff_t)bksz;
	const loff_t filemap_sz = (UT_FILEMAP_NCHILDS * UT_BK_SIZE);
	const loff_t filemap_sz2 = filemap_sz * UT_FILEMAP_NCHILDS;
	const loff_t filesize_max = UT_FILESIZE_MAX;

	ut_file_edges_1_(ute, filemap_sz, bksz);
	ut_file_edges_1_(ute, filemap_sz, 2 * bksz);
	ut_file_edges_1_(ute, filemap_sz - 11, bksz + 111);
	ut_file_edges_1_(ute, filemap_sz - 111, 2 * bksz + 1111);
	ut_file_edges_1_(ute, 2 * filemap_sz, 2 * bksz);
	ut_file_edges_1_(ute, 2 * filemap_sz - 1, bksz + 2);
	ut_file_edges_1_(ute, filemap_sz + filemap_sz2, 2 * bksz);
	ut_file_edges_1_(ute, filemap_sz + filemap_sz2 - 2, bksz + 3);
	ut_file_edges_1_(ute, filemap_sz2 - 2, bksz + 3);
	ut_file_edges_1_(ute, filesize_max / 2, bksz);
	ut_file_edges_1_(ute, filesize_max - (2 * bkssz), bksz);
	ut_file_edges_1_(ute, filesize_max - bkssz - 1, bksz);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Test I/O on file-mapping boundaries, where each operation falls on two
 * distinguished file mappings */
static void ut_file_edges_fmapping_(struct ut_env *ute,
                                    const loff_t *off_arr, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	loff_t off = -1;
	const char *name = UT_NAME;
	const size_t bsz = 512;
	uint8_t *buf = ut_randbuf(ute, bsz);

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
	long off_arr[] = {
		UT_1K,
		2 * UT_1K,
		UT_4K,
		UT_8K,
		2 * UT_8K,
		4 * UT_8K,
		UT_BK_SIZE,
		2 * UT_BK_SIZE,
		UT_BK_SIZE * UT_FILEMAP_NCHILDS,
		UT_BK_SIZE *(UT_FILEMAP_NCHILDS + 1),
		UT_BK_SIZE * 2 * UT_FILEMAP_NCHILDS,
		UT_BK_SIZE *((2 * UT_FILEMAP_NCHILDS) + 1),
		UT_BK_SIZE *UT_FILEMAP_NCHILDS * UT_FILEMAP_NCHILDS,
		UT_FILESIZE_MAX / 2,
		UT_FILESIZE_MAX - UT_BK_SIZE
	};
	const size_t off_arr_len = UT_ARRAY_SIZE(off_arr);

	for (size_t i = 0; i < 8; ++i) {
		ut_file_edges_fmapping_(ute, off_arr, off_arr_len);
		ut_reverse_inplace(off_arr, off_arr_len);
		ut_file_edges_fmapping_(ute, off_arr, off_arr_len);
		ut_prandom_shuffle(ute, off_arr, off_arr_len);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_edges_aligned),
	UT_DEFTEST(ut_file_edges_unaligned),
	UT_DEFTEST(ut_file_edges_special),
	UT_DEFTEST(ut_file_edges_fmapping),
};

const struct ut_testdefs ut_tdefs_file_edges = UT_MKTESTS(ut_local_tests);
