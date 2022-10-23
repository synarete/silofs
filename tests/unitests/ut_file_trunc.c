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


static void ut_file_trunc_data_(struct ut_env *ute,
                                loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const loff_t bk_size = (loff_t)UT_BK_SIZE;
	const loff_t off_bk_start = (off / bk_size) * bk_size;
	char *buf = ut_randbuf(ute, bsz);
	struct stat st = { .st_ino = 0 };

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off);
	ut_trunacate_file(ute, ino, 0);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_blocks, 0);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_gt(st.st_blocks, 0);
	ut_trunacate_file(ute, ino, off + 1);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_gt(st.st_blocks, 0);
	ut_trunacate_file(ute, ino, off_bk_start);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_blocks, 0);
	ut_trunacate_file(ute, ino, off + 1);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_blocks, 0);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_simple(struct ut_env *ute)
{
	ut_file_trunc_data_(ute, 0, UT_BK_SIZE);
	ut_file_trunc_data_(ute, UT_BK_SIZE, UT_BK_SIZE);
	ut_file_trunc_data_(ute, UT_MEGA, UT_BK_SIZE);
	ut_file_trunc_data_(ute, UT_GIGA, UT_BK_SIZE);
	ut_file_trunc_data_(ute, UT_TERA, UT_BK_SIZE);
}

static void ut_file_trunc_aligned(struct ut_env *ute)
{
	ut_file_trunc_data_(ute, 0, UT_UMEGA);
	ut_file_trunc_data_(ute, UT_BK_SIZE, UT_UMEGA);
	ut_file_trunc_data_(ute, UT_MEGA, UT_UMEGA);
	ut_file_trunc_data_(ute, UT_GIGA, UT_UMEGA);
	ut_file_trunc_data_(ute, UT_TERA, UT_UMEGA);
}

static void ut_file_trunc_unaligned(struct ut_env *ute)
{
	ut_file_trunc_data_(ute, 1, UT_BK_SIZE + 2);
	ut_file_trunc_data_(ute, UT_BK_SIZE - 1, 2 * UT_BK_SIZE + 3);
	ut_file_trunc_data_(ute, 7 * UT_BK_SIZE - 7, 7 * UT_BK_SIZE + 7);
	ut_file_trunc_data_(ute, 11 * UT_MEGA - 11, 11 * UT_BK_SIZE + 11);
	ut_file_trunc_data_(ute, 13 * UT_GIGA - 13, 13 * UT_BK_SIZE + 13);
	ut_file_trunc_data_(ute, UT_TERA - 11111, UT_BK_SIZE + 111111);
	ut_file_trunc_data_(ute, UT_TERA - 1111111, UT_BK_SIZE + 1111111);
	ut_file_trunc_data_(ute, UT_FSIZE_MAX - UT_MEGA - 1, UT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_mixed_(struct ut_env *ute,
                                 loff_t off, size_t len)
{
	ino_t ino;
	const loff_t eoff = off + (loff_t)len;
	const loff_t zoff = off - (loff_t)len;
	const size_t bsz = 2 * len;
	const char *name = UT_NAME;
	uint8_t *buf = ut_randbuf(ute, bsz);
	const ino_t root_ino = UT_ROOT_INO;

	ut_expect(len >= UT_BK_SIZE);
	ut_expect(zoff >= 0);

	memset(buf, 0, bsz / 2);
	ut_create_file(ute, root_ino, name, &ino);
	ut_write_read(ute, ino, buf + len, len, off);
	ut_trunacate_file(ute, ino, eoff - 1);
	ut_read_verify(ute, ino, buf, bsz - 1, zoff);
	ut_trunacate_file(ute, ino, eoff - UT_BK_SIZE + 1);
	ut_read_verify(ute, ino, buf, bsz - UT_BK_SIZE + 1, zoff);
	ut_trunacate_file(ute, ino, off);
	ut_read_verify(ute, ino, buf, len, zoff);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_trunc_mixed(struct ut_env *ute)
{
	ut_file_trunc_mixed_(ute, UT_BK_SIZE, UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_MEGA, 4 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_GIGA, 8 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_TERA, UT_IOSIZE_MAX / 2);

	ut_file_trunc_mixed_(ute, UT_MEGA - 11111, 11 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_MEGA + 11111, 11 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_GIGA - 11111, 11 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_GIGA + 11111, 11 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_TERA - 11111, 11 * UT_BK_SIZE);
	ut_file_trunc_mixed_(ute, UT_TERA + 11111, 11 * UT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_hole_(struct ut_env *ute,
                                loff_t off1, loff_t off2, size_t len)
{
	ino_t ino;
	ino_t dino;
	loff_t hole_off1;
	loff_t hole_off2;
	size_t hole_len;
	size_t nzeros;
	void *buf1 = NULL;
	void *buf2 = NULL;
	void *zeros = NULL;
	const char *name = UT_NAME;
	const char *dname = UT_NAME;

	hole_off1 = off1 + (loff_t)len;
	hole_len = (size_t)(off2 - hole_off1);
	nzeros = (hole_len < UT_UMEGA) ? hole_len : UT_UMEGA;
	hole_off2 = off2 - (loff_t)nzeros;

	buf1 = ut_randbuf(ute, len);
	buf2 = ut_randbuf(ute, len);
	zeros = ut_zerobuf(ute, nzeros);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf1, len, off1);
	ut_write_read(ute, ino, buf2, len, off2);
	ut_trunacate_file(ute, ino, off2);
	ut_read_verify(ute, ino, zeros, nzeros, hole_off1);
	ut_read_verify(ute, ino, zeros, nzeros, hole_off2);
	ut_trunacate_file(ute, ino, off1 + 1);
	ut_write_read(ute, ino, buf1, 1, off1);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_file_trunc_hole(struct ut_env *ute)
{
	ut_file_trunc_hole_(ute, 0, UT_MEGA, UT_BK_SIZE);
	ut_file_trunc_hole_(ute, 1, UT_MEGA - 1, UT_BK_SIZE);
	ut_file_trunc_hole_(ute, 2, 2 * UT_MEGA - 2, UT_UMEGA);
	ut_file_trunc_hole_(ute, 3, 3 * UT_MEGA + 3, UT_UMEGA);
	ut_file_trunc_hole_(ute, UT_MEGA + 1,
	                    UT_MEGA + UT_BK_SIZE + 2, UT_BK_SIZE);
	ut_file_trunc_hole_(ute, 0, UT_GIGA, UT_UMEGA);
	ut_file_trunc_hole_(ute, 1, UT_GIGA - 1, UT_UMEGA);
	ut_file_trunc_hole_(ute, 2, 2 * UT_GIGA - 2, UT_IOSIZE_MAX);
	ut_file_trunc_hole_(ute, UT_GIGA + 1,
	                    UT_GIGA + UT_MEGA + 2, UT_UMEGA);
	ut_file_trunc_hole_(ute, 0, UT_TERA, UT_UMEGA);
	ut_file_trunc_hole_(ute, 1, UT_TERA - 1, UT_UMEGA);
	ut_file_trunc_hole_(ute, 2, 2 * UT_TERA - 2, UT_UMEGA);
	ut_file_trunc_hole_(ute, UT_TERA + 1,
	                    UT_TERA + UT_MEGA + 2, UT_UMEGA);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_read_zero_byte(struct ut_env *ute, ino_t ino, loff_t off)
{
	const uint8_t zero[1] = { 0 };

	if (off >= 0) {
		ut_read_verify(ute, ino, zero, 1, off);
	}
}

static void ut_file_trunc_single_byte_(struct ut_env *ute,
                                       const loff_t *off_arr, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	loff_t off = -1;
	const char *name = UT_NAME;
	const char *dname = UT_NAME;
	const uint8_t one[1] = { 1 };

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		ut_write_read(ute, ino, one, 1, off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		ut_read_verify(ute, ino, one, 1, off);
		ut_read_zero_byte(ute, ino, off - 1);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = off_arr[i];
		ut_trunacate_file(ute, ino, off);
		ut_read_zero_byte(ute, ino, off - 1);
	}
	ut_trunacate_zero(ute, ino);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_file_trunc_single_byte(struct ut_env *ute)
{
	const loff_t off1[] = {
		0, UT_BK_SIZE, UT_MEGA, UT_GIGA, UT_TERA
	};
	const loff_t off2[] = {
		1, UT_BK_SIZE + 1, UT_MEGA + 1, UT_GIGA + 1, UT_TERA + 1
	};
	const loff_t off3[] = {
		77, 777, 7777, 77777, 777777, 7777777
	};

	ut_file_trunc_single_byte_(ute, off1, UT_ARRAY_SIZE(off1));
	ut_file_trunc_single_byte_(ute, off2, UT_ARRAY_SIZE(off2));
	ut_file_trunc_single_byte_(ute, off3, UT_ARRAY_SIZE(off3));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_tail_(struct ut_env *ute,
                                loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const ssize_t ssz = (loff_t)bsz;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_file(ute, dino, fname, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_read_zero_byte(ute, ino, off - 1);
	ut_trunacate_file(ute, ino, off + 1);
	ut_read_ok(ute, ino, buf, 1, off);
	ut_read_zero_byte(ute, ino, off - 1);
	ut_trunacate_file(ute, ino, off + ssz);
	ut_read_zero_byte(ute, ino, off + ssz - 1);
	ut_trunacate_file(ute, ino, off + ssz + 1);
	ut_read_zero_byte(ute, ino, off + ssz);
	ut_remove_file(ute, dino, fname, ino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_file_trunc_tail(struct ut_env *ute)
{
	ut_file_trunc_tail_(ute, 0, UT_UMEGA);
	ut_file_trunc_tail_(ute, 1, UT_UMEGA + 4);
	ut_file_trunc_tail_(ute, UT_MEGA, UT_UMEGA);
	ut_file_trunc_tail_(ute, UT_MEGA - 1, UT_UMEGA + 8);
	ut_file_trunc_tail_(ute, UT_GIGA - 1, UT_UMEGA + 16);
	ut_file_trunc_tail_(ute, UT_FSIZE_MAX - UT_MEGA - 1, UT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_void_(struct ut_env *ute,
                                loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	uint8_t dat = 67;
	const ino_t root_ino = UT_ROOT_INO;
	const ssize_t ssz = (loff_t)bsz;
	const loff_t end = off + ssz;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	struct stat st;

	ut_mkdir_oki(ute, root_ino, dname, &dino);
	ut_create_file(ute, dino, fname, &ino);
	ut_trunacate_file(ute, ino, end);
	ut_read_zeros(ute, ino, off, bsz);
	ut_getattr_ok(ute, ino, &st);
	ut_expect_eq(st.st_blocks, 0);
	ut_trunacate_file(ute, ino, 0);
	ut_trunacate_file(ute, ino, end);
	ut_write_read(ute, ino, &dat, 1, end);
	ut_read_zeros(ute, ino, off, bsz);
	ut_remove_file(ute, dino, fname, ino);
	ut_rmdir_ok(ute, root_ino, dname);
}

static void ut_file_trunc_void(struct ut_env *ute)
{
	ut_file_trunc_void_(ute, 0, UT_KILO);
	ut_file_trunc_void_(ute, 1, UT_KILO);
	ut_file_trunc_void_(ute, 0, UT_UMEGA);
	ut_file_trunc_void_(ute, 1, UT_UMEGA - 11);
	ut_file_trunc_void_(ute, UT_MEGA, UT_KILO);
	ut_file_trunc_void_(ute, UT_MEGA - 11, UT_KILO + 1);
	ut_file_trunc_void_(ute, UT_GIGA - 11, UT_UMEGA + 111);
	ut_file_trunc_void_(ute, UT_FSIZE_MAX - UT_MEGA - 1, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_zero_size_(struct ut_env *ute,
                                     loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	struct stat st[3];
	struct statvfs stv[3];
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_statfs_ok(ute, ino, &stv[0]);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_getattr_ok(ute, ino, &st[1]);
	ut_statfs_ok(ute, ino, &stv[1]);
	ut_expect_eq(st[1].st_size, off + (loff_t)bsz);
	ut_expect_gt(st[1].st_blocks, st[0].st_blocks);
	ut_expect_lt(stv[1].f_bfree, stv[0].f_bfree);
	ut_trunacate_file(ute, ino, 0);
	ut_getattr_ok(ute, ino, &st[2]);
	ut_statfs_ok(ute, ino, &stv[2]);
	ut_expect_eq(st[2].st_size, 0);
	ut_expect_eq(st[2].st_blocks, 0);
	ut_expect_eq(stv[2].f_bfree, stv[0].f_bfree);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_zero_size(struct ut_env *ute)
{
	ut_file_trunc_zero_size_(ute, 1, UT_BK_SIZE);
	ut_file_trunc_zero_size_(ute, UT_KILO, UT_BK_SIZE);
	ut_file_trunc_zero_size_(ute, UT_MEGA, UT_BK_SIZE);
	ut_file_trunc_zero_size_(ute, UT_MEGA - 1, UT_BK_SIZE);
	ut_file_trunc_zero_size_(ute, 11 * UT_MEGA + 11, UT_BK_SIZE);
	ut_file_trunc_zero_size_(ute, 111 * UT_GIGA - 111, UT_BK_SIZE);
	ut_file_trunc_zero_size_(ute, UT_TERA, UT_UMEGA);
	ut_file_trunc_zero_size_(ute, UT_TERA + 1111111, UT_UMEGA - 1);
	ut_file_trunc_zero_size_(ute, UT_FSIZE_MAX - UT_MEGA, UT_UMEGA);
	ut_file_trunc_zero_size_(ute, UT_FSIZE_MAX - UT_MEGA - 1,
	                         UT_UMEGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_null_data_(struct ut_env *ute, loff_t off)
{
	ino_t ino;
	ino_t dino;
	uint8_t dat[1] = { 0xC7 };
	uint8_t nil[1] = { 0x00 };
	uint8_t rnd[256];
	const size_t rsz = sizeof(rnd);
	const char *name = UT_NAME;

	ut_expect_ge(off, sizeof(rnd));
	ut_randfill(ute, rnd, rsz);
	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, rnd, rsz, off - (int)rsz);
	ut_trunacate_file(ute, ino, off - (int)rsz);
	ut_trunacate_file(ute, ino, off);
	ut_read_verify(ute, ino, nil, 1, off - 1);
	ut_read_verify(ute, ino, nil, 1, off - 2);
	ut_read_verify(ute, ino, nil, 1, off - 3);
	ut_write_read(ute, ino, dat, 1, off - 2);
	ut_read_verify(ute, ino, nil, 1, off - 1);
	ut_read_verify(ute, ino, dat, 1, off - 2);
	ut_read_verify(ute, ino, nil, 1, off - 3);
	ut_trunacate_file(ute, ino, off - 3);
	ut_trunacate_file(ute, ino, off);
	ut_read_verify(ute, ino, nil, 1, off - 1);
	ut_read_verify(ute, ino, nil, 1, off - 2);
	ut_read_verify(ute, ino, nil, 1, off - 3);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_null_data(struct ut_env *ute)
{
	ut_file_trunc_null_data_(ute, UT_KILO);
	ut_file_trunc_null_data_(ute, UT_BK_SIZE);
	ut_file_trunc_null_data_(ute, UT_MEGA + UT_KILO);
	ut_file_trunc_null_data_(ute, UT_GIGA + UT_MEGA);
	ut_file_trunc_null_data_(ute, UT_TERA + UT_GIGA);

	ut_file_trunc_null_data_(ute, UT_KILO + 1);
	ut_file_trunc_null_data_(ute, UT_BK_SIZE - 1);
	ut_file_trunc_null_data_(ute, UT_BK_SIZE + 1);
	ut_file_trunc_null_data_(ute, UT_MEGA + UT_KILO + 1);
	ut_file_trunc_null_data_(ute, UT_GIGA + UT_MEGA + 1);
	ut_file_trunc_null_data_(ute, UT_TERA + UT_GIGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_trunc_simple),
	UT_DEFTEST(ut_file_trunc_aligned),
	UT_DEFTEST(ut_file_trunc_unaligned),
	UT_DEFTEST(ut_file_trunc_mixed),
	UT_DEFTEST(ut_file_trunc_hole),
	UT_DEFTEST(ut_file_trunc_single_byte),
	UT_DEFTEST(ut_file_trunc_tail),
	UT_DEFTEST(ut_file_trunc_void),
	UT_DEFTEST(ut_file_trunc_zero_size),
	UT_DEFTEST(ut_file_trunc_null_data),
};

const struct ut_testdefs ut_tdefs_file_truncate = UT_MKTESTS(ut_local_tests);


