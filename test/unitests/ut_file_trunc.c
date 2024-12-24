/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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

static void ut_file_trunc_data_(struct ut_env *ute, loff_t off, size_t len)
{
	struct stat st = { .st_ino = 0 };
	const char *name = UT_NAME;
	const loff_t bk_size = (loff_t)UT_BK_SIZE;
	const loff_t off_bk_start = (off / bk_size) * bk_size;
	char *buf = ut_randbuf(ute, len);
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off);
	ut_trunacate_file(ute, ino, 0);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_blocks, 0);
	ut_write_read(ute, ino, buf, len, off);
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
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_64K),      //
		UT_MKRANGE1(UT_64K, UT_64K), //
		UT_MKRANGE1(UT_1M, UT_64K),  //
		UT_MKRANGE1(UT_1G, UT_64K),  //
		UT_MKRANGE1(UT_1T, UT_64K),  //
	};

	ut_exec_with_ranges(ute, ut_file_trunc_data_, ranges);
}

static void ut_file_trunc_aligned(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_1M),
		UT_MKRANGE1(UT_64K, UT_1M),
		UT_MKRANGE1(UT_1M, UT_1M),
		UT_MKRANGE1(UT_1G, UT_1M),
		UT_MKRANGE1(UT_1T, UT_1M),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_1M, UT_1M),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_data_, ranges);
}

static void ut_file_trunc_unaligned(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(1, UT_64K + 2),
		UT_MKRANGE1(UT_64K - 1, 2 * UT_64K + 3),
		UT_MKRANGE1(7 * UT_64K - 7, 7 * UT_64K + 7),
		UT_MKRANGE1(11 * UT_1M - 11, 11 * UT_64K + 11),
		UT_MKRANGE1(13 * UT_1G - 13, 13 * UT_64K + 13),
		UT_MKRANGE1(UT_1T - 11111, UT_64K + 111111),
		UT_MKRANGE1(UT_1T - 1111111, UT_64K + 1111111),
		UT_MKRANGE1(UT_FILESIZE_MAX / 11, UT_1M / 11),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_1M - 1, UT_1M),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_data_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_mixed_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	const loff_t eoff = off + (loff_t)len;
	const loff_t zoff = off - (loff_t)len;
	const size_t bsz = 2 * len;
	uint8_t *buf = ut_randbuf(ute, bsz);
	ino_t dino = 0;
	ino_t ino = 0;

	ut_expect(len >= UT_BK_SIZE);
	ut_expect(zoff >= 0);

	memset(buf, 0, bsz / 2);
	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf + len, len, off);
	ut_trunacate_file(ute, ino, eoff - 1);
	ut_read_verify(ute, ino, buf, bsz - 1, zoff);
	ut_trunacate_file(ute, ino, eoff - UT_BK_SIZE + 1);
	ut_read_verify(ute, ino, buf, bsz - UT_BK_SIZE + 1, zoff);
	ut_trunacate_file(ute, ino, off);
	ut_read_verify(ute, ino, buf, len, zoff);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_mixed(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(UT_BK_SIZE, UT_BK_SIZE),
		UT_MKRANGE1(UT_1M, 4 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1G, 8 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1T, UT_IOSIZE_MAX / 2),
		UT_MKRANGE1(UT_1M - 11111, 11 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1M + 11111, 11 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1G - 11111, 11 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1G + 11111, 11 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1T - 11111, 11 * UT_BK_SIZE),
		UT_MKRANGE1(UT_1T + 11111, 11 * UT_BK_SIZE),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_mixed_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_trunc_hole_(struct ut_env *ute, loff_t off1, loff_t off2, size_t len)
{
	const char *name = UT_NAME;
	void *buf1 = NULL;
	void *buf2 = NULL;
	void *zeros = NULL;
	loff_t hole_off1 = -1;
	loff_t hole_off2 = -1;
	size_t hole_len = 0;
	size_t nzeros = 0;
	ino_t dino = 0;
	ino_t ino = 0;

	hole_off1 = off1 + (loff_t)len;
	hole_len = (size_t)(off2 - hole_off1);
	nzeros = (hole_len < UT_1M) ? hole_len : UT_1M;
	hole_off2 = off2 - (loff_t)nzeros;
	buf1 = ut_randbuf(ute, len);
	buf2 = ut_randbuf(ute, len);
	zeros = ut_zerobuf(ute, nzeros);
	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf1, len, off1);
	ut_write_read(ute, ino, buf2, len, off2);
	ut_trunacate_file(ute, ino, off2);
	ut_read_verify(ute, ino, zeros, nzeros, hole_off1);
	ut_read_verify(ute, ino, zeros, nzeros, hole_off2);
	ut_trunacate_file(ute, ino, off1 + 1);
	ut_write_read(ute, ino, buf1, 1, off1);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_hole(struct ut_env *ute)
{
	const struct ut_range2 range[] = {
		UT_MKRANGE2(0, UT_1M, UT_BK_SIZE),
		UT_MKRANGE2(1, UT_1M - 1, UT_BK_SIZE),
		UT_MKRANGE2(2, 2 * UT_1M - 2, UT_1M),
		UT_MKRANGE2(3, 3 * UT_1M + 3, UT_1M),
		UT_MKRANGE2(UT_1M + 1, UT_1M + UT_BK_SIZE + 2, UT_BK_SIZE),
		UT_MKRANGE2(0, UT_1G, UT_1M),
		UT_MKRANGE2(1, UT_1G - 1, UT_1M),
		UT_MKRANGE2(2, 2 * UT_1G - 2, UT_IOSIZE_MAX),
		UT_MKRANGE2(UT_1G + 1, UT_1G + UT_1M + 2, UT_1M),
		UT_MKRANGE2(0, UT_1T, UT_1M),
		UT_MKRANGE2(1, UT_1T - 1, UT_1M),
		UT_MKRANGE2(2, 2 * UT_1T - 2, UT_1M),
		UT_MKRANGE2(UT_1T + 1, UT_1T + UT_1M + 2, UT_1M),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_trunc_hole_(ute, range[i].off1, range[i].off2,
		                    range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_read_zero_byte(struct ut_env *ute, ino_t ino, loff_t off)
{
	const uint8_t zero[1] = { 0 };

	if (off >= 0) {
		ut_read_verify(ute, ino, zero, 1, off);
	}
}

static void ut_file_trunc_single_byte_(struct ut_env *ute,
                                       const loff_t *off_arr, size_t cnt)
{
	const char *name = UT_NAME;
	const uint8_t one[1] = { 1 };
	loff_t off = -1;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
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
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_single_byte(struct ut_env *ute)
{
	const loff_t off1[] = {
		0, UT_BK_SIZE, UT_1M, UT_1G, UT_1T,
	};
	const loff_t off2[] = {
		1, UT_BK_SIZE + 1, UT_1M + 1, UT_1G + 1, UT_1T + 1,
	};
	const loff_t off3[] = {
		77, 777, 7777, 77777, 777777, 7777777,
	};

	ut_file_trunc_single_byte_(ute, off1, UT_ARRAY_SIZE(off1));
	ut_relax_mem(ute);
	ut_file_trunc_single_byte_(ute, off2, UT_ARRAY_SIZE(off2));
	ut_relax_mem(ute);
	ut_file_trunc_single_byte_(ute, off3, UT_ARRAY_SIZE(off3));
	ut_relax_mem(ute);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_tail_(struct ut_env *ute, loff_t off, size_t ulen)
{
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, ulen);
	const ssize_t len = (loff_t)ulen;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_read_zero_byte(ute, ino, off - 1);
	ut_trunacate_file(ute, ino, off + 1);
	ut_read(ute, ino, buf, 1, off);
	ut_read_zero_byte(ute, ino, off - 1);
	ut_trunacate_file(ute, ino, off + len);
	ut_read_zero_byte(ute, ino, off + len - 1);
	ut_trunacate_file(ute, ino, off + len + 1);
	ut_read_zero_byte(ute, ino, off + len);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_tail(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_1M),
		UT_MKRANGE1(1, UT_1M + 4),
		UT_MKRANGE1(UT_1M, UT_1M),
		UT_MKRANGE1(UT_1M - 1, UT_1M + 8),
		UT_MKRANGE1(UT_1G - 1, UT_1M + 16),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_1M - 1, UT_1M),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_tail_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_trunc_void_(struct ut_env *ute, loff_t off, size_t ulen)
{
	struct stat st = { .st_size = -1 };
	const char *name = UT_NAME;
	const ssize_t len = (loff_t)ulen;
	const loff_t end = off + len;
	uint8_t dat = 67;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, end);
	ut_read_zeros(ute, ino, off, ulen);
	ut_getattr(ute, ino, &st);
	ut_expect_eq(st.st_blocks, 0);
	ut_trunacate_file(ute, ino, 0);
	ut_trunacate_file(ute, ino, end);
	ut_write_read(ute, ino, &dat, 1, end);
	ut_read_zeros(ute, ino, off, ulen);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_void(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(0, UT_1K),
		UT_MKRANGE1(1, UT_1K),
		UT_MKRANGE1(0, UT_1M),
		UT_MKRANGE1(1, UT_1M - 11),
		UT_MKRANGE1(UT_1M, UT_1K),
		UT_MKRANGE1(UT_1M - 11, UT_1K + 1),
		UT_MKRANGE1(UT_1G - 11, UT_1M + 111),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_1M - 1, UT_1M),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_void_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_trunc_zero_size_(struct ut_env *ute, loff_t off, size_t len)
{
	struct stat st[3];
	struct statvfs stv[3];
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, len);
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_getattr(ute, ino, &st[0]);
	ut_statfs(ute, ino, &stv[0]);
	ut_write_read(ute, ino, buf, len, off);
	ut_getattr(ute, ino, &st[1]);
	ut_statfs(ute, ino, &stv[1]);
	ut_expect_eq(st[1].st_size, off + (loff_t)len);
	ut_expect_gt(st[1].st_blocks, st[0].st_blocks);
	ut_expect_lt(stv[1].f_bfree, stv[0].f_bfree);
	ut_trunacate_file(ute, ino, 0);
	ut_getattr(ute, ino, &st[2]);
	ut_statfs(ute, ino, &stv[2]);
	ut_expect_eq(st[2].st_size, 0);
	ut_expect_eq(st[2].st_blocks, 0);
	ut_expect_eq(stv[2].f_bfree, stv[0].f_bfree);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_trunc_zero_size(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE1(1, UT_BK_SIZE),
		UT_MKRANGE1(UT_1K, UT_BK_SIZE),
		UT_MKRANGE1(UT_1M, UT_BK_SIZE),
		UT_MKRANGE1(UT_1M - 1, UT_BK_SIZE),
		UT_MKRANGE1(11 * UT_1M + 11, UT_BK_SIZE),
		UT_MKRANGE1(111 * UT_1G - 111, UT_BK_SIZE),
		UT_MKRANGE1(UT_1T, UT_1M),
		UT_MKRANGE1(UT_1T + 1111111, UT_1M - 1),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_1M, UT_1M),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_1M - 1, UT_1M + 1),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_zero_size_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_trunc_null_data_(struct ut_env *ute, loff_t off, size_t unused_len)
{
	uint8_t rnd[256];
	uint8_t dat[1] = { 0xC7 };
	uint8_t nil[1] = { 0x00 };
	const size_t rsz = sizeof(rnd);
	const char *name = UT_NAME;
	ino_t dino = 0;
	ino_t ino = 0;

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
	ut_unused(unused_len);
}

static void ut_file_trunc_null_data(struct ut_env *ute)
{
	const struct ut_range ranges[] = {
		UT_MKRANGE0(UT_1K),
		UT_MKRANGE0(UT_BK_SIZE),
		UT_MKRANGE0(UT_1M + UT_1K),
		UT_MKRANGE0(UT_1G + UT_1M),
		UT_MKRANGE0(UT_1T + UT_1G),
		UT_MKRANGE0(UT_1K + 1),
		UT_MKRANGE0(UT_BK_SIZE - 1),
		UT_MKRANGE0(UT_BK_SIZE + 1),
		UT_MKRANGE0(UT_1M + UT_1K + 1),
		UT_MKRANGE0(UT_1G + UT_1M + 1),
		UT_MKRANGE0(UT_1T + UT_1G + 1),
	};

	ut_exec_with_ranges(ute, ut_file_trunc_null_data_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST2(ut_file_trunc_simple),
	UT_DEFTEST2(ut_file_trunc_aligned),
	UT_DEFTEST2(ut_file_trunc_unaligned),
	UT_DEFTEST2(ut_file_trunc_mixed),
	UT_DEFTEST2(ut_file_trunc_hole),
	UT_DEFTEST2(ut_file_trunc_single_byte),
	UT_DEFTEST2(ut_file_trunc_tail),
	UT_DEFTEST2(ut_file_trunc_void),
	UT_DEFTEST2(ut_file_trunc_zero_size),
	UT_DEFTEST2(ut_file_trunc_null_data),
};

const struct ut_testdefs ut_tdefs_file_truncate = UT_MKTESTS(ut_local_tests);
