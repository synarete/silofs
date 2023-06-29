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
#include "fftests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) a regular file named by path to have a size which
 * shall be equal to length bytes.
 */
static void test_truncate_basic_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	size_t nwr;
	loff_t off;
	struct stat st;
	const char *path = ft_new_path_unique(fte);

	ft_creat(path, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		ft_write(fd, path, strlen(path), &nwr);
	}
	for (size_t i = cnt; i > 0; i--) {
		off = (loff_t)(19 * i);
		ft_ftruncate(fd, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off);
	}
	for (size_t i = 0; i < cnt; i++) {
		off = (loff_t)(1811 * i);
		ft_ftruncate(fd, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_truncate_basic(struct ft_env *fte)
{
	test_truncate_basic_(fte, 11);
	test_truncate_basic_(fte, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) to create zeros at the truncated tail-range.
 */
static void test_truncate_tail_(struct ft_env *fte, loff_t base_off,
                                size_t data_sz, size_t tail_sz)
{
	int fd = -1;
	loff_t off[2] = { 0, 0 };
	struct stat st;
	void *buf1 = ft_new_buf_rands(fte, data_sz);
	void *buf2 = ft_new_buf_zeros(fte, data_sz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, data_sz, base_off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, base_off + (loff_t)data_sz);
	off[0] = base_off + (loff_t)(data_sz - tail_sz);
	ft_ftruncate(fd, off[0]);
	off[1] = off[0] + (loff_t)data_sz;
	ft_ftruncate(fd, off[1]);
	ft_preadn(fd, buf1, data_sz, off[0]);
	ft_expect_eqm(buf1, buf2, data_sz);

	ft_close(fd);
	ft_unlink(path);
}

static void test_truncate_tail(struct ft_env *fte)
{
	test_truncate_tail_(fte, 0, FT_UMEGA, FT_BK_SIZE);
	test_truncate_tail_(fte, 0, FT_UMEGA, 1);
	test_truncate_tail_(fte, 0, FT_UMEGA, 11);
	test_truncate_tail_(fte, 1, FT_UMEGA + 111, (7 * FT_BK_SIZE) - 7);
	test_truncate_tail_(fte, FT_MEGA - 1, FT_UMEGA + 2, FT_UMEGA / 2);
	test_truncate_tail_(fte, FT_GIGA - 11,
	                    FT_UMEGA + 111, FT_UMEGA / 3);
	test_truncate_tail_(fte, FT_FILESIZE_MAX / 3,
	                    FT_UMEGA + 3, FT_UMEGA / 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) to create zeros at extended area without written data
 */
static void test_truncate_extend_(struct ft_env *fte,
                                  loff_t base_off, size_t data_sz)
{
	int fd = -1;
	loff_t off;
	loff_t off2;
	struct stat st;
	void *buf1 = ft_new_buf_rands(fte, data_sz);
	void *buf2 = ft_new_buf_zeros(fte, data_sz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, data_sz, base_off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, base_off + (loff_t)data_sz);
	off = base_off + (loff_t)(2 * data_sz);
	ft_ftruncate(fd, off);
	off2 = base_off + (loff_t)(data_sz);
	ft_preadn(fd, buf1, data_sz, off2);
	ft_expect_eqm(buf1, buf2, data_sz);
	ft_close(fd);
	ft_unlink(path);
}

static void test_truncate_extend(struct ft_env *fte)
{
	test_truncate_extend_(fte, 0, FT_BK_SIZE);
	test_truncate_extend_(fte, 1, FT_BK_SIZE);
	test_truncate_extend_(fte, FT_BK_SIZE - 11, 11 * FT_BK_SIZE);
	test_truncate_extend_(fte, 0, FT_UMEGA);
	test_truncate_extend_(fte, 1, FT_UMEGA);
	test_truncate_extend_(fte, FT_UMEGA - 1, FT_UMEGA + 2);
	test_truncate_extend_(fte, FT_UGIGA - 11, FT_UMEGA + 111);
	test_truncate_extend_(fte, (11 * FT_UGIGA) - 111, FT_UMEGA + 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful truncate(3p) to yield zero bytes
 */
static void test_truncate_zeros_(struct ft_env *fte, loff_t off, size_t len)
{
	int fd = -1;
	uint8_t byte = 1;
	loff_t end = off + (loff_t)len;
	struct stat st;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0700, &fd);
	ft_ftruncate(fd, end);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, end);
	ft_preadn(fd, &byte, 1, off);
	ft_expect_eq(byte, 0);
	ft_preadn(fd, &byte, 1, end - 1);
	ft_expect_eq(byte, 0);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, end);
	ft_expect_eq(st.st_blocks, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_truncate_zeros(struct ft_env *fte)
{
	test_truncate_zeros_(fte, 0, 2);
	test_truncate_zeros_(fte, 0, FT_BK_SIZE);
	test_truncate_zeros_(fte, 1, FT_BK_SIZE);
	test_truncate_zeros_(fte, 11, FT_BK_SIZE / 11);
	test_truncate_zeros_(fte, FT_UMEGA, FT_UMEGA);
	test_truncate_zeros_(fte, FT_UMEGA - 1, FT_UMEGA + 3);
	test_truncate_zeros_(fte, FT_UGIGA - 11, FT_UMEGA + 111);
	test_truncate_zeros_(fte, FT_UTERA - 111, FT_UGIGA + 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_truncate_basic),
	FT_DEFTEST(test_truncate_tail),
	FT_DEFTEST(test_truncate_extend),
	FT_DEFTEST(test_truncate_zeros),
};

const struct ft_tests ft_test_truncate_io =
        FT_DEFTESTS(ft_local_tests);
