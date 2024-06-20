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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) a regular file named by path to have a size which
 * shall be equal to length bytes.
 */
static void test_truncate_basic_(struct ft_env *fte, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	size_t nwr = 0;
	loff_t off = -1;
	int fd = -1;

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
	const size_t cnt[] = { 100, 1000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_truncate_basic_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) to create zeros at the truncated tail-range.
 */
static void test_truncate_tail_(struct ft_env *fte, loff_t base_off,
                                size_t data_sz, size_t tail_sz)
{
	struct stat st = { .st_size = -1 };
	void *buf1 = ft_new_buf_rands(fte, data_sz);
	void *buf2 = ft_new_buf_zeros(fte, data_sz);
	const char *path = ft_new_path_unique(fte);
	loff_t off[2] = { 0, 0 };
	int fd = -1;

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
	test_truncate_tail_(fte, 0, FT_1M, FT_BK_SIZE);
	test_truncate_tail_(fte, 0, FT_1M, 1);
	test_truncate_tail_(fte, 0, FT_1M, 11);
	test_truncate_tail_(fte, 1, FT_1M + 111, (7 * FT_BK_SIZE) - 7);
	test_truncate_tail_(fte, FT_1M - 1, FT_1M + 2, FT_1M / 2);
	test_truncate_tail_(fte, FT_1G - 11,
	                    FT_1M + 111, FT_1M / 3);
	test_truncate_tail_(fte, FT_FILESIZE_MAX / 3,
	                    FT_1M + 3, FT_1M / 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects truncate(3p) to create zeros at extended area without written data
 */
static void test_truncate_extend_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_zeros(fte, len);
	const char *path = ft_new_path_unique(fte);
	loff_t pos1 = -1;
	loff_t pos2 = -1;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)len);
	pos1 = off + (loff_t)(2 * len);
	ft_ftruncate(fd, pos1);
	pos2 = off + (loff_t)(len);
	ft_preadn(fd, buf1, len, pos2);
	ft_expect_eqm(buf1, buf2, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_truncate_extend(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(1, FT_64K),
		FT_MKRANGE(FT_64K - 11, 11 * FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(1, FT_1M),
		FT_MKRANGE(FT_1M - 1, FT_1M + 2),
		FT_MKRANGE(FT_1G - 11, FT_1M + 111),
		FT_MKRANGE((11 * FT_1G) - 111, FT_1M + 1111),
	};

	ft_exec_with_ranges(fte, test_truncate_extend_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful truncate(3p) to yield zero bytes
 */
static void test_truncate_zeros_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const loff_t end = off + (ssize_t)len;
	int fd = -1;
	uint8_t byte = 1;

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
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, 2),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(1, FT_64K),
		FT_MKRANGE(11, FT_64K / 11),
		FT_MKRANGE(FT_1M, FT_1M),
		FT_MKRANGE(FT_1M - 1, FT_1M + 3),
		FT_MKRANGE(FT_1G - 11, FT_1M + 111),
		FT_MKRANGE(FT_1T - 111, FT_1G + 1111),
	};

	ft_exec_with_ranges(fte, test_truncate_zeros_, ranges);
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
