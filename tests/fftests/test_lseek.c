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
#include "fftests.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid lseek(3p) with whence as SEEK_SET, SEEK_CUR and SEEK_END
 */
static void test_lseek_simple_(struct ft_env *fte, size_t len)
{
	uint8_t *buf = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	loff_t pos = -1;
	size_t nrd = 0;
	size_t nwr = 0;
	int fd = -1;
	uint8_t byte = 0;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_write(fd, buf, len, &nwr);
	ft_expect_eq(len, nwr);

	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	ft_read(fd, &byte, 1, &nrd);
	ft_expect_eq(1, nrd);
	ft_expect_eq(buf[pos], byte);

	ft_llseek(fd, 2, SEEK_CUR, &pos);
	ft_expect_eq(pos, 3);
	ft_read(fd, &byte, 1, &nrd);
	ft_expect_eq(1, nrd);
	ft_expect_eq(buf[pos], byte);

	ft_llseek(fd, -1, SEEK_END, &pos);
	ft_expect_eq(pos, len - 1);
	ft_read(fd, &byte, 1, &nrd);
	ft_expect_eq(1, nrd);
	ft_expect_eq(buf[pos], byte);

	ft_close(fd);
	ft_unlink(path);
}

static void test_lseek_simple(struct ft_env *fte)
{
	test_lseek_simple_(fte, FT_1M / 8);
	test_lseek_simple_(fte, FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid lseek(2) with SEEK_DATA
 */
static void test_lseek_data_(struct ft_env *fte, size_t bsz)
{
	int fd = -1;
	loff_t from = 0;
	loff_t pos = 0;
	uint8_t byte = 0;
	const loff_t off = (loff_t)(bsz * 2);
	uint8_t *buf1 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, bsz, off);
	from = off - 2;
	ft_llseek(fd, from, SEEK_DATA, &pos);
	ft_expect_eq(pos, off);
	ft_readn(fd, &byte, 1);
	ft_expect_eq(buf1[0], byte);
	ft_preadn(fd, &byte, 1, pos + 1);
	ft_expect_eq(buf1[1], byte);

	ft_close(fd);
	ft_unlink(path);
}

static void test_lseek_data(struct ft_env *fte)
{
	test_lseek_data_(fte, FT_BK_SIZE);
	test_lseek_data_(fte, 2 * FT_BK_SIZE);
	test_lseek_data_(fte, FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid lseek(2) with SEEK_HOLE
 */
static void test_lseek_hole_(struct ft_env *fte, size_t bsz)
{
	int fd = -1;
	loff_t from;
	loff_t off;
	loff_t pos = -1;
	size_t nrd = 0;
	uint8_t byte = 0;
	uint8_t *buf1 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	off = (loff_t)bsz;
	ft_pwriten(fd, buf1, bsz, off);
	off = (loff_t)(bsz * 100);
	ft_pwriten(fd, buf1, bsz, off);
	off = (loff_t)bsz;
	from = off - 1;
	ft_llseek(fd, from, SEEK_HOLE, &pos);
	ft_expect_eq(pos, from);
	ft_read(fd, &byte, 1, &nrd);
	ft_expect_eq(1, nrd);
	ft_expect_eq(0, byte);
	from = (loff_t)(bsz * 2) - 2;
	ft_llseek(fd, from, SEEK_HOLE, &pos);
	ft_expect_eq(pos, (loff_t)(bsz * 2));
	ft_preadn(fd, &byte, 1, pos);
	ft_expect_eq(0, byte);
	ft_close(fd);
	ft_unlink(path);
}

static void test_lseek_hole(struct ft_env *fte)
{
	test_lseek_hole_(fte, FT_BK_SIZE);
	test_lseek_hole_(fte, 2 * FT_BK_SIZE);
	test_lseek_hole_(fte, FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Tests lseek(2) with SEEK_DATA on sparse file
 */
static void test_lseek_data_sparse_(struct ft_env *fte, size_t nsteps)
{
	int fd = -1;
	loff_t off;
	loff_t pos;
	loff_t data_off;
	const size_t size = FT_BK_SIZE;
	const ssize_t ssize = (ssize_t)size;
	const size_t step = FT_1M;
	const void *buf1 = ft_new_buf_rands(fte, size);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nsteps; ++i) {
		off = (loff_t)(step * (i + 1));
		data_off = off - ssize;
		ft_ftruncate(fd, off);
		ft_pwriten(fd, buf1, size, data_off);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	for (size_t i = 0; i < nsteps; ++i) {
		off = (loff_t)(step * i);
		data_off = (loff_t)(step * (i + 1)) - ssize;
		ft_llseek(fd, off, SEEK_DATA, &pos);
		ft_expect_eq(pos, data_off);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_lseek_data_sparse(struct ft_env *fte)
{
	test_lseek_data_sparse_(fte, 16);
	test_lseek_data_sparse_(fte, 256);
}

/*
 * Tests lseek(2) with SEEK_HOLE on sparse file
 */
static void test_lseek_hole_sparse_(struct ft_env *fte, size_t nsteps)
{
	int fd = -1;
	loff_t pos = 0;
	loff_t off = 0;
	loff_t hole_off = 0;
	const size_t size = FT_BK_SIZE;
	const ssize_t ssize = (loff_t)size;
	const size_t step = FT_1M;
	const void *buf1 = ft_new_buf_rands(fte, size);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nsteps; ++i) {
		off = (loff_t)(step * i);
		ft_pwriten(fd, buf1, size, off);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	for (size_t i = 0; i < nsteps - 1; ++i) {
		off = (loff_t)(step * i);
		hole_off = off + ssize;
		ft_llseek(fd, off, SEEK_HOLE, &pos);
		ft_expect_eq(pos, hole_off);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	for (size_t i = 0; i < nsteps - 1; ++i) {
		off = (loff_t)(step * i) + ssize + 1;
		hole_off = off;
		ft_llseek(fd, off, SEEK_HOLE, &pos);
		ft_expect_eq(pos, hole_off);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_lseek_hole_sparse(struct ft_env *fte)
{
	test_lseek_hole_sparse_(fte, 16);
	test_lseek_hole_sparse_(fte, 256);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_lseek_simple),
	FT_DEFTEST(test_lseek_data),
	FT_DEFTEST(test_lseek_hole),
	FT_DEFTEST(test_lseek_data_sparse),
	FT_DEFTEST(test_lseek_hole_sparse),
};

const struct ft_tests ft_test_lseek = FT_DEFTESTS(ft_local_tests);

