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
 * Tests read-write data-consistency over sparse file.
 */
static void test_sparse_simple_(struct ft_env *fte, size_t cnt)
{
	const char *path = ft_new_path_unique(fte);
	const size_t step = 524287;
	loff_t pos = -1;
	size_t nsz = 0;
	size_t num = 0;
	size_t num2 = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = (i * step);
		pos = (loff_t)num;
		nsz = sizeof(num);
		ft_pwriten(fd, &num, nsz, pos);
	}
	ft_close(fd);
	ft_open(path, O_RDONLY, 0, &fd);
	for (size_t j = 0; j < cnt; ++j) {
		num = (j * step);
		pos = (loff_t)num;
		nsz = sizeof(num2);
		ft_preadn(fd, &num2, nsz, pos);
		ft_expect_eq(num, num2);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_sparse_simple(struct ft_env *fte)
{
	const size_t cnt[] = { 17, 7717 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_sparse_simple_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file with syncs over same file
 */
static void test_sparse_rdwr_(struct ft_env *fte, size_t cnt)
{
	const char *path = ft_new_path_unique(fte);
	const size_t step = 524287;
	loff_t pos = -1;
	size_t nsz = 0;
	size_t num = 0;
	size_t num2 = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);
	for (size_t i = 0; i < 11; ++i) {
		for (size_t j = 0; j < cnt; ++j) {
			ft_open(path, O_RDWR, 0, &fd);
			num = i + (j * step);
			pos = (loff_t)num;
			nsz = sizeof(num);
			ft_pwriten(fd, &num, nsz, pos);
			ft_fdatasync(fd);
			ft_preadn(fd, &num2, nsz, pos);
			ft_expect_eq(num, num2);
			ft_close(fd);
		}
	}
	ft_unlink(path);
}

static void test_sparse_rdwr(struct ft_env *fte)
{
	const size_t cnt[] = { 3, 11, 127 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_sparse_rdwr_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file with overwrites.
 */
static void test_sparse_overwrite_(struct ft_env *fte, loff_t base_off)
{
	const size_t len1 = 10037;
	const size_t len2 = 10039;
	uint8_t *buf1 = ft_new_buf_rands(fte, len1);
	uint8_t *buf2 = ft_new_buf_rands(fte, len2);
	uint8_t *buf3 = ft_new_buf_rands(fte, len1 + len2);
	char *path = ft_new_path_unique(fte);
	const loff_t offs[] = {
		737717, 280411, 10007, 31033, 42043, 53113, 161881, 375533,
		86767, 97171, 75353, 611999, 1108007, 64601, 1272211, 20323
	};
	const size_t noffs = FT_ARRAY_SIZE(offs);
	loff_t off = -1;
	uint8_t byte = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < noffs; ++i) {
		off = base_off + offs[i];
		ft_pwriten(fd, buf1, len1, off);
	}
	for (size_t i = 0; i < noffs; ++i) {
		off = base_off + offs[i] + 1;
		ft_pwriten(fd, buf2, len2, off);
	}
	for (size_t i = 0; i < noffs; ++i) {
		off = base_off + offs[i];
		ft_preadn(fd, &byte, 1, off);
		ft_expect_eq(buf1[0], byte);
		ft_preadn(fd, buf3, len2, off + 1);
		ft_expect_eqm(buf2, buf3, len2);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_sparse_overwrite(struct ft_env *fte)
{
	const loff_t base_off[] = { 0, 1, FT_UMEGA - 2, FT_UGIGA - 3 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(base_off); ++i) {
		test_sparse_overwrite_(fte, base_off[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_sparse_simple),
	FT_DEFTEST(test_sparse_rdwr),
	FT_DEFTEST(test_sparse_overwrite),
};

const struct ft_tests ft_test_rw_sparse = FT_DEFTESTS(ft_local_tests);
