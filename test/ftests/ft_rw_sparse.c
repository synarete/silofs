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
#include "ftests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file.
 */
static void test_rw_sparse_simple_(struct ft_env *fte, size_t cnt)
{
	const char  *path = ft_new_path_unique(fte);
	const size_t step = 524287;
	off_t        pos  = -1;
	size_t       nsz  = 0;
	size_t       num  = 0;
	size_t       num2 = 0;
	int          fd   = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = (i * step);
		pos = (off_t)num;
		nsz = sizeof(num);
		ft_pwriten(fd, &num, nsz, pos);
	}
	ft_close(fd);
	ft_open(path, O_RDONLY, 0, &fd);
	for (size_t j = 0; j < cnt; ++j) {
		num = (j * step);
		pos = (off_t)num;
		nsz = sizeof(num2);
		ft_preadn(fd, &num2, nsz, pos);
		ft_expect_eq(num, num2);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_rw_sparse_simple(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 1000, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_rw_sparse_simple_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file with syncs over same file
 */
static void test_rw_sparse_repeat_(struct ft_env *fte, size_t cnt)
{
	const char  *path = ft_new_path_unique(fte);
	const size_t step = 524287;
	off_t        pos  = -1;
	size_t       nsz  = 0;
	size_t       num  = 0;
	size_t       num2 = 0;
	int          fd   = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_close(fd);
	for (size_t i = 0; i < 10; ++i) {
		for (size_t j = 0; j < cnt; ++j) {
			ft_open(path, O_RDWR, 0, &fd);
			num = i + (j * step);
			pos = (off_t)num;
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

static void test_rw_sparse_repeat(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 1000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_rw_sparse_repeat_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file with overwrites.
 */
static void test_rw_sparse_overwrite_(struct ft_env *fte, off_t base_off)
{
	const size_t len1   = 10037;
	const size_t len2   = 10039;
	uint8_t     *buf1   = ft_new_buf_rands(fte, len1);
	uint8_t     *buf2   = ft_new_buf_rands(fte, len2);
	uint8_t     *buf3   = ft_new_buf_rands(fte, len1 + len2);
	const char  *path   = ft_new_path_unique(fte);
	const off_t  offs[] = {
                737717, 280411, 10007, 31033,  42043,   53113, 161881,  375533,
                86767,  97171,  75353, 611999, 1108007, 64601, 1272211, 20323,
	};
	const size_t noffs = FT_ARRAY_SIZE(offs);
	off_t        off   = -1;
	uint8_t      byte  = 0;
	int          fd    = -1;

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

static void test_rw_sparse_overwrite(struct ft_env *fte)
{
	const off_t base_off[] = { 0, 1, FT_1M - 2, FT_1G - 3 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(base_off); ++i) {
		test_rw_sparse_overwrite_(fte, base_off[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Test st_blocks vs st_size on sparse files.
 */
static void test_rw_sparse_stat_(struct ft_env *fte, off_t from_off,
                                 size_t data_size, size_t skip_size)
{
	struct stat  st     = { .st_size = -1 };
	const size_t nsteps = 8;
	const char  *path   = ft_new_path_unique(fte);
	const char  *name   = ft_new_name_unique(fte);
	uint8_t     *buf1   = ft_new_buf_rands(fte, data_size);
	uint8_t     *buf2   = ft_new_buf_zeros(fte, data_size);
	ssize_t      size   = -1;
	off_t        off    = -1;
	int          dfd    = -1;
	int          fd     = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nsteps; ++i) {
		buf1[0] = (uint8_t)i;
		buf2[0] = 0xFF - (uint8_t)i;
		off     = from_off + (ssize_t)(i * skip_size);
		ft_pwriten(fd, buf1, data_size, off);
		size = off + (ssize_t)data_size;
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, size);
		ft_expect_lt(st.st_blocks * 512, size);
		ft_ftruncate(fd, (off_t)size + 1);
		ft_preadn(fd, buf2, data_size, off);
		ft_expect_eqm(buf1, buf2, data_size);
		ft_preadn(fd, &buf2[0], 1, (off_t)size);
		ft_expect_eq(buf2[0], 0);
	}
	ft_ftruncate(fd, 0);
	ft_ftruncate(fd, (off_t)size);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, size);
	ft_expect_eq(st.st_blocks, 0);
	ft_close(fd);
	ft_unlinkat(dfd, name, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_rw_sparse_stat(struct ft_env *fte)
{
	test_rw_sparse_stat_(fte, FT_1K, FT_1K, FT_1M);
	test_rw_sparse_stat_(fte, FT_4K, FT_1K, FT_1M);
	test_rw_sparse_stat_(fte, FT_4K, FT_4K, FT_1M);
	test_rw_sparse_stat_(fte, FT_64K, FT_4K, FT_1M);
	test_rw_sparse_stat_(fte, FT_1M, FT_4K, FT_1G);
	test_rw_sparse_stat_(fte, FT_1G, FT_64K, FT_1G);
	test_rw_sparse_stat_(fte, FT_1T, FT_1M, FT_1G);
	test_rw_sparse_stat_(fte, FT_1G - 1, FT_64K + 11, FT_1M + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_rw_sparse_simple),
	FT_DEFTEST(test_rw_sparse_repeat),
	FT_DEFTEST(test_rw_sparse_overwrite),
	FT_DEFTEST(test_rw_sparse_stat),
};

const struct ft_tests ft_test_rw_sparse = FT_DEFTESTS(ft_local_tests);
