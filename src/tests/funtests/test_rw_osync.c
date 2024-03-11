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
 * Expects read-write data-consistency when file is opened with O_SYNC.
 */
static void test_osync_simple_(struct ft_env *fte, loff_t off, size_t len)
{
	void *buf0 = ft_new_buf_zeros(fte, len);
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	int fd1 = -1;
	int fd2 = -1;

	ft_open(path, O_CREAT | O_RDWR, 0644, &fd1);
	ft_pwriten(fd1, buf1, len, off);
	ft_close(fd1);
	ft_open(path, O_RDONLY, 0, &fd2);
	ft_preadn(fd2, buf0, len, off);
	ft_expect_eqm(buf1, buf0, len);
	ft_open(path, O_RDWR | O_SYNC, 0, &fd1);
	ft_pwriten(fd1, buf2, len, off);
	ft_preadn(fd2, buf0, len, off);
	ft_expect_eqm(buf2, buf0, len);
	ft_unlink(path);
	ft_pwriten(fd1, buf1, len, off);
	ft_preadn(fd2, buf0, len, off);
	ft_expect_eqm(buf1, buf0, len);
	ft_close(fd1);
	ft_close(fd2);
}

static void test_osync_simple(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_BK_SIZE),
		FT_MKRANGE(FT_1K, FT_64K + 1),
		FT_MKRANGE(FT_1K + 1, FT_1M),
		FT_MKRANGE(FT_1G, 2 * FT_1M - 1),
		FT_MKRANGE(FT_1T, 3 * FT_1M - 3),
	};

	ft_exec_with_ranges(fte, test_osync_simple_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when multiple files are opened with
 * O_SYNC.
 */
static void test_osync_multi_(struct ft_env *fte, size_t bsz, loff_t off)
{
	void *buf0 = ft_new_buf_zeros(fte, bsz);
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path[16];
	int fd[16];

	for (size_t i = 0; i < FT_ARRAY_SIZE(path); ++i) {
		path[i] = ft_new_path_unique(fte);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(fd); ++i) {
		ft_open(path[i], O_CREAT | O_RDWR | O_SYNC, 0640, &fd[i]);
		ft_pwriten(fd[i], buf1, bsz, off + (int)i);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(fd); ++i) {
		ft_preadn(fd[i], buf0, bsz, off + (int)i);
		ft_expect_eqm(buf1, buf0, bsz);
		ft_pwriten(fd[i], buf2, bsz, off + (int)i + 1);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(fd); ++i) {
		ft_preadn(fd[i], buf0, bsz, off + (int)i + 1);
		ft_expect_eqm(buf2, buf0, bsz);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(fd); ++i) {
		ft_close(fd[i]);
	}
	for (size_t i = 0; i < FT_ARRAY_SIZE(path); ++i) {
		ft_unlink(path[i]);
	}
}

static void test_osync_multi(struct ft_env *fte)
{
	test_osync_multi_(fte, FT_64K, 0);
	test_osync_multi_(fte, FT_64K + 1, FT_1K);
	test_osync_multi_(fte, FT_1M, FT_1K + 1);
	test_osync_multi_(fte, 2 * FT_1M - 1, FT_1G);
	test_osync_multi_(fte, 3 * FT_1M - 3, FT_1T);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_osync_simple),
	FT_DEFTEST(test_osync_multi),
};

const struct ft_tests ft_test_rw_osync = FT_DEFTESTS(ft_local_tests);
