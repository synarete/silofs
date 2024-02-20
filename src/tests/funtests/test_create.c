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
 * Expects success for simple creat(3p)/unlink(3p) X N
 */
static void test_create_simple_(struct ft_env *fte, size_t cnt)
{
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	for (size_t i = 0; i < cnt; ++i) {
		ft_creat(path, 0600, &fd);
		ft_close(fd);
		ft_unlink(path);
	}
}

static void test_create_simple(struct ft_env *fte)
{
	const size_t cnt[] = { 1, 10, 1000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_create_simple_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects success for sequence of creat(3p)/unlink(3p) of regular files.
 */
static void test_create_unlink_(struct ft_env *fte, size_t cnt)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = NULL;
	int fd = -1;

	ft_mkdir(path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		path1 = ft_new_pathf(fte, path0, "%lu", i);
		ft_creat(path1, 0600, &fd);
		ft_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		path1 = ft_new_pathf(fte, path0, "%lu", i);
		ft_unlink(path1);
	}
	ft_rmdir(path0);
}

static void test_create_unlink(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_create_unlink_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects success for sequence of creat(3p) plus pwrite(3p) of regular file.
 */
static void test_create_pwrite_(struct ft_env *fte, loff_t off, size_t len)
{
	void *buf = ft_new_buf_rands(fte, len);
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	int fd = -1;

	ft_mkdir(path0, 0700);
	ft_creat(path1, 0600, &fd);
	ft_pwriten(fd, buf, len, off);
	ft_close(fd);
	ft_unlink(path1);
	ft_rmdir(path0);
}

static void test_create_pwrite(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1K, FT_1K),
		FT_MKRANGE(FT_64K, FT_4K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, FT_4K),
		FT_MKRANGE(FT_1T, FT_1K),
		/* unaligned */
		FT_MKRANGE(1, FT_1K + 11),
		FT_MKRANGE(11, FT_1M - 111),
		FT_MKRANGE(FT_1K - 1, FT_1K + 11),
		FT_MKRANGE(FT_64K + 1, FT_4K + 111),
		FT_MKRANGE(FT_1M - 11, FT_64K + 1111),
		FT_MKRANGE(FT_1G - 1, FT_4K + 11),
		FT_MKRANGE(FT_1T - 1111, 11111),
	};
	ft_exec_with_ranges(fte, test_create_pwrite_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_create_simple),
	FT_DEFTEST(test_create_unlink),
	FT_DEFTEST(test_create_pwrite),
};

const struct ft_tests ft_test_create = FT_DEFTESTS(ft_local_tests);
