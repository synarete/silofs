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
 * Tests data-consistency of I/O via fd where file's path is unlinked from
 * filesyatem's namespace. Data truncated to zero explicitly before close.
 */
static void test_unlinked_simple_(struct ft_env *fte, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	const size_t cnt = 100;
	loff_t pos = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_unlink(path);
	for (size_t i = 0; i < cnt; ++i) {
		ft_unlink_noent(path);
		ft_write(fd, buf1, len, &nwr);
		ft_expect_eq(nwr, len);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ft_unlink_noent(path);
		ft_read(fd, buf2, len, &nrd);
		ft_expect_eq(nrd, len);
		ft_expect_eqm(buf1, buf2, len);
	}
	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink_noent(path);
}

static void test_unlinked_simple(struct ft_env *fte)
{
	const size_t len[] = {
		1,
		FT_1K,
		FT_4K,
		FT_64K,
		FT_64K - 1,
		3 * FT_64K + 3,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(len); ++i) {
		test_unlinked_simple_(fte, len[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O via fd where file's path is unlinked from
 * filesyatem's namespace and data is truncated implicitly upon close.
 */
static void test_unlinked_complex_(struct ft_env *fte,
                                   loff_t off, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	uint8_t *buf1 = ft_new_buf_rands(fte, len);
	uint8_t *buf2 = ft_new_buf_rands(fte, len);
	const size_t cnt = 100;
	loff_t pos = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_unlink(path);
	for (size_t i = 0; i < cnt; ++i) {
		pos = off + (loff_t)(i * len);
		buf1[0] = (uint8_t)i;
		ft_pwriten(fd, buf1, len, pos);
	}
	for (size_t j = 0; j < cnt; ++j) {
		pos = off + (loff_t)(j * len);
		ft_preadn(fd, buf2, len, pos);
		buf1[0] = (uint8_t)j;
		ft_expect_eqm(buf1, buf2, len);
	}
	ft_close(fd);
	ft_unlink_noent(path);
}

static void test_unlinked_complex(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(1, 2),
		FT_MKRANGE(1, FT_64K - 2),
		FT_MKRANGE(1, FT_64K + 2),
		FT_MKRANGE(1, FT_1M - 2),
		FT_MKRANGE(1, FT_1M + 2),
		FT_MKRANGE(FT_1K, FT_64K),
		FT_MKRANGE(FT_1K + 1, FT_64K - 11),
		FT_MKRANGE(FT_64K - 1, FT_64K + 2),
		FT_MKRANGE(FT_1M - FT_64K + 1, 2 * FT_64K + 1),
		FT_MKRANGE(FT_1M - 1, FT_64K + 11),
		FT_MKRANGE(FT_1M - FT_64K - 1, 11 * FT_64K),
		FT_MKRANGE(FT_1G - 1, FT_64K + 2),
		FT_MKRANGE(FT_1G - FT_64K - 1, 2 * FT_64K + 2),
		FT_MKRANGE(FT_1G + FT_64K + 1, FT_64K - 1),
		FT_MKRANGE(FT_1T + 1, FT_64K - 1),
	};

	ft_exec_with_ranges(fte, test_unlinked_complex_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O via multiple fds where file's path is
 * unlinked from filesyatem's namespace.
 */
static void test_unlinked_multi_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	const size_t cnt = 100;
	loff_t pos = 0;
	int fd1 = -1;
	int fd2 = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path, O_RDONLY, 0, &fd2);
	ft_unlink(path);
	for (size_t i = 0; i < cnt; ++i) {
		pos = off + (loff_t)(cnt * FT_1M);
		ft_pwriten(fd1, buf1, len, pos);
	}
	for (size_t j = 0; j < cnt; ++j) {
		pos = off + (loff_t)(cnt * FT_1M);
		ft_preadn(fd2, buf2, len, pos);
		ft_expect_eqm(buf1, buf2, len);
	}
	ft_unlink_noent(path);
	ft_close(fd1);
	ft_close(fd2);
}

static void test_unlinked_multi(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(1, 2),
		FT_MKRANGE(1, FT_64K - 2),
		FT_MKRANGE(FT_1K, FT_64K),
		FT_MKRANGE(FT_1K + 1, FT_64K - 11),
		FT_MKRANGE(FT_64K - 1, FT_64K + 2),
		FT_MKRANGE(FT_1M - FT_64K + 1, 2 * FT_64K + 1),
		FT_MKRANGE(FT_1M - 1, FT_64K + 11),
		FT_MKRANGE(FT_1M - FT_64K - 1, 11 * FT_64K),
		FT_MKRANGE(FT_1G - 1, FT_64K + 2),
		FT_MKRANGE(FT_1G - FT_64K - 1, 2 * FT_64K + 2),
		FT_MKRANGE(FT_1G + FT_64K + 1, FT_64K - 1),
		FT_MKRANGE(FT_1T + 1, FT_64K - 1),
	};

	ft_exec_with_ranges(fte, test_unlinked_multi_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O after rename operations (with possible
 * implicit unlink).
 */
static void test_unlinked_rename_(struct ft_env *fte, size_t cnt)
{
	loff_t pos = 0;
	size_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);
	int fd1 = -1;
	int fd2 = -1;

	ft_open(path1, O_CREAT | O_RDWR, 0600, &fd1);
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		val = i;
		ft_pwriten(fd1, &val, vsz, pos);
	}
	ft_rename(path1, path2);
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		ft_preadn(fd1, &val, vsz, pos);
		ft_expect_eq(i, val);
	}
	ft_open(path2, O_RDONLY, 0, &fd2);
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		ft_preadn(fd2, &val, vsz, pos);
		ft_expect_eq(i, val);
	}
	ft_unlink_noent(path1);
	ft_unlink(path2);
	ft_close(fd1);
	ft_unlink_noent(path2);
	ft_close(fd2);
}

static void test_unlinked_rename(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100, 1000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_unlinked_rename_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests I/O over several unlinked files, all created with the same pathname.
 */
static void test_unlinked_same_path_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	int dat = -1;
	int *fds = ft_new_buf_zeros(fte, cnt * sizeof(fd));
	const char *path = ft_new_path_unique(fte);
	loff_t pos;

	for (size_t i = 0; i < cnt; ++i) {
		ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
		ft_unlink(path);
		fds[i] = fd;
		pos = (loff_t)((i * FT_1M) + i);
		ft_pwriten(fd, &fd, sizeof(fd), pos);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fd = fds[i];
		pos = (loff_t)((i * FT_1M) + i);
		ft_preadn(fd, &dat, sizeof(dat), pos);
		ft_expect_eq(fd, dat);
	}
	for (size_t i = 0; i < cnt; ++i) {
		ft_unlink_noent(path);
		fd = fds[i];
		ft_close(fd);
	}
}

static void test_unlinked_same_path(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_unlinked_same_path_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_unlinked_simple),
	FT_DEFTEST(test_unlinked_complex),
	FT_DEFTEST(test_unlinked_multi),
	FT_DEFTEST(test_unlinked_rename),
	FT_DEFTEST(test_unlinked_same_path),
};

const struct ft_tests ft_test_unlinked_file = FT_DEFTESTS(ft_local_tests);
