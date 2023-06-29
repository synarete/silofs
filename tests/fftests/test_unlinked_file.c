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
 * Tests data-consistency of I/O via fd where file's path is unlinked from
 * filesyatem's namespace. Data truncated to zero explicitly before close.
 */
static void test_unlinked_simple_(struct ft_env *fte,
                                  size_t bsz,
                                  size_t cnt)
{
	int fd;
	loff_t pos = -1;
	size_t nwr;
	size_t nrd;
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_unlink(path);

	for (size_t i = 0; i < cnt; ++i) {
		ft_unlink_noent(path);
		ft_write(fd, buf1, bsz, &nwr);
		ft_expect_eq(nwr, bsz);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ft_unlink_noent(path);
		ft_read(fd, buf2, bsz, &nrd);
		ft_expect_eq(nrd, bsz);
		ft_expect_eqm(buf1, buf2, bsz);
	}

	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink_noent(path);
}


static void test_unlinked_simple1(struct ft_env *fte)
{
	test_unlinked_simple_(fte, 1, 1);
	test_unlinked_simple_(fte, FT_BK_SIZE, 2);
	test_unlinked_simple_(fte, FT_BK_SIZE - 3, 3);
}

static void test_unlinked_simple2(struct ft_env *fte)
{
	test_unlinked_simple_(fte, FT_BK_SIZE, FT_UKILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O via fd where file's path is unlinked from
 * filesyatem's namespace and data is truncated implicitly upon close.
 */
static void test_unlinked_complex_(struct ft_env *fte,
                                   loff_t base, size_t bsz, size_t cnt)
{
	int fd = -1;
	loff_t pos = 0;
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_unlink(path);
	for (size_t i = 0; i < cnt; ++i) {
		pos = base + (loff_t)(i * bsz);
		ft_pwriten(fd, buf1, bsz, pos);
	}
	for (size_t j = 0; j < cnt; ++j) {
		pos = base + (loff_t)(j * bsz);
		ft_preadn(fd, buf2, bsz, pos);
		ft_expect_eqm(buf1, buf2, bsz);
	}
	ft_close(fd);
	ft_unlink_noent(path);
}


static void test_unlinked_complex1(struct ft_env *fte)
{
	test_unlinked_complex_(fte, 0, 1, 1);
	test_unlinked_complex_(fte, 0, FT_BK_SIZE, 2);
	test_unlinked_complex_(fte, 0, FT_BK_SIZE - 3, 3);
}

static void test_unlinked_complex2(struct ft_env *fte)
{
	test_unlinked_complex_(fte, 0, FT_BK_SIZE, FT_UKILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O via multiple fds where file's path is
 * unlinked from filesyatem's namespace.
 */
static void test_unlinked_multi(struct ft_env *fte)
{
	int fd1 = -1;
	int fd2 = -1;
	loff_t pos = 0;
	const size_t bsz = FT_BK_SIZE;
	const size_t cnt = FT_UKILO;
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path, O_RDONLY, 0, &fd2);
	ft_unlink(path);

	for (size_t i = 0; i < cnt; ++i) {
		pos = (loff_t)(cnt * FT_UMEGA);
		ft_pwriten(fd1, buf1, bsz, pos);
	}
	for (size_t j = 0; j < cnt; ++j) {
		pos = (loff_t)(cnt * FT_UMEGA);
		ft_preadn(fd2, buf2, bsz, pos);
		ft_expect_eqm(buf1, buf2, bsz);
	}

	ft_unlink_noent(path);
	ft_close(fd1);
	ft_close(fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O after rename operations (with possible
 * implicit unlink).
 */
static void test_unlinked_rename_(struct ft_env *fte, size_t cnt)
{
	int fd1 = -1;
	int fd2 = -1;
	loff_t pos = 0;
	size_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);

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
	test_unlinked_rename_(fte, 11);
	test_unlinked_rename_(fte, 111);
	test_unlinked_rename_(fte, 1111);
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
		pos = (loff_t)((i * FT_UMEGA) + i);
		ft_pwriten(fd, &fd, sizeof(fd), pos);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fd = fds[i];
		pos = (loff_t)((i * FT_UMEGA) + i);
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
	test_unlinked_same_path_(fte, 10);
	test_unlinked_same_path_(fte, 100);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_unlinked_simple1),
	FT_DEFTEST(test_unlinked_simple2),
	FT_DEFTEST(test_unlinked_complex1),
	FT_DEFTEST(test_unlinked_complex2),
	FT_DEFTEST(test_unlinked_multi),
	FT_DEFTEST(test_unlinked_rename),
	FT_DEFTEST(test_unlinked_same_path),
};

const struct ft_tests ft_test_unlinked_file = FT_DEFTESTS(ft_local_tests);
