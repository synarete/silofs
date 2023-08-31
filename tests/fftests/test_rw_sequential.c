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
 * Tests data-consistency of sequential writes followed by sequential reads.
 */
static void test_sequencial_(struct ft_env *fte, loff_t from,
                             size_t bsz, size_t cnt, int rewrite)
{
	void *buf1 = NULL;
	void *buf2 = ft_new_buf_zeros(fte, bsz);
	char *path = ft_new_path_unique(fte);
	const size_t nitr = rewrite ? 2 : 1;
	loff_t pos = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nitr; ++i) {
		ft_llseek(fd, from, SEEK_SET, &pos);
		for (size_t j = 0; j < cnt; ++j) {
			buf1 = ft_new_buf_nums(fte, (long)j, bsz);
			ft_write(fd, buf1, bsz, &nwr);
			ft_expect_eq(nwr, bsz);
		}
		ft_llseek(fd, from, SEEK_SET, &pos);
		for (size_t j = 0; j < cnt; ++j) {
			buf1 = ft_new_buf_nums(fte, (long)j, bsz);
			ft_read(fd, buf2, bsz, &nrd);
			ft_expect_eq(nrd, bsz);
			ft_expect_eqm(buf1, buf2, bsz);
		}
	}
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_sequencial_aligned_bk(struct ft_env *fte)
{
	const size_t bsz = FT_BK_SIZE;
	const size_t cnt[] = { 1, 2, 63 };
	const loff_t from[] = {
		0,
		FT_BK_SIZE,
		FT_1M,
		FT_1M - FT_BK_SIZE,
		FT_1G / 2,
		FT_1G,
		FT_1G - FT_BK_SIZE,
		FT_1G + FT_BK_SIZE,
		FT_1G - FT_1M,
		FT_1T - (64 * FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_sequencial_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_sequencial_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_sequencial_aligned_mega(struct ft_env *fte)
{
	const size_t bsz = FT_1M;
	const size_t cnt[] = { 1, 2, 4 };
	const loff_t from[] = {
		0,
		FT_1M,
		FT_1G,
		FT_1G - FT_1M,
		FT_1G + FT_1M,
		2 * FT_1G,
		FT_1T - (64 * FT_1M),
		FT_1T + FT_1G + FT_1M,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_sequencial_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_sequencial_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_sequencial_unaligned_bk(struct ft_env *fte)
{
	const size_t bsz = FT_BK_SIZE;
	const size_t cnt[] = { 1, 2, 4 };
	const loff_t from[] = {
		1,
		FT_BK_SIZE - 11,
		FT_BK_SIZE + 11,
		FT_1M - 11,
		FT_1M - FT_BK_SIZE - 1,
		FT_1G - 111,
		FT_1G - FT_BK_SIZE - 1,
		FT_1G + FT_BK_SIZE + 1,
		FT_1T - 1111,
		FT_1T - (11 * FT_1G) + 111,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_sequencial_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_sequencial_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_sequencial_unaligned_mega(struct ft_env *fte)
{
	const size_t bsz = FT_1M;
	const size_t cnt[] = { 1, 2, 3 };
	const loff_t from[] = {
		11,
		FT_BK_SIZE - 11,
		FT_1M - 11,
		FT_1M - FT_BK_SIZE - 1,
		11 * FT_1M - 1,
		FT_1G - 111,
		FT_1G - FT_BK_SIZE - 1,
		FT_1G + FT_BK_SIZE + 1,
		FT_1T - 1111,
		FT_1T - (11 * FT_1G) + 111,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_sequencial_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_sequencial_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_sequencial_unaligned_(struct ft_env *fte, size_t bsz)
{
	const size_t cnt[] = { 1, 2, 3 };
	const loff_t from[] = {
		7,
		FT_BK_SIZE - 7,
		FT_1M - 7,
		FT_1M - FT_BK_SIZE - 7,
		7 * FT_1M - 7,
		FT_1G - 17,
		FT_1G - FT_BK_SIZE - 17,
		FT_1G + FT_BK_SIZE + 17,
		FT_1T - 7,
		FT_1T - (7 * FT_1G) + 7,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_sequencial_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_sequencial_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

static void test_sequencial_unaligned(struct ft_env *fte)
{
	test_sequencial_unaligned_(fte, 7907);
	test_sequencial_unaligned_(fte, 66601);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of sequential writes followed by sequential reads
 * of variable length strings
 */
static void test_sequencial_strings_(struct ft_env *fte,
                                     loff_t start_off, size_t cnt)
{
	char buf1[128] = "";
	char buf2[128] = "";
	const char *path = ft_new_path_unique(fte);
	loff_t pos = -1;
	size_t nu = 0;
	size_t nwr = 0;
	size_t nrd = 0;
	int fd = -1;
	int ni = 0;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_llseek(fd, start_off, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ni = snprintf(buf1, sizeof(buf1), "%lu", i);
		nu = (size_t)ni;
		ft_expect_eq(nu, strlen(buf1));
		ft_write(fd, buf1, nu, &nwr);
		ft_expect_eq(nu, nwr);
	}
	ft_llseek(fd, start_off, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ni = snprintf(buf1, sizeof(buf1), "%lu", i);
		nu = (size_t)ni;
		ft_expect_eq(nu, strlen(buf1));
		ft_read(fd, buf2, nu, &nrd);
		ft_expect_eq(nu, nrd);
		ft_expect_eq(0, strcmp(buf1, buf2));
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_sequencial_strings(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100, 1000, 10000 };
	const loff_t from[] = {
		0,
		FT_BK_SIZE,
		FT_1M,
		FT_1G,
		FT_1T,
		7,
		FT_BK_SIZE - 7,
		FT_1M - FT_BK_SIZE - 7,
		7 * FT_1M - 7,
		FT_1G - 17,
		FT_1G - FT_BK_SIZE - 17,
		FT_1T - 7,
		FT_1T - (7 * FT_1G) + 7,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_sequencial_strings_(fte, from[i], cnt[j]);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_sequencial_aligned_bk),
	FT_DEFTEST(test_sequencial_aligned_mega),
	FT_DEFTEST(test_sequencial_unaligned_bk),
	FT_DEFTEST(test_sequencial_unaligned_mega),
	FT_DEFTEST(test_sequencial_unaligned),
	FT_DEFTEST(test_sequencial_strings),
};

const struct ft_tests ft_test_rw_sequencial = FT_DEFTESTS(ft_local_tests);

