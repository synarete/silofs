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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of sequential writes followed by sequential reads.
 */
static void test_rw_sequencial_(struct ft_env *fte, loff_t from, size_t len,
                                size_t cnt, int rewrite)
{
	void *buf2 = ft_new_buf_zeros(fte, len);
	char *path = ft_new_path_unique(fte);
	void *buf1 = NULL;
	const size_t nitr = rewrite ? 2 : 1;
	loff_t pos = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nitr; ++i) {
		ft_llseek(fd, from, SEEK_SET, &pos);
		for (size_t j = 0; j < cnt; ++j) {
			buf1 = ft_new_buf_nums(fte, (long)j, len);
			ft_write(fd, buf1, len, &nwr);
			ft_expect_eq(nwr, len);
		}
		ft_llseek(fd, from, SEEK_SET, &pos);
		for (size_t j = 0; j < cnt; ++j) {
			buf1 = ft_new_buf_nums(fte, (long)j, len);
			ft_read(fd, buf2, len, &nrd);
			ft_expect_eq(nrd, len);
			ft_expect_eqm(buf1, buf2, len);
		}
	}
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_sequencial_aligned_64k(struct ft_env *fte)
{
	const size_t len = FT_64K;
	const size_t cnt[] = { 1, 2, 63 };
	const loff_t from[] = {
		0,
		FT_64K,
		FT_1M,
		FT_1M - FT_64K,
		FT_1G / 2,
		FT_1G,
		FT_1G - FT_64K,
		FT_1G + FT_64K,
		FT_1G - FT_1M,
		FT_1T - (64 * FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_rw_sequencial_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_sequencial_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_sequencial_aligned_1m(struct ft_env *fte)
{
	const size_t len = FT_1M;
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
			test_rw_sequencial_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_sequencial_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_sequencial_unaligned_64k(struct ft_env *fte)
{
	const size_t len = FT_64K;
	const size_t cnt[] = { 1, 2, 4 };
	const loff_t from[] = {
		1,
		FT_64K - 11,
		FT_64K + 11,
		FT_1M - 11,
		FT_1M - FT_64K - 1,
		FT_1G - 111,
		FT_1G - FT_64K - 1,
		FT_1G + FT_64K + 1,
		FT_1T - 1111,
		FT_1T - (11 * FT_1G) + 111,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_rw_sequencial_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_sequencial_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_sequencial_unaligned_1m(struct ft_env *fte)
{
	const size_t len = FT_1M;
	const size_t cnt[] = { 1, 2, 3 };
	const loff_t from[] = {
		11,
		FT_64K - 11,
		FT_1M - 11,
		FT_1M - FT_64K - 1,
		11 * FT_1M - 1,
		FT_1G - 111,
		FT_1G - FT_64K - 1,
		FT_1G + FT_64K + 1,
		FT_1T - 1111,
		FT_1T - (11 * FT_1G) + 111,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_rw_sequencial_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_sequencial_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_sequencial_unaligned_(struct ft_env *fte, size_t len)
{
	const size_t cnt[] = { 1, 2, 3 };
	const loff_t from[] = {
		7,
		FT_64K - 7,
		FT_1M - 7,
		FT_1M - FT_64K - 7,
		7 * FT_1M - 7,
		FT_1G - 17,
		FT_1G - FT_64K - 17,
		FT_1G + FT_64K + 17,
		FT_1T - 7,
		FT_1T - (7 * FT_1G) + 7,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(from); ++i) {
		for (size_t j = 0; j < FT_ARRAY_SIZE(cnt); ++j) {
			test_rw_sequencial_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_sequencial_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

static void test_rw_sequencial_unaligned_some(struct ft_env *fte)
{
	const size_t len[] = { 1023, 7907, 66601 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(len); ++i) {
		test_sequencial_unaligned_(fte, len[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of sequential writes followed by sequential reads
 * of variable length strings
 */
static void
test_sequencial_strings_(struct ft_env *fte, loff_t start_off, size_t cnt)
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
		ft_expect_eq(nu, ft_strlen(buf1));
		ft_write(fd, buf1, nu, &nwr);
		ft_expect_eq(nu, nwr);
	}
	ft_llseek(fd, start_off, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ni = snprintf(buf1, sizeof(buf1), "%lu", i);
		nu = (size_t)ni;
		ft_expect_eq(nu, ft_strlen(buf1));
		ft_read(fd, buf2, nu, &nrd);
		ft_expect_eq(nu, nrd);
		ft_expect_eq(0, strcmp(buf1, buf2));
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_rw_sequencial_strings(struct ft_env *fte)
{
	const size_t cnt[] = { 10, 100, 1000, 10000 };
	const loff_t from[] = {
		0,
		FT_1K,
		FT_4K,
		FT_64K,
		FT_1M,
		FT_1G,
		FT_1T,
		7,
		FT_4K - 7,
		FT_8K + 7,
		FT_64K - 7,
		FT_1M - FT_64K - 7,
		7 * FT_1M - 7,
		FT_1G - 17,
		FT_1G - FT_64K - 17,
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
	FT_DEFTEST(test_rw_sequencial_aligned_64k),
	FT_DEFTEST(test_rw_sequencial_aligned_1m),
	FT_DEFTEST(test_rw_sequencial_unaligned_64k),
	FT_DEFTEST(test_rw_sequencial_unaligned_1m),
	FT_DEFTEST(test_rw_sequencial_unaligned_some),
	FT_DEFTEST(test_rw_sequencial_strings),
};

const struct ft_tests ft_test_rw_sequencial = FT_DEFTESTS(ft_local_tests);
