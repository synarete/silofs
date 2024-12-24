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
 * Tests read-write data-consistency for a sequence of IOs at pseudo random
 * offsets.
 */
static void test_rw_random_(struct ft_env *fte, loff_t from, size_t len,
                            size_t cnt, int unlinked)
{
	const char *path = ft_new_path_unique(fte);
	const long *pseq = ft_new_buf_randseq(fte, cnt, 0);
	void *buf1 = NULL;
	void *buf2 = ft_new_buf_zeros(fte, len);
	loff_t pos = 0;
	long seed = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0640, &fd);
	if (unlinked) {
		ft_unlink(path);
	}
	for (size_t i = 0; i < 2; ++i) {
		for (size_t j = 0; j < cnt; ++j) {
			pos = from + ((long)len * pseq[j]);
			seed = (long)(i + j) + pos;
			buf1 = ft_new_buf_nums(fte, seed, len);
			ft_pwriten(fd, buf1, len, pos);
		}
		for (size_t j = 0; j < cnt; ++j) {
			pos = from + ((long)len * pseq[j]);
			seed = (long)(i + j) + pos;
			buf1 = ft_new_buf_nums(fte, seed, len);
			ft_preadn(fd, buf2, len, pos);
			ft_expect_eqm(buf1, buf2, len);
		}
	}
	ft_close(fd);
	if (!unlinked) {
		ft_unlink(path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_random_aligned_64k(struct ft_env *fte)
{
	const size_t len = FT_64K;
	const size_t cnt[] = { 1, 2, 64 };
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
			test_rw_random_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_random_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_random_aligned_1m(struct ft_env *fte)
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
			test_rw_random_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_random_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_random_unaligned_64k(struct ft_env *fte)
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
			test_rw_random_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_random_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_random_unaligned_1m(struct ft_env *fte)
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
			test_rw_random_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_random_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_rw_random_unaligned_some_(struct ft_env *fte, size_t len)
{
	const size_t cnt[] = { 1, 7, 77 };
	const loff_t from[] = {
		7,
		1023,
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
			test_rw_random_(fte, from[i], len, cnt[j], 0);
			ft_relax_mem(fte);
			test_rw_random_(fte, from[i], len, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

static void test_rw_random_unaligned_some(struct ft_env *fte)
{
	const size_t len[] = { 1023, 7907, 66601 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(len); ++i) {
		test_rw_random_unaligned_some_(fte, len[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_rw_random_aligned_64k),
	FT_DEFTEST(test_rw_random_aligned_1m),
	FT_DEFTEST(test_rw_random_unaligned_64k),
	FT_DEFTEST(test_rw_random_unaligned_1m),
	FT_DEFTEST(test_rw_random_unaligned_some),
};

const struct ft_tests ft_test_rw_random = FT_DEFTESTS(ft_local_tests);
