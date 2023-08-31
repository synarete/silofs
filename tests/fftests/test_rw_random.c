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
 * Tests read-write data-consistency for a sequence of IOs at pseudo random
 * offsets.
 */
static void test_random_(struct ft_env *fte,
                         loff_t from, size_t len, size_t cnt, int unlinked)
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

static void test_random_aligned_bk(struct ft_env *fte)
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
			test_random_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_random_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_aligned_mega(struct ft_env *fte)
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
			test_random_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_random_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_bk(struct ft_env *fte)
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
			test_random_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_random_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_mega(struct ft_env *fte)
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
			test_random_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_random_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_(struct ft_env *fte, size_t bsz)
{
	const size_t cnt[] = { 1, 7, 77 };
	const loff_t from[] = {
		7,
		1023,
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
			test_random_(fte, from[i], bsz, cnt[j], 0);
			ft_relax_mem(fte);
			test_random_(fte, from[i], bsz, cnt[j], 1);
			ft_relax_mem(fte);
		}
	}
}

static void test_random_unaligned(struct ft_env *fte)
{
	test_random_unaligned_(fte, 7907);
	test_random_unaligned_(fte, 66601);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_random_aligned_bk),
	FT_DEFTEST(test_random_aligned_mega),
	FT_DEFTEST(test_random_unaligned_bk),
	FT_DEFTEST(test_random_unaligned_mega),
	FT_DEFTEST(test_random_unaligned),
};

const struct ft_tests ft_test_rw_random = FT_DEFTESTS(ft_local_tests);
