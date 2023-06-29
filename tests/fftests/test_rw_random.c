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
static void test_random_(struct ft_env *fte, loff_t from,
                         size_t len, size_t cnt, size_t niter)
{
	int fd = -1;
	loff_t pos = 0;
	long seed = 0;
	void *buf1 = NULL;
	void *buf2 = ft_new_buf_zeros(fte, len);
	const long *pseq = ft_new_buf_randseq(fte, cnt, 0);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0640, &fd);
	for (size_t i = 0; i < niter; ++i) {
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
	ft_unlink(path);
}


static void test_random_io(struct ft_env *fte, loff_t from,
                           size_t len, size_t cnt)
{
	test_random_(fte, from, len, cnt, 1);
	test_random_(fte, from, len, cnt, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_aligned_blk(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t len = FT_BK_SIZE;

	from = 0;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_BK_SIZE;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_UMEGA;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE);
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_UGIGA;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE);
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE);
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UGIGA - (len * cnt));
	test_random_io(fte, from, len, cnt);
	from = (loff_t)((FT_UGIGA) / 2);
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UTERA - (len * cnt));
	test_random_io(fte, from, len, cnt);
}

static void test_random_aligned_blk1(struct ft_env *fte)
{
	test_random_aligned_blk(fte, 1);
}

static void test_random_aligned_blk2(struct ft_env *fte)
{
	test_random_aligned_blk(fte, 2);
}

static void test_random_aligned_blk63(struct ft_env *fte)
{
	test_random_aligned_blk(fte, 63);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_aligned_mega(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_UMEGA;

	from = 0;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_UMEGA);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_UMEGA);
	test_random_io(fte, from, bsz, 2 * cnt);
	from = (loff_t)(2 * FT_UGIGA);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)((FT_UGIGA) / 2);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt));
	test_random_io(fte, from, bsz, cnt);
}

static void test_random_aligned_mega1(struct ft_env *fte)
{
	test_random_aligned_mega(fte, 1);
}

static void test_random_aligned_mega2(struct ft_env *fte)
{
	test_random_aligned_mega(fte, 2);
}

static void test_random_aligned_mega3(struct ft_env *fte)
{
	test_random_aligned_mega(fte, 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_blk(struct ft_env *fte,
                                      size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_BK_SIZE;

	from = 1;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE - 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE + 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA - 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE - 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA - 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE - 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE + 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - (bsz * cnt) + 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)((FT_UGIGA * 13) / 11);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt) - 11);
	test_random_io(fte, from, bsz, cnt);
}

static void test_random_unaligned_blk1(struct ft_env *fte)
{
	test_random_unaligned_blk(fte, 1);
}

static void test_random_unaligned_blk2(struct ft_env *fte)
{
	test_random_unaligned_blk(fte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_mega(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_UMEGA;

	from = 1;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE - 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE + 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA - 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE - 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA - 11;
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE - 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE + 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - (bsz * cnt) + 1);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)((FT_UGIGA * 13) / 11);
	test_random_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt) - 11);
	test_random_io(fte, from, bsz, cnt);
}

static void test_random_unaligned_mega1(struct ft_env *fte)
{
	test_random_unaligned_mega(fte, 1);
}

static void test_random_unaligned_mega2(struct ft_env *fte)
{
	test_random_unaligned_mega(fte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_(struct ft_env *fte, size_t len, size_t cnt)
{
	loff_t from;

	from = 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_BK_SIZE - 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_BK_SIZE + 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_UMEGA - 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_UMEGA / 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_UGIGA - 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)FT_UGIGA / 7;
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UGIGA + (len * cnt) - 7);
	test_random_io(fte, from, len, cnt);
	from = (loff_t)((FT_UGIGA / 7) - 7);
	test_random_io(fte, from, len, cnt);
	from = (loff_t)(FT_UTERA - (len * cnt) - 7);
	test_random_io(fte, from, len, cnt);
}

static void test_random_unaligned_small(struct ft_env *fte)
{
	const size_t len = 7907;

	test_random_unaligned_(fte, len, 1);
	test_random_unaligned_(fte, len, 7);
	test_random_unaligned_(fte, len, 79);
	test_random_unaligned_(fte, len, 797);
}

static void test_random_unaligned_large(struct ft_env *fte)
{
	const size_t len = 66601;

	test_random_unaligned_(fte, len, 1);
	test_random_unaligned_(fte, len, 61);
	test_random_unaligned_(fte, len, 661);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_random_aligned_blk1),
	FT_DEFTEST(test_random_aligned_blk2),
	FT_DEFTEST(test_random_aligned_blk63),
	FT_DEFTEST(test_random_aligned_mega1),
	FT_DEFTEST(test_random_aligned_mega2),
	FT_DEFTEST(test_random_aligned_mega3),
	FT_DEFTEST(test_random_unaligned_blk1),
	FT_DEFTEST(test_random_unaligned_blk2),
	FT_DEFTEST(test_random_unaligned_mega1),
	FT_DEFTEST(test_random_unaligned_mega2),
	FT_DEFTEST(test_random_unaligned_small),
	FT_DEFTEST(test_random_unaligned_large),
};

const struct ft_tests ft_test_rw_random = FT_DEFTESTS(ft_local_tests);
