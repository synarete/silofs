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
	int fd = -1;
	loff_t pos;
	size_t nwr = 0;
	size_t nrd = 0;
	void *buf1 = NULL;
	void *buf2 = ft_new_buf_zeros(fte, bsz);
	char *path = ft_new_path_unique(fte);
	const size_t nitr = rewrite ? 2 : 1;

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

static void test_sequencial_io(struct ft_env *fte,
                               loff_t from, size_t bsz, size_t cnt)
{
	test_sequencial_(fte, from, bsz, cnt, 0);
	test_sequencial_(fte, from, bsz, cnt, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_aligned_blk(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_BK_SIZE;

	from = 0;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - (bsz * cnt));
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)((FT_UGIGA * 2) / 2);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt));
	test_sequencial_io(fte, from, bsz, cnt);
}

static void test_sequencial_aligned_blk1(struct ft_env *fte)
{
	test_sequencial_aligned_blk(fte, 1);
}

static void test_sequencial_aligned_blk2(struct ft_env *fte)
{
	test_sequencial_aligned_blk(fte, 2);
}

static void test_sequencial_aligned_blk63(struct ft_env *fte)
{
	test_sequencial_aligned_blk(fte, 63);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_aligned_mega(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_UMEGA;

	from = 0;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_UMEGA);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_UMEGA);
	test_sequencial_io(fte, from, bsz, 2 * cnt);
	from = (loff_t)(2 * FT_UGIGA);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA / 2);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt));
	test_sequencial_io(fte, from, bsz, cnt);
}

static void test_sequencial_aligned_mega1(struct ft_env *fte)
{
	test_sequencial_aligned_mega(fte, 1);
}

static void test_sequencial_aligned_mega2(struct ft_env *fte)
{
	test_sequencial_aligned_mega(fte, 2);
}

static void test_sequencial_aligned_mega3(struct ft_env *fte)
{
	test_sequencial_aligned_mega(fte, 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_unaligned_blk(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_BK_SIZE;

	from = 1;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE - 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE + 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA - 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE - 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA - 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE - 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE + 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - (bsz * cnt) + 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA / 11);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt) - 11);
	test_sequencial_io(fte, from, bsz, cnt);
}

static void test_sequencial_unaligned_blk1(struct ft_env *fte)
{
	test_sequencial_unaligned_blk(fte, 1);
}

static void test_sequencial_unaligned_blk2(struct ft_env *fte)
{
	test_sequencial_unaligned_blk(fte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_unaligned_mega(struct ft_env *fte, size_t cnt)
{
	loff_t from;
	const size_t bsz = FT_UMEGA;

	from = 1;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE - 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_BK_SIZE + 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UMEGA - 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UMEGA - FT_BK_SIZE - 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)FT_UGIGA - 11;
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - FT_BK_SIZE - 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA + FT_BK_SIZE + 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA - (bsz * cnt) + 1);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UGIGA / 11);
	test_sequencial_io(fte, from, bsz, cnt);
	from = (loff_t)(FT_UTERA - (bsz * cnt) - 11);
	test_sequencial_io(fte, from, bsz, cnt);
}

static void test_sequencial_unaligned_mega1(struct ft_env *fte)
{
	test_sequencial_unaligned_mega(fte, 1);
}

static void test_sequencial_unaligned_mega2(struct ft_env *fte)
{
	test_sequencial_unaligned_mega(fte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_unaligned_(struct ft_env *fte, size_t len, size_t cnt)
{
	loff_t from;

	from = 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)FT_BK_SIZE - 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)FT_BK_SIZE + 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)FT_UMEGA - 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)FT_UMEGA / 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)FT_UGIGA - 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)FT_UGIGA / 7;
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)(FT_UGIGA + (len * cnt) - 7);
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)((FT_UGIGA / 7) - 7);
	test_sequencial_io(fte, from, len, cnt);
	from = (loff_t)(FT_UTERA - (len * cnt) - 7);
	test_sequencial_io(fte, from, len, cnt);
}

static void test_sequencial_unaligned_small(struct ft_env *fte)
{
	const size_t len = 7907;

	test_sequencial_unaligned_(fte, len, 1);
	test_sequencial_unaligned_(fte, len, 7);
	test_sequencial_unaligned_(fte, len, 79);
	test_sequencial_unaligned_(fte, len, 797);
}

static void test_sequencial_unaligned_large(struct ft_env *fte)
{
	const size_t len = 66601;

	test_sequencial_unaligned_(fte, len, 1);
	test_sequencial_unaligned_(fte, len, 61);
	test_sequencial_unaligned_(fte, len, 661);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of sequential writes followed by sequential reads
 * of variable length strings
 */
static void test_sequencial_nstrings(struct ft_env *fte,
                                     loff_t start_off, size_t cnt)
{
	int fd = -1;
	int ni = 0;
	loff_t pos = -1;
	size_t nu;
	size_t nwr = 0;
	size_t nrd = 0;
	char buf1[128] = "";
	char buf2[128] = "";
	const char *path = ft_new_path_unique(fte);
	const int whence = SEEK_SET;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_llseek(fd, start_off, whence, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ni = snprintf(buf1, sizeof(buf1), "%lu", i);
		nu = (size_t)ni;
		ft_expect_eq(nu, strlen(buf1));
		ft_write(fd, buf1, nu, &nwr);
		ft_expect_eq(nu, nwr);
	}
	ft_llseek(fd, start_off, whence, &pos);
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

static void test_sequencial_nstrings_(struct ft_env *fte,
                                      size_t n)
{
	test_sequencial_nstrings(fte, 0, n);
	test_sequencial_nstrings(fte, FT_BK_SIZE - 1, n);
	test_sequencial_nstrings(fte, FT_BK_SIZE, n);
	test_sequencial_nstrings(fte, FT_UMEGA - 1, n);
	test_sequencial_nstrings(fte, FT_UGIGA, n);
}

static void test_sequencial_strings10(struct ft_env *fte)
{
	test_sequencial_nstrings_(fte, 10);
}

static void test_sequencial_strings100(struct ft_env *fte)
{
	test_sequencial_nstrings_(fte, 100);
}

static void test_sequencial_strings1000(struct ft_env *fte)
{
	test_sequencial_nstrings_(fte, 1000);
}

static void test_sequencial_strings10000(struct ft_env *fte)
{
	test_sequencial_nstrings_(fte, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_sequencial_aligned_blk1),
	FT_DEFTEST(test_sequencial_aligned_blk2),
	FT_DEFTEST(test_sequencial_aligned_blk63),
	FT_DEFTEST(test_sequencial_aligned_mega1),
	FT_DEFTEST(test_sequencial_aligned_mega2),
	FT_DEFTEST(test_sequencial_aligned_mega3),
	FT_DEFTEST(test_sequencial_unaligned_blk1),
	FT_DEFTEST(test_sequencial_unaligned_blk2),
	FT_DEFTEST(test_sequencial_unaligned_mega1),
	FT_DEFTEST(test_sequencial_unaligned_mega2),
	FT_DEFTEST(test_sequencial_unaligned_small),
	FT_DEFTEST(test_sequencial_unaligned_large),
	FT_DEFTEST(test_sequencial_strings10),
	FT_DEFTEST(test_sequencial_strings100),
	FT_DEFTEST(test_sequencial_strings1000),
	FT_DEFTEST(test_sequencial_strings10000),
};

const struct ft_tests ft_test_rw_sequencial = FT_DEFTESTS(ft_local_tests);

