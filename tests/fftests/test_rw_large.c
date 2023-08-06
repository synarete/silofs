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

struct ft_rw_large_args {
	loff_t off_base;
	size_t nskip;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency upon n-gigbytes write in chunks of 1M
 */
static void test_ngiga_rdwr_by_(struct ft_env *fte, int fd,
                                const struct ft_rw_large_args *args)
{
	const loff_t off_base = args->off_base;
	const size_t nskip = args->nskip;
	const size_t bsz = FT_MEGA;
	const size_t cnt = FT_GIGA / bsz;
	void *buf = ft_new_buf_rands(fte, bsz);
	size_t num = 0;
	loff_t off = -1;

	for (size_t i = 0; i < cnt; ++i) {
		num = i + 1;
		off = off_base + (loff_t)(i * (bsz + nskip));

		ft_pwriten(fd, buf, bsz, off);
		ft_pwriten(fd, &num, sizeof(num), off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		num = 0;
		off = off_base + (loff_t)(i * (bsz + nskip));

		ft_preadn(fd, &num, sizeof(num), off);
		ft_expect_eq(num, i + 1);
		ft_preadn(fd, buf, bsz, off);
	}
}

static void test_ngiga_rdwr_(struct ft_env *fte,
                             const struct ft_rw_large_args *args)
{
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	test_ngiga_rdwr_by_(fte, fd, args);
	ft_close(fd);
	ft_unlink(path);
}

static void test_ngiga_rdwr_unlinked_(struct ft_env *fte,
                                      const struct ft_rw_large_args *args)
{
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_unlink(path);
	test_ngiga_rdwr_by_(fte, fd, args);
	ft_close(fd);
}

static void test_large_simple(struct ft_env *fte)
{
	const struct ft_rw_large_args args[] = {
		{ 0, 0 },
		{ 0, FT_MEGA },
		{ FT_TERA, FT_GIGA },
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(args); ++i) {
		test_ngiga_rdwr_(fte, &args[i]);
		ft_relax_mem(fte);
	}
}

static void test_large_unaligned(struct ft_env *fte)
{
	const struct ft_rw_large_args args[] = {
		{ 1, 1 },
		{ FT_MEGA - 5, 7 * FT_MEGA + 7 },
		{ FT_TERA - 11, 11 * FT_MEGA + 1 },
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(args); ++i) {
		test_ngiga_rdwr_(fte, &args[i]);
		ft_relax_mem(fte);
	}
}

static void test_large_unlinked(struct ft_env *fte)
{
	const struct ft_rw_large_args args[] = {
		{ 0, 0 },
		{ FT_1K, FT_MEGA },
		{ FT_MEGA - 5, 7 * FT_MEGA + 7 },
		{ FT_TERA - 11, 11 * FT_MEGA + 1 },
	};


	for (size_t i = 0; i < FT_ARRAY_SIZE(args); ++i) {
		test_ngiga_rdwr_unlinked_(fte, &args[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_large_simple),
	FT_DEFTEST(test_large_unaligned),
	FT_DEFTEST(test_large_unlinked),
};

const struct ft_tests ft_test_rw_large = FT_DEFTESTS(ft_local_tests);
