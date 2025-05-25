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
#include "ftests.h"

static void test_copy_file_range_simple(struct ft_sub_exec *se)
{
	const uint64_t tail = 0xCAFEBEB;
	uint8_t *buf_src = ft_new_buf_rands(se->fte, se->len);
	uint8_t *buf_dst = ft_new_buf_rands(se->fte, se->len);
	loff_t tail_pos = ft_off_end(se->off, se->len);
	size_t iter = 0;
	int fd_src = -1;
	int fd_dst = -1;
	uint64_t xdat;

	ft_open(se->path, O_RDWR, 0600, &fd_src);
	ft_open(se->path2, O_RDWR, 0600, &fd_dst);
	while (se->keep_run && (iter++ < se->niter)) {
		xdat = 0;
		buf_src[0] ^= (uint8_t)iter;
		ft_ftruncate(fd_src, se->end);
		ft_ftruncate(fd_dst, se->end + (ssize_t)sizeof(tail));
		ft_pwriten(fd_src, buf_src, se->len, se->off);
		ft_pwriten(fd_dst, &tail, sizeof(tail), tail_pos);
		ft_copy_file_rangen(fd_src, se->off, fd_dst, se->off, se->len);
		ft_preadn(fd_dst, buf_dst, se->len, se->off);
		ft_expect_eqm(buf_src, buf_dst, se->len);
		ft_preadn(fd_dst, &xdat, sizeof(xdat), tail_pos);
		ft_expect_eqm(&tail, &xdat, sizeof(tail));
		ft_ftruncate(fd_src, 0);
	}
	ft_close(fd_src);
	ft_close(fd_dst);
}

static void
test_mt_copy_file_range_simple_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_sub_exec se[10];
	const size_t nse = FT_ARRAY_SIZE(se);

	ft_sub_setup2(se, nse, fte, 100, off, len);
	ft_sub_run(se, nse, test_copy_file_range_simple);
}

static void test_mt_copy_file_range_simple(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
		FT_MKRANGE(0, 2 * FT_1M),
		FT_MKRANGE(2 * FT_64K, 2 * FT_1M),
		FT_MKRANGE(FT_1T, 4 * FT_1M),
		FT_MKRANGE(FT_1T, FT_64K),
	};

	ft_exec_with_ranges(fte, test_mt_copy_file_range_simple_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_copy_file_range_toggle(struct ft_sub_exec *se)
{
	const size_t len = se->len;
	uint64_t head = 0xCAFEBEB;
	uint8_t *buf1 = ft_new_buf_rands(se->fte, len);
	uint8_t *buf2 = ft_new_buf_rands(se->fte, len);
	uint8_t *buf3 = ft_new_buf_zeros(se->fte, len);
	uint64_t iter = 0;
	int fd1 = -1;
	int fd2 = -1;

	ft_open(se->path, O_RDWR, 0600, &fd1);
	ft_open(se->path2, O_RDWR, 0600, &fd2);
	while (se->keep_run && (iter++ < se->niter)) {
		head |= (1UL << (iter % 32));
		ft_ftruncate(fd1, se->end);
		ft_ftruncate(fd2, se->end);
		if (iter % 2) {
			memcpy(buf1, &head, sizeof(head));
			ft_pwriten(fd1, buf1, len, se->off);
			ft_copy_file_rangen(fd1, se->off, fd2, se->off, len);
			ft_preadn(fd2, buf3, len, se->off);
			ft_expect_eqm(buf1, buf3, len);
		} else {
			memcpy(buf2, &head, sizeof(head));
			ft_pwriten(fd2, buf2, len, se->off);
			ft_copy_file_rangen(fd2, se->off, fd1, se->off, len);
			ft_preadn(fd1, buf3, len, se->off);
			ft_expect_eqm(buf2, buf3, len);
		}
	}
	ft_ftruncate(fd1, 0);
	ft_ftruncate(fd2, 0);
	ft_close(fd1);
	ft_close(fd2);
}

static void
test_mt_copy_file_range_toggle_(struct ft_env *fte, loff_t off, size_t len)
{
	struct ft_sub_exec se[10];
	const size_t nse = FT_ARRAY_SIZE(se);

	ft_sub_setup2(se, nse, fte, 100, off, len);
	ft_sub_run(se, nse, test_copy_file_range_toggle);
}

static void test_mt_copy_file_range_toggle(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_64K),     FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_1M), FT_MKRANGE(FT_1M, FT_1M),
		FT_MKRANGE(FT_1G, FT_1M),  FT_MKRANGE(FT_1T, FT_1M),
	};

	ft_exec_with_ranges(fte, test_mt_copy_file_range_toggle_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_mt_copy_file_range_simple),
	FT_DEFTEST(test_mt_copy_file_range_toggle),
};

const struct ft_tests ft_mt_copy_file_range = FT_DEFTESTS(ft_local_tests);
