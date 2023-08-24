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

struct ft_copy_range_args {
	loff_t off_src;
	size_t len_src;
	loff_t off_dst;
	size_t len_dst;
};

#define COPYARGS1(a_, b_) \
	{ .off_src = (a_), .len_src = (b_) }

#define COPYARGS2(a_, b_, c_, d_) \
	{ .off_src = (a_), .len_src = (b_), .off_dst = (c_), .len_dst = (d_) }

#define COPYARGS3(a_, b_, c_) \
	{ .off_src = (a_), .len_src = (c_), .off_dst = (b_), .len_dst = (c_) }


#define ft_copy_range1(fte_, fn_, args_) \
	ft_copy_range1_(fte_, fn_, args_, FT_ARRAY_SIZE(args_))

#define ft_copy_range2(fte_, fn_, args_) \
	ft_copy_range2_(fte_, fn_, args_, FT_ARRAY_SIZE(args_))

#define ft_copy_range3(fte_, fn_, args_) \
	ft_copy_range3_(fte_, fn_, args_, FT_ARRAY_SIZE(args_))

static void ft_copy_range1_(struct ft_env *fte,
                            void (*fn)(struct ft_env *, loff_t, size_t),
                            const struct ft_copy_range_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(fte, args[i].off_src, args[i].len_src);
		ft_relax_mem(fte);
	}
}

static void
ft_copy_range2_(struct ft_env *fte,
                void (*fn)(struct ft_env *, loff_t, size_t, loff_t, size_t),
                const struct ft_copy_range_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(fte, args[i].off_src, args[i].len_src,
		   args[i].off_dst, args[i].len_dst);
		ft_relax_mem(fte);
	}
}

static void
ft_copy_range3_(struct ft_env *fte,
                void (*fn)(struct ft_env *, size_t, loff_t, loff_t),
                const struct ft_copy_range_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(fte, args[i].len_src, args[i].off_src, args[i].off_dst);
		ft_relax_mem(fte);
	}
}

/* TODO: make me common util */
static size_t ft_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

static size_t ft_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

static long ft_lmax(long a, long b)
{
	return (a > b) ? a : b;
}

static loff_t ft_off_end(loff_t off, size_t len)
{
	return off + (long)len;
}

static void ft_close2(int fd1, int fd2)
{
	ft_close(fd1);
	ft_close(fd2);
}

static void ft_unlink2(const char *path1, const char *path2)
{
	ft_unlink(path1);
	ft_unlink(path2);
}

static void ft_copy_file_rangen(int fd_src, loff_t off_in, int fd_dst,
                                loff_t off_out, size_t len)
{
	size_t ncp = 0;
	loff_t off_src = off_in;
	loff_t off_dst = off_out;

	ft_copy_file_range(fd_src, &off_src, fd_dst, &off_dst, len, &ncp);
	ft_expect_eq(len, ncp);
	ft_expect_eq(off_in + (long)ncp, off_src);
	ft_expect_eq(off_out + (long)ncp, off_dst);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects copy_file_range(2) to successfully reflink-copy partial file range
 * between two files.
 */
static void test_copy_file_range_(struct ft_env *fte,
                                  loff_t off_src, size_t len_src,
                                  loff_t off_dst, size_t len_dst)
{
	const char *path_src = ft_new_path_unique(fte);
	const char *path_dst = ft_new_path_unique(fte);
	const size_t len = ft_max(len_src, len_dst);
	void *buf_src = ft_new_buf_rands(fte, len);
	void *buf_dst = ft_new_buf_rands(fte, len);
	int fd_src = -1;
	int fd_dst = -1;

	ft_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	ft_ftruncate(fd_src, ft_off_end(off_src, len));
	ft_ftruncate(fd_dst, ft_off_end(off_dst, len));
	ft_pwriten(fd_src, buf_src, len_src, off_src);
	ft_pwriten(fd_dst, buf_dst, len_dst, off_dst);
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	ft_preadn(fd_src, buf_src, len, off_src);
	ft_preadn(fd_dst, buf_dst, len, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_ftruncate(fd_src, off_src);
	ft_ftruncate(fd_src, ft_off_end(off_src, len));
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	ft_preadn(fd_src, buf_src, len, off_src);
	ft_preadn(fd_dst, buf_dst, len, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_close2(fd_src, fd_dst);
	ft_unlink2(path_src, path_dst);
}

static void test_copy_file_range_aligned(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		COPYARGS2(0, FT_1K, 0, FT_1K),
		COPYARGS2(0, FT_1K, FT_1K, FT_1K),
		COPYARGS2(FT_1K, FT_1K, 0, FT_1K),
		COPYARGS2(FT_1K, FT_1K, FT_1K, FT_1K),
		COPYARGS2(0, FT_1K, 2 * FT_1K, 2 * FT_1K),
		COPYARGS2(0, FT_4K, 0, FT_4K),
		COPYARGS2(FT_4K, FT_4K, FT_4K, FT_4K),
		COPYARGS2(FT_4K, FT_4K, 2 * FT_4K, 2 * FT_4K),
		COPYARGS2(2 * FT_4K, 4 * FT_4K, FT_4K, 2 * FT_4K),
		COPYARGS2(0, FT_4K, FT_1K, FT_4K),
		COPYARGS2(FT_1K, 2 * FT_4K, FT_4K, 3 * FT_4K),
		COPYARGS2(0, FT_64K, 0, FT_64K),
		COPYARGS2(FT_64K, FT_64K, FT_64K, FT_64K),
		COPYARGS2(FT_MEGA, FT_64K, 0, FT_64K),
		COPYARGS2(FT_MEGA, FT_64K, FT_GIGA, 2 * FT_64K),
		COPYARGS2(FT_TERA, 3 * FT_64K, FT_MEGA, FT_64K),
		COPYARGS2(FT_TERA, 3 * FT_64K, 0, FT_MEGA),
	};

	ft_copy_range2(fte, test_copy_file_range_, args);
}

static void test_copy_file_range_unaligned(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		COPYARGS2(1, FT_1K - 1, 1, FT_1K - 1),
		COPYARGS2(1, FT_1K - 1, 1, FT_1K - 1),
		COPYARGS2(1, FT_1K + 1, FT_1K + 2, FT_1K + 2),
		COPYARGS2(FT_1K + 3, 3 * FT_1K + 1, 3, 3 * FT_1K),
		COPYARGS2(FT_1K + 11, FT_1K + 1, FT_1K - 1, FT_1K),
		COPYARGS2(7, FT_1K + 17, 7 * FT_1K + 1, 17 * FT_1K),
		COPYARGS2(1, FT_4K - 1, 2, FT_4K - 2),
		COPYARGS2(FT_4K + 1, FT_4K + 1, FT_4K + 1, FT_4K + 1),
		COPYARGS2(FT_4K, FT_4K, 2 * FT_4K - 1, 2 * FT_4K + 3),
		COPYARGS2(2 * FT_4K + 2, 4 * FT_4K, FT_4K + 1, FT_4K),
		COPYARGS2(1, FT_4K, FT_1K + 1, FT_4K + 11),
		COPYARGS2(1, FT_64K + 11, 11, FT_64K + 1),
		COPYARGS2(FT_64K + 11, 11 * FT_64K, FT_64K + 1, FT_64K - 11),
		COPYARGS2(FT_MEGA - 1, FT_64K - 2, 1, FT_64K - 3),
		COPYARGS2(FT_MEGA + 11, FT_MEGA,
		          FT_GIGA + 111, FT_MEGA + 1111),
		COPYARGS2(FT_TERA + 111, FT_MEGA + 333, FT_MEGA - 111, 11111),
		COPYARGS2(FT_TERA - 1111, 111111, 1, FT_MEGA + 1111),
	};

	ft_copy_range2(fte, test_copy_file_range_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects copy_file_range(2) to successfully reflink-copy partial file range
 * between regions within same file.
 */
static void test_copy_file_range_self_(struct ft_env *fte,
                                       loff_t off_src, size_t len_src,
                                       loff_t off_dst, size_t len_dst)
{
	const char *path = ft_new_path_unique(fte);
	const size_t len = ft_max(len_src, len_dst);
	const size_t len_max = ft_max(len_src, len_dst);
	const loff_t off_max = ft_off_end(ft_lmax(off_src, off_dst), len_max);
	void *buf_src = ft_new_buf_rands(fte, len);
	void *buf_dst = ft_new_buf_rands(fte, len);
	int fd_src = -1;
	int fd_dst = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path, O_RDWR, 0600, &fd_dst);
	ft_ftruncate(fd_src, off_max);
	ft_pwriten(fd_src, buf_src, len_src, off_src);
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	ft_preadn(fd_src, buf_src, len, off_src);
	ft_preadn(fd_dst, buf_dst, len, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_ftruncate(fd_src, 0);
	ft_ftruncate(fd_src, off_max);
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	ft_preadn(fd_src, buf_src, len, off_src);
	ft_preadn(fd_dst, buf_dst, len, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_close2(fd_src, fd_dst);
	ft_unlink(path);
}

static void
test_copy_file_range_self2_(struct ft_env *fte,
                            loff_t off1, size_t len1, loff_t off2, size_t len2)
{
	test_copy_file_range_self_(fte, off1, len1, off2, len2);
	test_copy_file_range_self_(fte, off2, len2, off1, len1);
}

static void test_copy_file_range_self(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		/* aligned */
		COPYARGS2(0, FT_1K, FT_1K, FT_1K),
		COPYARGS2(0, FT_1K, FT_64K, FT_1K),
		COPYARGS2(0, FT_1K, FT_4K, FT_4K),
		COPYARGS2(FT_1K, FT_4K, FT_64K, FT_4K),
		COPYARGS2(FT_64K, FT_64K, 4 * FT_64K, FT_4K),
		COPYARGS2(FT_MEGA, FT_64K, FT_GIGA, FT_MEGA),
		COPYARGS2(FT_GIGA, FT_MEGA, 0, FT_4K),
		COPYARGS2(FT_GIGA, FT_MEGA, FT_TERA, FT_MEGA / 2),
		/* unaligned */
		COPYARGS2(1, FT_1K - 1, 2 * FT_1K + 1, FT_1K + 1),
		COPYARGS2(FT_4K + 1, FT_4K - 1, FT_64K - 1, FT_4K + 1),
		COPYARGS2(2 * FT_64K + 11, FT_64K - 111, FT_MEGA - 1, 11111),
		COPYARGS2(FT_MEGA - 1, 11111, 333, 33333),
		COPYARGS2(FT_GIGA - 111, 11111, FT_64K - 11, FT_64K + 111),
		COPYARGS2(FT_TERA - 1111, 11111, FT_64K - 111, FT_64K + 1111),
	};

	ft_copy_range2(fte, test_copy_file_range_self2_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_between_(struct ft_env *fte,
                              loff_t off_src, size_t len_src,
                              loff_t off_dst, size_t len_dst)
{
	const char *path_src = ft_new_path_unique(fte);
	const char *path_dst = ft_new_path_unique(fte);
	const size_t len_max = ft_max(len_src, len_dst);
	const size_t len_min = ft_min(len_src, len_dst);
	void *buf_src = ft_new_buf_rands(fte, len_max);
	void *buf_dst = ft_new_buf_rands(fte, len_max);
	void *buf_alt = ft_new_buf_rands(fte, len_max);
	void *buf_zeros = ft_new_buf_zeros(fte, len_max);
	int fd_src = -1;
	int fd_dst = -1;

	ft_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	ft_ftruncate(fd_src, ft_off_end(off_src, len_max));
	ft_ftruncate(fd_dst, ft_off_end(off_dst, len_max));
	ft_pwriten(fd_src, buf_src, len_src, off_src);
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len_dst);
	ft_preadn(fd_src, buf_src, len_min, off_src);
	ft_preadn(fd_dst, buf_dst, len_min, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len_min);
	ft_preadn(fd_dst, buf_alt, len_dst - len_min,
	          ft_off_end(off_dst, len_min));
	ft_expect_eqm(buf_alt, buf_zeros, len_dst - len_min);
	ft_close2(fd_src, fd_dst);
	ft_unlink2(path_src, path_dst);
}

static void test_copy_file_range_between(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		/* aligned */
		COPYARGS2(0, FT_1K, 0, FT_1K),
		COPYARGS2(0, FT_1K, FT_1K, FT_1K),
		COPYARGS2(FT_1K, FT_1K, 0, FT_1K),
		COPYARGS2(FT_1K, FT_1K, FT_1K, FT_1K),
		COPYARGS2(0, FT_1K, 2 * FT_1K, 2 * FT_1K),
		COPYARGS2(0, FT_4K, 0, FT_4K),
		COPYARGS2(FT_4K, FT_4K, FT_4K, FT_4K),
		COPYARGS2(FT_4K, FT_4K, 2 * FT_4K, 2 * FT_4K),
		COPYARGS2(2 * FT_4K, 4 * FT_4K, FT_4K, 2 * FT_4K),
		COPYARGS2(0, FT_4K, FT_1K, FT_4K),
		COPYARGS2(FT_1K, 2 * FT_4K, FT_4K, 3 * FT_4K),
		COPYARGS2(0, FT_64K, 0, FT_64K),
		COPYARGS2(FT_64K, FT_64K, FT_64K, FT_64K),
		COPYARGS2(FT_MEGA, FT_64K, 0, FT_64K),
		COPYARGS2(FT_MEGA, FT_64K, FT_GIGA, 2 * FT_64K),
		COPYARGS2(FT_TERA, 3 * FT_64K, FT_MEGA, FT_64K),
		COPYARGS2(FT_TERA, 3 * FT_64K, 0, FT_MEGA),
		/* unaligned */
		COPYARGS2(1, FT_1K - 1, 1, FT_1K - 1),
		COPYARGS2(1, FT_1K - 1, 1, FT_1K - 1),
		COPYARGS2(1, FT_1K + 1, FT_1K + 2, FT_1K + 2),
		COPYARGS2(FT_1K + 3, 3 * FT_1K + 1, 3, 3 * FT_1K),
		COPYARGS2(FT_1K + 11, FT_1K + 1, FT_1K - 1, FT_1K),
		COPYARGS2(7, FT_1K + 17, 7 * FT_1K + 1, 17 * FT_1K),
		COPYARGS2(1, FT_4K - 1, 2, FT_4K - 2),
		COPYARGS2(FT_4K + 1, FT_4K + 1, FT_4K + 1, FT_4K + 1),
		COPYARGS2(FT_4K, FT_4K, 2 * FT_4K - 1, 2 * FT_4K + 3),
		COPYARGS2(2 * FT_4K + 2, 4 * FT_4K, FT_4K + 1, FT_4K),
		COPYARGS2(1, FT_4K, FT_1K + 1, FT_4K + 11),
		COPYARGS2(1, FT_64K + 11, 11, FT_64K + 1),
		COPYARGS2(FT_64K + 11, 11 * FT_64K, FT_64K + 1, FT_64K - 11),
		COPYARGS2(FT_MEGA - 1, FT_64K - 2, 1, FT_64K - 3),
		COPYARGS2(FT_MEGA + 11, FT_MEGA, FT_GIGA + 11, FT_MEGA + 1111),
		COPYARGS2(FT_TERA + 111, FT_MEGA + 333, FT_MEGA - 111, 11111),
		COPYARGS2(FT_TERA - 1111, 111111, 1, FT_MEGA + 1111),
	};

	ft_copy_range2(fte, test_copy_file_range_between_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_truncate_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path_src = ft_new_path_unique(fte);
	const char *path_dst = ft_new_path_unique(fte);
	uint8_t *buf_src = ft_new_buf_rands(fte, len);
	uint8_t *buf_alt = ft_new_buf_rands(fte, len);
	const loff_t end = ft_off_end(off, len);
	int fd_src = -1;
	int fd_dst = -1;
	uint8_t byte = 0;

	ft_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	ft_pwriten(fd_src, buf_src, len, off);
	ft_ftruncate(fd_dst, end);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_preadn(fd_dst, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_ftruncate(fd_dst, end - 1);
	ft_ftruncate(fd_dst, end);
	ft_preadn(fd_dst, buf_alt, len - 1, off);
	ft_expect_eqm(buf_src, buf_alt, len - 1);
	ft_preadn(fd_dst, &byte, 1, end - 1);
	ft_expect_eq(byte, 0);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_ftruncate(fd_dst, off + 1);
	ft_ftruncate(fd_dst, end);
	ft_preadn(fd_dst, &byte, 1, off);
	ft_expect_eq(byte, buf_src[0]);
	ft_preadn(fd_dst, &byte, 1, off + 1);
	ft_expect_eq(byte, 0);
	ft_preadn(fd_dst, &byte, 1, end - 1);
	ft_expect_eq(byte, 0);
	ft_close2(fd_src, fd_dst);
	ft_unlink2(path_src, path_dst);
}

static void test_copy_file_range_truncate(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		COPYARGS1(0, FT_1K),
		COPYARGS1(0, FT_4K),
		COPYARGS1(FT_1K, FT_4K),
		COPYARGS1(0, FT_64K),
		COPYARGS1(FT_64K, FT_64K),
		COPYARGS1(2 * FT_64K, 4 * FT_64K),
		COPYARGS1(0, FT_MEGA),
		COPYARGS1(FT_MEGA, FT_MEGA),
		COPYARGS1(FT_GIGA, FT_64K),
		COPYARGS1(FT_TERA, FT_4K),
		COPYARGS1(1, FT_1K - 1),
		COPYARGS1(FT_4K - 1, FT_4K + 3),
		COPYARGS1(FT_64K - 3, FT_MEGA),
		COPYARGS1((2 * FT_64K) - 3, FT_MEGA),
		COPYARGS1(FT_GIGA - 3, FT_64K + 5),
		COPYARGS1(FT_TERA - 3, FT_MEGA + 5),
	};

	ft_copy_range1(fte, test_copy_file_range_truncate_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_overwrite_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path_src = ft_new_path_unique(fte);
	const char *path_dst = ft_new_path_unique(fte);
	uint8_t *buf_src = ft_new_buf_rands(fte, len);
	uint8_t *buf_dst = ft_new_buf_rands(fte, len);
	uint8_t *buf_alt = ft_new_buf_rands(fte, len);
	const loff_t end = ft_off_end(off, len);
	int fd_src = -1;
	int fd_dst = -1;

	ft_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	ft_pwriten(fd_src, buf_src, len, off);
	ft_ftruncate(fd_dst, end);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_preadn(fd_dst, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_preadn(fd_src, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_preadn(fd_dst, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_preadn(fd_src, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_ftruncate(fd_dst, end - 1);
	ft_ftruncate(fd_dst, end);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_preadn(fd_dst, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_preadn(fd_src, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_pwriten(fd_dst, buf_dst, len, off);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_preadn(fd_dst, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_preadn(fd_src, buf_alt, len, off);
	ft_expect_eqm(buf_src, buf_alt, len);
	ft_ftruncate(fd_src, 0);
	ft_ftruncate(fd_src, end);
	ft_preadn(fd_src, buf_alt, len, off);
	ft_expect_eq(buf_alt[0], 0);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_preadn(fd_dst, buf_alt, len, off);
	ft_expect_eq(buf_alt[0], 0);
	ft_close2(fd_src, fd_dst);
	ft_unlink2(path_src, path_dst);
}

static void test_copy_file_range_overwrite(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		COPYARGS1(0, FT_1K),
		COPYARGS1(0, FT_4K),
		COPYARGS1(FT_1K, FT_4K),
		COPYARGS1(0, FT_64K),
		COPYARGS1(FT_64K, FT_64K),
		COPYARGS1(2 * FT_64K, 4 * FT_64K),
		COPYARGS1(0, FT_MEGA),
		COPYARGS1(FT_MEGA, FT_MEGA),
		COPYARGS1(FT_GIGA, FT_64K),
		COPYARGS1(FT_TERA, FT_4K),
		COPYARGS1(1, FT_1K - 1),
		COPYARGS1(FT_4K - 1, FT_4K + 3),
		COPYARGS1(FT_64K - 3, FT_MEGA),
		COPYARGS1((2 * FT_64K) - 3, FT_MEGA),
		COPYARGS1(FT_GIGA - 3, FT_64K + 5),
		COPYARGS1(FT_TERA - 3, FT_MEGA + 5),
	};

	ft_copy_range1(fte, test_copy_file_range_overwrite_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_nfiles_(struct ft_env *fte, loff_t off, size_t len)
{
	const loff_t end = ft_off_end(off, len);
	uint8_t *buf_src = ft_new_buf_rands(fte, len);
	uint8_t *buf_alt = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	const char *name_src = ft_new_name_unique(fte);
	const char *name_dst = NULL;
	const size_t nfiles = 256;
	int dfd = -1;
	int fd_src = -1;
	int fd_dst = -1;

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	ft_openat(dfd, name_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_pwriten(fd_src, buf_src, len, off);
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = ft_make_ulong_name(fte, i);
		ft_openat(dfd, name_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
		ft_ftruncate(fd_dst, end);
		ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
		ft_preadn(fd_dst, buf_alt, len, off);
		ft_expect_eqm(buf_src, buf_alt, len);
		ft_close(fd_dst);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = ft_make_ulong_name(fte, i);
		ft_unlinkat(dfd, name_dst, 0);
	}
	ft_close(fd_src);
	ft_unlinkat(dfd, name_src, 0);
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_copy_file_range_nfiles(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		COPYARGS1(0, FT_1K),
		COPYARGS1(0, FT_4K),
		COPYARGS1(FT_1K, FT_4K),
		COPYARGS1(0, FT_64K),
		COPYARGS1(FT_64K, FT_64K),
		COPYARGS1(2 * FT_64K, 4 * FT_64K),
		COPYARGS1(0, FT_MEGA / 4),
		COPYARGS1(FT_MEGA, FT_MEGA / 8),
		COPYARGS1(FT_GIGA, FT_64K),
		COPYARGS1(FT_TERA, FT_4K),
		COPYARGS1(1, FT_1K - 1),
		COPYARGS1(FT_4K - 1, FT_4K + 3),
		COPYARGS1(FT_64K - 3, FT_MEGA / 16),
		COPYARGS1((2 * FT_64K) - 3, FT_MEGA / 32),
		COPYARGS1(FT_GIGA - 3, FT_64K + 5),
		COPYARGS1(FT_TERA - 3, FT_MEGA + 5),
	};

	ft_copy_range1(fte, test_copy_file_range_nfiles_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects copy_file_range(2) to update mtime of destination-file upon
 * successful completion.
 */
static void test_copy_file_range_mtime_(struct ft_env *fte, size_t len,
                                        loff_t off_src, loff_t off_dst)
{
	struct stat st[3];
	void *buf_src = ft_new_buf_rands(fte, len);
	void *buf_dst = ft_new_buf_rands(fte, len);
	const char *path_src = ft_new_path_unique(fte);
	const char *path_dst = ft_new_path_unique(fte);
	int fd_src = -1;
	int fd_dst = -1;

	ft_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	ft_ftruncate(fd_src, ft_off_end(off_src, len));
	ft_ftruncate(fd_dst, ft_off_end(off_dst, len));
	ft_fstat(fd_dst, &st[0]);
	ft_pwriten(fd_src, buf_src, len, off_src);
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	ft_fstat(fd_dst, &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_preadn(fd_src, buf_src, len, off_src);
	ft_preadn(fd_dst, buf_dst, len, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_ftruncate(fd_dst, 0);
	ft_ftruncate(fd_dst, ft_off_end(off_dst, len));
	ft_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	ft_fstat(fd_dst, &st[2]);
	ft_expect_mtime_gt(&st[1], &st[2]);
	ft_preadn(fd_src, buf_src, len, off_src);
	ft_preadn(fd_dst, buf_dst, len, off_dst);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_close2(fd_src, fd_dst);
	ft_unlink2(path_src, path_dst);
}

static void test_copy_file_range_mtime(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		/* aligned */
		COPYARGS3(0, 0, 1),
		COPYARGS3(0, 0, FT_64K),
		COPYARGS3(0, FT_64K, FT_64K),
		COPYARGS3(FT_4K, FT_64K, 4 * FT_64K),
		COPYARGS3(FT_64K, FT_64K, FT_MEGA),
		COPYARGS3(FT_MEGA, FT_64K, FT_GIGA),
		COPYARGS3(FT_GIGA, FT_MEGA, FT_MEGA),
		COPYARGS3(FT_TERA, FT_GIGA, FT_MEGA / 2),
		/* unaligned */
		COPYARGS3(1, 11, FT_64K),
		COPYARGS3(1, FT_64K - 1, 3 * FT_64K + 3),
		COPYARGS3(FT_MEGA - 1, FT_64K, FT_MEGA),
		COPYARGS3(FT_GIGA - 1, FT_MEGA - 1, FT_MEGA + 11),
		COPYARGS3(FT_TERA, FT_GIGA - 1, FT_MEGA + 11),
	};

	ft_copy_range3(fte, test_copy_file_range_mtime_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects copy_file_range(2) over zero-length destination file to extend it
 * upon successful completion.
 */
static void
test_copy_file_range_extend_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st[2];
	void *buf_src = ft_new_buf_rands(fte, len);
	void *buf_dst = ft_new_buf_rands(fte, len);
	const char *path_src = ft_new_path_unique(fte);
	const char *path_dst = ft_new_path_unique(fte);
	const loff_t end = ft_off_end(off, len);
	int fd_src = -1;
	int fd_dst = -1;

	ft_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	ft_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	ft_pwriten(fd_src, buf_src, len, off);
	ft_fstat(fd_dst, &st[0]);
	ft_copy_file_rangen(fd_src, off, fd_dst, off, len);
	ft_fstat(fd_dst, &st[1]);
	ft_expect_eq(st[1].st_size, end);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_preadn(fd_dst, buf_dst, len, off);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_ftruncate(fd_src, 0);
	ft_preadn(fd_dst, buf_dst, len, off);
	ft_expect_eqm(buf_src, buf_dst, len);
	ft_close2(fd_src, fd_dst);
	ft_unlink2(path_src, path_dst);
}

static void test_file_copy_range_extend(struct ft_env *fte)
{
	const struct ft_copy_range_args args[] = {
		/* aligned */
		COPYARGS1(0, FT_1K),
		COPYARGS1(0, FT_4K),
		COPYARGS1(0, FT_64K),
		COPYARGS1(FT_1K, FT_4K),
		COPYARGS1(FT_1K, FT_64K),
		COPYARGS1(FT_64K, FT_64K),
		COPYARGS1(FT_64K, FT_MEGA),
		COPYARGS1(FT_MEGA, FT_64K),
		COPYARGS1(FT_GIGA, FT_MEGA),
		COPYARGS1(FT_TERA, 2 * FT_64K),
		/* unaligned */
		COPYARGS1(1, FT_1K + 11),
		COPYARGS1(11, FT_4K - 111),
		COPYARGS1(111, FT_64K + 1111),
		COPYARGS1(FT_1K + 1, FT_4K + 11),
		COPYARGS1(FT_1K - 11, FT_64K + 111),
		COPYARGS1(FT_64K - 1, FT_64K + 11),
		COPYARGS1(FT_64K + 11, FT_MEGA - 111),
		COPYARGS1(FT_MEGA - 111, FT_64K + 1111),
		COPYARGS1(FT_GIGA + 11, FT_MEGA - 11111),
		COPYARGS1(FT_TERA - 1111, 11 * FT_64K + 1),
	};

	ft_copy_range1(fte, test_copy_file_range_extend_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_copy_file_range_aligned),
	FT_DEFTEST(test_copy_file_range_unaligned),
	FT_DEFTEST(test_copy_file_range_self),
	FT_DEFTEST(test_copy_file_range_between),
	FT_DEFTEST(test_copy_file_range_truncate),
	FT_DEFTEST(test_copy_file_range_overwrite),
	FT_DEFTEST(test_copy_file_range_nfiles),
	FT_DEFTEST(test_copy_file_range_mtime),
	FT_DEFTEST(test_file_copy_range_extend),
};

const struct ft_tests
ft_test_copy_file_range = FT_DEFTESTS(ft_local_tests);
