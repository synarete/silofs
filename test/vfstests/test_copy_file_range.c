/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include "vfstests.h"

struct vt_copy_args {
	loff_t off_src;
	size_t len_src;
	loff_t off_dst;
	size_t len_dst;
};

#define COPYARGS(a_, b_, c_, d_) \
	{ .off_src = (a_), .len_src = (b_), .off_dst = (c_), .len_dst = (d_) }


/* TODO: make me common util */
static size_t vt_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

static long vt_lmax(long a, long b)
{
	return (a > b) ? a : b;
}

static void vt_close2(int fd1, int fd2)
{
	vt_close(fd1);
	vt_close(fd2);
}

static void vt_unlink2(const char *path1, const char *path2)
{
	vt_unlink(path1);
	vt_unlink(path2);
}

static void vt_copy_file_rangen(int fd_src, loff_t off_in, int fd_dst,
                                loff_t off_out, size_t len)
{
	size_t ncp = 0;
	loff_t off_src = off_in;
	loff_t off_dst = off_out;

	vt_copy_file_range(fd_src, &off_src, fd_dst, &off_dst, len, &ncp);
	vt_expect_eq(len, ncp);
	vt_expect_eq(off_in + (long)ncp, off_src);
	vt_expect_eq(off_out + (long)ncp, off_dst);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects copy_file_range(2) to successfully reflink-copy partial file range
 * between two files.
 */
static void test_copy_file_range_(struct vt_env *vte,
                                  loff_t off_src, size_t len_src,
                                  loff_t off_dst, size_t len_dst)
{
	int fd_src = -1;
	int fd_dst = -1;
	const size_t len = vt_max(len_src, len_dst);
	void *buf_src = vt_new_buf_rands(vte, len);
	void *buf_dst = vt_new_buf_rands(vte, len);
	const char *path_src = vt_new_path_unique(vte);
	const char *path_dst = vt_new_path_unique(vte);

	vt_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	vt_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	vt_ftruncate(fd_src, off_src + (long)len);
	vt_ftruncate(fd_dst, off_dst + (long)len);
	vt_pwriten(fd_src, buf_src, len_src, off_src);
	vt_pwriten(fd_dst, buf_dst, len_dst, off_dst);
	vt_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	vt_preadn(fd_src, buf_src, len, off_src);
	vt_preadn(fd_dst, buf_dst, len, off_dst);
	vt_expect_eqm(buf_src, buf_dst, len);
	vt_ftruncate(fd_src, off_src);
	vt_ftruncate(fd_src, off_src + (long)len);
	vt_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	vt_preadn(fd_src, buf_src, len, off_src);
	vt_preadn(fd_dst, buf_dst, len, off_dst);
	vt_expect_eqm(buf_src, buf_dst, len);
	vt_close2(fd_src, fd_dst);
	vt_unlink2(path_src, path_dst);
}

static void test_copy_file_range_aligned(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		COPYARGS(0, VT_1K, 0, VT_1K),
		COPYARGS(0, VT_1K, VT_1K, VT_1K),
		COPYARGS(VT_1K, VT_1K, 0, VT_1K),
		COPYARGS(VT_1K, VT_1K, VT_1K, VT_1K),
		COPYARGS(0, VT_1K, 2 * VT_1K, 2 * VT_1K),
		COPYARGS(0, VT_4K, 0, VT_4K),
		COPYARGS(VT_4K, VT_4K, VT_4K, VT_4K),
		COPYARGS(VT_4K, VT_4K, 2 * VT_4K, 2 * VT_4K),
		COPYARGS(2 * VT_4K, 4 * VT_4K, VT_4K, 2 * VT_4K),
		COPYARGS(0, VT_4K, VT_1K, VT_4K),
		COPYARGS(VT_1K, 2 * VT_4K, VT_4K, 3 * VT_4K),
		COPYARGS(0, VT_64K, 0, VT_64K),
		COPYARGS(VT_64K, VT_64K, VT_64K, VT_64K),
		COPYARGS(VT_MEGA, VT_64K, 0, VT_64K),
		COPYARGS(VT_MEGA, VT_64K, VT_GIGA, 2 * VT_64K),
		COPYARGS(VT_TERA, 3 * VT_64K, VT_MEGA, VT_64K),
		COPYARGS(VT_TERA, 3 * VT_64K, 0, VT_MEGA),
	};

	for (size_t i = 0; i < VT_ARRAY_SIZE(args); ++i) {
		test_copy_file_range_(vte,
		                      args[i].off_src, args[i].len_src,
		                      args[i].off_dst, args[i].len_dst);
	}
}

static void test_copy_file_range_unaligned(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		COPYARGS(1, VT_1K - 1, 1, VT_1K - 1),
		COPYARGS(1, VT_1K - 1, 1, VT_1K - 1),
		COPYARGS(1, VT_1K + 1, VT_1K + 2, VT_1K + 2),
		COPYARGS(VT_1K + 3, 3 * VT_1K + 1, 3, 3 * VT_1K),
		COPYARGS(VT_1K + 11, VT_1K + 1, VT_1K - 1, VT_1K),
		COPYARGS(7, VT_1K + 17, 7 * VT_1K + 1, 17 * VT_1K),
		COPYARGS(1, VT_4K - 1, 2, VT_4K - 2),
		COPYARGS(VT_4K + 1, VT_4K + 1, VT_4K + 1, VT_4K + 1),
		COPYARGS(VT_4K, VT_4K, 2 * VT_4K - 1, 2 * VT_4K + 3),
		COPYARGS(2 * VT_4K + 2, 4 * VT_4K, VT_4K + 1, VT_4K),
		COPYARGS(1, VT_4K, VT_1K + 1, VT_4K + 11),
		COPYARGS(1, VT_64K + 11, 11, VT_64K + 1),
		COPYARGS(VT_64K + 11, 11 * VT_64K, VT_64K + 1, VT_64K - 11),
		COPYARGS(VT_MEGA - 1, VT_64K - 2, 1, VT_64K - 3),
		COPYARGS(VT_MEGA + 11, VT_MEGA, VT_GIGA + 111, VT_MEGA + 1111),
		COPYARGS(VT_TERA + 111, VT_MEGA + 333, VT_MEGA - 111, 11111),
		COPYARGS(VT_TERA - 1111, 111111, 1, VT_MEGA + 1111),
	};

	for (size_t i = 0; i < VT_ARRAY_SIZE(args); ++i) {
		test_copy_file_range_(vte,
		                      args[i].off_src, args[i].len_src,
		                      args[i].off_dst, args[i].len_dst);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects copy_file_range(2) to successfully reflink-copy partial file range
 * between regions within same file.
 */
static void test_copy_file_range_self_(struct vt_env *vte,
                                       loff_t off_src, size_t len_src,
                                       loff_t off_dst, size_t len_dst)
{
	int fd_src = -1;
	int fd_dst = -1;
	const size_t len = vt_max(len_src, len_dst);
	const size_t len_max = vt_max(len_src, len_dst);
	const loff_t off_max = vt_lmax(off_src, off_dst) + (long)len_max;
	void *buf_src = vt_new_buf_rands(vte, len);
	void *buf_dst = vt_new_buf_rands(vte, len);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd_src);
	vt_open(path, O_RDWR, 0600, &fd_dst);
	vt_ftruncate(fd_src, off_max);
	vt_pwriten(fd_src, buf_src, len_src, off_src);
	vt_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	vt_preadn(fd_src, buf_src, len, off_src);
	vt_preadn(fd_dst, buf_dst, len, off_dst);
	vt_expect_eqm(buf_src, buf_dst, len);
	vt_ftruncate(fd_src, 0);
	vt_ftruncate(fd_src, off_max);
	vt_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	vt_preadn(fd_src, buf_src, len, off_src);
	vt_preadn(fd_dst, buf_dst, len, off_dst);
	vt_expect_eqm(buf_src, buf_dst, len);
	vt_close2(fd_src, fd_dst);
	vt_unlink(path);
}

static void test_copy_file_range_self(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		/* aligned */
		COPYARGS(0, VT_1K, VT_1K, VT_1K),
		COPYARGS(0, VT_1K, VT_64K, VT_1K),
		COPYARGS(0, VT_1K, VT_4K, VT_4K),
		COPYARGS(VT_1K, VT_4K, VT_64K, VT_4K),
		COPYARGS(VT_64K, VT_64K, 4 * VT_64K, VT_4K),
		COPYARGS(VT_MEGA, VT_64K, VT_GIGA, VT_MEGA),
		COPYARGS(VT_GIGA, VT_MEGA, 0, VT_4K),
		COPYARGS(VT_GIGA, VT_MEGA, VT_TERA, VT_MEGA / 2),
		/* unaligned */
		COPYARGS(1, VT_1K - 1, 2 * VT_1K + 1, VT_1K + 1),
		COPYARGS(VT_4K + 1, VT_4K - 1, VT_64K - 1, VT_4K + 1),
		COPYARGS(2 * VT_64K + 11, VT_64K - 111, VT_MEGA - 1, 11111),
		COPYARGS(VT_MEGA - 1, 11111, 333, 33333),
		COPYARGS(VT_GIGA - 111, 11111, VT_64K - 11, VT_64K + 111),
		COPYARGS(VT_TERA - 1111, 11111, VT_64K - 111, VT_64K + 1111),
	};

	for (size_t i = 0; i < VT_ARRAY_SIZE(args); ++i) {
		test_copy_file_range_self_(vte,
		                           args[i].off_src, args[i].len_src,
		                           args[i].off_dst, args[i].len_dst);
		test_copy_file_range_self_(vte,
		                           args[i].off_dst, args[i].len_dst,
		                           args[i].off_src, args[i].len_src);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_copy_file_range_aligned),
	VT_DEFTEST(test_copy_file_range_unaligned),
	VT_DEFTEST(test_copy_file_range_self),
};

const struct vt_tests
vt_test_copy_file_range = VT_DEFTESTS(vt_local_tests);
