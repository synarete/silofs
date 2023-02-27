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
#include "vfstests.h"

struct vt_copy_args {
	loff_t off_src;
	size_t len_src;
	loff_t off_dst;
	size_t len_dst;
};

#define COPYARGS1(a_, b_) \
	{ .off_src = (a_), .len_src = (b_) }

#define COPYARGS2(a_, b_, c_, d_) \
	{ .off_src = (a_), .len_src = (b_), .off_dst = (c_), .len_dst = (d_) }


static void
vt_copy_range1(void (*fn)(struct vt_env *, loff_t, size_t),
               struct vt_env *vte, const struct vt_copy_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(vte, args[i].off_src, args[i].len_src);
	}
}

static void
vt_copy_range2(void (*fn)(struct vt_env *, loff_t, size_t, loff_t, size_t),
               struct vt_env *vte, const struct vt_copy_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(vte, args[i].off_src, args[i].len_src,
		   args[i].off_dst, args[i].len_dst);
	}
}

/* TODO: make me common util */
static size_t vt_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

static size_t vt_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

static long vt_lmax(long a, long b)
{
	return (a > b) ? a : b;
}

static loff_t vt_off_end(loff_t off, size_t len)
{
	return off + (long)len;
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
	vt_ftruncate(fd_src, vt_off_end(off_src, len));
	vt_ftruncate(fd_dst, vt_off_end(off_dst, len));
	vt_pwriten(fd_src, buf_src, len_src, off_src);
	vt_pwriten(fd_dst, buf_dst, len_dst, off_dst);
	vt_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len);
	vt_preadn(fd_src, buf_src, len, off_src);
	vt_preadn(fd_dst, buf_dst, len, off_dst);
	vt_expect_eqm(buf_src, buf_dst, len);
	vt_ftruncate(fd_src, off_src);
	vt_ftruncate(fd_src, vt_off_end(off_src, len));
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
		COPYARGS2(0, VT_1K, 0, VT_1K),
		COPYARGS2(0, VT_1K, VT_1K, VT_1K),
		COPYARGS2(VT_1K, VT_1K, 0, VT_1K),
		COPYARGS2(VT_1K, VT_1K, VT_1K, VT_1K),
		COPYARGS2(0, VT_1K, 2 * VT_1K, 2 * VT_1K),
		COPYARGS2(0, VT_4K, 0, VT_4K),
		COPYARGS2(VT_4K, VT_4K, VT_4K, VT_4K),
		COPYARGS2(VT_4K, VT_4K, 2 * VT_4K, 2 * VT_4K),
		COPYARGS2(2 * VT_4K, 4 * VT_4K, VT_4K, 2 * VT_4K),
		COPYARGS2(0, VT_4K, VT_1K, VT_4K),
		COPYARGS2(VT_1K, 2 * VT_4K, VT_4K, 3 * VT_4K),
		COPYARGS2(0, VT_64K, 0, VT_64K),
		COPYARGS2(VT_64K, VT_64K, VT_64K, VT_64K),
		COPYARGS2(VT_MEGA, VT_64K, 0, VT_64K),
		COPYARGS2(VT_MEGA, VT_64K, VT_GIGA, 2 * VT_64K),
		COPYARGS2(VT_TERA, 3 * VT_64K, VT_MEGA, VT_64K),
		COPYARGS2(VT_TERA, 3 * VT_64K, 0, VT_MEGA),
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
		COPYARGS2(1, VT_1K - 1, 1, VT_1K - 1),
		COPYARGS2(1, VT_1K - 1, 1, VT_1K - 1),
		COPYARGS2(1, VT_1K + 1, VT_1K + 2, VT_1K + 2),
		COPYARGS2(VT_1K + 3, 3 * VT_1K + 1, 3, 3 * VT_1K),
		COPYARGS2(VT_1K + 11, VT_1K + 1, VT_1K - 1, VT_1K),
		COPYARGS2(7, VT_1K + 17, 7 * VT_1K + 1, 17 * VT_1K),
		COPYARGS2(1, VT_4K - 1, 2, VT_4K - 2),
		COPYARGS2(VT_4K + 1, VT_4K + 1, VT_4K + 1, VT_4K + 1),
		COPYARGS2(VT_4K, VT_4K, 2 * VT_4K - 1, 2 * VT_4K + 3),
		COPYARGS2(2 * VT_4K + 2, 4 * VT_4K, VT_4K + 1, VT_4K),
		COPYARGS2(1, VT_4K, VT_1K + 1, VT_4K + 11),
		COPYARGS2(1, VT_64K + 11, 11, VT_64K + 1),
		COPYARGS2(VT_64K + 11, 11 * VT_64K, VT_64K + 1, VT_64K - 11),
		COPYARGS2(VT_MEGA - 1, VT_64K - 2, 1, VT_64K - 3),
		COPYARGS2(VT_MEGA + 11, VT_MEGA,
		          VT_GIGA + 111, VT_MEGA + 1111),
		COPYARGS2(VT_TERA + 111, VT_MEGA + 333, VT_MEGA - 111, 11111),
		COPYARGS2(VT_TERA - 1111, 111111, 1, VT_MEGA + 1111),
	};

	vt_copy_range2(test_copy_file_range_, vte, args, VT_ARRAY_SIZE(args));
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
	const loff_t off_max = vt_off_end(vt_lmax(off_src, off_dst), len_max);
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

static void
test_copy_file_range_self2_(struct vt_env *vte,
                            loff_t off1, size_t len1, loff_t off2, size_t len2)
{
	test_copy_file_range_self_(vte, off1, len1, off2, len2);
	test_copy_file_range_self_(vte, off2, len2, off1, len1);
}

static void test_copy_file_range_self(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		/* aligned */
		COPYARGS2(0, VT_1K, VT_1K, VT_1K),
		COPYARGS2(0, VT_1K, VT_64K, VT_1K),
		COPYARGS2(0, VT_1K, VT_4K, VT_4K),
		COPYARGS2(VT_1K, VT_4K, VT_64K, VT_4K),
		COPYARGS2(VT_64K, VT_64K, 4 * VT_64K, VT_4K),
		COPYARGS2(VT_MEGA, VT_64K, VT_GIGA, VT_MEGA),
		COPYARGS2(VT_GIGA, VT_MEGA, 0, VT_4K),
		COPYARGS2(VT_GIGA, VT_MEGA, VT_TERA, VT_MEGA / 2),
		/* unaligned */
		COPYARGS2(1, VT_1K - 1, 2 * VT_1K + 1, VT_1K + 1),
		COPYARGS2(VT_4K + 1, VT_4K - 1, VT_64K - 1, VT_4K + 1),
		COPYARGS2(2 * VT_64K + 11, VT_64K - 111, VT_MEGA - 1, 11111),
		COPYARGS2(VT_MEGA - 1, 11111, 333, 33333),
		COPYARGS2(VT_GIGA - 111, 11111, VT_64K - 11, VT_64K + 111),
		COPYARGS2(VT_TERA - 1111, 11111, VT_64K - 111, VT_64K + 1111),
	};

	vt_copy_range2(test_copy_file_range_self2_,
	               vte, args, VT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_between_(struct vt_env *vte,
                              loff_t off_src, size_t len_src,
                              loff_t off_dst, size_t len_dst)
{
	int fd_src = -1;
	int fd_dst = -1;
	const size_t len_max = vt_max(len_src, len_dst);
	const size_t len_min = vt_min(len_src, len_dst);
	void *buf_src = vt_new_buf_rands(vte, len_max);
	void *buf_dst = vt_new_buf_rands(vte, len_max);
	void *buf_alt = vt_new_buf_rands(vte, len_max);
	void *buf_zeros = vt_new_buf_zeros(vte, len_max);
	const char *path_src = vt_new_path_unique(vte);
	const char *path_dst = vt_new_path_unique(vte);

	vt_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	vt_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	vt_ftruncate(fd_src, vt_off_end(off_src, len_max));
	vt_ftruncate(fd_dst, vt_off_end(off_dst, len_max));
	vt_pwriten(fd_src, buf_src, len_src, off_src);
	vt_copy_file_rangen(fd_src, off_src, fd_dst, off_dst, len_dst);
	vt_preadn(fd_src, buf_src, len_min, off_src);
	vt_preadn(fd_dst, buf_dst, len_min, off_dst);
	vt_expect_eqm(buf_src, buf_dst, len_min);
	vt_preadn(fd_dst, buf_alt, len_dst - len_min,
	          vt_off_end(off_dst, len_min));
	vt_expect_eqm(buf_alt, buf_zeros, len_dst - len_min);
	vt_close2(fd_src, fd_dst);
	vt_unlink2(path_src, path_dst);
}

static void test_copy_file_range_between(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		/* aligned */
		COPYARGS2(0, VT_1K, 0, VT_1K),
		COPYARGS2(0, VT_1K, VT_1K, VT_1K),
		COPYARGS2(VT_1K, VT_1K, 0, VT_1K),
		COPYARGS2(VT_1K, VT_1K, VT_1K, VT_1K),
		COPYARGS2(0, VT_1K, 2 * VT_1K, 2 * VT_1K),
		COPYARGS2(0, VT_4K, 0, VT_4K),
		COPYARGS2(VT_4K, VT_4K, VT_4K, VT_4K),
		COPYARGS2(VT_4K, VT_4K, 2 * VT_4K, 2 * VT_4K),
		COPYARGS2(2 * VT_4K, 4 * VT_4K, VT_4K, 2 * VT_4K),
		COPYARGS2(0, VT_4K, VT_1K, VT_4K),
		COPYARGS2(VT_1K, 2 * VT_4K, VT_4K, 3 * VT_4K),
		COPYARGS2(0, VT_64K, 0, VT_64K),
		COPYARGS2(VT_64K, VT_64K, VT_64K, VT_64K),
		COPYARGS2(VT_MEGA, VT_64K, 0, VT_64K),
		COPYARGS2(VT_MEGA, VT_64K, VT_GIGA, 2 * VT_64K),
		COPYARGS2(VT_TERA, 3 * VT_64K, VT_MEGA, VT_64K),
		COPYARGS2(VT_TERA, 3 * VT_64K, 0, VT_MEGA),
		/* unaligned */
		COPYARGS2(1, VT_1K - 1, 1, VT_1K - 1),
		COPYARGS2(1, VT_1K - 1, 1, VT_1K - 1),
		COPYARGS2(1, VT_1K + 1, VT_1K + 2, VT_1K + 2),
		COPYARGS2(VT_1K + 3, 3 * VT_1K + 1, 3, 3 * VT_1K),
		COPYARGS2(VT_1K + 11, VT_1K + 1, VT_1K - 1, VT_1K),
		COPYARGS2(7, VT_1K + 17, 7 * VT_1K + 1, 17 * VT_1K),
		COPYARGS2(1, VT_4K - 1, 2, VT_4K - 2),
		COPYARGS2(VT_4K + 1, VT_4K + 1, VT_4K + 1, VT_4K + 1),
		COPYARGS2(VT_4K, VT_4K, 2 * VT_4K - 1, 2 * VT_4K + 3),
		COPYARGS2(2 * VT_4K + 2, 4 * VT_4K, VT_4K + 1, VT_4K),
		COPYARGS2(1, VT_4K, VT_1K + 1, VT_4K + 11),
		COPYARGS2(1, VT_64K + 11, 11, VT_64K + 1),
		COPYARGS2(VT_64K + 11, 11 * VT_64K, VT_64K + 1, VT_64K - 11),
		COPYARGS2(VT_MEGA - 1, VT_64K - 2, 1, VT_64K - 3),
		COPYARGS2(VT_MEGA + 11, VT_MEGA, VT_GIGA + 11, VT_MEGA + 1111),
		COPYARGS2(VT_TERA + 111, VT_MEGA + 333, VT_MEGA - 111, 11111),
		COPYARGS2(VT_TERA - 1111, 111111, 1, VT_MEGA + 1111),
	};

	vt_copy_range2(test_copy_file_range_between_,
	               vte, args, VT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_truncate_(struct vt_env *vte, loff_t off, size_t len)
{
	int fd_src = -1;
	int fd_dst = -1;
	uint8_t byte;
	const loff_t end = vt_off_end(off, len);
	uint8_t *buf_src = vt_new_buf_rands(vte, len);
	uint8_t *buf_alt = vt_new_buf_rands(vte, len);
	const char *path_src = vt_new_path_unique(vte);
	const char *path_dst = vt_new_path_unique(vte);

	vt_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	vt_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	vt_pwriten(fd_src, buf_src, len, off);
	vt_ftruncate(fd_dst, end);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_preadn(fd_dst, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_ftruncate(fd_dst, end - 1);
	vt_ftruncate(fd_dst, end);
	vt_preadn(fd_dst, buf_alt, len - 1, off);
	vt_expect_eqm(buf_src, buf_alt, len - 1);
	vt_preadn(fd_dst, &byte, 1, end - 1);
	vt_expect_eq(byte, 0);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_ftruncate(fd_dst, off + 1);
	vt_ftruncate(fd_dst, end);
	vt_preadn(fd_dst, &byte, 1, off);
	vt_expect_eq(byte, buf_src[0]);
	vt_preadn(fd_dst, &byte, 1, off + 1);
	vt_expect_eq(byte, 0);
	vt_preadn(fd_dst, &byte, 1, end - 1);
	vt_expect_eq(byte, 0);
	vt_close2(fd_src, fd_dst);
	vt_unlink2(path_src, path_dst);
}

static void test_copy_file_range_truncate(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		COPYARGS1(0, VT_1K),
		COPYARGS1(0, VT_4K),
		COPYARGS1(VT_1K, VT_4K),
		COPYARGS1(0, VT_64K),
		COPYARGS1(VT_64K, VT_64K),
		COPYARGS1(2 * VT_64K, 4 * VT_64K),
		COPYARGS1(0, VT_MEGA),
		COPYARGS1(VT_MEGA, VT_MEGA),
		COPYARGS1(VT_GIGA, VT_64K),
		COPYARGS1(VT_TERA, VT_4K),
		COPYARGS1(1, VT_1K - 1),
		COPYARGS1(VT_4K - 1, VT_4K + 3),
		COPYARGS1(VT_64K - 3, VT_MEGA),
		COPYARGS1((2 * VT_64K) - 3, VT_MEGA),
		COPYARGS1(VT_GIGA - 3, VT_64K + 5),
		COPYARGS1(VT_TERA - 3, VT_MEGA + 5),
	};

	vt_copy_range1(test_copy_file_range_truncate_,
	               vte, args, VT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_overwrite_(struct vt_env *vte, loff_t off, size_t len)
{
	int fd_src = -1;
	int fd_dst = -1;
	const loff_t end = vt_off_end(off, len);
	uint8_t *buf_src = vt_new_buf_rands(vte, len);
	uint8_t *buf_dst = vt_new_buf_rands(vte, len);
	uint8_t *buf_alt = vt_new_buf_rands(vte, len);
	const char *path_src = vt_new_path_unique(vte);
	const char *path_dst = vt_new_path_unique(vte);

	vt_open(path_src, O_CREAT | O_RDWR, 0600, &fd_src);
	vt_open(path_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
	vt_pwriten(fd_src, buf_src, len, off);
	vt_ftruncate(fd_dst, end);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_preadn(fd_dst, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_preadn(fd_src, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_preadn(fd_dst, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_preadn(fd_src, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_ftruncate(fd_dst, end - 1);
	vt_ftruncate(fd_dst, end);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_preadn(fd_dst, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_preadn(fd_src, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_pwriten(fd_dst, buf_dst, len, off);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_preadn(fd_dst, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_preadn(fd_src, buf_alt, len, off);
	vt_expect_eqm(buf_src, buf_alt, len);
	vt_ftruncate(fd_src, 0);
	vt_ftruncate(fd_src, end);
	vt_preadn(fd_src, buf_alt, len, off);
	vt_expect_eq(buf_alt[0], 0);
	vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
	vt_preadn(fd_dst, buf_alt, len, off);
	vt_expect_eq(buf_alt[0], 0);
	vt_close2(fd_src, fd_dst);
	vt_unlink2(path_src, path_dst);
}

static void test_copy_file_range_overwrite(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		COPYARGS1(0, VT_1K),
		COPYARGS1(0, VT_4K),
		COPYARGS1(VT_1K, VT_4K),
		COPYARGS1(0, VT_64K),
		COPYARGS1(VT_64K, VT_64K),
		COPYARGS1(2 * VT_64K, 4 * VT_64K),
		COPYARGS1(0, VT_MEGA),
		COPYARGS1(VT_MEGA, VT_MEGA),
		COPYARGS1(VT_GIGA, VT_64K),
		COPYARGS1(VT_TERA, VT_4K),
		COPYARGS1(1, VT_1K - 1),
		COPYARGS1(VT_4K - 1, VT_4K + 3),
		COPYARGS1(VT_64K - 3, VT_MEGA),
		COPYARGS1((2 * VT_64K) - 3, VT_MEGA),
		COPYARGS1(VT_GIGA - 3, VT_64K + 5),
		COPYARGS1(VT_TERA - 3, VT_MEGA + 5),
	};

	vt_copy_range1(test_copy_file_range_overwrite_,
	               vte, args, VT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_copy_file_range_nfiles_(struct vt_env *vte, loff_t off, size_t len)
{
	int dfd = -1;
	int fd_src = -1;
	int fd_dst = -1;
	const loff_t end = vt_off_end(off, len);
	const size_t nfiles = 256;
	uint8_t *buf_src = vt_new_buf_rands(vte, len);
	uint8_t *buf_alt = vt_new_buf_rands(vte, len);
	const char *path = vt_new_path_unique(vte);
	const char *name_src = vt_new_name_unique(vte);
	const char *name_dst = NULL;

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	vt_openat(dfd, name_src, O_CREAT | O_RDWR, 0600, &fd_src);
	vt_pwriten(fd_src, buf_src, len, off);
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = vt_make_ulong_name(vte, i);
		vt_openat(dfd, name_dst, O_CREAT | O_RDWR, 0600, &fd_dst);
		vt_ftruncate(fd_dst, end);
		vt_copy_file_rangen(fd_src, off, fd_dst, off, len);
		vt_preadn(fd_dst, buf_alt, len, off);
		vt_expect_eqm(buf_src, buf_alt, len);
		vt_close(fd_dst);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = vt_make_ulong_name(vte, i);
		vt_unlinkat(dfd, name_dst, 0);
	}
	vt_close(fd_src);
	vt_unlinkat(dfd, name_src, 0);
	vt_close(dfd);
	vt_rmdir(path);
}

static void test_copy_file_range_nfiles(struct vt_env *vte)
{
	const struct vt_copy_args args[] = {
		COPYARGS1(0, VT_1K),
		COPYARGS1(0, VT_4K),
		COPYARGS1(VT_1K, VT_4K),
		COPYARGS1(0, VT_64K),
		COPYARGS1(VT_64K, VT_64K),
		COPYARGS1(2 * VT_64K, 4 * VT_64K),
		COPYARGS1(0, VT_MEGA / 4),
		COPYARGS1(VT_MEGA, VT_MEGA / 8),
		COPYARGS1(VT_GIGA, VT_64K),
		COPYARGS1(VT_TERA, VT_4K),
		COPYARGS1(1, VT_1K - 1),
		COPYARGS1(VT_4K - 1, VT_4K + 3),
		COPYARGS1(VT_64K - 3, VT_MEGA / 16),
		COPYARGS1((2 * VT_64K) - 3, VT_MEGA / 32),
		COPYARGS1(VT_GIGA - 3, VT_64K + 5),
		COPYARGS1(VT_TERA - 3, VT_MEGA + 5),
	};

	vt_copy_range1(test_copy_file_range_nfiles_,
	               vte, args, VT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_copy_file_range_aligned),
	VT_DEFTEST(test_copy_file_range_unaligned),
	VT_DEFTEST(test_copy_file_range_self),
	VT_DEFTEST(test_copy_file_range_between),
	VT_DEFTEST(test_copy_file_range_truncate),
	VT_DEFTEST(test_copy_file_range_overwrite),
	VT_DEFTEST(test_copy_file_range_nfiles),
};

const struct vt_tests
vt_test_copy_file_range = VT_DEFTESTS(vt_local_tests);
