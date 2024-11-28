/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include "unitests.h"

struct ut_copy_range_args {
	loff_t off_src;
	size_t len_src;
	loff_t off_dst;
	size_t len_dst;
};

#define COPYARGS1(a_, b_) COPYARGS2(a_, b_, 0, 0)

#define COPYARGS2(a_, b_, c_, d_) \
	{                         \
		.off_src = (a_),  \
		.len_src = (b_),  \
		.off_dst = (c_),  \
		.len_dst = (d_),  \
	}

#define ut_copy_range1(ute_, fn_, args_) \
	ut_copy_range1_(ute_, fn_, args_, UT_ARRAY_SIZE(args_))

#define ut_copy_range2(ute_, fn_, args_) \
	ut_copy_range2_(ute_, fn_, args_, UT_ARRAY_SIZE(args_))

static void ut_copy_range1_(struct ut_env *ute,
			    void (*fn)(struct ut_env *, loff_t, size_t),
			    const struct ut_copy_range_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(ute, args[i].off_src, args[i].len_src);
		ut_relax_mem(ute);
	}
}

static void
ut_copy_range2_(struct ut_env *ute,
		void (*fn)(struct ut_env *, loff_t, size_t, loff_t, size_t),
		const struct ut_copy_range_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(ute, args[i].off_src, args[i].len_src, args[i].off_dst,
		   args[i].len_dst);
		ut_relax_mem(ute);
	}
}

/* TODO: make me common */
static long ut_lmax(long x, long y)
{
	return (x > y) ? x : y;
}

static loff_t ut_off_end(loff_t off, size_t len)
{
	return off + (long)len;
}

static void ut_expect_gt_mtime(const struct stat *st1, const struct stat *st0)
{
	ut_expect_ge(st1->st_mtim.tv_sec, st0->st_mtim.tv_sec);
	if (st1->st_mtim.tv_sec == st0->st_mtim.tv_sec) {
		ut_expect_gt(st1->st_mtim.tv_nsec, st0->st_mtim.tv_nsec);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_simple_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf = ut_randbuf(ute, len);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, ut_off_end(off, len));
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_simple_aligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(UT_1K, 2 * UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_4K, 8 * UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_1K, UT_1M),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, UT_64K),
		COPYARGS1(UT_1M, 2 * UT_64K),
		COPYARGS1(UT_1G, UT_1M),
		COPYARGS1(UT_1T, UT_1M + UT_64K),
	};

	ut_copy_range1(ute, ut_file_copy_range_simple_, args);
}

static void ut_file_copy_range_simple_unaligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(2, UT_1K + 2),
		COPYARGS1(3, 3 * UT_1K + 3),
		COPYARGS1(4, UT_4K + 4),
		COPYARGS1(UT_1K - 1, UT_1M + 3),
		COPYARGS1(UT_4K - 5, UT_4K + 7),
		COPYARGS1(2 * UT_4K - 5, 3 * UT_4K),
		COPYARGS1(3 * UT_4K - 3, UT_1M + 3),
		COPYARGS1(UT_64K - 11, UT_64K + 111),
		COPYARGS1(UT_64K - 111, UT_1M + 1111),
		COPYARGS1(UT_1M - 1, 11 * UT_64K + 11),
		COPYARGS1(UT_1G - 11, UT_1M + 111),
		COPYARGS1(UT_1T - 111, 11 * UT_64K + 111),
	};

	ut_copy_range1(ute, ut_file_copy_range_simple_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_between_(struct ut_env *ute, loff_t off_src, size_t len_src,
			    loff_t off_dst, size_t len_dst)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const size_t len_max = ut_max(len_src, len_dst);
	const size_t len_min = ut_min(len_src, len_dst);
	void *buf_src = ut_randbuf(ute, len_max);
	void *buf_dst = ut_randbuf(ute, len_max);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_max));
	ut_trunacate_file(ute, ino_dst, ut_off_end(off_dst, len_max));
	ut_write_read(ute, ino_src, buf_src, len_src, off_src);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len_dst);
	ut_read_verify(ute, ino_dst, buf_src, len_min, off_dst);
	ut_read_zeros(ute, ino_dst, ut_off_end(off_dst, len_min),
		      len_dst - len_min);
	ut_write_read(ute, ino_dst, buf_dst, len_dst, off_dst);
	ut_trunacate_file(ute, ino_src, off_src);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_max));
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len_dst);
	ut_read_zeros(ute, ino_dst, off_dst, len_min);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_between_aligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS2(0, UT_1K, 0, UT_1K),
		COPYARGS2(0, UT_1K, UT_1K, UT_1K),
		COPYARGS2(UT_1K, UT_1K, 0, UT_1K),
		COPYARGS2(UT_1K, UT_1K, UT_1K, UT_1K),
		COPYARGS2(0, UT_1K, 2 * UT_1K, 2 * UT_1K),
		COPYARGS2(0, UT_4K, 0, UT_4K),
		COPYARGS2(UT_4K, UT_4K, UT_4K, UT_4K),
		COPYARGS2(UT_4K, UT_4K, 2 * UT_4K, 2 * UT_4K),
		COPYARGS2(2 * UT_4K, 4 * UT_4K, UT_4K, 2 * UT_4K),
		COPYARGS2(0, UT_4K, UT_1K, UT_4K),
		COPYARGS2(UT_1K, 2 * UT_4K, UT_4K, 3 * UT_4K),
		COPYARGS2(0, UT_64K, 0, UT_64K),
		COPYARGS2(UT_64K, UT_64K, UT_64K, UT_64K),
		COPYARGS2(UT_1M, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1M, UT_64K, UT_1G, 2 * UT_64K),
		COPYARGS2(UT_1T, 3 * UT_64K, UT_1M, UT_64K),
		COPYARGS2(UT_1T, 3 * UT_64K, 0, UT_1M),
	};

	ut_copy_range2(ute, ut_file_copy_range_between_, args);
}

static void ut_file_copy_range_between_unaligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS2(1, UT_1K - 1, 1, UT_1K - 1),
		COPYARGS2(1, UT_1K - 1, 1, UT_1K - 1),
		COPYARGS2(1, UT_1K + 1, UT_1K + 2, UT_1K + 2),
		COPYARGS2(UT_1K + 3, 3 * UT_1K + 1, 3, 3 * UT_1K),
		COPYARGS2(UT_1K + 11, UT_1K + 1, UT_1K - 1, UT_1K),
		COPYARGS2(7, UT_1K + 17, 7 * UT_1K + 1, 17 * UT_1K),
		COPYARGS2(1, UT_4K - 1, 2, UT_4K - 2),
		COPYARGS2(UT_4K + 1, UT_4K + 1, UT_4K + 1, UT_4K + 1),
		COPYARGS2(UT_4K, UT_4K, 2 * UT_4K - 1, 2 * UT_4K + 3),
		COPYARGS2(2 * UT_4K + 2, 4 * UT_4K, UT_4K + 1, UT_4K),
		COPYARGS2(1, UT_4K, UT_1K + 1, UT_4K + 11),
		COPYARGS2(1, UT_64K + 11, 11, UT_64K + 1),
		COPYARGS2(UT_64K + 11, 11 * UT_64K, UT_64K + 1, UT_64K - 11),
		COPYARGS2(UT_1M - 1, UT_64K - 2, 1, UT_64K - 3),
		COPYARGS2(UT_1M + 11, UT_1M, UT_1G + 11, UT_1M + 1111),
		COPYARGS2(UT_1T + 111, UT_1M + 333, UT_1M - 111, 11111),
		COPYARGS2(UT_1T - 1111, 111111, 1, UT_1M + 1111),
	};

	ut_copy_range2(ute, ut_file_copy_range_between_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_self_(struct ut_env *ute, loff_t off_src, size_t len_src,
			 loff_t off_dst, size_t len_dst)
{
	const char *name = UT_NAME;
	const size_t len_max = ut_max(len_src, len_dst);
	const size_t len_min = ut_min(len_src, len_dst);
	const size_t len_zeros = len_dst - len_min;
	const loff_t off_max = ut_off_end(ut_lmax(off_src, off_dst), len_max);
	const loff_t off_zeros = ut_off_end(off_dst, len_min);
	void *buf_src = ut_randbuf(ute, len_src);
	void *buf_dst = ut_randbuf(ute, len_dst);
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off_max);
	ut_write_read(ute, ino, buf_src, len_src, off_src);
	ut_copy_file_range(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_verify(ute, ino, buf_src, len_min, off_dst);
	ut_read_zeros(ute, ino, off_zeros, len_zeros);
	ut_write_read(ute, ino, buf_dst, len_dst, off_dst);
	ut_trunacate_file(ute, ino, 0);
	ut_trunacate_file(ute, ino, off_max);
	ut_copy_file_range(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_zeros(ute, ino, off_dst, len_min);
	ut_write_read(ute, ino, buf_src, len_src, off_src);
	ut_copy_file_range(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_verify(ute, ino, buf_src, len_min, off_dst);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_self2_(struct ut_env *ute, loff_t off1,
				      size_t len1, loff_t off2, size_t len2)
{
	ut_file_copy_range_self_(ute, off1, len1, off2, len2);
	ut_file_copy_range_self_(ute, off2, len2, off1, len1);
}

static void ut_file_copy_range_self_aligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS2(0, UT_1K, UT_1K, UT_1K),
		COPYARGS2(0, UT_1K, UT_64K, UT_1K),
		COPYARGS2(0, UT_1K, UT_4K, UT_4K),
		COPYARGS2(UT_1K, UT_4K, UT_64K, UT_4K),
		COPYARGS2(UT_1K, UT_1M, UT_1G, UT_1M),
		COPYARGS2(UT_4K, UT_1M, UT_1G + UT_64K, UT_1M),
		COPYARGS2(UT_64K, UT_64K, 4 * UT_64K, UT_4K),
		COPYARGS2(UT_1M, UT_64K, UT_1G, UT_1M),
		COPYARGS2(UT_1G, UT_1M, 0, UT_4K),
		COPYARGS2(UT_1G, UT_1M, UT_1T, UT_1M / 2),
	};

	ut_copy_range2(ute, ut_file_copy_range_self2_, args);
}

static void ut_file_copy_range_self_unaligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS2(1, UT_1K - 1, 2 * UT_1K + 1, UT_1K + 1),
		COPYARGS2(UT_4K + 1, UT_4K - 1, UT_64K - 1, UT_4K + 1),
		COPYARGS2(UT_1K - 1, UT_1M + 3, UT_1G, UT_1M + 3),
		COPYARGS2(UT_4K - 3, 111111, UT_1G + UT_64K - 3, 111111),
		COPYARGS2(2 * UT_64K + 11, UT_64K - 111, UT_1M - 1, 11111),
		COPYARGS2(UT_1M - 1, 11111, 333, 33333),
		COPYARGS2(UT_1G - 111, 11111, UT_64K - 11, UT_64K + 111),
		COPYARGS2(UT_1T - 1111, 11111, UT_64K - 111, UT_64K + 1111),
	};

	ut_copy_range2(ute, ut_file_copy_range_self2_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_truncate_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const loff_t end = ut_off_end(off, len);
	uint8_t *buf = ut_randbuf(ute, len);
	ino_t dino = 0;
	ino_t ino_src = 0;
	ino_t ino_dst = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end);
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end - 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len - 1, off);
	ut_read_zero(ute, ino_dst, end - 1);
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_trunacate_file(ute, ino_dst, off + 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, 1, off);
	ut_read_zeros(ute, ino_dst, off + 1, len - 1);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_truncate(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_1K, UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, 4 * UT_64K),
		COPYARGS1(0, UT_1M),
		COPYARGS1(UT_1M, UT_1M),
		COPYARGS1(UT_1G, UT_64K),
		COPYARGS1(UT_1T, UT_4K),
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(UT_4K - 1, UT_4K + 3),
		COPYARGS1(UT_64K - 3, UT_1M),
		COPYARGS1((2 * UT_64K) - 3, UT_1M),
		COPYARGS1(UT_1G - 3, UT_64K + 5),
		COPYARGS1(UT_1T - 3, UT_1M + 5),
	};

	ut_copy_range1(ute, ut_file_copy_range_truncate_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_overwrite_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino = 0;
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	const loff_t end = ut_off_end(off, len);
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	uint8_t *buf1 = ut_randbuf(ute, len);
	uint8_t *buf2 = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf1, len, off);
	ut_trunacate_file(ute, ino_dst, end);
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_src, buf1, len, off);
	ut_read_verify(ute, ino_dst, buf1, len, off);
	ut_write_read(ute, ino_src, buf2, len, off);
	ut_read_verify(ute, ino_dst, buf1, len, off);
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf2, len, off);
	ut_read_verify(ute, ino_src, buf2, len, off);
	ut_write_read(ute, ino_src, buf1, len, off);
	ut_read_verify(ute, ino_dst, buf2, len, off);
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf1, len, off);
	ut_read_verify(ute, ino_src, buf1, len, off);
	ut_trunacate_file(ute, ino_src, 0);
	ut_read_verify(ute, ino_dst, buf1, len, off);
	ut_trunacate_file(ute, ino_dst, 0);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_zeros(ute, ino_dst, off, len);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_overwrite(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_1K, UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, 4 * UT_64K),
		COPYARGS1(0, UT_1M),
		COPYARGS1(UT_1M, UT_1M),
		COPYARGS1(UT_1G, UT_64K),
		COPYARGS1(UT_1T, UT_4K),
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(UT_4K - 1, UT_4K + 3),
		COPYARGS1(UT_64K - 3, UT_1M),
		COPYARGS1((2 * UT_64K) - 3, UT_1M),
		COPYARGS1(UT_1G - 3, UT_64K + 5),
		COPYARGS1(UT_1T - 3, UT_1M + 5),
	};

	ut_copy_range1(ute, ut_file_copy_range_overwrite_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_nfiles_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino = 0;
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	const loff_t end = ut_off_end(off, len);
	const size_t nfiles = 256;
	const char *name = UT_NAME;
	const char *name_src = UT_NAME;
	const char *name_dst = NULL;
	uint8_t *buf = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_write_read(ute, ino_src, buf, len, off);
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = ut_make_name(ute, name, i);
		ut_create_file(ute, dino, name_dst, &ino_dst);
		ut_trunacate_file(ute, ino_dst, end);
		ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
		ut_read_verify(ute, ino_dst, buf, len, off);
		ut_release(ute, ino_dst);
		ut_read_verify(ute, ino_src, buf, len, off);
		ut_lookup_file(ute, dino, name_dst, ino_dst);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = ut_make_name(ute, name, i);
		ut_lookup_ino(ute, dino, name_dst, &ino_dst);
		ut_unlink(ute, dino, name_dst);
		ut_read_verify(ute, ino_src, buf, len, off);
	}
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_nfiles_aligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS1(0, UT_1K),       COPYARGS1(0, UT_4K),
		COPYARGS1(UT_1K, UT_4K),   COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K), COPYARGS1(2 * UT_64K, 4 * UT_64K),
		COPYARGS1(0, UT_1M / 4),   COPYARGS1(UT_1M, UT_1M / 8),
		COPYARGS1(UT_1G, UT_64K),  COPYARGS1(UT_1T, UT_4K),
	};

	ut_copy_range1(ute, ut_file_copy_range_nfiles_, args);
}

static void ut_file_copy_range_nfiles_unaligned(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(UT_4K - 1, UT_4K + 3),
		COPYARGS1(UT_64K - 3, UT_1M / 16),
		COPYARGS1((2 * UT_64K) - 3, UT_1M / 32),
		COPYARGS1(UT_1G - 3, UT_64K + 5),
		COPYARGS1(UT_1T - 3, UT_1M + 5),
	};

	ut_copy_range1(ute, ut_file_copy_range_nfiles_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_from_hole_(struct ut_env *ute, loff_t off_src,
			      size_t len_src, loff_t off_dst, size_t len_dst)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const size_t len = ut_min(len_src, len_dst);
	void *buf = ut_randbuf(ute, len);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_src));
	ut_read_zeros(ute, ino_src, off_src, len_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_dst, ut_off_end(off_dst, len_dst));
	ut_write_read(ute, ino_dst, buf, len, off_dst);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_zeros(ute, ino_dst, off_dst, len);
	ut_write_read(ute, ino_dst, buf, len, off_dst);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_zeros(ute, ino_src, off_src, len_src);
	ut_read_zeros(ute, ino_dst, off_dst, len_dst);
	ut_trunacate_file(ute, ino_src, 0);
	ut_read_zeros(ute, ino_dst, off_dst, len_dst);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_src));
	ut_write_read(ute, ino_src, buf, len / 2, off_src);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_verify(ute, ino_dst, buf, 1, off_dst);
	ut_read_zero(ute, ino_dst, off_dst - 1);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_from_hole(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		/* aligned */
		COPYARGS2(0, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1K, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1K, UT_1M, UT_64K - UT_1K, UT_64K),
		COPYARGS2(UT_64K, UT_64K, UT_1M, UT_64K),
		COPYARGS2(UT_1G, 2 * UT_64K, UT_64K, UT_64K),
		COPYARGS2(UT_1T, UT_64K, UT_1M, UT_64K),
		/* unaligned */
		COPYARGS2(1, 11, UT_64K, UT_1K - 1),
		COPYARGS2(1, UT_64K - 1, 3 * UT_64K + 3, UT_64K - 5),
		COPYARGS2(UT_1M - 1, UT_64K, UT_1M, UT_64K + 1),
		COPYARGS2(UT_1G - 1, UT_1M - 1, UT_1M + 11, UT_1M + 1),
		COPYARGS2(UT_1T - 1, UT_1M + 11, UT_1G - 1, UT_1M - 1),
	};

	ut_copy_range2(ute, ut_file_copy_range_from_hole_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_into_hole_(struct ut_env *ute, loff_t off_src,
			      size_t len_src, loff_t off_dst, size_t len_dst)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const size_t len = ut_min(len_src, len_dst);
	void *buf = ut_randbuf(ute, len);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_src));
	ut_write_read(ute, ino_src, buf, len, off_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_dst, ut_off_end(off_dst, len_dst));
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_verify(ute, ino_dst, buf, len, off_dst);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_verify(ute, ino_dst, buf, len, off_dst);
	ut_trunacate_file(ute, ino_src, 0);
	ut_read_verify(ute, ino_dst, buf, len, off_dst);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_into_hole(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		/* aligned */
		COPYARGS2(0, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1K, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1K, UT_1M, UT_64K - UT_1K, UT_64K),
		COPYARGS2(UT_64K, UT_64K, UT_1M, UT_64K),
		COPYARGS2(UT_1G, 2 * UT_64K, UT_64K, UT_64K),
		COPYARGS2(UT_1T, UT_64K, UT_1M, UT_64K),
		/* unaligned */
		COPYARGS2(1, 11, UT_64K, UT_1K - 1),
		COPYARGS2(1, UT_64K - 1, 3 * UT_64K + 3, UT_64K - 5),
		COPYARGS2(UT_1M - 1, UT_64K, UT_1M, UT_64K + 1),
		COPYARGS2(UT_1G - 1, UT_1M - 1, UT_1M + 11, UT_1M + 1),
		COPYARGS2(UT_1T - 1, UT_1M + 11, UT_1G - 1, UT_1M - 1),
	};

	ut_copy_range2(ute, ut_file_copy_range_into_hole_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_mtime_(struct ut_env *ute, loff_t off_src, size_t len_src,
			  loff_t off_dst, size_t len_dst)
{
	struct stat st[3];
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const size_t len = ut_min(len_src, len_dst);
	void *buf = ut_randbuf(ute, len);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_write_read(ute, ino_src, buf, len, off_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_dst, ut_off_end(off_dst, len_dst));
	ut_getattr(ute, ino_dst, &st[0]);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_verify(ute, ino_dst, buf, len, off_dst);
	ut_getattr(ute, ino_dst, &st[1]);
	ut_expect_gt_mtime(&st[1], &st[0]);
	ut_copy_file_range(ute, ino_src, off_src, ino_dst, off_dst, len);
	ut_read_verify(ute, ino_dst, buf, len, off_dst);
	ut_getattr(ute, ino_dst, &st[2]);
	ut_expect_gt_mtime(&st[2], &st[1]);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_mtime(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		/* aligned */
		COPYARGS2(0, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1K, UT_64K, 0, UT_64K),
		COPYARGS2(UT_1K, UT_1M, UT_64K - UT_1K, UT_64K),
		COPYARGS2(UT_64K, UT_64K, UT_1M, UT_64K),
		COPYARGS2(UT_1G, 2 * UT_64K, UT_64K, UT_64K),
		COPYARGS2(UT_1T, UT_64K, UT_1M, UT_64K),
		/* unaligned */
		COPYARGS2(1, 11, UT_64K, UT_1K - 1),
		COPYARGS2(1, UT_64K - 1, 3 * UT_64K + 3, UT_64K - 5),
		COPYARGS2(UT_1M - 1, UT_64K, UT_1M, UT_64K + 1),
		COPYARGS2(UT_1G - 1, UT_1M - 1, UT_1M + 11, UT_1M + 1),
		COPYARGS2(UT_1T - 1, UT_1M + 11, UT_1G - 1, UT_1M - 1),
	};

	ut_copy_range2(ute, ut_file_copy_range_mtime_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_extend_(struct ut_env *ute, loff_t off, size_t len)
{
	struct stat st[2];
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf = ut_randbuf(ute, len);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_getattr(ute, ino_dst, &st[0]);
	ut_copy_file_range(ute, ino_src, off, ino_dst, off, len);
	ut_getattr(ute, ino_dst, &st[1]);
	ut_expect_gt_mtime(&st[1], &st[0]);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_trunacate_zero(ute, ino_src);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_extend(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		/* aligned */
		COPYARGS1(0, UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_1K, UT_4K),
		COPYARGS1(UT_1K, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(UT_64K, UT_1M),
		COPYARGS1(UT_1M, UT_64K),
		COPYARGS1(UT_1G, UT_1M),
		COPYARGS1(UT_1T, 2 * UT_64K),
		/* unaligned */
		COPYARGS1(1, UT_1K + 11),
		COPYARGS1(11, UT_4K - 111),
		COPYARGS1(111, UT_64K + 1111),
		COPYARGS1(UT_1K + 1, UT_4K + 11),
		COPYARGS1(UT_1K - 11, UT_64K + 111),
		COPYARGS1(UT_64K - 1, UT_64K + 11),
		COPYARGS1(UT_64K + 11, UT_1M - 111),
		COPYARGS1(UT_1M - 111, UT_64K + 1111),
		COPYARGS1(UT_1G + 11, UT_1M - 11111),
		COPYARGS1(UT_1T - 1111, 11 * UT_64K + 1),
	};

	ut_copy_range1(ute, ut_file_copy_range_extend_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_empty_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const loff_t end = ut_off_end(off, len);
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_src, end);
	ut_copy_file_range(ute, ino_src, 0, ino_dst, 0, (size_t)end);
	ut_read_zeros(ute, ino_dst, off, len);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_empty(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		/* aligned */
		COPYARGS1(UT_1M, UT_1M),
		COPYARGS1(UT_1G, UT_1M),
		COPYARGS1(4 * UT_1G, UT_1M),
		COPYARGS1(64 * UT_1G, UT_1M),
		COPYARGS1(UT_1T, UT_1M),
		/* unaligned */
		COPYARGS1(UT_1M - 1, UT_1M + 11),
		COPYARGS1(UT_1G - 11, UT_1M + 111),
		COPYARGS1(11 * UT_1G - 11, UT_1M - 1111),
		COPYARGS1(111 * UT_1G + 1, UT_1M + 11),
		COPYARGS1(UT_1T - 111, UT_1M + 1111),
	};

	ut_copy_range1(ute, ut_file_copy_range_empty_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_sparse_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	const loff_t end = ut_off_end(off, len);
	uint8_t b[2] = { 'A', 'B' };
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, &b[0], 1, off);
	ut_write_read(ute, ino_src, &b[1], 1, end - 1);
	ut_copy_file_range(ute, ino_src, 0, ino_dst, 0, (size_t)end);
	ut_read_verify(ute, ino_dst, &b[0], 1, off);
	ut_read_verify(ute, ino_dst, &b[1], 1, end - 1);
	ut_read_zero(ute, ino_dst, off + 1);
	ut_read_zero(ute, ino_dst, end - 2);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_sparse(struct ut_env *ute)
{
	const struct ut_copy_range_args args[] = {
		/* aligned */
		COPYARGS1(UT_1M, UT_1M),
		COPYARGS1(UT_1G, UT_1M),
		COPYARGS1(4 * UT_1G, UT_1M),
		COPYARGS1(64 * UT_1G, UT_1M),
		COPYARGS1(UT_1T, UT_1M),
		/* unaligned */
		COPYARGS1(UT_1M - 1, UT_1M + 11),
		COPYARGS1(UT_1G - 11, UT_1M + 111),
		COPYARGS1(11 * UT_1G - 11, UT_1M - 1111),
		COPYARGS1(111 * UT_1G + 1, UT_1M + 11),
		COPYARGS1(UT_1T - 111, UT_1M + 1111),
	};

	ut_copy_range1(ute, ut_file_copy_range_sparse_, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST2(ut_file_copy_range_simple_aligned),
	UT_DEFTEST2(ut_file_copy_range_simple_unaligned),
	UT_DEFTEST2(ut_file_copy_range_self_aligned),
	UT_DEFTEST2(ut_file_copy_range_self_unaligned),
	UT_DEFTEST2(ut_file_copy_range_between_aligned),
	UT_DEFTEST2(ut_file_copy_range_between_unaligned),
	UT_DEFTEST2(ut_file_copy_range_truncate),
	UT_DEFTEST2(ut_file_copy_range_overwrite),
	UT_DEFTEST2(ut_file_copy_range_nfiles_aligned),
	UT_DEFTEST2(ut_file_copy_range_nfiles_unaligned),
	UT_DEFTEST2(ut_file_copy_range_from_hole),
	UT_DEFTEST2(ut_file_copy_range_into_hole),
	UT_DEFTEST2(ut_file_copy_range_mtime),
	UT_DEFTEST2(ut_file_copy_range_extend),
	UT_DEFTEST2(ut_file_copy_range_empty),
	UT_DEFTEST2(ut_file_copy_range_sparse),
};

const struct ut_testdefs ut_tdefs_file_copy_range = UT_MKTESTS(ut_local_tests);
