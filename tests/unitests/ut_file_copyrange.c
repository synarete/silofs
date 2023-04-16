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
#include "unitests.h"

struct ut_copy_args {
	loff_t off_src;
	size_t len_src;
	loff_t off_dst;
	size_t len_dst;
};

#define COPYARGS1(a_, b_) \
	COPYARGS2(a_, b_, 0, 0)

#define COPYARGS2(a_, b_, c_, d_) \
	{ .off_src = (a_), .len_src = (b_), .off_dst = (c_), .len_dst = (d_) }


static void
ut_copy_range1(void (*fn)(struct ut_env *, loff_t, size_t),
               struct ut_env *ute, const struct ut_copy_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(ute, args[i].off_src, args[i].len_src);
	}
}

static void
ut_copy_range2(void (*fn)(struct ut_env *, loff_t, size_t, loff_t, size_t),
               struct ut_env *ute, const struct ut_copy_args *args, size_t na)
{
	for (size_t i = 0; i < na; ++i) {
		fn(ute, args[i].off_src, args[i].len_src,
		   args[i].off_dst, args[i].len_dst);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_copy_range1_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino = 0;
	ino_t ino_src = 0;
	ino_t ino_dst = 0;
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, ut_off_end(off, len));
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_aligned(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(UT_1K, 2 * UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_4K, 8 * UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, UT_64K),
		COPYARGS1(UT_MEGA, 2 * UT_64K),
		COPYARGS1(UT_GIGA, UT_MEGA),
		COPYARGS1(UT_TERA, UT_MEGA + UT_64K),
	};

	ut_copy_range1(ut_file_copy_range1_, ute, args, UT_ARRAY_SIZE(args));
}

static void ut_file_copy_range_unaligned(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(2, UT_1K + 2),
		COPYARGS1(3, 3 * UT_1K + 3),
		COPYARGS1(4, UT_4K + 4),
		COPYARGS1(UT_4K - 5, UT_4K + 7),
		COPYARGS1(2 * UT_4K - 5, 3 * UT_4K),
		COPYARGS1(UT_64K - 11, UT_64K + 111),
		COPYARGS1(UT_64K - 111, UT_MEGA + 1111),
		COPYARGS1(UT_MEGA - 1, 11 * UT_64K + 11),
		COPYARGS1(UT_GIGA - 11, UT_MEGA + 111),
		COPYARGS1(UT_TERA - 111, 11 * UT_64K + 111),
	};

	ut_copy_range1(ut_file_copy_range1_, ute, args, UT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_copy_range_between_(struct ut_env *ute,
                                        loff_t off_src, size_t len_src,
                                        loff_t off_dst, size_t len_dst)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
	const size_t len_max = ut_max(len_src, len_dst);
	const size_t len_min = ut_min(len_src, len_dst);
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf_src = ut_randbuf(ute, len_max);
	void *buf_dst = ut_randbuf(ute, len_max);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_max));
	ut_trunacate_file(ute, ino_dst, ut_off_end(off_dst, len_max));
	ut_write_read(ute, ino_src, buf_src, len_src, off_src);
	ut_copy_file_range_ok(ute, ino_src, off_src,
	                      ino_dst, off_dst, len_dst);
	ut_read_verify(ute, ino_dst, buf_src, len_min, off_dst);
	ut_read_zeros(ute, ino_dst, ut_off_end(off_dst, len_min),
	              len_dst - len_min);
	ut_write_read(ute, ino_dst, buf_dst, len_dst, off_dst);
	ut_trunacate_file(ute, ino_src, off_src);
	ut_trunacate_file(ute, ino_src, ut_off_end(off_src, len_max));
	ut_copy_file_range_ok(ute, ino_src, off_src,
	                      ino_dst, off_dst, len_dst);
	ut_read_zeros(ute, ino_dst, off_dst, len_min);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_between(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		/* aligned */
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
		COPYARGS2(UT_MEGA, UT_64K, 0, UT_64K),
		COPYARGS2(UT_MEGA, UT_64K, UT_GIGA, 2 * UT_64K),
		COPYARGS2(UT_TERA, 3 * UT_64K, UT_MEGA, UT_64K),
		COPYARGS2(UT_TERA, 3 * UT_64K, 0, UT_MEGA),
		/* unaligned */
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
		COPYARGS2(UT_MEGA - 1, UT_64K - 2, 1, UT_64K - 3),
		COPYARGS2(UT_MEGA + 11, UT_MEGA, UT_GIGA + 11, UT_MEGA + 1111),
		COPYARGS2(UT_TERA + 111, UT_MEGA + 333, UT_MEGA - 111, 11111),
		COPYARGS2(UT_TERA - 1111, 111111, 1, UT_MEGA + 1111),
	};

	ut_copy_range2(ut_file_copy_range_between_,
	               ute, args, UT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_copy_range_self_(struct ut_env *ute,
                                     loff_t off_src, size_t len_src,
                                     loff_t off_dst, size_t len_dst)
{
	ino_t dino;
	ino_t ino;
	const size_t len_max = ut_max(len_src, len_dst);
	const size_t len_min = ut_min(len_src, len_dst);
	const loff_t off_max = ut_off_end(ut_lmax(off_src, off_dst), len_max);
	void *buf_src = ut_randbuf(ute, len_src);
	void *buf_dst = ut_randbuf(ute, len_dst);
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off_max);
	ut_write_read(ute, ino, buf_src, len_src, off_src);
	ut_copy_file_range_ok(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_verify(ute, ino, buf_src, len_min, off_dst);
	ut_read_zeros(ute, ino, ut_off_end(off_dst, len_min),
	              len_dst - len_min);
	ut_write_read(ute, ino, buf_dst, len_dst, off_dst);
	ut_trunacate_file(ute, ino, 0);
	ut_trunacate_file(ute, ino, off_max);
	ut_copy_file_range_ok(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_zeros(ute, ino, off_dst, len_min);
	ut_write_read(ute, ino, buf_src, len_src, off_src);
	ut_copy_file_range_ok(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_verify(ute, ino, buf_src, len_min, off_dst);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void
ut_file_copy_range_self2_(struct ut_env *ute,
                          loff_t off1, size_t len1, loff_t off2, size_t len2)
{
	ut_file_copy_range_self_(ute, off1, len1, off2, len2);
	ut_file_copy_range_self_(ute, off2, len2, off1, len1);
}

static void ut_file_copy_range_self(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		/* aligned */
		COPYARGS2(0, UT_1K, UT_1K, UT_1K),
		COPYARGS2(0, UT_1K, UT_64K, UT_1K),
		COPYARGS2(0, UT_1K, UT_4K, UT_4K),
		COPYARGS2(UT_1K, UT_4K, UT_64K, UT_4K),
		COPYARGS2(UT_64K, UT_64K, 4 * UT_64K, UT_4K),
		COPYARGS2(UT_MEGA, UT_64K, UT_GIGA, UT_MEGA),
		COPYARGS2(UT_GIGA, UT_MEGA, 0, UT_4K),
		COPYARGS2(UT_GIGA, UT_MEGA, UT_TERA, UT_MEGA / 2),
		/* unaligned */
		COPYARGS2(1, UT_1K - 1, 2 * UT_1K + 1, UT_1K + 1),
		COPYARGS2(UT_4K + 1, UT_4K - 1, UT_64K - 1, UT_4K + 1),
		COPYARGS2(2 * UT_64K + 11, UT_64K - 111, UT_MEGA - 1, 11111),
		COPYARGS2(UT_MEGA - 1, 11111, 333, 33333),
		COPYARGS2(UT_GIGA - 111, 11111, UT_64K - 11, UT_64K + 111),
		COPYARGS2(UT_TERA - 1111, 11111, UT_64K - 111, UT_64K + 1111),
	};

	ut_copy_range2(ut_file_copy_range_self2_,
	               ute, args, UT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_truncate_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
	const loff_t end = ut_off_end(off, len);
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	uint8_t *buf = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_trunacate_file(ute, ino_dst, end - 1);
	ut_trunacate_file(ute, ino_dst, end);
	ut_read_verify(ute, ino_src, buf, len, off);
	ut_read_verify(ute, ino_dst, buf, len - 1, off);
	ut_read_zero(ute, ino_dst, end - 1);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
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
	const struct ut_copy_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_1K, UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, 4 * UT_64K),
		COPYARGS1(0, UT_MEGA),
		COPYARGS1(UT_MEGA, UT_MEGA),
		COPYARGS1(UT_GIGA, UT_64K),
		COPYARGS1(UT_TERA, UT_4K),
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(UT_4K - 1, UT_4K + 3),
		COPYARGS1(UT_64K - 3, UT_MEGA),
		COPYARGS1((2 * UT_64K) - 3, UT_MEGA),
		COPYARGS1(UT_GIGA - 3, UT_64K + 5),
		COPYARGS1(UT_TERA - 3, UT_MEGA + 5),
	};

	ut_copy_range1(ut_file_copy_range_truncate_,
	               ute, args, UT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_overwrite_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
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
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_src, buf1, len, off);
	ut_read_verify(ute, ino_dst, buf1, len, off);
	ut_write_read(ute, ino_src, buf2, len, off);
	ut_read_verify(ute, ino_dst, buf1, len, off);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf2, len, off);
	ut_read_verify(ute, ino_src, buf2, len, off);
	ut_write_read(ute, ino_src, buf1, len, off);
	ut_read_verify(ute, ino_dst, buf2, len, off);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
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
	const struct ut_copy_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_1K, UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, 4 * UT_64K),
		COPYARGS1(0, UT_MEGA),
		COPYARGS1(UT_MEGA, UT_MEGA),
		COPYARGS1(UT_GIGA, UT_64K),
		COPYARGS1(UT_TERA, UT_4K),
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(UT_4K - 1, UT_4K + 3),
		COPYARGS1(UT_64K - 3, UT_MEGA),
		COPYARGS1((2 * UT_64K) - 3, UT_MEGA),
		COPYARGS1(UT_GIGA - 3, UT_64K + 5),
		COPYARGS1(UT_TERA - 3, UT_MEGA + 5),
	};

	ut_copy_range1(ut_file_copy_range_overwrite_,
	               ute, args, UT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_copy_range_nfiles_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
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
		ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
		ut_read_verify(ute, ino_dst, buf, len, off);
		ut_release_ok(ute, ino_dst);
		ut_read_verify(ute, ino_src, buf, len, off);
		ut_lookup_file(ute, dino, name_dst, ino_dst);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		name_dst = ut_make_name(ute, name, i);
		ut_lookup_ino(ute, dino, name_dst, &ino_dst);
		ut_unlink_ok(ute, dino, name_dst);
		ut_read_verify(ute, ino_src, buf, len, off);
	}
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_nfiles(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_1K, UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, 4 * UT_64K),
		COPYARGS1(0, UT_MEGA / 4),
		COPYARGS1(UT_MEGA, UT_MEGA / 8),
		COPYARGS1(UT_GIGA, UT_64K),
		COPYARGS1(UT_TERA, UT_4K),
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(UT_4K - 1, UT_4K + 3),
		COPYARGS1(UT_64K - 3, UT_MEGA / 16),
		COPYARGS1((2 * UT_64K) - 3, UT_MEGA / 32),
		COPYARGS1(UT_GIGA - 3, UT_64K + 5),
		COPYARGS1(UT_TERA - 3, UT_MEGA + 5),
	};

	ut_copy_range1(ut_file_copy_range_nfiles_,
	               ute, args, UT_ARRAY_SIZE(args));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_copy_range_aligned),
	UT_DEFTEST(ut_file_copy_range_unaligned),
	UT_DEFTEST(ut_file_copy_range_self),
	UT_DEFTEST(ut_file_copy_range_between),
	UT_DEFTEST(ut_file_copy_range_truncate),
	UT_DEFTEST(ut_file_copy_range_overwrite),
	UT_DEFTEST(ut_file_copy_range_nfiles),
};

const struct ut_testdefs ut_tdefs_file_copy_range = UT_MKTESTS(ut_local_tests);
