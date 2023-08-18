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


static void
ut_file_fallocate_simple_(struct ut_env *ute, loff_t off, size_t ulen)
{
	const void *buf = ut_randbuf(ute, ulen);
	const char *name = UT_NAME;
	const ino_t root_ino = UT_ROOT_INO;
	const ssize_t len = (ssize_t)ulen;
	ino_t ino = 0;

	ut_create_file(ute, root_ino, name, &ino);
	ut_fallocate_reserve(ute, ino, off, len);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_fallocate_aligned(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_BK_SIZE),
		UT_MKRANGE1(0, UT_UMEGA),
		UT_MKRANGE1(UT_MEGA, UT_UMEGA),
		UT_MKRANGE1(UT_GIGA, UT_UMEGA),
		UT_MKRANGE1(UT_TERA, UT_UMEGA),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_simple_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

static void ut_file_fallocate_unaligned(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(1, 3 * UT_BK_SIZE),
		UT_MKRANGE1(3, UT_UMEGA / 3),
		UT_MKRANGE1(5 * UT_MEGA, UT_UMEGA / 5),
		UT_MKRANGE1(7 * UT_GIGA, UT_UMEGA / 7),
		UT_MKRANGE1(UT_TERA, UT_UMEGA / 11),
		UT_MKRANGE1(UT_FILESIZE_MAX / 2, UT_UMEGA),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_simple_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_rdonly_(struct ut_env *ute, loff_t off, size_t ulen)
{
	const char *name = UT_NAME;
	const ino_t root_ino = UT_ROOT_INO;
	const ssize_t len = (ssize_t)ulen;
	ino_t ino = 0;

	ut_create_file(ute, root_ino, name, &ino);
	ut_fallocate_reserve(ute, ino, off, len);
	ut_read_zero(ute, ino, off);
	ut_read_zero(ute, ino, off + len - 1);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_fallocate_rdonly(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(0, UT_8K),
		UT_MKRANGE1(UT_8K, UT_8K),
		UT_MKRANGE1(0, UT_BK_SIZE),
		UT_MKRANGE1(1, UT_UMEGA),
		UT_MKRANGE1(0, SILOFS_BLOB_SIZE_MAX),
		UT_MKRANGE1(UT_MEGA - 1, SILOFS_BLOB_SIZE_MAX + 2),
		UT_MKRANGE1(UT_GIGA, UT_UMEGA),
		UT_MKRANGE1(UT_TERA - 2, SILOFS_BLOB_SIZE_MAX + 3),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_rdonly_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_truncate_(struct ut_env *ute, loff_t off, size_t ulen)
{
	const char *name = UT_NAME;
	const ssize_t len = (ssize_t)ulen;
	const loff_t mid = off + (len / 2);
	const loff_t end = off + len;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_fallocate_reserve(ute, ino, off, len);
	ut_read_zero(ute, ino, off);
	ut_read_zero(ute, ino, end - 1);
	ut_trunacate_file(ute, ino, mid);
	ut_read_zero(ute, ino, off);
	ut_read_zero(ute, ino, mid - 1);
	ut_trunacate_file(ute, ino, end);
	ut_read_zero(ute, ino, mid);
	ut_read_zero(ute, ino, off);
	ut_read_zero(ute, ino, end - 1);
	ut_write_read1(ute, ino, mid);
	ut_read_zero(ute, ino, off);
	ut_write_read1(ute, ino, end - 1);
	ut_read_zero(ute, ino, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_truncate(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(UT_4K, 2 * UT_4K),
		UT_MKRANGE1(UT_4K - 1, 2 * UT_4K + 3),
		UT_MKRANGE1(0, UT_8K),
		UT_MKRANGE1(UT_8K, UT_8K),
		UT_MKRANGE1(0, UT_BK_SIZE),
		UT_MKRANGE1(11, UT_BK_SIZE),
		UT_MKRANGE1(11, UT_UMEGA),
		UT_MKRANGE1(0, SILOFS_BLOB_SIZE_MAX),
		UT_MKRANGE1(UT_MEGA - 1, SILOFS_BLOB_SIZE_MAX + 2),
		UT_MKRANGE1(UT_GIGA, UT_UMEGA),
		UT_MKRANGE1(UT_TERA - 2, SILOFS_BLOB_SIZE_MAX + 3),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_truncate_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_unwritten_(struct ut_env *ute, loff_t off, size_t ulen)
{
	const char *name = UT_NAME;
	const ssize_t len = (ssize_t)ulen;
	const uint8_t b = 1;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_fallocate_reserve(ute, ino, off, len);
	ut_read_zeros(ute, ino, off, ulen);
	ut_write_read(ute, ino, &b, 1, off);
	ut_write_read(ute, ino, &b, 1, off + len - 1);
	ut_read_zeros(ute, ino, off + 1, ulen - 2);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_unwritten(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_BK_SIZE),
		UT_MKRANGE1(UT_MEGA, 2 * UT_BK_SIZE),
		UT_MKRANGE1(UT_GIGA, 3 * UT_BK_SIZE),
		UT_MKRANGE1(UT_TERA, 4 * UT_BK_SIZE),
		UT_MKRANGE1(UT_MEGA - 111, UT_UMEGA + 1111),
		UT_MKRANGE1(UT_GIGA - 1111, UT_UMEGA + 111),
		UT_MKRANGE1(UT_TERA - 11111, UT_UMEGA + 11),
		UT_MKRANGE1(UT_FILESIZE_MAX - 111111, 111111),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_unwritten_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_drop_caches_(struct ut_env *ute, loff_t off, size_t ulen)
{
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, ulen);
	const ssize_t len = (ssize_t)ulen;
	const ino_t root_ino = UT_ROOT_INO;
	ino_t ino = 0;

	ut_create_file(ute, root_ino, name, &ino);
	ut_fallocate_reserve(ute, ino, off, len);
	ut_release_file(ute, ino);
	ut_sync_drop(ute);
	ut_open_rdwr(ute, ino);
	ut_read_zero(ute, ino, off);
	ut_read_zero(ute, ino, off + len - 1);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_fallocate_drop_caches(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_UMEGA),
		UT_MKRANGE1(3, UT_UMEGA / 3),
		UT_MKRANGE1(5 * UT_MEGA + 5, UT_UMEGA / 5),
		UT_MKRANGE1(UT_TERA / 11, UT_UMEGA / 11),
		UT_MKRANGE1(UT_FILESIZE_MAX / 2, UT_UMEGA),
		UT_MKRANGE1(UT_FILESIZE_MAX - UT_UMEGA - 11, UT_UMEGA + 11),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_drop_caches_(ute, range[i].off,
		                               range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_punch_hole1_(struct ut_env *ute, loff_t off, size_t len)
{
	const char *name = UT_NAME;
	uint8_t *buf = ut_randbuf(ute, len);
	const loff_t off1 = off + (loff_t)len;
	const loff_t off2 = off1 + (loff_t)len;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, len, off);
	ut_trunacate_file(ute, ino, off2);
	ut_fallocate_punch_hole(ute, ino, off1, off2 - off1);
	ut_read_zero(ute, ino, off1);
	ut_read_zero(ute, ino, off2 - 1);
	ut_fallocate_punch_hole(ute, ino, off1 - 1, off2 - off1 - 1);
	ut_read_zero(ute, ino, off1 - 1);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_punch_hole1(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_UMEGA),
		UT_MKRANGE1(UT_MEGA, UT_UMEGA),
		UT_MKRANGE1(UT_GIGA, UT_UMEGA),
		UT_MKRANGE1(UT_TERA, UT_UMEGA),
		UT_MKRANGE1(UT_MEGA - 11, UT_UMEGA + 111),
		UT_MKRANGE1(UT_GIGA - 111, UT_UMEGA + 11),
		UT_MKRANGE1(UT_TERA - 1111, UT_UMEGA + 1),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_punch_hole1_(ute, range[i].off,
		                               range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_punch_hole2_(struct ut_env *ute,
                               loff_t off1, loff_t off2, size_t len)
{
	uint8_t *buf = ut_randbuf(ute, len);
	const char *name = UT_NAME;
	uint8_t zero[1] = { 0 };
	const ino_t root_ino = UT_ROOT_INO;
	ino_t ino = 0;

	ut_create_file(ute, root_ino, name, &ino);
	ut_write_read(ute, ino, buf, len, off1);
	ut_write_read(ute, ino, buf, len, off2);
	ut_fallocate_punch_hole(ute, ino, off1, off2 - off1);
	ut_read_verify(ute, ino, zero, 1, off1);
	ut_read_verify(ute, ino, zero, 1, off2 - 1);

	ut_fallocate_punch_hole(ute, ino, off1, off2 - off1 + 1);
	ut_read_verify(ute, ino, zero, 1, off2);
	ut_read_verify(ute, ino, buf + 1, 1 /* bsz - 1 */, off2 + 1);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_fallocate_punch_hole2(struct ut_env *ute)
{
	const struct ut_range2 range[] = {
		UT_MKRANGE2(0, UT_BK_SIZE, UT_BK_SIZE),
		UT_MKRANGE2(0, UT_MEGA, UT_BK_SIZE),
		UT_MKRANGE2(0, UT_GIGA, UT_UMEGA),
		UT_MKRANGE2(0, UT_TERA, UT_UMEGA),
		UT_MKRANGE2(UT_MEGA, 2 * UT_MEGA, UT_BK_SIZE),
		UT_MKRANGE2(UT_MEGA, UT_GIGA, UT_UMEGA),
		UT_MKRANGE2(UT_MEGA, UT_TERA, UT_UMEGA),
		UT_MKRANGE2(UT_GIGA, UT_TERA, UT_UMEGA),
		UT_MKRANGE2(7, 7 * UT_BK_SIZE - 7, UT_BK_SIZE),
		UT_MKRANGE2(77, 7 * UT_MEGA, 7 * UT_BK_SIZE + 7),
		UT_MKRANGE2(777, 7 * UT_GIGA - 7, UT_UMEGA + 77),
		UT_MKRANGE2(7777, UT_TERA - 7, UT_UMEGA + 77),
		UT_MKRANGE2(77 * UT_MEGA - 7, 7 * UT_GIGA - 7, UT_UMEGA + 77),
		UT_MKRANGE2(777 * UT_GIGA + 77, UT_TERA - 7, UT_UMEGA + 77),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_punch_hole2_(ute, range[i].off1,
		                               range[i].off2, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_punch_hole_sparse_(struct ut_env *ute,
                                     loff_t off_base, loff_t step, size_t cnt)
{
	const char *name = UT_NAME;
	const loff_t bk_size = UT_BK_SIZE;
	loff_t off_end = -1;
	loff_t off = -1;
	ino_t dino = 0;
	ino_t ino = 0;


	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = off_base + ((loff_t)i * step);
		ut_write_read1(ute, ino, off);
		off = off + (3 * bk_size);
		ut_write_read1(ute, ino, off);
		off = off_base + ((loff_t)(i + 1) * step);
		ut_trunacate_file(ute, ino, off);
		off_end = off;
	}
	ut_fallocate_punch_hole(ute, ino, off_base, off_end - off_base);
	for (size_t i = 0; i < cnt; ++i) {
		off = off_base + ((loff_t)i * step);
		ut_read_zero(ute, ino, off);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_punch_hole_sparse(struct ut_env *ute)
{
	ut_file_fallocate_punch_hole_sparse_(ute, 0, UT_MEGA, 111);
	ut_file_fallocate_punch_hole_sparse_(ute, UT_GIGA, 11 * UT_GIGA, 111);
	ut_file_fallocate_punch_hole_sparse_(ute, UT_TERA, 111 * UT_GIGA, 11);
	/* TODO: non aligned ranges */
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_zero_range_(struct ut_env *ute, loff_t off, size_t ulen)
{
	ino_t ino;
	ino_t dino;
	const ssize_t len = (ssize_t)ulen;
	const char *name = UT_NAME;
	uint8_t *buf = ut_randbuf(ute, ulen);
	bool keep_size;

	keep_size = true;
	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_fallocate_zero_range(ute, ino, off, len, keep_size);
	ut_read_zeros(ute, ino, off, ulen);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_fallocate_zero_range(ute, ino, off, 1, keep_size);
	ut_read_zero(ute, ino, off);
	ut_read_verify(ute, ino, buf + 1, ulen - 1, off + 1);

	ut_trunacate_file(ute, ino, off + (2 * len));
	ut_write_read(ute, ino, buf, ulen, off);
	ut_fallocate_zero_range(ute, ino, off + len - 1, len, keep_size);
	ut_write_read(ute, ino, buf, ulen - 1, off);
	ut_read_zero(ute, ino, off + len - 1);

	ut_write_read(ute, ino, buf, ulen, off + len);
	ut_fallocate_zero_range(ute, ino, off, len, keep_size);
	ut_read_verify(ute, ino, buf, ulen, off + len);
	ut_read_zeros(ute, ino, off, ulen);

	keep_size = false;
	ut_trunacate_file(ute, ino, 0);
	ut_fallocate_zero_range(ute, ino, off, len, keep_size);
	ut_read_zero(ute, ino, off + len - 1);
	ut_fallocate_zero_range(ute, ino, off, len + 1, keep_size);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_read_zero(ute, ino, off + len);
	ut_fallocate_zero_range(ute, ino, off + len, len, keep_size);
	ut_write_read(ute, ino, buf, ulen, off + 1);
	ut_read_zero(ute, ino, off + (2 * len) - 1);

	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_zero_range(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_1K),
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(0, UT_BK_SIZE),
		UT_MKRANGE1(UT_MEGA, UT_BK_SIZE),
		UT_MKRANGE1(UT_GIGA, 2 * UT_BK_SIZE),
		UT_MKRANGE1(UT_TERA, UT_MEGA),
		UT_MKRANGE1(UT_MEGA - 11, UT_BK_SIZE + 111),
		UT_MKRANGE1(UT_GIGA - 111, UT_BK_SIZE + 11),
		UT_MKRANGE1(UT_TERA - 1111, UT_MEGA + 1),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_zero_range_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t off_to_nbk(loff_t off)
{
	return off / UT_BK_SIZE;
}

static loff_t off_to_nbk_up(loff_t off)
{
	return off_to_nbk(off + UT_BK_SIZE - 1);
}

static blkcnt_t blocks_count_of(loff_t off, loff_t len)
{
	const silofs_lba_t lba_beg = off_to_nbk(off);
	const silofs_lba_t lba_end = off_to_nbk_up(off + len);
	const loff_t length = (lba_end - lba_beg) * UT_BK_SIZE;

	return length / 512;
}

static void ut_file_fallocate_stat_(struct ut_env *ute, loff_t base_off,
                                    loff_t len, loff_t step_size)
{
	struct stat st[2];
	const char *name = UT_NAME;
	const size_t cnt = 64;
	blkcnt_t nblk = 0;
	loff_t off = -1;
	ino_t dino = 0;
	ino_t ino = 0;


	ut_expect_eq(base_off % UT_BK_SIZE, 0);
	ut_expect_eq(step_size % UT_BK_SIZE, 0);
	ut_expect_le(len, step_size);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);

	ut_getattr_ok(ute, ino, &st[0]);
	ut_expect_eq(st[0].st_size, 0);
	ut_expect_eq(st[0].st_blocks, 0);

	off = base_off;
	for (size_t i = 0; i < cnt; ++i) {
		nblk = blocks_count_of(off, len);

		ut_getattr_ok(ute, ino, &st[0]);
		ut_fallocate_reserve(ute, ino, off, len);
		ut_getattr_ok(ute, ino, &st[1]);

		ut_expect_eq(off + len, st[1].st_size);
		ut_expect_eq(st[0].st_blocks + nblk, st[1].st_blocks);
		off += step_size;
	}
	off = base_off;
	for (size_t j = 0; j < cnt; ++j) {
		nblk = blocks_count_of(off, len);
		ut_getattr_ok(ute, ino, &st[0]);
		ut_fallocate_punch_hole(ute, ino, off, nblk * 512);
		ut_getattr_ok(ute, ino, &st[1]);
		ut_expect_eq(st[0].st_blocks - nblk, st[1].st_blocks);
		off += step_size;
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_stat(struct ut_env *ute)
{
	ut_file_fallocate_stat_(ute, 0, UT_BK_SIZE, UT_BK_SIZE);
	ut_file_fallocate_stat_(ute, 0, UT_BK_SIZE - 1, UT_BK_SIZE);
	ut_file_fallocate_stat_(ute, UT_BK_SIZE, UT_BK_SIZE - 3, UT_BK_SIZE);
	ut_file_fallocate_stat_(ute, 0, UT_MEGA, UT_MEGA);
	ut_file_fallocate_stat_(ute, UT_BK_SIZE, UT_BK_SIZE, UT_MEGA);
	ut_file_fallocate_stat_(ute, UT_MEGA, UT_MEGA - 1, UT_UMEGA);
	ut_file_fallocate_stat_(ute, UT_GIGA, UT_MEGA - 11, 11 * UT_UMEGA);
	ut_file_fallocate_stat_(ute, UT_TERA, UT_MEGA - 111, 111 * UT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_fallocate_sparse_(struct ut_env *ute,
                                      loff_t base_off, loff_t step_size)
{
	ino_t ino;
	ino_t dino;
	loff_t off = -1;
	loff_t len = 0;
	loff_t zero = 0;
	blkcnt_t blocks = 0;
	const char *name = UT_NAME;
	const long cnt = 1024;
	struct stat st;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);

	ut_getattr_ok(ute, ino, &st);
	ut_expect_eq(st.st_size, 0);
	ut_expect_eq(st.st_blocks, 0);

	off = base_off;
	for (long i = 0; i < cnt; ++i) {
		off = base_off + (i * step_size);
		len = (int)sizeof(off);
		ut_fallocate_reserve(ute, ino, off, len);
		ut_getattr_reg(ute, ino, &st);
		ut_expect_eq(st.st_size, off + len);
		ut_expect_gt(st.st_blocks, blocks);
		ut_read_verify(ute, ino, &zero, (size_t)len, off);

		blocks = st.st_blocks;
		ut_write_read(ute, ino, &off, (size_t)len, off);
		ut_getattr_reg(ute, ino, &st);
		ut_expect_eq(st.st_size, off + len);
		ut_expect_eq(st.st_blocks, blocks);
	}

	ut_trunacate_file(ute, ino, 0);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_sparse(struct ut_env *ute)
{
	ut_file_fallocate_sparse_(ute, 0, UT_MEGA);
	ut_file_fallocate_sparse_(ute, 1, UT_MEGA);
	ut_file_fallocate_sparse_(ute, UT_MEGA, UT_GIGA);
	ut_file_fallocate_sparse_(ute, 11 * UT_MEGA - 1, UT_GIGA);
	ut_file_fallocate_sparse_(ute, UT_TERA - 11, UT_GIGA);
	ut_file_fallocate_sparse_(ute, UT_FILESIZE_MAX / 2, UT_GIGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_file_fallocate_beyond_(struct ut_env *ute, loff_t off, size_t ulen)
{
	struct stat st = { .st_size = -1 };
	const char *name = UT_NAME;
	uint8_t *buf = ut_randbuf(ute, ulen);
	const ssize_t len = (ssize_t)ulen;
	blkcnt_t blocks = 0;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_fallocate_reserve(ute, ino, off, len);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_size, off + len);
	ut_read_zeros(ute, ino, off, ulen);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_remove_file(ute, dino, name, ino);

	ut_create_file(ute, dino, name, &ino);
	ut_fallocate_keep_size(ute, ino, off, len);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_size, 0);
	ut_trunacate_file(ute, ino, off + 1);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_size, off + 1);
	ut_read_zeros(ute, ino, off, 1);
	ut_write_read(ute, ino, buf, ulen, off);
	ut_trunacate_file(ute, ino, off);
	ut_remove_file(ute, dino, name, ino);

	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off);
	ut_fallocate_keep_size(ute, ino, off + len, len);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_size, off);
	ut_expect_gt(st.st_blocks, 0);
	blocks = st.st_blocks;
	ut_write_read(ute, ino, buf, ulen, off + (len / 2));
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_size, off + (len / 2) + len);
	ut_expect_gt(st.st_blocks, blocks);
	ut_trunacate_zero(ute, ino);
	ut_remove_file(ute, dino, name, ino);

	ut_rmdir_at_root(ute, name);
}

static void ut_file_fallocate_beyond(struct ut_env *ute)
{
	const struct ut_range range[] = {
		UT_MKRANGE1(0, UT_1K),
		UT_MKRANGE1(0, UT_4K),
		UT_MKRANGE1(0, UT_BK_SIZE),
		UT_MKRANGE1(UT_MEGA, UT_BK_SIZE),
		UT_MKRANGE1(UT_GIGA, 2 * UT_BK_SIZE),
		UT_MKRANGE1(UT_TERA, UT_MEGA),
		UT_MKRANGE1(UT_MEGA - 11, (11 * UT_BK_SIZE) + 111),
		UT_MKRANGE1(UT_GIGA - 111, UT_MEGA + 1111),
		UT_MKRANGE1(UT_TERA - 1111, UT_MEGA + 11111),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(range); ++i) {
		ut_file_fallocate_beyond_(ute, range[i].off, range[i].len);
		ut_relax_mem(ute);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_fallocate_aligned),
	UT_DEFTEST(ut_file_fallocate_unaligned),
	UT_DEFTEST(ut_file_fallocate_rdonly),
	UT_DEFTEST(ut_file_fallocate_truncate),
	UT_DEFTEST(ut_file_fallocate_unwritten),
	UT_DEFTEST(ut_file_fallocate_drop_caches),
	UT_DEFTEST(ut_file_fallocate_punch_hole2),
	UT_DEFTEST(ut_file_fallocate_punch_hole1),
	UT_DEFTEST(ut_file_fallocate_punch_hole_sparse),
	UT_DEFTEST(ut_file_fallocate_zero_range),
	UT_DEFTEST(ut_file_fallocate_stat),
	UT_DEFTEST(ut_file_fallocate_sparse),
	UT_DEFTEST(ut_file_fallocate_beyond),
};

const struct ut_testdefs ut_tdefs_file_fallocate = UT_MKTESTS(ut_local_tests);

