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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to successfully allocate space, and return EBADF if
 * fd is not opened for writing.
 */
static void test_fallocate_basic_(struct ft_env *fte, ssize_t len)
{
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_creat(path, 0600, &fd);
	ft_fallocate(fd, 0, 0, len);
	ft_close(fd);
	ft_open(path, O_RDONLY, 0, &fd);
	ft_fallocate_err(fd, 0, len, 2 * len, -EBADF);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_basic(struct ft_env *fte)
{
	const ssize_t len[] = { FT_64K, 2 * FT_64K, FT_1M, FT_2M };

	for (size_t i = 0; i < FT_ARRAY_SIZE(len); ++i) {
		test_fallocate_basic_(fte, len[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to successfully allocate space for file's sub-ranges.
 */
static void test_fallocate_(struct ft_env *fte, loff_t off, size_t ulen)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	ssize_t len = (ssize_t)ulen;
	int fd = -1;

	ft_creat(path, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);
	ft_fallocate(fd, 0, off, len);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + len);
	ft_expect_gt(st.st_blocks, 0);
	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_aligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_64K),     FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1M, FT_64K), FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
	};

	ft_exec_with_ranges(fte, test_fallocate_, ranges);
}

static void test_fallocate_unaligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, 1),
		FT_MKRANGE(0, FT_64K - 1),
		FT_MKRANGE(0, FT_1M - 1),
		FT_MKRANGE(FT_64K, FT_64K - 1),
		FT_MKRANGE(1, FT_64K + 3),
		FT_MKRANGE(FT_64K - 1, FT_64K + 3),
		FT_MKRANGE(1, FT_1M + 3),
		FT_MKRANGE(FT_1M - 1, FT_1M + 3),
		FT_MKRANGE(FT_1G - 11, FT_1M + 11),
		FT_MKRANGE(FT_1T - 111, FT_1M + 111),
	};

	ft_exec_with_ranges(fte, test_fallocate_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to report allocated space as zero
 */
static void test_fallocate_zeros_(struct ft_env *fte, loff_t off, size_t ulen)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const ssize_t len = (ssize_t)ulen;
	int fd = -1;
	uint8_t byte = 1;
	uint8_t zero = 0;
	uint8_t ab = 0xAB;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, len);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + len);
	ft_preadn(fd, &byte, 1, off);
	ft_expect_eq(byte, zero);
	ft_preadn(fd, &byte, 1, off + len - 1);
	ft_expect_eq(byte, zero);
	ft_pwriten(fd, &ab, 1, off);
	ft_preadn(fd, &byte, 1, off + 1);
	ft_expect_eq(byte, zero);
	ft_pwriten(fd, &ab, 1, off + len - 1);
	ft_preadn(fd, &byte, 1, off + len - 2);
	ft_expect_eq(byte, zero);
	ft_unlink(path);
	ft_close(fd);
}

static void test_fallocate_zeros(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_64K / 2),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
		FT_MKRANGE(1, FT_1M + 3),
		FT_MKRANGE(FT_1M - 1, FT_1M + 11),
		FT_MKRANGE(FT_1G - 11, FT_1M + 111),
		FT_MKRANGE(FT_1T - 111, FT_1M + 1111),
	};

	ft_exec_with_ranges(fte, test_fallocate_zeros_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) and ftruncate(2) to be synchronized.
 */
static void
test_fallocate_truncate_(struct ft_env *fte, loff_t off, size_t ulen)
{
	const char *path = ft_new_path_unique(fte);
	const ssize_t len = (ssize_t)ulen;
	const loff_t mid = off + (len / 2);
	const loff_t end = off + len;
	int fd = -1;
	uint16_t abcd = 0xABCD;
	uint8_t byte = 1;
	uint8_t zero = 0;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, len);
	ft_preadn(fd, &byte, 1, off);
	ft_expect_eq(byte, zero);
	ft_preadn(fd, &byte, 1, end - 1);
	ft_expect_eq(byte, zero);
	ft_preadn(fd, &byte, 1, mid);
	ft_expect_eq(byte, zero);
	ft_ftruncate(fd, mid);
	ft_preadn(fd, &byte, 1, off);
	ft_expect_eq(byte, zero);
	ft_preadn(fd, &byte, 1, mid - 1);
	ft_expect_eq(byte, zero);
	ft_ftruncate(fd, end);
	ft_preadn(fd, &byte, 1, end - 1);
	ft_expect_eq(byte, zero);
	ft_pwriten(fd, &abcd, 2, mid);
	ft_preadn(fd, &byte, 1, off);
	ft_expect_eq(byte, zero);
	ft_preadn(fd, &byte, 1, end - 1);
	ft_expect_eq(byte, zero);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_truncate(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_64K / 4),
		FT_MKRANGE(3, FT_64K / 3),
		FT_MKRANGE(FT_64K / 2, FT_64K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(11, FT_64K),
		FT_MKRANGE(11, FT_1M + 111),
		FT_MKRANGE(0, SILOFS_LSEG_SIZE_MAX),
		FT_MKRANGE(FT_1M - 1, SILOFS_LSEG_SIZE_MAX + 2),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T - 2, SILOFS_LSEG_SIZE_MAX + 3),
		FT_MKRANGE(FT_1T - 1111, FT_1M + 1111),
	};

	ft_exec_with_ranges(fte, test_fallocate_truncate_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful fallocate(2) beyond end-of-file.
 */
static void test_fallocate_beyond_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	const ssize_t ssz = (ssize_t)len;
	void *data = ft_new_buf_rands(fte, len);
	void *rand = ft_new_buf_rands(fte, len);
	void *zero = ft_new_buf_zeros(fte, len);
	const int mode = FALLOC_FL_KEEP_SIZE;
	blkcnt_t blocks = 0;
	int fd = -1;
	uint8_t byte = 1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, ssz);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + ssz);
	ft_preadn(fd, rand, len, off);
	ft_expect_eqm(zero, rand, len);
	ft_close(fd);
	ft_unlink(path);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, mode, off, ssz);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_ftruncate(fd, off + 1);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + 1);
	ft_preadn(fd, &byte, 1, off);
	ft_expect_eq(byte, 0);
	ft_pwriten(fd, data, len, off);
	ft_preadn(fd, rand, len, off);
	ft_expect_eqm(data, rand, len);
	ft_ftruncate(fd, off);
	ft_close(fd);
	ft_unlink(path);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, off);
	ft_fallocate(fd, mode, off + ssz, ssz);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off);
	ft_expect_gt(st.st_blocks, 0);
	blocks = st.st_blocks;
	ft_pwriten(fd, data, len, off + (ssz / 2));
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (ssz / 2) + ssz);
	ft_expect_ge(st.st_blocks, blocks); /* FTYPE1: gt; FTYPE2: ge */
	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_beyond(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, 2 * FT_64K),
		FT_MKRANGE(FT_1T, FT_1M),
		FT_MKRANGE(FT_1M - 11, (11 * FT_64K) + 111),
		FT_MKRANGE(FT_1G - 111, FT_1M + 1111),
		FT_MKRANGE(FT_1T - 1111, FT_1M + 11111),
	};

	ft_exec_with_ranges(fte, test_fallocate_beyond_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) with FALLOC_FL_PUNCH_HOLE to return zeros on hole
 */
static void
test_fallocate_punch_hole_(struct ft_env *fte, loff_t data_off,
                           size_t data_len, loff_t hole_off, size_t hole_len)
{
	const void *buf = ft_new_buf_rands(fte, data_len);
	const char *path = ft_new_path_unique(fte);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	loff_t pos = 0;
	int fd = -1;
	uint8_t byte;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf, data_len, data_off);
	ft_fallocate(fd, mode, hole_off, (loff_t)hole_len);
	ft_preadn(fd, &byte, 1, hole_off);
	ft_expect_eq(byte, 0);
	pos = hole_off + (loff_t)(hole_len - 1);
	ft_preadn(fd, &byte, 1, pos);
	ft_expect_eq(byte, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_punch_hole(struct ft_env *fte)
{
	test_fallocate_punch_hole_(fte, 0, FT_1K, 0, FT_1K / 2);
	test_fallocate_punch_hole_(fte, 0, FT_64K, 0, 32);
	test_fallocate_punch_hole_(fte, 0, FT_64K, 1, 17);
	test_fallocate_punch_hole_(fte, FT_64K, FT_64K, FT_64K + 1,
	                           FT_64K - 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests fallocate(2) with FALLOC_FL_PUNCH_HOLE on various corner cases
 */
static void
test_fallocate_punch_into_hole_(struct ft_env *fte, loff_t base_off)
{
	struct stat st[2];
	const size_t size = FT_1M;
	const loff_t zlen = FT_1M / 4;
	const loff_t off = base_off;
	const loff_t off_end = base_off + (loff_t)size;
	void *buf1 = ft_new_buf_rands(fte, size);
	void *buf2 = ft_new_buf_zeros(fte, size);
	void *buf3 = ft_new_buf_rands(fte, size);
	const char *path = ft_new_path_unique(fte);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	size_t nrd = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, off_end);
	ft_fallocate(fd, mode, off, zlen);
	ft_fstat(fd, &st[0]);
	ft_expect_eq(st[0].st_blocks, 0);
	ft_preadn(fd, buf1, size, off);
	ft_expect_eqm(buf1, buf2, size);
	ft_fallocate(fd, mode, off_end - zlen, zlen);
	ft_pread(fd, buf1, size, off_end - zlen, &nrd);
	ft_expect_eq(nrd, zlen);
	ft_expect_eqm(buf1, buf2, (size_t)zlen);
	ft_pwriten(fd, buf3, (size_t)zlen, off);
	ft_fstat(fd, &st[0]);
	ft_expect_gt(st[0].st_blocks, 0);
	ft_fallocate(fd, mode, off + zlen, zlen);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[0].st_blocks, st[1].st_blocks);
	ft_fallocate(fd, mode, off, zlen);
	ft_fstat(fd, &st[0]);
	ft_expect_lt(st[0].st_blocks, st[1].st_blocks);
	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_punch_into_hole(struct ft_env *fte)
{
	const loff_t off[] = {
		0,
		FT_1M,
		FT_1M - 1,
		FT_1G,
		FT_1G + 1,
		FT_1T,
		FT_1T - 1,
		FT_FILESIZE_MAX / 2,
		(FT_FILESIZE_MAX / 2) + 1,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(off); ++i) {
		test_fallocate_punch_into_hole_(fte, off[i]);
	}
}

static void test_fallocate_punch_into_allocated(struct ft_env *fte)
{
	const size_t size = FT_1M;
	const size_t nzeros = FT_64K;
	const loff_t off = (loff_t)nzeros;
	const char *path = ft_new_path_unique(fte);
	char *buf1 = ft_new_buf_rands(fte, size);
	char *buf2 = ft_new_buf_zeros(fte, size);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	size_t nrd = 0;
	loff_t pos = -1;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, (loff_t)size);
	ft_pwriten(fd, buf2, nzeros, off);
	ft_preadn(fd, buf1, size, 0);
	ft_expect_eqm(buf1, buf2, size);
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	ft_llseek(fd, 0, SEEK_DATA, &pos);
	ft_expect_eq(pos, off);
	ft_fallocate(fd, mode, off, (ssize_t)nzeros);
	ft_pread(fd, buf1, size, 0, &nrd);
	ft_expect_eq(nrd, size);
	ft_expect_eqm(buf1, buf2, size);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests fallocate(2) with FALLOC_FL_ZERO_RANGE on with/without data,
 * with/without FALLOC_FL_KEEP_SIZE.
 */
static void
test_fallocate_zero_range_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	uint8_t *data_buf = ft_new_buf_rands(fte, len);
	uint8_t *read_buf = ft_new_buf_rands(fte, len);
	uint8_t *zero_buf = ft_new_buf_zeros(fte, len);
	const ssize_t ssz = (ssize_t)len;
	int fd = -1;
	int mode;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;
	ft_pwriten(fd, data_buf, len, off);
	ft_preadn(fd, read_buf, len, off);
	ft_expect_eqm(read_buf, data_buf, len);

	ft_fstat(fd, &st[0]);
	ft_fallocate(fd, mode, off, ssz);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[0].st_size, st[1].st_size);
	ft_expect_eq(st[0].st_blocks, st[1].st_blocks);
	ft_preadn(fd, read_buf, len, off);
	ft_expect_eqm(read_buf, zero_buf, len);

	ft_pwriten(fd, data_buf, len, off);
	ft_fstat(fd, &st[0]);
	ft_fallocate(fd, mode, off, 1);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[0].st_size, st[1].st_size);
	ft_expect_eq(st[0].st_blocks, st[1].st_blocks);
	ft_preadn(fd, read_buf, 1, off);
	ft_expect_eq(read_buf[0], 0);
	ft_preadn(fd, read_buf, len - 1, off + 1);
	ft_expect_eqm(read_buf, data_buf + 1, len - 1);

	ft_ftruncate(fd, off + (2 * ssz));
	ft_pwriten(fd, data_buf, len, off);
	ft_fstat(fd, &st[0]);
	ft_fallocate(fd, mode, off + ssz - 1, ssz);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[0].st_size, st[1].st_size);
	ft_expect_eq(st[0].st_blocks, st[1].st_blocks);
	ft_pwriten(fd, data_buf, len - 1, off);
	ft_preadn(fd, read_buf, 1, off + ssz - 1);
	ft_expect_eq(read_buf[0], 0);

	ft_pwriten(fd, data_buf, len, off + ssz);
	ft_fstat(fd, &st[0]);
	ft_fallocate(fd, mode, off, ssz);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[0].st_size, st[1].st_size);
	ft_expect_eq(st[0].st_blocks, st[1].st_blocks);
	ft_preadn(fd, read_buf, len, off);
	ft_expect_eq(read_buf[0], 0);
	ft_expect_eq(read_buf[len - 1], 0);

	/* TODO: split into 2 sub-tests */
	mode = FALLOC_FL_ZERO_RANGE;
	ft_ftruncate(fd, 0);
	ft_fallocate(fd, mode, off, ssz);
	ft_fstat(fd, &st[0]);
	ft_expect_eq(st[0].st_size, off + ssz);
	ft_preadn(fd, read_buf, 1, off);
	ft_expect_eq(read_buf[0], 0);
	ft_preadn(fd, read_buf, 1, off + ssz - 1);
	ft_expect_eq(read_buf[0], 0);
	ft_fallocate(fd, mode, off, ssz + 1);
	ft_pwriten(fd, data_buf, len, off);
	ft_preadn(fd, read_buf, len, off);
	ft_expect_eqm(read_buf, data_buf, len);
	ft_preadn(fd, read_buf, 1, off + ssz);
	ft_expect_eq(read_buf[0], 0);
	ft_fallocate(fd, mode, off + ssz, ssz);
	ft_fstat(fd, &st[1]);
	ft_expect_eq(st[1].st_size, off + (2 * ssz));
	ft_pwriten(fd, data_buf, len, off + 1);
	ft_preadn(fd, read_buf, 1, off + (2 * ssz) - 1);
	ft_expect_eq(read_buf[0], 0);

	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_zero_range(struct ft_env *fte)
{
	/*
	 * Linux kernel commit 4adb83029de8ef5144a14dbb5c21de0f156c1a03
	 * disabled FALLOC_FL_ZERO_RANGE. Sigh..
	 *
	 * TODO: Submit patch to kernel upstream.
	 */
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, 2 * FT_64K),
		FT_MKRANGE(FT_1T, FT_1M),
		FT_MKRANGE(FT_1M - 11, FT_64K + 111),
		FT_MKRANGE(FT_1G - 111, FT_64K + 11),
		FT_MKRANGE(FT_1T - 1111, FT_1M + 1),
	};

	ft_exec_with_ranges(fte, test_fallocate_zero_range_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) on sparse file change size and blocks count. Expects
 * write-on-fallocated to change none.
 */
static void
test_fallocate_sparse_(struct ft_env *fte, loff_t base_off, size_t step_size)
{
	struct stat st;
	const char *path = ft_new_path_unique(fte);
	const size_t cnt = 1024;
	blkcnt_t blocks = 0;
	loff_t off = -1;
	loff_t len = 0;
	loff_t tmp = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);

	blocks = 0;
	off = base_off;
	for (size_t i = 0; i < cnt; ++i) {
		off = base_off + (ssize_t)(i * step_size);
		len = (int)sizeof(off);
		ft_fallocate(fd, 0, off, len);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off + len);
		ft_expect_gt(st.st_blocks, blocks);
		ft_preadn(fd, &tmp, (size_t)len, off);
		ft_expect_eq(tmp, 0);
		blocks = st.st_blocks;
		ft_pwriten(fd, &off, (size_t)len, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off + len);
		ft_expect_eq(st.st_blocks, blocks);
		ft_preadn(fd, &tmp, (size_t)len, off);
		ft_expect_eq(tmp, off);
	}
	ft_ftruncate(fd, 0);
	ft_close(fd);
	ft_unlink(path);
}

static void test_fallocate_sparse(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(1, FT_1M),
		FT_MKRANGE(FT_1M, FT_1G),
		FT_MKRANGE(11 * FT_1M + 1, FT_1G),
		FT_MKRANGE(FT_1T - 111, FT_1G),
		FT_MKRANGE(FT_FILESIZE_MAX / 2, FT_1G),
		FT_MKRANGE((FT_FILESIZE_MAX / 2) - 7, FT_1G + 77),
	};

	ft_exec_with_ranges(fte, test_fallocate_sparse_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_fallocate_basic),
	FT_DEFTEST(test_fallocate_aligned),
	FT_DEFTEST(test_fallocate_unaligned),
	FT_DEFTEST(test_fallocate_zeros),
	FT_DEFTEST(test_fallocate_sparse),
	FT_DEFTEST(test_fallocate_truncate),
	FT_DEFTEST(test_fallocate_beyond),
	FT_DEFTEST(test_fallocate_punch_hole),
	FT_DEFTEST(test_fallocate_punch_into_hole),
	FT_DEFTEST(test_fallocate_punch_into_allocated),
	FT_DEFTEST(test_fallocate_zero_range),
};

const struct ft_tests ft_test_fallocate = FT_DEFTESTS(ft_local_tests);
