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
 * Expects read-write data-consistency, sequential writes of single block.
 */
static void test_basic_simple_(struct ft_env *fte, size_t bsz, size_t cnt)
{
	int fd;
	loff_t pos = -1;
	size_t num;
	struct stat st;
	void *buf = ft_new_buf_zeros(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0644, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = i;
		memcpy(buf, &num, sizeof(num));
		ft_writen(fd, buf, bsz);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, (i + 1) * bsz);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ft_readn(fd, buf, bsz);
		memcpy(&num, buf, sizeof(num));
		ft_expect_eq(i, num);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_basic_simple(struct ft_env *fte)
{
	test_basic_simple_(fte, FT_BK_SIZE, 256);
	test_basic_simple_(fte, FT_BK_SIZE + 1, 256);
	test_basic_simple_(fte, FT_UMEGA, 16);
	test_basic_simple_(fte, FT_UMEGA - 1, 16);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for n uint64_t integers
 */
static void test_basic_seq_(struct ft_env *fte, size_t count)
{
	int fd;
	uint64_t num;
	loff_t off;
	const size_t bsz = sizeof(num);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < count; ++i) {
		num = i;
		off = (loff_t)(i * bsz);
		ft_pwriten(fd, &num, bsz, off);
	}
	for (size_t i = 0; i < count; ++i) {
		off = (loff_t)(i * bsz);
		ft_preadn(fd, &num, bsz, off);
		ft_expect_eq(i, num);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_basic_seq1(struct ft_env *fte)
{
	test_basic_seq_(fte, 1);
	test_basic_seq_(fte, 2);
	test_basic_seq_(fte, 10);
}

static void test_basic_seq_1k(struct ft_env *fte)
{
	test_basic_seq_(fte, FT_UKILO / sizeof(uint64_t));
}

static void test_basic_seq_8k(struct ft_env *fte)
{
	test_basic_seq_(fte, 8 * FT_UKILO / sizeof(uint64_t));
}

static void test_basic_seq_1m(struct ft_env *fte)
{
	test_basic_seq_(fte, FT_UMEGA / sizeof(uint64_t));
}

static void test_basic_seq_8m(struct ft_env *fte)
{
	test_basic_seq_(fte, (8 * FT_UMEGA) / sizeof(uint64_t));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for buffer-size
 */
static void test_basic_rdwr_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st;
	void *buf1 = NULL;
	void *buf2 = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < 10; ++i) {
		buf1 = ft_new_buf_rands(fte, len);
		ft_pwriten(fd, buf1, len, off);
		ft_fsync(fd);
		ft_preadn(fd, buf2, len, off);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, off + (ssize_t)len);
		ft_expect_eqm(buf1, buf2, len);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_basic_rdwr(struct ft_env *fte)
{
	const struct ft_range range[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_1K, FT_1K),
		FT_MKRANGE(2 * FT_1K, 2 * FT_4K),
		FT_MKRANGE(FT_4K, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_64K - FT_4K, 4 * FT_64K),
		FT_MKRANGE(FT_MEGA, FT_4K),
		FT_MKRANGE(FT_GIGA, FT_MEGA),
		FT_MKRANGE(FT_TERA, 8 * FT_MEGA),
		/* unaligned */
		FT_MKRANGE(FT_1K - 1, 2 * FT_1K),
		FT_MKRANGE(FT_4K - 1, FT_4K + 3),
		FT_MKRANGE(FT_64K - 1, FT_64K + 3),
		FT_MKRANGE(FT_MEGA - 1, FT_4K + 11),
		FT_MKRANGE(FT_GIGA - 11, FT_MEGA + 111),
		FT_MKRANGE(FT_TERA - 111, 11 * FT_MEGA - 1111),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_basic_rdwr_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Must _not_ get ENOSPC for sequence of write-overwrite of large buffer.
 */
static void test_basic_space(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	size_t bsz = FT_UMEGA;
	void *buf1 = NULL;
	void *buf2 = NULL;
	loff_t off = -1;
	int fd = -1;

	for (size_t i = 0; i < 256; ++i) {
		off  = (loff_t)i;
		buf1 = ft_new_buf_rands(fte, bsz);
		buf2 = ft_new_buf_rands(fte, bsz);
		ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
		ft_pwriten(fd, buf1, bsz, off);
		ft_preadn(fd, buf2, bsz, off);
		ft_expect_eqm(buf1, buf2, bsz);
		ft_close(fd);
		ft_unlink(path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency, reverse over-writes.
 */
static void
test_basic_reserve_overwrite_(struct ft_env *fte, loff_t off, size_t len)
{
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_zeros(fte, len);
	const char *path = ft_new_path_unique(fte);
	loff_t pos = -1;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0644, &fd);
	for (size_t i = 0; i < len; ++i) {
		pos = off + (ssize_t)(len - i - 1);
		ft_pwriten(fd, buf1, i + 1, pos);
	}
	ft_preadn(fd, buf2, len, pos);
	ft_expect_eqm(buf1, buf2, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_basic_reserve_overwrite(struct ft_env *fte)
{
	const struct ft_range range[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_4K, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_MEGA, FT_4K),
		FT_MKRANGE(FT_GIGA, FT_4K),
		FT_MKRANGE(FT_TERA, FT_64K),
		/* unaligned */
		FT_MKRANGE(FT_1K - 1, 2 * FT_1K),
		FT_MKRANGE(FT_4K - 1, FT_4K + 3),
		FT_MKRANGE(FT_64K - 1, FT_64K + 3),
		FT_MKRANGE(FT_MEGA - 1, FT_4K + 11),
		FT_MKRANGE(FT_GIGA - 11, FT_4K + 111),
		FT_MKRANGE(FT_TERA - 111, FT_4K + 1111),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_basic_reserve_overwrite_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when I/O overlaps
 */
static void test_basic_overlap(struct ft_env *fte)
{
	size_t cnt = 0;
	size_t bsz = FT_UMEGA;
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	void *buf3 = ft_new_buf_zeros(fte, bsz);
	const char *path = ft_new_path_unique(fte);
	loff_t off = -1;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, bsz, 0);
	ft_preadn(fd, buf3, bsz, 0);
	ft_expect_eqm(buf1, buf3, bsz);

	off = 17;
	cnt = 100;
	ft_pwriten(fd, buf2, cnt, off);
	ft_preadn(fd, buf3, cnt, off);
	ft_expect_eqm(buf2, buf3, cnt);

	off = 2099;
	cnt = 1000;
	ft_pwriten(fd, buf2, cnt, off);
	ft_preadn(fd, buf3, cnt, off);
	ft_expect_eqm(buf2, buf3, cnt);

	off = 32077;
	cnt = 10000;
	ft_pwriten(fd, buf2, cnt, off);
	ft_preadn(fd, buf3, cnt, off);
	ft_expect_eqm(buf2, buf3, cnt);

	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when I/O in complex patterns
 */
static void test_basic_rw(struct ft_env *fte,
                          loff_t pos, loff_t lim, loff_t step)
{
	int fd;
	size_t bsz = FT_BK_SIZE;
	void *buf1 = NULL;
	void *buf2 = NULL;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (loff_t off = pos; off < lim; off += step) {
		buf1 = ft_new_buf_rands(fte, bsz);
		buf2 = ft_new_buf_rands(fte, bsz);
		ft_pwriten(fd, buf1, bsz, off);
		ft_fsync(fd);
		ft_preadn(fd, buf2, bsz, off);
		ft_fsync(fd);
		ft_expect_eqm(buf1, buf2, bsz);
	}
	ft_close(fd);
	ft_unlink(path);
}


static void test_basic_rw_aligned(struct ft_env *fte)
{
	const loff_t step = FT_BK_SIZE;

	test_basic_rw(fte, 0, FT_UMEGA, step);
	test_basic_rw(fte, 0, 2 * FT_UMEGA, step);
	test_basic_rw(fte, FT_UGIGA - FT_UMEGA, FT_UMEGA, step);
}

static void test_basic_rw_unaligned(struct ft_env *fte)
{
	const loff_t step1 = FT_BK_SIZE + 1;
	const loff_t step2 = FT_BK_SIZE - 1;

	test_basic_rw(fte, 0, FT_UMEGA, step1);
	test_basic_rw(fte, 0, FT_UMEGA, step2);
	test_basic_rw(fte, 0, 2 * FT_UMEGA, step1);
	test_basic_rw(fte, 0, 2 * FT_UMEGA, step2);
	test_basic_rw(fte, FT_UGIGA - FT_UMEGA, FT_UMEGA, step1);
	test_basic_rw(fte, FT_UGIGA - FT_UMEGA, FT_UMEGA, step2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of single full large-chunk to regular file
 */
static void test_basic_chunk_(struct ft_env *fte, loff_t off, size_t len)
{
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf1, len, off);
	ft_preadn(fd, buf2, len, off);
	ft_expect_eqm(buf1, buf2, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_basic_chunk_aligned(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_UMEGA),
		FT_MKRANGE(FT_UMEGA, 2 * FT_UMEGA),
		FT_MKRANGE(FT_GIGA, 4 * FT_UMEGA),
		FT_MKRANGE(FT_TERA, 8 * FT_UMEGA),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_basic_chunk_(fte, range[i].off,  range[i].len);
		ft_relax_mem(fte);
	}
}

static void test_basic_chunk_unaligned(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(1, FT_UMEGA),
		FT_MKRANGE(FT_UMEGA - 1, 2 * FT_UMEGA + 2),
		FT_MKRANGE(FT_GIGA - 1, 4 * FT_UMEGA + 4),
		FT_MKRANGE(FT_TERA - 1, 8 * FT_UMEGA + 8),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_basic_chunk_(fte, range[i].off,  range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of ascending files-offsets
 */
static void
test_basic_backword_byte_(struct ft_env *fte, loff_t off, size_t len)
{
	uint8_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path = ft_new_path_unique(fte);
	loff_t pos = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = len; i > 0; --i) {
		pos = off + (loff_t)(i - 1);
		val = (uint8_t)i;
		ft_pwriten(fd, &val, vsz, pos);
		val = 0;
		ft_preadn(fd, &val, vsz, pos);
		ft_expect_eq(0xFF & i, val);
	}
	for (size_t i = len; i > 0; --i) {
		pos = off + (loff_t)(i - 1);
		ft_preadn(fd, &val, vsz, pos);
		ft_expect_eq(0xFF & i, val);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_basic_backword_byte(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, 11),
		FT_MKRANGE(0, 111),
		FT_MKRANGE(0, 1111),
		FT_MKRANGE(0, 11111),
		FT_MKRANGE(FT_MEGA, 1111),
		FT_MKRANGE(FT_MEGA + 11, 1111),
		FT_MKRANGE(FT_GIGA, 1111),
		FT_MKRANGE(FT_GIGA + 11, 1111),
		FT_MKRANGE(FT_TERA, 1111),
		FT_MKRANGE(FT_TERA + 11, 1111),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_basic_backword_byte_(fte, range[i].off,  range[i].len);
		ft_relax_mem(fte);
	}
}

static void test_basic_backword_ulong_(struct ft_env *fte, size_t cnt)
{
	int fd1 = -1;
	int fd2 = -1;
	loff_t pos = 0;
	uint64_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path, O_RDONLY, 0, &fd2);

	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		val = i;
		ft_pwriten(fd1, &val, vsz, pos);
		val = 0;
		ft_preadn(fd1, &val, vsz, pos);
		ft_expect_eq(i, val);
	}
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		ft_preadn(fd1, &val, vsz, pos);
		ft_expect_eq(i, val);
	}
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		ft_preadn(fd2, &val, vsz, pos);
		ft_expect_eq(i, val);
	}
	ft_close(fd1);
	ft_close(fd2);
	ft_unlink(path);
}

static void test_basic_backword_ulong(struct ft_env *fte)
{
	test_basic_backword_ulong_(fte, 11);
	test_basic_backword_ulong_(fte, 111);
	test_basic_backword_ulong_(fte, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_basic_simple),
	FT_DEFTEST(test_basic_rdwr),
	FT_DEFTEST(test_basic_seq1),
	FT_DEFTEST(test_basic_seq_1k),
	FT_DEFTEST(test_basic_seq_8k),
	FT_DEFTEST(test_basic_seq_1m),
	FT_DEFTEST(test_basic_seq_8m),
	FT_DEFTEST(test_basic_space),
	FT_DEFTEST(test_basic_reserve_overwrite),
	FT_DEFTEST(test_basic_overlap),
	FT_DEFTEST(test_basic_rw_aligned),
	FT_DEFTEST(test_basic_rw_unaligned),
	FT_DEFTEST(test_basic_chunk_aligned),
	FT_DEFTEST(test_basic_chunk_unaligned),
	FT_DEFTEST(test_basic_backword_byte),
	FT_DEFTEST(test_basic_backword_ulong),
};

const struct ft_tests ft_test_rw_basic = FT_DEFTESTS(ft_local_tests);
