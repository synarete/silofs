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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency, sequential writes of single block.
 */
static void test_rw_basic_simple_(struct ft_env *fte, size_t bsz, size_t cnt)
{
	struct stat st = { .st_size = -1 };
	void *buf = ft_new_buf_zeros(fte, bsz);
	const char *path = ft_new_path_unique(fte);
	loff_t pos = -1;
	size_t num = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0644, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = i;
		ft_memcpy(buf, &num, sizeof(num));
		ft_writen(fd, buf, bsz);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, (i + 1) * bsz);
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	for (size_t i = 0; i < cnt; ++i) {
		ft_readn(fd, buf, bsz);
		ft_memcpy(&num, buf, sizeof(num));
		ft_expect_eq(i, num);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_rw_basic_simple(struct ft_env *fte)
{
	test_rw_basic_simple_(fte, FT_1K, 1000);
	test_rw_basic_simple_(fte, FT_1K - 1, 1000);
	ft_relax_mem(fte);
	test_rw_basic_simple_(fte, FT_64K, 100);
	test_rw_basic_simple_(fte, FT_64K + 1, 100);
	ft_relax_mem(fte);
	test_rw_basic_simple_(fte, FT_1M, 10);
	test_rw_basic_simple_(fte, FT_1M - 1, 10);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for n uint64_t integers
 */
static void test_rw_basic_seq_(struct ft_env *fte, size_t cnt)
{
	const char *path = ft_new_path_unique(fte);
	uint64_t num = 0;
	const size_t bsz = sizeof(num);
	loff_t off = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = i;
		off = (loff_t)(i * bsz);
		ft_pwriten(fd, &num, bsz, off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		off = (loff_t)(i * bsz);
		ft_preadn(fd, &num, bsz, off);
		ft_expect_eq(i, num);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_rw_basic_seq_simple(struct ft_env *fte)
{
	const size_t cnt[] = { 1, 10, 100 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_rw_basic_seq_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

static void test_rw_basic_seq_long(struct ft_env *fte)
{
	const size_t cnt[] = { 1000, 10000, 100000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_rw_basic_seq_(fte, cnt[i]);
		ft_relax_mem(fte);
	}

	test_rw_basic_seq_(fte, FT_1K / sizeof(uint64_t));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects pwrite-pread data-consistency with multiple overwrites
 */
static void test_rw_basic_multi_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
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

static void test_rw_basic_multi(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_1K, FT_1K),
		FT_MKRANGE(2 * FT_1K, 2 * FT_4K),
		FT_MKRANGE(FT_4K, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_64K - FT_4K, 4 * FT_64K),
		FT_MKRANGE(FT_1M, FT_4K),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, 8 * FT_1M),
		/* unaligned */
		FT_MKRANGE(FT_1K - 1, 2 * FT_1K),
		FT_MKRANGE(FT_4K - 1, FT_4K + 3),
		FT_MKRANGE(FT_64K - 1, FT_64K + 3),
		FT_MKRANGE(FT_1M - 1, FT_4K + 11),
		FT_MKRANGE(FT_1G - 11, FT_1M + 111),
		FT_MKRANGE(FT_1T - 111, 11 * FT_1M - 1111),
	};

	ft_exec_with_ranges(fte, test_rw_basic_multi_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Must _not_ get ENOSPC for sequence of write-overwrite of large buffer.
 */
static void test_rw_basic_space(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	size_t bsz = FT_1M;
	void *buf1 = NULL;
	void *buf2 = NULL;
	loff_t off = -1;
	int fd = -1;

	for (size_t i = 0; i < 256; ++i) {
		off = (loff_t)i;
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
test_rw_basic_reserve_overwrite_(struct ft_env *fte, loff_t off, size_t len)
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

static void test_rw_basic_reserve_overwrite(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(FT_4K, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_1M, FT_4K),
		FT_MKRANGE(FT_1G, FT_4K),
		FT_MKRANGE(FT_1T, FT_64K),
		/* unaligned */
		FT_MKRANGE(FT_1K - 1, 2 * FT_1K),
		FT_MKRANGE(FT_4K - 1, FT_4K + 3),
		FT_MKRANGE(FT_64K - 1, FT_64K + 3),
		FT_MKRANGE(FT_1M - 1, FT_4K + 11),
		FT_MKRANGE(FT_1G - 11, FT_4K + 111),
		FT_MKRANGE(FT_1T - 111, FT_4K + 1111),
	};

	ft_exec_with_ranges(fte, test_rw_basic_reserve_overwrite_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when I/O overlaps
 */
static void test_rw_basic_overlap(struct ft_env *fte)
{
	size_t cnt = 0;
	size_t bsz = FT_1M;
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
static void
test_rw_basic_steps_(struct ft_env *fte, loff_t pos, loff_t lim, loff_t step)
{
	size_t bsz = FT_64K;
	void *buf1 = NULL;
	void *buf2 = NULL;
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

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

static void test_rw_basic_aligned_steps(struct ft_env *fte)
{
	const loff_t step = FT_64K;

	test_rw_basic_steps_(fte, 0, FT_1M, step);
	test_rw_basic_steps_(fte, 0, 2 * FT_1M, step);
	test_rw_basic_steps_(fte, FT_1G - FT_1M, FT_1M, step);
}

static void test_rw_basic_unaligned_steps(struct ft_env *fte)
{
	const loff_t step1 = FT_64K + 1;
	const loff_t step2 = FT_64K - 1;

	test_rw_basic_steps_(fte, 0, FT_1M, step1);
	ft_relax_mem(fte);
	test_rw_basic_steps_(fte, 0, FT_1M, step2);
	ft_relax_mem(fte);
	test_rw_basic_steps_(fte, 0, 2 * FT_1M, step1);
	ft_relax_mem(fte);
	test_rw_basic_steps_(fte, 0, 2 * FT_1M, step2);
	ft_relax_mem(fte);
	test_rw_basic_steps_(fte, FT_1G - FT_1M, FT_1M, step1);
	ft_relax_mem(fte);
	test_rw_basic_steps_(fte, FT_1G - FT_1M, FT_1M, step2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of single full large-chunk to regular file
 */
static void test_rw_basic_chunk_(struct ft_env *fte, loff_t off, size_t len)
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

static void test_rw_basic_chunk_aligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1M, 2 * FT_1M),
		FT_MKRANGE(FT_1G, 4 * FT_1M),
		FT_MKRANGE(FT_1T, 8 * FT_1M),
	};

	ft_exec_with_ranges(fte, test_rw_basic_chunk_, ranges);
}

static void test_rw_basic_chunk_unaligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(1, FT_1M),
		FT_MKRANGE(FT_1M - 1, 2 * FT_1M + 2),
		FT_MKRANGE(FT_1G - 1, 4 * FT_1M + 4),
		FT_MKRANGE(FT_1T - 1, 8 * FT_1M + 8),
	};

	ft_exec_with_ranges(fte, test_rw_basic_chunk_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of ascending files-offsets
 */
static void
test_rw_basic_backward_byte_(struct ft_env *fte, loff_t off, size_t len)
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

static void test_rw_basic_backward_byte(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, 11),            //
		FT_MKRANGE(0, 111),           //
		FT_MKRANGE(0, 1111),          //
		FT_MKRANGE(0, 11111),         //
		FT_MKRANGE(FT_1M, 1111),      //
		FT_MKRANGE(FT_1M + 11, 1111), //
		FT_MKRANGE(FT_1G, 1111),      //
		FT_MKRANGE(FT_1G + 11, 1111), //
		FT_MKRANGE(FT_1T, 1111),      //
		FT_MKRANGE(FT_1T + 11, 1111), //
	};

	ft_exec_with_ranges(fte, test_rw_basic_backward_byte_, ranges);
}

static void test_rw_basic_backward_u64_(struct ft_env *fte, size_t cnt)
{
	uint64_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path = ft_new_path_unique(fte);
	loff_t pos = 0;
	int fd1 = -1;
	int fd2 = -1;

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

static void test_rw_basic_backward_u64(struct ft_env *fte)
{
	const size_t cnt[] = { 100, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(cnt); ++i) {
		test_rw_basic_backward_u64_(fte, cnt[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_rw_basic_simple),
	FT_DEFTEST(test_rw_basic_multi),
	FT_DEFTEST(test_rw_basic_seq_simple),
	FT_DEFTEST(test_rw_basic_seq_long),
	FT_DEFTEST(test_rw_basic_space),
	FT_DEFTEST(test_rw_basic_reserve_overwrite),
	FT_DEFTEST(test_rw_basic_overlap),
	FT_DEFTEST(test_rw_basic_aligned_steps),
	FT_DEFTEST(test_rw_basic_unaligned_steps),
	FT_DEFTEST(test_rw_basic_chunk_aligned),
	FT_DEFTEST(test_rw_basic_chunk_unaligned),
	FT_DEFTEST(test_rw_basic_backward_byte),
	FT_DEFTEST(test_rw_basic_backward_u64),
};

const struct ft_tests ft_test_rw_basic = FT_DEFTESTS(ft_local_tests);
