/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency, sequential writes of single block.
 */
static void test_basic_simple_(struct vt_env *vte, size_t bsz, size_t cnt)
{
	int fd;
	loff_t pos = -1;
	size_t num;
	struct stat st;
	void *buf = vt_new_buf_zeros(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0644, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = i;
		memcpy(buf, &num, sizeof(num));
		vt_writen(fd, buf, bsz);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, (i + 1) * bsz);
	}
	vt_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		vt_readn(fd, buf, bsz);
		memcpy(&num, buf, sizeof(num));
		vt_expect_eq(i, num);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_basic_simple(struct vt_env *vte)
{
	test_basic_simple_(vte, VT_BK_SIZE, 256);
	test_basic_simple_(vte, VT_BK_SIZE + 1, 256);
	test_basic_simple_(vte, VT_UMEGA, 16);
	test_basic_simple_(vte, VT_UMEGA - 1, 16);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for n uint64_t integers
 */
static void test_basic_seq_(struct vt_env *vte, size_t count)
{
	int fd;
	uint64_t num;
	loff_t off;
	const size_t bsz = sizeof(num);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < count; ++i) {
		num = i;
		off = (loff_t)(i * bsz);
		vt_pwriten(fd, &num, bsz, off);
	}
	for (size_t i = 0; i < count; ++i) {
		off = (loff_t)(i * bsz);
		vt_preadn(fd, &num, bsz, off);
		vt_expect_eq(i, num);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_basic_seq1(struct vt_env *vte)
{
	test_basic_seq_(vte, 1);
	test_basic_seq_(vte, 2);
	test_basic_seq_(vte, 10);
}

static void test_basic_seq_1k(struct vt_env *vte)
{
	test_basic_seq_(vte, VT_UKILO / sizeof(uint64_t));
}

static void test_basic_seq_8k(struct vt_env *vte)
{
	test_basic_seq_(vte, 8 * VT_UKILO / sizeof(uint64_t));
}

static void test_basic_seq_1m(struct vt_env *vte)
{
	test_basic_seq_(vte, VT_UMEGA / sizeof(uint64_t));
}

static void test_basic_seq_8m(struct vt_env *vte)
{
	test_basic_seq_(vte, (8 * VT_UMEGA) / sizeof(uint64_t));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for buffer-size
 */
static void test_basic_rdwr(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	struct stat st;
	void *buf1 = NULL;
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < 64; ++i) {
		buf1 = vt_new_buf_rands(vte, bsz);
		vt_pwriten(fd, buf1, bsz, 0);
		vt_fsync(fd);
		vt_preadn(fd, buf2, bsz, 0);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, bsz);
		vt_expect_eqm(buf1, buf2, bsz);
	}

	vt_close(fd);
	vt_unlink(path);
}

static void test_basic_rdwr_1k(struct vt_env *vte)
{
	test_basic_rdwr(vte, VT_UKILO);
}

static void test_basic_rdwr_2k(struct vt_env *vte)
{
	test_basic_rdwr(vte, 2 * VT_UKILO);
}

static void test_basic_rdwr_4k(struct vt_env *vte)
{
	test_basic_rdwr(vte, 4 * VT_UKILO);
}

static void test_basic_rdwr_8k(struct vt_env *vte)
{
	test_basic_rdwr(vte, 8 * VT_UKILO);
}

static void test_basic_rdwr_1m(struct vt_env *vte)
{
	test_basic_rdwr(vte, VT_UMEGA);
}

static void test_basic_rdwr_8m(struct vt_env *vte)
{
	test_basic_rdwr(vte, 8 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Must _not_ get ENOSPC for sequence of write-overwrite of large buffer.
 */
static void test_basic_space(struct vt_env *vte)
{
	int fd;
	loff_t off;
	size_t bsz = VT_UMEGA;
	void *buf1 = NULL;
	void *buf2 = NULL;
	const char *path = vt_new_path_unique(vte);

	for (size_t i = 0; i < 256; ++i) {
		off  = (loff_t)i;
		buf1 = vt_new_buf_rands(vte, bsz);
		buf2 = vt_new_buf_rands(vte, bsz);
		vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
		vt_pwriten(fd, buf1, bsz, off);
		vt_preadn(fd, buf2, bsz, off);
		vt_expect_eqm(buf1, buf2, bsz);
		vt_close(fd);
		vt_unlink(path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency, reverse writes.
 */
static void test_basic_reserve_at(struct vt_env *vte,
                                  loff_t off, size_t ssz)
{
	int fd;
	loff_t pos = -1;
	uint8_t buf[2] = { 0, 0 };
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0644, &fd);
	for (size_t i = 0; i < ssz; ++i) {
		buf[0] = (uint8_t)i;
		pos = off + (loff_t)(ssz - i - 1);
		vt_pwriten(fd, buf, 1, pos);
	}
	for (size_t i = 0; i < ssz; ++i) {
		pos = off + (loff_t)(ssz - i - 1);
		vt_preadn(fd, buf, 1, pos);
		vt_expect_eq(buf[0], (uint8_t)i);
		vt_expect_eq(buf[1], 0);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_basic_reserve1(struct vt_env *vte)
{
	test_basic_reserve_at(vte, 0, VT_BK_SIZE);
}

static void test_basic_reserve2(struct vt_env *vte)
{
	test_basic_reserve_at(vte, 100000, 2 * VT_BK_SIZE);
}

static void test_basic_reserve3(struct vt_env *vte)
{
	test_basic_reserve_at(vte, 9999999, VT_BK_SIZE - 1);
}

static void test_basic_reserve4(struct vt_env *vte)
{
	test_basic_reserve_at(vte,  100003, 7 * VT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when I/O overlaps
 */
static void test_basic_overlap(struct vt_env *vte)
{
	int fd;
	loff_t off;
	size_t cnt = 0;
	size_t bsz = VT_UMEGA;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	void *buf3 = vt_new_buf_zeros(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf1, bsz, 0);
	vt_preadn(fd, buf3, bsz, 0);
	vt_expect_eqm(buf1, buf3, bsz);

	off = 17;
	cnt = 100;
	vt_pwriten(fd, buf2, cnt, off);
	vt_preadn(fd, buf3, cnt, off);
	vt_expect_eqm(buf2, buf3, cnt);

	off = 2099;
	cnt = 1000;
	vt_pwriten(fd, buf2, cnt, off);
	vt_preadn(fd, buf3, cnt, off);
	vt_expect_eqm(buf2, buf3, cnt);

	off = 32077;
	cnt = 10000;
	vt_pwriten(fd, buf2, cnt, off);
	vt_preadn(fd, buf3, cnt, off);
	vt_expect_eqm(buf2, buf3, cnt);

	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when I/O in complex patterns
 */
static void test_basic_rw(struct vt_env *vte,
                          loff_t pos, loff_t lim, loff_t step)
{
	int fd;
	size_t bsz = VT_BK_SIZE;
	void *buf1 = NULL;
	void *buf2 = NULL;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (loff_t off = pos; off < lim; off += step) {
		buf1 = vt_new_buf_rands(vte, bsz);
		buf2 = vt_new_buf_rands(vte, bsz);
		vt_pwriten(fd, buf1, bsz, off);
		vt_fsync(fd);
		vt_preadn(fd, buf2, bsz, off);
		vt_fsync(fd);
		vt_expect_eqm(buf1, buf2, bsz);
	}
	vt_close(fd);
	vt_unlink(path);
}


static void test_basic_rw_aligned(struct vt_env *vte)
{
	const loff_t step = VT_BK_SIZE;

	test_basic_rw(vte, 0, VT_UMEGA, step);
	test_basic_rw(vte, 0, 2 * VT_UMEGA, step);
	test_basic_rw(vte, VT_UGIGA - VT_UMEGA, VT_UMEGA, step);
}

static void test_basic_rw_unaligned(struct vt_env *vte)
{
	const loff_t step1 = VT_BK_SIZE + 1;
	const loff_t step2 = VT_BK_SIZE - 1;

	test_basic_rw(vte, 0, VT_UMEGA, step1);
	test_basic_rw(vte, 0, VT_UMEGA, step2);
	test_basic_rw(vte, 0, 2 * VT_UMEGA, step1);
	test_basic_rw(vte, 0, 2 * VT_UMEGA, step2);
	test_basic_rw(vte, VT_UGIGA - VT_UMEGA, VT_UMEGA, step1);
	test_basic_rw(vte, VT_UGIGA - VT_UMEGA, VT_UMEGA, step2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of single full large-chunk to regular file
 */
static void test_basic_chunk_(struct vt_env *vte,
                              loff_t off, size_t bsz)
{
	int fd = -1;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf1, bsz, off);
	vt_preadn(fd, buf2, bsz, off);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_basic_chunk_x(struct vt_env *vte, size_t bsz)
{
	test_basic_chunk_(vte, 0, bsz);
	test_basic_chunk_(vte, VT_UMEGA, bsz);
	test_basic_chunk_(vte, 1, bsz);
	test_basic_chunk_(vte, VT_UMEGA - 1, bsz);
}

static void test_basic_chunk_1m(struct vt_env *vte)
{
	test_basic_chunk_x(vte, VT_UMEGA);
}

static void test_basic_chunk_2m(struct vt_env *vte)
{
	test_basic_chunk_x(vte, 2 * VT_UMEGA);
}

static void test_basic_chunk_4m(struct vt_env *vte)
{
	test_basic_chunk_x(vte, 4 * VT_UMEGA);
}

static void test_basic_chunk_8m(struct vt_env *vte)
{
	test_basic_chunk_x(vte, 8 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of ascending files-offsets
 */
static void test_basic_backword_byte_(struct vt_env *vte,
                                      loff_t base_off, size_t len)
{
	int fd = -1;
	loff_t pos = 0;
	uint8_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = len; i > 0; --i) {
		pos = base_off + (loff_t)(i - 1);
		val = (uint8_t)i;
		vt_pwriten(fd, &val, vsz, pos);
		val = 0;
		vt_preadn(fd, &val, vsz, pos);
		vt_expect_eq(0xFF & i, val);
	}
	for (size_t i = len; i > 0; --i) {
		pos = base_off + (loff_t)(i - 1);
		vt_preadn(fd, &val, vsz, pos);
		vt_expect_eq(0xFF & i, val);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_basic_backword_byte(struct vt_env *vte)
{
	test_basic_backword_byte_(vte, 0, 11);
	test_basic_backword_byte_(vte, 0, 111);
	test_basic_backword_byte_(vte, 0, 1111);
	test_basic_backword_byte_(vte, 0, 11111);
	test_basic_backword_byte_(vte, VT_MEGA, 1111);
	test_basic_backword_byte_(vte, VT_MEGA + 11, 1111);
	test_basic_backword_byte_(vte, VT_GIGA, 1111);
	test_basic_backword_byte_(vte, VT_GIGA + 11, 1111);
	test_basic_backword_byte_(vte, VT_TERA, 1111);
	test_basic_backword_byte_(vte, VT_TERA + 11, 1111);
}

static void test_basic_backword_ulong_(struct vt_env *vte, size_t cnt)
{
	int fd1 = -1;
	int fd2 = -1;
	loff_t pos = 0;
	uint64_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDONLY, 0, &fd2);

	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		val = i;
		vt_pwriten(fd1, &val, vsz, pos);
		val = 0;
		vt_preadn(fd1, &val, vsz, pos);
		vt_expect_eq(i, val);
	}
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		vt_preadn(fd1, &val, vsz, pos);
		vt_expect_eq(i, val);
	}
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		vt_preadn(fd2, &val, vsz, pos);
		vt_expect_eq(i, val);
	}
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_basic_backword_ulong(struct vt_env *vte)
{
	test_basic_backword_ulong_(vte, 11);
	test_basic_backword_ulong_(vte, 111);
	test_basic_backword_ulong_(vte, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_basic_simple),
	VT_DEFTEST(test_basic_rdwr_1k),
	VT_DEFTEST(test_basic_rdwr_2k),
	VT_DEFTEST(test_basic_rdwr_4k),
	VT_DEFTEST(test_basic_rdwr_8k),
	VT_DEFTEST(test_basic_rdwr_1m),
	VT_DEFTEST(test_basic_rdwr_8m),
	VT_DEFTEST(test_basic_seq1),
	VT_DEFTEST(test_basic_seq_1k),
	VT_DEFTEST(test_basic_seq_8k),
	VT_DEFTEST(test_basic_seq_1m),
	VT_DEFTEST(test_basic_seq_8m),
	VT_DEFTEST(test_basic_space),
	VT_DEFTEST(test_basic_reserve1),
	VT_DEFTEST(test_basic_reserve2),
	VT_DEFTEST(test_basic_reserve3),
	VT_DEFTEST(test_basic_reserve4),
	VT_DEFTEST(test_basic_overlap),
	VT_DEFTEST(test_basic_rw_aligned),
	VT_DEFTEST(test_basic_rw_unaligned),
	VT_DEFTEST(test_basic_chunk_1m),
	VT_DEFTEST(test_basic_chunk_2m),
	VT_DEFTEST(test_basic_chunk_4m),
	VT_DEFTEST(test_basic_chunk_8m),
	VT_DEFTEST(test_basic_backword_byte),
	VT_DEFTEST(test_basic_backword_ulong),
};

const struct vt_tests vt_test_rw_basic = VT_DEFTESTS(vt_local_tests);
