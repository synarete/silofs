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
 * Expects fallocate(2) to successfully allocate space, and return EBADF if
 * fd is not opened for writing.
 */
static void test_fallocate_basic(struct vt_env *vte)
{
	int fd = -1;
	loff_t len = VT_BK_SIZE;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	vt_fallocate(fd, 0, 0, len);
	vt_close(fd);
	vt_open(path, O_RDONLY, 0, &fd);
	vt_fallocate_err(fd, 0, len, 2 * len, -EBADF);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to successfully allocate space for file's sub-ranges.
 */
static void test_fallocate_(struct vt_env *vte, loff_t off, ssize_t len)
{
	int fd = -1;
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);
	vt_fallocate(fd, 0, off, len);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + len);
	vt_expect_gt(st.st_blocks, 0);
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_aligned(struct vt_env *vte)
{
	test_fallocate_(vte, 0, VT_BK_SIZE);
	test_fallocate_(vte, 0, VT_UMEGA);
	test_fallocate_(vte, VT_UMEGA, VT_BK_SIZE);
	test_fallocate_(vte, VT_UGIGA, VT_UMEGA);
	test_fallocate_(vte, VT_UTERA, VT_UMEGA);
}

static void test_fallocate_unaligned(struct vt_env *vte)
{
	test_fallocate_(vte, 0, 1);
	test_fallocate_(vte, 0, VT_BK_SIZE - 1);
	test_fallocate_(vte, 0, VT_UMEGA - 1);
	test_fallocate_(vte, VT_BK_SIZE, VT_BK_SIZE - 1);
	test_fallocate_(vte, 1, VT_BK_SIZE + 3);
	test_fallocate_(vte, VT_BK_SIZE - 1, VT_BK_SIZE + 3);
	test_fallocate_(vte, 1, VT_UMEGA + 3);
	test_fallocate_(vte, VT_UMEGA - 1, VT_UMEGA + 3);
	test_fallocate_(vte, VT_UGIGA - 11, VT_UMEGA + 11);
	test_fallocate_(vte, VT_UTERA - 111, VT_UMEGA + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to report allocated space as zero
 */
static void test_fallocate_zeros_(struct vt_env *vte, loff_t off, ssize_t len)
{
	int fd = -1;
	uint8_t byte = 1;
	uint8_t zero = 0;
	uint8_t ab = 0xAB;
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, len);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + len);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, off + len - 1);
	vt_expect_eq(byte, zero);
	vt_pwriten(fd, &ab, 1, off);
	vt_preadn(fd, &byte, 1, off + 1);
	vt_expect_eq(byte, zero);
	vt_pwriten(fd, &ab, 1, off + len - 1);
	vt_preadn(fd, &byte, 1, off + len - 2);
	vt_expect_eq(byte, zero);
	vt_unlink(path);
	vt_close(fd);
}

static void test_fallocate_zeros(struct vt_env *vte)
{
	test_fallocate_zeros_(vte, 0, VT_BK_SIZE / 2);
	test_fallocate_zeros_(vte, 0, VT_BK_SIZE);
	test_fallocate_zeros_(vte, 0, VT_UMEGA);
	test_fallocate_zeros_(vte, VT_UMEGA, VT_BK_SIZE);
	test_fallocate_zeros_(vte, VT_UGIGA, VT_UMEGA);
	test_fallocate_zeros_(vte, VT_UTERA, VT_UMEGA);
	test_fallocate_zeros_(vte, 1, VT_UMEGA + 3);
	test_fallocate_zeros_(vte, VT_UMEGA - 1, VT_UMEGA + 11);
	test_fallocate_zeros_(vte, VT_UGIGA - 11, VT_UMEGA + 111);
	test_fallocate_zeros_(vte, VT_UTERA - 111, VT_UMEGA + 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) and ftruncate(2) to be synchronized.
 */
static void test_fallocate_truncate_(struct vt_env *vte,
                                     loff_t off, ssize_t len)
{
	int fd = -1;
	uint8_t byte = 1;
	uint8_t zero = 0;
	uint16_t abcd = 0xABCD;
	const loff_t mid = off + (len / 2);
	const loff_t end = off + len;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, len);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, end - 1);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, mid);
	vt_expect_eq(byte, zero);
	vt_ftruncate(fd, mid);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, mid - 1);
	vt_expect_eq(byte, zero);
	vt_ftruncate(fd, end);
	vt_preadn(fd, &byte, 1, end - 1);
	vt_expect_eq(byte, zero);
	vt_pwriten(fd, &abcd, 2, mid);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, end - 1);
	vt_expect_eq(byte, zero);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_truncate(struct vt_env *vte)
{
	test_fallocate_truncate_(vte, 0, VT_BK_SIZE / 4);
	test_fallocate_truncate_(vte, 3, VT_BK_SIZE / 3);
	test_fallocate_truncate_(vte, VT_BK_SIZE / 2, VT_BK_SIZE);
	test_fallocate_truncate_(vte, 0, VT_BK_SIZE);
	test_fallocate_truncate_(vte, 11, VT_BK_SIZE);
	test_fallocate_truncate_(vte, 11, VT_UMEGA + 111);
	test_fallocate_truncate_(vte, 0, SILOFS_BLOB_SIZE_MAX);
	test_fallocate_truncate_(vte, VT_MEGA - 1, SILOFS_BLOB_SIZE_MAX + 2);
	test_fallocate_truncate_(vte, VT_GIGA, VT_UMEGA);
	test_fallocate_truncate_(vte, VT_TERA - 2, SILOFS_BLOB_SIZE_MAX + 3);
	test_fallocate_truncate_(vte, VT_TERA - 1111, VT_UMEGA + 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful fallocate(2) beyond end-of-file.
 */
static void test_fallocate_beyond_(struct vt_env *vte, loff_t off, size_t bsz)
{
	int fd = -1;
	uint8_t byte = 1;
	blkcnt_t blocks = 0;
	struct stat st;
	const ssize_t ssz = (ssize_t)bsz;
	void *data = vt_new_buf_rands(vte, bsz);
	void *rand = vt_new_buf_rands(vte, bsz);
	void *zero = vt_new_buf_zeros(vte, bsz);
	const char *path = vt_new_path_unique(vte);
	const int mode = FALLOC_FL_KEEP_SIZE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, ssz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + ssz);
	vt_preadn(fd, rand, bsz, off);
	vt_expect_eqm(zero, rand, bsz);
	vt_close(fd);
	vt_unlink(path);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, mode, off, ssz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_ftruncate(fd, off + 1);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + 1);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, 0);
	vt_pwriten(fd, data, bsz, off);
	vt_preadn(fd, rand, bsz, off);
	vt_expect_eqm(data, rand, bsz);
	vt_ftruncate(fd, off);
	vt_close(fd);
	vt_unlink(path);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_ftruncate(fd, off);
	vt_fallocate(fd, mode, off + ssz, ssz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off);
	vt_expect_gt(st.st_blocks, 0);
	blocks = st.st_blocks;
	vt_pwriten(fd, data, bsz, off + (ssz / 2));
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (ssz / 2) + ssz);
	vt_expect_gt(st.st_blocks, blocks);
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_beyond(struct vt_env *vte)
{
	test_fallocate_beyond_(vte, 0, VT_1K);
	test_fallocate_beyond_(vte, 0, VT_4K);
	test_fallocate_beyond_(vte, 0, VT_BK_SIZE);
	test_fallocate_beyond_(vte, VT_MEGA, VT_BK_SIZE);
	test_fallocate_beyond_(vte, VT_GIGA, 2 * VT_BK_SIZE);
	test_fallocate_beyond_(vte, VT_TERA, VT_MEGA);
	test_fallocate_beyond_(vte, VT_MEGA - 11, (11 * VT_BK_SIZE) + 111);
	test_fallocate_beyond_(vte, VT_GIGA - 111, VT_MEGA + 1111);
	test_fallocate_beyond_(vte, VT_TERA - 1111, VT_MEGA + 11111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) with FALLOC_FL_PUNCH_HOLE to return zeros on hole
 */
static void test_fallocate_punch_hole_(struct vt_env *vte,
                                       loff_t data_off, size_t data_len,
                                       loff_t hole_off, size_t hole_len)
{
	int fd = -1;
	loff_t pos;
	uint8_t byte;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	const void *buf =  vt_new_buf_rands(vte, data_len);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf, data_len, data_off);
	vt_fallocate(fd, mode, hole_off, (loff_t)hole_len);
	vt_preadn(fd, &byte, 1, hole_off);
	vt_expect_eq(byte, 0);
	pos = hole_off + (loff_t)(hole_len - 1);
	vt_preadn(fd, &byte, 1, pos);
	vt_expect_eq(byte, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_punch_hole(struct vt_env *vte)
{
	test_fallocate_punch_hole_(vte, 0, 1024, 0, 512);
	test_fallocate_punch_hole_(vte, 0, VT_BK_SIZE, 0, 32);
	test_fallocate_punch_hole_(vte, 0, VT_BK_SIZE, 1, 17);
	test_fallocate_punch_hole_(vte, VT_BK_SIZE, VT_BK_SIZE,
	                           VT_BK_SIZE + 1, VT_BK_SIZE - 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests fallocate(2) with FALLOC_FL_PUNCH_HOLE on various corner cases
 */
static void
test_fallocate_punch_into_hole_(struct vt_env *vte, loff_t base_off)
{
	int fd;
	size_t nrd;
	struct stat st[2];
	const size_t size = VT_UMEGA;
	const loff_t zlen = VT_UMEGA / 4;
	const loff_t off = base_off;
	const loff_t off_end = base_off + (loff_t)size;
	void *buf1 = vt_new_buf_rands(vte, size);
	void *buf2 = vt_new_buf_zeros(vte, size);
	void *buf3 = vt_new_buf_rands(vte, size);
	const char *path = vt_new_path_unique(vte);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_ftruncate(fd, off_end);
	vt_fallocate(fd, mode, off, zlen);
	vt_fstat(fd, &st[0]);
	vt_expect_eq(st[0].st_blocks, 0);
	vt_preadn(fd, buf1, size, off);
	vt_expect_eqm(buf1, buf2, size);
	vt_fallocate(fd, mode, off_end - zlen, zlen);
	vt_pread(fd, buf1, size, off_end - zlen, &nrd);
	vt_expect_eq(nrd, zlen);
	vt_expect_eqm(buf1, buf2, (size_t)zlen);
	vt_pwriten(fd, buf3, (size_t)zlen, off);
	vt_fstat(fd, &st[0]);
	vt_expect_gt(st[0].st_blocks, 0);
	vt_fallocate(fd, mode, off + zlen, zlen);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_fallocate(fd, mode, off, zlen);
	vt_fstat(fd, &st[0]);
	vt_expect_lt(st[0].st_blocks, st[1].st_blocks);
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_punch_into_hole(struct vt_env *vte)
{
	test_fallocate_punch_into_hole_(vte, 0);
	test_fallocate_punch_into_hole_(vte, VT_UMEGA);
	test_fallocate_punch_into_hole_(vte, VT_UMEGA - 1);
	test_fallocate_punch_into_hole_(vte, VT_UGIGA);
	test_fallocate_punch_into_hole_(vte, VT_UGIGA + 1);
	test_fallocate_punch_into_hole_(vte, VT_UTERA);
	test_fallocate_punch_into_hole_(vte, VT_UTERA - 1);
	test_fallocate_punch_into_hole_(vte, VT_FILESIZE_MAX / 2);
	test_fallocate_punch_into_hole_(vte, (VT_FILESIZE_MAX / 2) + 1);
}

static void test_fallocate_punch_into_allocated(struct vt_env *vte)
{
	int fd = -1;
	loff_t pos;
	size_t nrd = 0;
	const size_t size = 20 * VT_UKILO;
	const size_t nzeros = 4 * VT_UKILO;
	const loff_t off = (loff_t)nzeros;
	const char *path = vt_new_path_unique(vte);
	char *buf1 = vt_new_buf_rands(vte, size);
	char *buf2 = vt_new_buf_zeros(vte, size);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_ftruncate(fd, (loff_t)size);
	vt_pwriten(fd, buf2, nzeros, off);
	vt_preadn(fd, buf1, size, 0);
	vt_expect_eqm(buf1, buf2, size);
	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	vt_llseek(fd, 0, SEEK_DATA, &pos);
	vt_expect_eq(pos, off);
	vt_fallocate(fd, mode, off, off);
	vt_pread(fd, buf1, size, 0, &nrd);
	vt_expect_eq(nrd, size);
	vt_expect_eqm(buf1, buf2, size);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests fallocate(2) with FALLOC_FL_ZERO_RANGE on with/without data,
 * with/without FALLOC_FL_KEEP_SIZE.
 */
static void test_fallocate_zero_range_(struct vt_env *vte,
                                       loff_t off, size_t bsz)
{
	int fd = -1;
	int mode;
	const ssize_t ssz = (ssize_t)bsz;
	uint8_t *data_buf = vt_new_buf_rands(vte, bsz);
	uint8_t *read_buf = vt_new_buf_rands(vte, bsz);
	uint8_t *zero_buf = vt_new_buf_zeros(vte, bsz);
	const char *path = vt_new_path_unique(vte);
	struct stat st[2];

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);

	mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;
	vt_pwriten(fd, data_buf, bsz, off);
	vt_preadn(fd, read_buf, bsz, off);
	vt_expect_eqm(read_buf, data_buf, bsz);

	vt_fstat(fd, &st[0]);
	vt_fallocate(fd, mode, off, ssz);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[0].st_size, st[1].st_size);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_preadn(fd, read_buf, bsz, off);
	vt_expect_eqm(read_buf, zero_buf, bsz);

	vt_pwriten(fd, data_buf, bsz, off);
	vt_fstat(fd, &st[0]);
	vt_fallocate(fd, mode, off, 1);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[0].st_size, st[1].st_size);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_preadn(fd, read_buf, 1, off);
	vt_expect_eq(read_buf[0], 0);
	vt_preadn(fd, read_buf, bsz - 1, off + 1);
	vt_expect_eqm(read_buf, data_buf + 1, bsz - 1);

	vt_ftruncate(fd, off + (2 * ssz));
	vt_pwriten(fd, data_buf, bsz, off);
	vt_fstat(fd, &st[0]);
	vt_fallocate(fd, mode, off + ssz - 1, ssz);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[0].st_size, st[1].st_size);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_pwriten(fd, data_buf, bsz - 1, off);
	vt_preadn(fd, read_buf, 1, off + ssz - 1);
	vt_expect_eq(read_buf[0], 0);

	vt_pwriten(fd, data_buf, bsz, off + ssz);
	vt_fstat(fd, &st[0]);
	vt_fallocate(fd, mode, off, ssz);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[0].st_size, st[1].st_size);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_preadn(fd, read_buf, bsz, off);
	vt_expect_eq(read_buf[0], 0);
	vt_expect_eq(read_buf[bsz - 1], 0);

	/* TODO: split into 2 sub-tests */
	mode = FALLOC_FL_ZERO_RANGE;
	vt_ftruncate(fd, 0);
	vt_fallocate(fd, mode, off, ssz);
	vt_fstat(fd, &st[0]);
	vt_expect_eq(st[0].st_size, off + ssz);
	vt_preadn(fd, read_buf, 1, off);
	vt_expect_eq(read_buf[0], 0);
	vt_preadn(fd, read_buf, 1, off + ssz - 1);
	vt_expect_eq(read_buf[0], 0);
	vt_fallocate(fd, mode, off, ssz + 1);
	vt_pwriten(fd, data_buf, bsz, off);
	vt_preadn(fd, read_buf, bsz, off);
	vt_expect_eqm(read_buf, data_buf, bsz);
	vt_preadn(fd, read_buf, 1, off + ssz);
	vt_expect_eq(read_buf[0], 0);
	vt_fallocate(fd, mode, off + ssz, ssz);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[1].st_size, off + (2 * ssz));
	vt_pwriten(fd, data_buf, bsz, off + 1);
	vt_preadn(fd, read_buf, 1, off + (2 * ssz) - 1);
	vt_expect_eq(read_buf[0], 0);

	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_zero_range(struct vt_env *vte)
{
	/*
	 * Linux kernel commit 4adb83029de8ef5144a14dbb5c21de0f156c1a03
	 * disabled FALLOC_FL_ZERO_RANGE. Sigh..
	 *
	 * TODO: Submit patch to kernel upstream.
	 */
	test_fallocate_zero_range_(vte, 0, VT_1K);
	test_fallocate_zero_range_(vte, 0, VT_4K);
	test_fallocate_zero_range_(vte, 0, VT_BK_SIZE);
	test_fallocate_zero_range_(vte, VT_MEGA, VT_BK_SIZE);
	test_fallocate_zero_range_(vte, VT_GIGA, 2 * VT_BK_SIZE);
	test_fallocate_zero_range_(vte, VT_TERA, VT_MEGA);
	test_fallocate_zero_range_(vte, VT_MEGA - 11, VT_BK_SIZE + 111);
	test_fallocate_zero_range_(vte, VT_GIGA - 111, VT_BK_SIZE + 11);
	test_fallocate_zero_range_(vte, VT_TERA - 1111, VT_MEGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) on sparse file change size and blocks count. Expects
 * wrtie-on-fallocated to change none.
 */
static void test_fallocate_sparse_(struct vt_env *vte,
                                   loff_t base_off, loff_t step_size)
{
	int fd = -1;
	loff_t off = -1;
	loff_t len = 0;
	loff_t tmp = 0;
	blkcnt_t blocks = 0;
	struct stat st;
	const char *path = vt_new_path_unique(vte);
	const long cnt = 1024;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);

	blocks = 0;
	off = base_off;
	for (long i = 0; i < cnt; ++i) {
		off = base_off + (i * step_size);
		len = (int)sizeof(off);
		vt_fallocate(fd, 0, off, len);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off + len);
		vt_expect_gt(st.st_blocks, blocks);
		vt_preadn(fd, &tmp, (size_t)len, off);
		vt_expect_eq(tmp, 0);
		blocks = st.st_blocks;
		vt_pwriten(fd, &off, (size_t)len, off);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off + len);
		vt_expect_eq(st.st_blocks, blocks);
		vt_preadn(fd, &tmp, (size_t)len, off);
		vt_expect_eq(tmp, off);
	}
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_sparse(struct vt_env *vte)
{
	test_fallocate_sparse_(vte, 0, VT_UMEGA);
	test_fallocate_sparse_(vte, 1, VT_UMEGA);
	test_fallocate_sparse_(vte, VT_UMEGA, VT_UGIGA);
	test_fallocate_sparse_(vte, 11 * VT_UMEGA + 1, VT_UGIGA);
	test_fallocate_sparse_(vte, VT_UTERA - 111, VT_UGIGA);
	test_fallocate_sparse_(vte, VT_FILESIZE_MAX / 2, VT_UGIGA);
	test_fallocate_sparse_(vte, (VT_FILESIZE_MAX / 2) - 7,  VT_UGIGA + 77);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_fallocate_basic),
	VT_DEFTEST(test_fallocate_aligned),
	VT_DEFTEST(test_fallocate_unaligned),
	VT_DEFTEST(test_fallocate_zeros),
	VT_DEFTEST(test_fallocate_sparse),
	VT_DEFTEST(test_fallocate_truncate),
	VT_DEFTEST(test_fallocate_beyond),
	VT_DEFTEST(test_fallocate_punch_hole),
	VT_DEFTEST(test_fallocate_punch_into_hole),
	VT_DEFTEST(test_fallocate_punch_into_allocated),
	VT_DEFTEST(test_fallocate_zero_range),
};

const struct vt_tests vt_test_fallocate = VT_DEFTESTS(vt_local_tests);
