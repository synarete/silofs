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
 * Expects mmap(3p) to successfully establish a mapping between a process'
 * address space and a file.
 */
static void test_mmap_basic_(struct vt_env *vte, loff_t off, size_t nbk)
{
	int fd = -1;
	size_t msz = VT_BK_SIZE * nbk;
	void *buf = NULL;
	void *addr = NULL;
	const char *path = vt_new_path_unique(vte);

	buf = vt_new_buf_rands(vte, msz);
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf, msz, off);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	vt_expect_eqm(addr, buf, msz);
	buf = vt_new_buf_rands(vte, msz);
	memcpy(addr, buf, msz);
	vt_expect_eqm(addr, buf, msz);
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_basic(struct vt_env *vte)
{
	test_mmap_basic_(vte, 0, 1);
	test_mmap_basic_(vte, 0, 2);
	test_mmap_basic_(vte, VT_BK_SIZE, 3);
	test_mmap_basic_(vte, VT_UMEGA, 4);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_simple_(struct vt_env *vte, loff_t off, size_t msz)
{
	int fd = -1;
	void *addr = NULL;
	void *mbuf = vt_new_buf_rands(vte, msz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	memcpy(addr, mbuf, msz);
	vt_expect_eqm(addr, mbuf, msz);
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_simple(struct vt_env *vte)
{
	test_mmap_simple_(vte, 0, VT_BK_SIZE);
	test_mmap_simple_(vte, VT_GIGA, VT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_fallocate_(struct vt_env *vte, loff_t off, size_t msz)
{
	int fd = -1;
	int mode = 0;
	void *addr = NULL;
	void *data = vt_new_buf_rands(vte, msz);
	void *zero = vt_new_buf_zeros(vte, msz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, mode, off, (loff_t)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	memcpy(addr, data, msz);
	vt_expect_eqm(addr, data, msz);

	/*
	 * Linux kernel commit 4adb83029de8ef5144a14dbb5c21de0f156c1a03
	 * disabled FALLOC_FL_ZERO_RANGE. Sigh..
	 *
	 * TODO: Submit patch to kernel upstream.
	 */
	/* mode = FALLOC_FL_ZERO_RANGE; */
	mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	vt_fallocate(fd, mode, off, (loff_t)msz);
	vt_expect_eqm(addr, zero, msz);
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_fallocate(struct vt_env *vte)
{
	test_mmap_fallocate_(vte, 0, VT_BK_SIZE);
	test_mmap_fallocate_(vte, VT_MEGA, VT_BK_SIZE);
	test_mmap_fallocate_(vte, VT_GIGA, VT_UMEGA);
	test_mmap_fallocate_(vte, VT_TERA, VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_sequential_(struct vt_env *vte, loff_t off, size_t msz)
{
	int fd = -1;
	uint8_t *ptr = NULL;
	void *addr = NULL;
	void *buf = NULL;
	const size_t bsz = VT_BK_SIZE;
	const char *path = vt_new_path_unique(vte);
	const size_t cnt = msz / bsz;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);

	for (size_t i = 0; i < cnt; ++i) {
		buf = vt_new_buf_nums(vte, (long)(i * 1000), bsz);
		ptr = (uint8_t *)addr + (i * bsz);
		memcpy(ptr, buf, bsz);
	}
	for (size_t i = 0; i < cnt; ++i) {
		buf = vt_new_buf_nums(vte, (long)(i * 1000), bsz);
		ptr = (uint8_t *)addr + (i * bsz);
		vt_expect_eqm(ptr, buf, bsz);
	}
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_sequential(struct vt_env *vte)
{
	test_mmap_sequential_(vte, 0, VT_UMEGA / 2);
	test_mmap_sequential_(vte, VT_GIGA, VT_UMEGA);
	test_mmap_sequential_(vte, VT_TERA, 2 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_sparse_(struct vt_env *vte, loff_t off, size_t msz)
{
	int fd = -1;
	long *ptr = NULL;
	void *addr = NULL;
	const size_t stepsz = VT_UMEGA;
	const size_t nsteps = msz / stepsz;
	const long *buf = vt_new_buf_randseq(vte, nsteps, off);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);

	for (size_t i = 0; i < nsteps; ++i) {
		ptr = (long *)addr + (i * (stepsz / sizeof(*ptr)));
		*ptr = buf[i];
	}
	for (size_t i = 0; i < nsteps; ++i) {
		ptr = (long *)addr + (i * (stepsz / sizeof(*ptr)));
		vt_expect_eq(*ptr, buf[i]);
	}
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_sparse(struct vt_env *vte)
{
	test_mmap_sparse_(vte, 0, 8 * VT_UMEGA);
	test_mmap_sparse_(vte, VT_MEGA - VT_BK_SIZE, 16 * VT_UMEGA);
	test_mmap_sparse_(vte, VT_GIGA - VT_UMEGA, 32 * VT_UMEGA);
	test_mmap_sparse_(vte, VT_TERA - VT_GIGA, 64 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_msync_at(struct vt_env *vte, loff_t step)
{
	int fd;
	void *addr = NULL;
	const size_t bsz = 2 * VT_UMEGA;
	const size_t page_size = vt_page_size();
	const loff_t off = step * (loff_t)page_size;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)bsz);
	vt_mmap(NULL, bsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	memcpy(addr, buf, bsz);
	vt_msync(addr, bsz, MS_SYNC);
	vt_munmap(addr, bsz);
	vt_mmap(NULL, bsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	vt_expect_eqm(addr, buf, bsz);
	vt_munmap(addr, bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_msync(struct vt_env *vte)
{
	test_mmap_msync_at(vte, 0);
	test_mmap_msync_at(vte, 1);
	test_mmap_msync_at(vte, 11);
	test_mmap_msync_at(vte, 111);
	test_mmap_msync_at(vte, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests mmap-ed I/O for unlinked file-path.
 */
static void test_mmap_unlinked_(struct vt_env *vte, loff_t off, size_t msz)
{
	int fd = -1;
	long val = 0;
	long *dat = NULL;
	void *addr = NULL;
	const size_t cnt = msz / sizeof(*dat);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	vt_unlink(path);

	for (size_t i = 0; i < cnt; ++i) {
		dat = ((long *)addr) + i;
		*dat = (long)i;
	}
	for (size_t i = 1; i < cnt; i += 2) {
		dat = ((long *)addr) + i;
		val = *dat;
		vt_expect_eq(val, i);
	}
	for (size_t i = 0; i < cnt; i += 2) {
		dat = ((long *)addr) + i;
		val = *dat;
		vt_expect_eq(val, i);
	}
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_stat_noent(path);
}

static void test_mmap_unlinked(struct vt_env *vte)
{
	test_mmap_unlinked_(vte, 0, VT_MEGA);
	test_mmap_unlinked_(vte, VT_GIGA - VT_MEGA, 2 * VT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests double mmap-ed I/O over same file-path.
 */
static void test_mmap_twice_(struct vt_env *vte, loff_t off, size_t msz)
{
	int fd = -1;
	void *addr;
	long *dat = NULL;
	const size_t cnt  = msz / sizeof(*dat);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)msz);
	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	dat = (long *)addr;
	for (size_t i = 0; i < cnt; i += 64) {
		dat[i] = (long)i + off;
	}
	vt_munmap(addr, msz);
	vt_close(fd);

	vt_open(path, O_RDONLY, 0, &fd);
	vt_mmap(NULL, msz, PROT_READ, MAP_SHARED, fd, off, &addr);
	dat = (long *)addr;
	for (size_t i = 0; i < cnt; i += 64) {
		vt_expect_eq((long)i + off, dat[i]);
	}
	vt_munmap(addr, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_twice(struct vt_env *vte)
{
	test_mmap_twice_(vte, 0, VT_UMEGA);
	test_mmap_twice_(vte, VT_TERA, 32 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests write-data followed by read-only mmap
 */
static void test_mmap_after_write_(struct vt_env *vte,
                                   loff_t off, size_t bsz)
{
	int fd = -1;
	void *mem = NULL;
	size_t nwr = 0;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, buf, bsz, off, &nwr);
	vt_expect_eq(bsz, nwr);
	vt_close(fd);
	vt_open(path, O_RDONLY, 0600, &fd);
	vt_mmap(NULL, bsz, PROT_READ, MAP_SHARED, fd, off, &mem);
	vt_expect_eqm(buf, mem, bsz);
	vt_munmap(mem, bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_before_write_(struct vt_env *vte,
                                    loff_t off, size_t bsz)
{
	int fd1 = -1;
	int fd2 = -1;
	void *mem = NULL;
	size_t nwr = 0;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_ftruncate(fd1, off + (loff_t)bsz);
	vt_mmap(NULL, bsz, PROT_READ, MAP_SHARED, fd1, off, &mem);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_pwrite(fd2, buf, bsz, off, &nwr);
	vt_expect_eq(bsz, nwr);
	vt_expect_eqm(mem, buf, bsz);
	vt_munmap(mem, bsz);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_after_write(struct vt_env *vte)
{
	test_mmap_after_write_(vte, 0, VT_UMEGA);
	test_mmap_after_write_(vte, 0, 5 * VT_UMEGA + 5);
	test_mmap_after_write_(vte, VT_UMEGA, VT_UMEGA);
	test_mmap_after_write_(vte, VT_UMEGA, 7 * VT_UMEGA + 7);
	test_mmap_after_write_(vte, VT_UGIGA, 11 * VT_UMEGA + 11);
}

static void test_mmap_before_write(struct vt_env *vte)
{
	test_mmap_before_write_(vte, 0, VT_UMEGA);
	test_mmap_before_write_(vte, 0, 5 * VT_UMEGA + 5);
	test_mmap_before_write_(vte, VT_UMEGA, VT_UMEGA);
	test_mmap_before_write_(vte, VT_UMEGA, 7 * VT_UMEGA + 7);
	test_mmap_before_write_(vte, VT_UGIGA, 11 * VT_UMEGA + 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests write-data with mmap on both data and holes
 */
static void test_mmap_on_holes_(struct vt_env *vte,
                                loff_t base_off, size_t bsz, size_t nsteps)
{
	int fd = -1;
	void *mem = NULL;
	uint8_t *dat = NULL;
	loff_t len = 0;
	loff_t off = 0;
	loff_t pos = 0;
	loff_t npos = 0;
	size_t nwr = 0;
	size_t msz;
	uint64_t num1 = 0;
	uint64_t num2 = 0;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);

	pos = (loff_t)(2 * nsteps * bsz);
	len = base_off + pos;
	msz = (size_t)len;
	vt_ftruncate(fd, len);

	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;
		vt_pwrite(fd, buf, bsz, off, &nwr);
		vt_expect_eq(bsz, nwr);
	}

	vt_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0, &mem);
	dat = mem;
	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;
		vt_expect_eqm(buf, dat + off, bsz);

		num1 = i + 1;
		npos = off + 1;
		memcpy(dat + npos, &num1, sizeof(num1));
		npos = off + (loff_t)bsz + 1;
		memcpy(dat + npos, &num1, sizeof(num1));
	}

	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;

		num1 = i + 1;
		npos = off + 1;
		memcpy(&num2, dat + npos, sizeof(num2));
		vt_expect_eq(num1, num2);

		npos = off + (loff_t)bsz + 1;
		memcpy(&num2, dat + npos, sizeof(num2));
		vt_expect_eq(num1, num2);
	}

	vt_munmap(mem, msz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_on_holes(struct vt_env *vte)
{
	test_mmap_on_holes_(vte, 0, VT_UMEGA, 3);
	test_mmap_on_holes_(vte, VT_BK_SIZE + 5, 5 * VT_BK_SIZE + 5, 5);
	test_mmap_on_holes_(vte, 111 * VT_BK_SIZE + 111, 11111, 111);
	test_mmap_on_holes_(vte, VT_UMEGA, 5 * VT_UMEGA + 5, 5);
	test_mmap_on_holes_(vte, VT_UGIGA, 11 * VT_UMEGA + 11, 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests mixed mmap and read/write operations
 */
static void test_mmap_rw_mixed_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	size_t nrd = 0;
	loff_t off = -1;
	void *addr = NULL;
	char *data = NULL;
	const size_t mlen = 4 * VT_UMEGA;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	char *buf1 = vt_new_buf_rands(vte, bsz);
	char *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mlen);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	vt_expect_ne(addr, NULL);
	data = addr;

	off = 0;
	memcpy(&data[off], buf1, bsz);
	vt_msync(&data[off], bsz, MS_SYNC);
	vt_pread(fd, buf2, bsz, off, &nrd);
	vt_expect_eqm(buf1, buf2, bsz);

	off = (loff_t)(3 * bsz);
	buf1 = vt_new_buf_rands(vte, bsz);
	memcpy(&data[off], buf1, bsz);
	vt_pread(fd, buf2, bsz, off, &nrd);
	vt_expect_eqm(buf1, buf2, bsz);

	off = (loff_t)(11 * bsz);
	buf1 = vt_new_buf_rands(vte, bsz);
	vt_pwrite(fd, buf1, bsz, off, &nrd);
	memcpy(buf2, &data[off], bsz);
	vt_expect_eqm(buf1, buf2, bsz);

	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_rw_mixed(struct vt_env *vte)
{
	test_mmap_rw_mixed_(vte, 4 * VT_KILO);
	test_mmap_rw_mixed_(vte, VT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid semantics for mmap(3p) to file with MAP_PRIVATE
 */
static void test_mmap_private_(struct vt_env *vte, size_t mlen)
{
	int fd = -1;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_PRIVATE;
	size_t nwr = 0;
	void *addr = NULL;
	uint8_t *dptr = NULL;
	uint8_t *data = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_write(fd, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	dptr = (uint8_t *)addr;
	vt_expect_eqm(dptr, data, mlen);
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_private(struct vt_env *vte)
{
	test_mmap_private_(vte, VT_UMEGA);
	test_mmap_private_(vte, 64 * VT_UMEGA);
}

static void test_mmap_private2_(struct vt_env *vte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_PRIVATE;
	void *addr1 = NULL;
	void *addr2 = NULL;
	uint8_t *dptr1 = NULL;
	uint8_t *dptr2 = NULL;
	uint8_t *data = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_write(fd1, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, flag, fd1, 0, &addr1);
	vt_mmap(NULL, mlen, prot, flag, fd2, 0, &addr2);
	dptr1 = (uint8_t *)addr1;
	dptr2 = (uint8_t *)addr2;
	vt_expect_eqm(dptr1, dptr2, mlen);
	vt_munmap(addr1, mlen);
	vt_munmap(addr2, mlen);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_private2(struct vt_env *vte)
{
	test_mmap_private2_(vte, VT_UMEGA);
	test_mmap_private2_(vte, 16 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_madvise_simple_(struct vt_env *vte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	void *addr1 = NULL;
	void *addr2 = NULL;
	void *data = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);
	const int prot = PROT_READ | PROT_WRITE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_write(fd1, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd1, 0, &addr1);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd2, 0, &addr2);
	vt_madvise(addr1, mlen, MADV_RANDOM);
	vt_madvise(addr2, mlen, MADV_SEQUENTIAL);
	vt_expect_eqm(addr1, addr2, mlen);
	vt_munmap(addr1, mlen);
	vt_munmap(addr2, mlen);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_madvise_simple(struct vt_env *vte)
{
	test_mmap_madvise_simple_(vte, VT_UMEGA);
	test_mmap_madvise_simple_(vte, 16 * VT_UMEGA);
}

static void test_mmap_madvise_dontneed_(struct vt_env *vte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	void *addr1 = NULL;
	void *addr2 = NULL;
	void *data = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);
	const int prot = PROT_READ | PROT_WRITE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_write(fd1, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd1, 0, &addr1);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd2, 0, &addr2);
	vt_expect_eqm(addr1, addr2, mlen);
	vt_madvise(addr1, mlen, MADV_DONTNEED);
	vt_madvise(addr2, mlen, MADV_DONTNEED);
	vt_suspends(vte, 2);
	vt_expect_eqm(addr1, addr2, mlen);
	vt_munmap(addr1, mlen);
	vt_munmap(addr2, mlen);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_madvise_dontneed(struct vt_env *vte)
{
	test_mmap_madvise_dontneed_(vte, VT_UMEGA);
	test_mmap_madvise_dontneed_(vte, 16 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_mmap_basic),
	VT_DEFTEST(test_mmap_simple),
	VT_DEFTEST(test_mmap_fallocate),
	VT_DEFTEST(test_mmap_sequential),
	VT_DEFTEST(test_mmap_sparse),
	VT_DEFTEST(test_mmap_msync),
	VT_DEFTEST(test_mmap_unlinked),
	VT_DEFTEST(test_mmap_twice),
	VT_DEFTEST(test_mmap_after_write),
	VT_DEFTEST(test_mmap_before_write),
	VT_DEFTEST(test_mmap_on_holes),
	VT_DEFTEST(test_mmap_rw_mixed),
	VT_DEFTEST(test_mmap_private),
	VT_DEFTEST(test_mmap_private2),
	VT_DEFTEST(test_mmap_madvise_simple),
	VT_DEFTEST(test_mmap_madvise_dontneed),
};

const struct vt_tests vt_test_mmap = VT_DEFTESTS(vt_local_tests);

