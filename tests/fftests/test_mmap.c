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
 * Expects mmap(3p) to successfully establish a mapping between a process'
 * address space and a file.
 */
static void test_mmap_basic_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	void *buf = NULL;
	void *addr = NULL;
	int fd = -1;

	buf = ft_new_buf_rands(fte, len);
	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf, len, off);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	ft_expect_eqm(addr, buf, len);
	buf = ft_new_buf_rands(fte, len);
	memcpy(addr, buf, len);
	ft_expect_eqm(addr, buf, len);
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_basic(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(0, FT_8K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1G, 2 * FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_basic_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_simple_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	void *mbuf = ft_new_buf_rands(fte, len);
	void *addr = NULL;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	memcpy(addr, mbuf, len);
	ft_expect_eqm(addr, mbuf, len);
	ft_munmap(addr, len);
	ft_close(fd);
	ft_open(path, O_RDONLY, 0600, &fd);
	ft_mmap(NULL, len, PROT_READ, MAP_SHARED, fd, off, &addr);
	ft_expect_eqm(addr, mbuf, len);
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_simple(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1G, FT_2M),
		FT_MKRANGE(FT_1T, FT_1M),
		FT_MKRANGE(FT_1T - FT_1M, FT_2M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_simple_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects mmap(3p) to update mtime and ctime after write.
 */
static void test_mmap_mctime_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st[2];
	void *addr = NULL;
	void *mbuf = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_ftruncate(fd, off + (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	ft_fstat(fd, &st[0]);
	ft_suspends(fte, 1);
	memcpy(addr, mbuf, len / 2);
	ft_msync(addr, len, MS_SYNC);
	ft_munmap(addr, len);
	ft_fsync(fd);
	ft_close(fd);
	ft_stat(path, &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_unlink(path);
}

static void test_mmap_mctime(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1G, FT_1M / 2),
		FT_MKRANGE(FT_1T, FT_1M / 4),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_mctime_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_fallocate_(struct ft_env *fte, loff_t off, size_t len)
{
	void *data = ft_new_buf_rands(fte, len);
	void *zero = ft_new_buf_zeros(fte, len);
	const char *path = ft_new_path_unique(fte);
	void *addr = NULL;
	int mode = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, mode, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	memcpy(addr, data, len);
	ft_expect_eqm(addr, data, len);

	/*
	 * Linux kernel commit 4adb83029de8ef5144a14dbb5c21de0f156c1a03
	 * disabled FALLOC_FL_ZERO_RANGE. Sigh..
	 *
	 * TODO: Submit patch to kernel upstream.
	 */
	/* mode = FALLOC_FL_ZERO_RANGE; */
	mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	ft_fallocate(fd, mode, off, (loff_t)len);
	ft_expect_eqm(addr, zero, len);
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_fallocate(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_fallocate_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_sequential_(struct ft_env *fte, loff_t off, size_t len)
{
	const size_t bsz = FT_64K;
	const char *path = ft_new_path_unique(fte);
	const size_t cnt = len / bsz;
	uint8_t *ptr = NULL;
	void *addr = NULL;
	void *buf = NULL;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);

	for (size_t i = 0; i < cnt; ++i) {
		buf = ft_new_buf_nums(fte, (long)(i * 1000), bsz);
		ptr = (uint8_t *)addr + (i * bsz);
		memcpy(ptr, buf, bsz);
	}
	for (size_t i = 0; i < cnt; ++i) {
		buf = ft_new_buf_nums(fte, (long)(i * 1000), bsz);
		ptr = (uint8_t *)addr + (i * bsz);
		ft_expect_eqm(ptr, buf, bsz);
	}
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_sequential(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_2M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_sequential_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_sparse_(struct ft_env *fte, loff_t off, size_t len)
{
	const size_t stepsz = FT_1M;
	const size_t nsteps = len / stepsz;
	const long *buf = ft_new_buf_randseq(fte, nsteps, off);
	const char *path = ft_new_path_unique(fte);
	long *ptr = NULL;
	void *addr = NULL;
	int fd = -1;


	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);

	for (size_t i = 0; i < nsteps; ++i) {
		ptr = (long *)addr + (i * (stepsz / sizeof(*ptr)));
		*ptr = buf[i];
	}
	for (size_t i = 0; i < nsteps; ++i) {
		ptr = (long *)addr + (i * (stepsz / sizeof(*ptr)));
		ft_expect_eq(*ptr, buf[i]);
	}
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_sparse(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, 8 * FT_1M),
		FT_MKRANGE(FT_1M - FT_BK_SIZE, 16 * FT_1M),
		FT_MKRANGE(FT_1G - FT_1M, 32 * FT_1M),
		FT_MKRANGE(FT_1T - FT_1G, 64 * FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_sparse_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_msync_at(struct ft_env *fte, loff_t step)
{
	const size_t len = 2 * FT_1M;
	const size_t page_size = ft_page_size();
	const loff_t off = step * (loff_t)page_size;
	void *buf = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	void *addr = NULL;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	memcpy(addr, buf, len);
	ft_msync(addr, len, MS_SYNC);
	ft_munmap(addr, len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	ft_expect_eqm(addr, buf, len);
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_msync(struct ft_env *fte)
{
	const loff_t step[] = { 0, 1, 11, 111, 1111 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(step); ++i) {
		test_mmap_msync_at(fte, step[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests mmap-ed I/O for unlinked file-path.
 */
static void test_mmap_unlinked_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	long *dat = NULL;
	void *addr = NULL;
	const size_t cnt = len / sizeof(*dat);
	long val = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	ft_unlink(path);

	for (size_t i = 0; i < cnt; ++i) {
		dat = ((long *)addr) + i;
		*dat = (long)i;
	}
	for (size_t i = 1; i < cnt; i += 2) {
		dat = ((long *)addr) + i;
		val = *dat;
		ft_expect_eq(val, i);
	}
	for (size_t i = 0; i < cnt; i += 2) {
		dat = ((long *)addr) + i;
		val = *dat;
		ft_expect_eq(val, i);
	}
	ft_munmap(addr, len);
	ft_close(fd);
	ft_stat_noent(path);
}

static void test_mmap_unlinked(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1G - FT_1M, 2 * FT_1M),
		FT_MKRANGE(FT_1T - FT_1M, 2 * FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_unlinked_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests double mmap-ed I/O over same file-path.
 */
static void test_mmap_twice_(struct ft_env *fte, loff_t off, size_t len)
{
	long *dat = NULL;
	const size_t cnt  = len / sizeof(*dat);
	const char *path = ft_new_path_unique(fte);
	void *addr = NULL;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, off, (loff_t)len);
	ft_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off, &addr);
	dat = (long *)addr;
	for (size_t i = 0; i < cnt; i += 64) {
		dat[i] = (long)i + off;
	}
	ft_munmap(addr, len);
	ft_close(fd);

	ft_open(path, O_RDONLY, 0, &fd);
	ft_mmap(NULL, len, PROT_READ, MAP_SHARED, fd, off, &addr);
	dat = (long *)addr;
	for (size_t i = 0; i < cnt; i += 64) {
		ft_expect_eq((long)i + off, dat[i]);
	}
	ft_munmap(addr, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_twice(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_1G - FT_1M, 4 * FT_1M),
		FT_MKRANGE(FT_1T - FT_1M, 16 * FT_1M),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_twice_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests write-data followed by read-only mmap
 */
static void test_mmap_after_write_(struct ft_env *fte, loff_t off, size_t len)
{
	void *buf = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	void *mem = NULL;
	size_t nwr = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwrite(fd, buf, len, off, &nwr);
	ft_expect_eq(len, nwr);
	ft_close(fd);
	ft_open(path, O_RDONLY, 0600, &fd);
	ft_mmap(NULL, len, PROT_READ, MAP_SHARED, fd, off, &mem);
	ft_expect_eqm(buf, mem, len);
	ft_munmap(mem, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_after_write(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(0, 4 * FT_1M),
		FT_MKRANGE(FT_1M, FT_1M),
		FT_MKRANGE(0, 3 * FT_1M - 3),
		FT_MKRANGE(FT_1M, 7 * FT_1M + 7),
		FT_MKRANGE(FT_1G, 11 * FT_1M + 11),
		FT_MKRANGE(FT_1T, FT_1M + 11111),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_after_write_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

static void test_mmap_before_write_(struct ft_env *fte, loff_t off, size_t len)
{
	void *buf = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	void *mem = NULL;
	size_t nwr = 0;
	int fd1 = -1;
	int fd2 = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_ftruncate(fd1, off + (loff_t)len);
	ft_mmap(NULL, len, PROT_READ, MAP_SHARED, fd1, off, &mem);
	ft_open(path, O_RDWR, 0600, &fd2);
	ft_pwrite(fd2, buf, len, off, &nwr);
	ft_expect_eq(len, nwr);
	ft_expect_eqm(mem, buf, len);
	ft_munmap(mem, len);
	ft_close(fd1);
	ft_close(fd2);
	ft_unlink(path);
}

static void test_mmap_before_write(struct ft_env *fte)
{
	const struct ft_range range[] = {
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(0, 4 * FT_1M),
		FT_MKRANGE(FT_1M, FT_1M),
		FT_MKRANGE(0, 3 * FT_1M - 3),
		FT_MKRANGE(FT_1M, 7 * FT_1M + 7),
		FT_MKRANGE(FT_1G, 11 * FT_1M + 11),
		FT_MKRANGE(FT_1T, FT_1M + 11111),
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(range); ++i) {
		test_mmap_before_write_(fte, range[i].off, range[i].len);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests write-data with mmap on both data and holes
 */
static void test_mmap_on_holes_(struct ft_env *fte,
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
	void *buf = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);

	pos = (loff_t)(2 * nsteps * bsz);
	len = base_off + pos;
	msz = (size_t)len;
	ft_ftruncate(fd, len);

	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;
		ft_pwrite(fd, buf, bsz, off, &nwr);
		ft_expect_eq(bsz, nwr);
	}

	ft_mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0, &mem);
	dat = mem;
	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;
		ft_expect_eqm(buf, dat + off, bsz);

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
		ft_expect_eq(num1, num2);

		npos = off + (loff_t)bsz + 1;
		memcpy(&num2, dat + npos, sizeof(num2));
		ft_expect_eq(num1, num2);
	}

	ft_munmap(mem, msz);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_on_holes(struct ft_env *fte)
{
	test_mmap_on_holes_(fte, 0, FT_1M, 3);
	test_mmap_on_holes_(fte, FT_BK_SIZE + 5, 5 * FT_BK_SIZE + 5, 5);
	test_mmap_on_holes_(fte, 111 * FT_BK_SIZE + 111, 11111, 111);
	test_mmap_on_holes_(fte, FT_1M, 5 * FT_1M + 5, 5);
	test_mmap_on_holes_(fte, FT_1G, 11 * FT_1M + 11, 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests mixed mmap and read/write operations
 */
static void test_mmap_rw_mixed_(struct ft_env *fte, size_t bsz)
{
	int fd = -1;
	size_t nrd = 0;
	loff_t off = -1;
	void *addr = NULL;
	char *data = NULL;
	const size_t mlen = 4 * FT_1M;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	char *buf1 = ft_new_buf_rands(fte, bsz);
	char *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fallocate(fd, 0, 0, (loff_t)mlen);
	ft_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	ft_expect_ne(addr, NULL);
	data = addr;

	off = 0;
	memcpy(&data[off], buf1, bsz);
	ft_msync(&data[off], bsz, MS_SYNC);
	ft_pread(fd, buf2, bsz, off, &nrd);
	ft_expect_eqm(buf1, buf2, bsz);

	off = (loff_t)(3 * bsz);
	buf1 = ft_new_buf_rands(fte, bsz);
	memcpy(&data[off], buf1, bsz);
	ft_pread(fd, buf2, bsz, off, &nrd);
	ft_expect_eqm(buf1, buf2, bsz);

	off = (loff_t)(11 * bsz);
	buf1 = ft_new_buf_rands(fte, bsz);
	ft_pwrite(fd, buf1, bsz, off, &nrd);
	memcpy(buf2, &data[off], bsz);
	ft_expect_eqm(buf1, buf2, bsz);

	ft_munmap(addr, mlen);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_rw_mixed(struct ft_env *fte)
{
	test_mmap_rw_mixed_(fte, 4 * FT_1K);
	test_mmap_rw_mixed_(fte, FT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid semantics for mmap(3p) to file with MAP_PRIVATE
 */
static void test_mmap_private_(struct ft_env *fte, size_t mlen)
{
	int fd = -1;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_PRIVATE;
	size_t nwr = 0;
	void *addr = NULL;
	uint8_t *dptr = NULL;
	uint8_t *data = ft_new_buf_rands(fte, mlen);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_write(fd, data, mlen, &nwr);
	ft_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	dptr = (uint8_t *)addr;
	ft_expect_eqm(dptr, data, mlen);
	ft_munmap(addr, mlen);
	ft_close(fd);
	ft_unlink(path);
}

static void test_mmap_private(struct ft_env *fte)
{
	test_mmap_private_(fte, FT_1M);
	test_mmap_private_(fte, 64 * FT_1M);
}

static void test_mmap_private2_(struct ft_env *fte, size_t mlen)
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
	uint8_t *data = ft_new_buf_rands(fte, mlen);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path, O_RDWR, 0600, &fd2);
	ft_write(fd1, data, mlen, &nwr);
	ft_mmap(NULL, mlen, prot, flag, fd1, 0, &addr1);
	ft_mmap(NULL, mlen, prot, flag, fd2, 0, &addr2);
	dptr1 = (uint8_t *)addr1;
	dptr2 = (uint8_t *)addr2;
	ft_expect_eqm(dptr1, dptr2, mlen);
	ft_munmap(addr1, mlen);
	ft_munmap(addr2, mlen);
	ft_close(fd1);
	ft_close(fd2);
	ft_unlink(path);
}

static void test_mmap_private2(struct ft_env *fte)
{
	test_mmap_private2_(fte, FT_1M);
	test_mmap_private2_(fte, 16 * FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_madvise_simple_(struct ft_env *fte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	void *addr1 = NULL;
	void *addr2 = NULL;
	void *data = ft_new_buf_rands(fte, mlen);
	const char *path = ft_new_path_unique(fte);
	const int prot = PROT_READ | PROT_WRITE;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path, O_RDWR, 0600, &fd2);
	ft_write(fd1, data, mlen, &nwr);
	ft_mmap(NULL, mlen, prot, MAP_SHARED, fd1, 0, &addr1);
	ft_mmap(NULL, mlen, prot, MAP_SHARED, fd2, 0, &addr2);
	ft_madvise(addr1, mlen, MADV_RANDOM);
	ft_madvise(addr2, mlen, MADV_SEQUENTIAL);
	ft_expect_eqm(addr1, addr2, mlen);
	ft_munmap(addr1, mlen);
	ft_munmap(addr2, mlen);
	ft_close(fd1);
	ft_close(fd2);
	ft_unlink(path);
}

static void test_mmap_madvise_simple(struct ft_env *fte)
{
	test_mmap_madvise_simple_(fte, FT_1M);
	test_mmap_madvise_simple_(fte, 16 * FT_1M);
}

static void test_mmap_madvise_dontneed_(struct ft_env *fte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	void *addr1 = NULL;
	void *addr2 = NULL;
	void *data = ft_new_buf_rands(fte, mlen);
	const char *path = ft_new_path_unique(fte);
	const int prot = PROT_READ | PROT_WRITE;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path, O_RDWR, 0600, &fd2);
	ft_write(fd1, data, mlen, &nwr);
	ft_mmap(NULL, mlen, prot, MAP_SHARED, fd1, 0, &addr1);
	ft_mmap(NULL, mlen, prot, MAP_SHARED, fd2, 0, &addr2);
	ft_expect_eqm(addr1, addr2, mlen);
	ft_madvise(addr1, mlen, MADV_DONTNEED);
	ft_madvise(addr2, mlen, MADV_DONTNEED);
	ft_suspends(fte, 2);
	ft_expect_eqm(addr1, addr2, mlen);
	ft_munmap(addr1, mlen);
	ft_munmap(addr2, mlen);
	ft_close(fd1);
	ft_close(fd2);
	ft_unlink(path);
}

static void test_mmap_madvise_dontneed(struct ft_env *fte)
{
	test_mmap_madvise_dontneed_(fte, FT_1M);
	test_mmap_madvise_dontneed_(fte, 16 * FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_mmap_basic),
	FT_DEFTEST(test_mmap_simple),
	FT_DEFTEST(test_mmap_mctime),
	FT_DEFTEST(test_mmap_fallocate),
	FT_DEFTEST(test_mmap_sequential),
	FT_DEFTEST(test_mmap_sparse),
	FT_DEFTEST(test_mmap_msync),
	FT_DEFTEST(test_mmap_unlinked),
	FT_DEFTEST(test_mmap_twice),
	FT_DEFTEST(test_mmap_after_write),
	FT_DEFTEST(test_mmap_before_write),
	FT_DEFTEST(test_mmap_on_holes),
	FT_DEFTEST(test_mmap_rw_mixed),
	FT_DEFTEST(test_mmap_private),
	FT_DEFTEST(test_mmap_private2),
	FT_DEFTEST(test_mmap_madvise_simple),
	FT_DEFTEST(test_mmap_madvise_dontneed),
};

const struct ft_tests ft_test_mmap = FT_DEFTESTS(ft_local_tests);

