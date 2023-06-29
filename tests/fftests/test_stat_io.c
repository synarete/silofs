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


/* Common meta-info for io-tests */
struct ft_ioargs {
	loff_t off;
	size_t bsz;
	size_t cnt;
};

static const struct ft_ioargs s_aligned_ioargs[] = {
	{ 0, 1, 0 },
	{ 0, FT_BK_SIZE, 0 },
	{ 0, FT_UMEGA, 0 },
	{ FT_BK_SIZE, FT_BK_SIZE, 0 },
	{ FT_BK_SIZE, 2 * FT_BK_SIZE, 0 },
	{ FT_BK_SIZE, FT_UMEGA, 0 },
	{ FT_UMEGA - FT_BK_SIZE, FT_BK_SIZE, 0 },
	{ FT_UMEGA, FT_BK_SIZE, 0 },
	{ FT_UMEGA - FT_BK_SIZE, 2 * FT_BK_SIZE, 0 },
	{ FT_UGIGA, FT_BK_SIZE, 0 },
	{ FT_UGIGA - FT_BK_SIZE, 2 * FT_BK_SIZE, 0 },
	{ FT_UGIGA + FT_BK_SIZE, FT_BK_SIZE, 0 },
};

static const struct ft_ioargs s_unaligned_ioargs[] = {
	{ 1, 2, 0 },
	{ 1, FT_BK_SIZE - 2, 0 },
	{ 1, FT_BK_SIZE + 2, 0 },
	{ 1, FT_UMEGA - 2, 0 },
	{ 1, FT_UMEGA + 2, 0 },
	{ FT_BK_SIZE - 1, FT_BK_SIZE + 2, 0 },
	{ FT_UMEGA - FT_BK_SIZE + 1, 2 * FT_BK_SIZE + 1, 0 },
	{ FT_UMEGA - 1, FT_BK_SIZE + 11, 0 },
	{ FT_UMEGA - FT_BK_SIZE - 1, 11 * FT_BK_SIZE, 0 },
	{ FT_UGIGA - 1, FT_BK_SIZE + 2, 0 },
	{ FT_UGIGA - FT_BK_SIZE - 1, 2 * FT_BK_SIZE + 2, 0 },
	{ FT_UGIGA + FT_BK_SIZE + 1, FT_BK_SIZE - 1, 0 },
};

static blkcnt_t calc_nfrgs_of(loff_t off, loff_t len, blksize_t blksz)
{
	const loff_t frgsz = 512; /* see stat(2) */
	const loff_t beg = (off / blksz) * blksz;
	const loff_t end = ((off + len + blksz - 1) / blksz) * blksz;
	const blkcnt_t nfrgs = (blkcnt_t)(end - beg) / frgsz;

	return nfrgs;
}

static void ft_calc_stat_blkcnt(loff_t off, size_t nbytes,
                                blkcnt_t *out_min, blkcnt_t *out_max)
{
	*out_min = calc_nfrgs_of(off, (loff_t)nbytes, 512);
	*out_max = calc_nfrgs_of(off, (loff_t)nbytes, 65536);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects write to modify file's stat's size & blocks attributes properly.
 * Performs sequential write, followed by over-write on same region.
 */
static void test_stat_write_(struct ft_env *fte,
                             const struct ft_ioargs *ioargs)
{
	int fd = -1;
	void *buf = NULL;
	blkcnt_t bcnt_min = 0;
	blkcnt_t bcnt_max = 0;
	struct stat st = { .st_ino = 0 };
	const loff_t off = ioargs->off;
	const size_t bsz = ioargs->bsz;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);

	buf = ft_new_buf_rands(fte, bsz);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)bsz);
	ft_calc_stat_blkcnt(off, bsz, &bcnt_min, &bcnt_max);
	ft_expect_ge(st.st_blocks, bcnt_min);
	ft_expect_le(st.st_blocks, bcnt_max);

	buf = ft_new_buf_rands(fte, bsz);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)bsz);
	ft_calc_stat_blkcnt(off, bsz, &bcnt_min, &bcnt_max);
	ft_expect_ge(st.st_blocks, bcnt_min);
	ft_expect_le(st.st_blocks, bcnt_max);

	ft_close(fd);
	ft_unlink(path);
}

static void test_stat_write_aligned(struct ft_env *fte)
{
	for (size_t i = 0; i < FT_ARRAY_SIZE(s_aligned_ioargs); ++i) {
		test_stat_write_(fte, &s_aligned_ioargs[i]);
	}
}

static void test_stat_write_unaligned(struct ft_env *fte)
{
	for (size_t i = 0; i < FT_ARRAY_SIZE(s_unaligned_ioargs); ++i) {
		test_stat_write_(fte, &s_unaligned_ioargs[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects write-punch to modify file's stat's size & blocks attributes
 * properly. Performs sequential write, followed by fallocate-punch on same
 * data region.
 */
static void test_stat_punch_(struct ft_env *fte,
                             const struct ft_ioargs *ioargs)
{
	int fd = -1;
	blkcnt_t bcnt_min = 0;
	blkcnt_t bcnt_max = 0;
	struct stat st = { .st_ino = 0 };
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	const loff_t off = ioargs->off;
	const size_t bsz = ioargs->bsz;
	void *buf = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)bsz);
	ft_calc_stat_blkcnt(off, bsz, &bcnt_min, &bcnt_max);
	ft_expect_ge(st.st_blocks, bcnt_min);
	ft_expect_le(st.st_blocks, bcnt_max);
	ft_fallocate(fd, mode, off, (loff_t)bsz);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)bsz);
	ft_close(fd);
	ft_unlink(path);
}

static void test_stat_punch_aligned(struct ft_env *fte)
{
	for (size_t i = 0; i < FT_ARRAY_SIZE(s_aligned_ioargs); ++i) {
		test_stat_punch_(fte, &s_aligned_ioargs[i]);
	}
}

static void test_stat_punch_unaligned(struct ft_env *fte)
{
	for (size_t i = 0; i < FT_ARRAY_SIZE(s_unaligned_ioargs); ++i) {
		test_stat_punch_(fte, &s_unaligned_ioargs[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects write to update the last data modification and last file status
 * change time-stamps, regardless of other files operation.
 */
static void test_write_stat_(struct ft_env *fte,
                             size_t nfiles)
{
	int fd = -1;
	int dfd = -1;
	long dif;
	loff_t off;
	struct stat st;
	struct stat *sts = ft_new_buf_zeros(fte, nfiles * sizeof(st));
	const char *path = ft_new_path_unique(fte);
	char name[128] = "";

	ft_mkdir(path, 0700);
	ft_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < nfiles; ++i) {
		off = (loff_t)(i * nfiles);
		snprintf(name, sizeof(name) - 1, "%lx-%ld", i, off);
		ft_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
		ft_fstat(fd, &st);
		ft_pwriten(fd, name, strlen(name), off);
		ft_fstat(fd, &sts[i]);
		ft_expect_mtime_gt(&st, &sts[i]);
		ft_expect_ctime_gt(&st, &sts[i]);
		ft_close(fd);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		off = (loff_t)(i * nfiles);
		snprintf(name, sizeof(name) - 1, "%lx-%ld", i, off);
		ft_openat(dfd, name, O_RDONLY, 0600, &fd);
		ft_fstat(fd, &st);
		ft_expect_mtime_eq(&st, &sts[i]);
		/*
		 * For some unexplained reason, CTIME may change slightly every
		 * once in a million iterations. Happens only when 'nfiles' is
		 * large. Could be a deep bug in FUSE or something elsewhere
		 * -- I don't have a clue :(
		 *
		 * TODO: investigate more and change to:
		 *         ft_expect_ctime_eq(&st, sti);
		 */
		dif = ft_timespec_diff(&sts[i].st_ctim, &st.st_ctim);
		ft_expect_ge(dif, 0);
		ft_expect_lt(dif, 100000000L);
		ft_close(fd);
		ft_unlinkat(dfd, name, 0);
	}
	ft_close(dfd);
	ft_rmdir(path);
}

static void test_write_stat(struct ft_env *fte)
{
	test_write_stat_(fte, 111);
	test_write_stat_(fte, 11111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_stat_write_aligned),
	FT_DEFTEST(test_stat_write_unaligned),
	FT_DEFTEST(test_stat_punch_aligned),
	FT_DEFTEST(test_stat_punch_unaligned),
	FT_DEFTEST(test_write_stat),
};

const struct ft_tests ft_test_stat_io = FT_DEFTESTS(ft_local_tests);
