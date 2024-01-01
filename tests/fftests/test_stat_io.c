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
#include "fftests.h"

static blkcnt_t calc_nfrgs_of(loff_t off, loff_t len, blksize_t blksz)
{
	const loff_t frgsz = FT_FRGSIZE;
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
static void test_stat_write_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_ino = 0 };
	const char *path = ft_new_path_unique(fte);
	blkcnt_t bcnt_min = 0;
	blkcnt_t bcnt_max = 0;
	void *buf = NULL;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);

	buf = ft_new_buf_rands(fte, len);
	ft_pwriten(fd, buf, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)len);
	ft_calc_stat_blkcnt(off, len, &bcnt_min, &bcnt_max);
	ft_expect_ge(st.st_blocks, bcnt_min);
	ft_expect_le(st.st_blocks, bcnt_max);

	buf = ft_new_buf_rands(fte, len);
	ft_pwriten(fd, buf, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)len);
	ft_calc_stat_blkcnt(off, len, &bcnt_min, &bcnt_max);
	ft_expect_ge(st.st_blocks, bcnt_min);
	ft_expect_le(st.st_blocks, bcnt_max);

	ft_close(fd);
	ft_unlink(path);
}

static void test_stat_write_aligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, 1),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_64K, 2 * FT_64K),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1M - FT_64K, FT_64K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1M - FT_64K, 2 * FT_64K),
		FT_MKRANGE(FT_1G, FT_64K),
		FT_MKRANGE(FT_1G - FT_64K, 2 * FT_64K),
		FT_MKRANGE(FT_1G + FT_64K, FT_64K),
	};

	ft_exec_with_ranges(fte, test_stat_write_, ranges);
}

static void test_stat_write_unaligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(1, 2),
		FT_MKRANGE(1, FT_64K - 2),
		FT_MKRANGE(1, FT_64K + 2),
		FT_MKRANGE(1, FT_1M - 2),
		FT_MKRANGE(1, FT_1M + 2),
		FT_MKRANGE(FT_64K - 1, FT_64K + 2),
		FT_MKRANGE(FT_1M - FT_64K + 1, 2 * FT_64K + 1),
		FT_MKRANGE(FT_1M - 1, FT_64K + 11),
		FT_MKRANGE(FT_1M - FT_64K - 1, 11 * FT_64K),
		FT_MKRANGE(FT_1G - 1, FT_64K + 2),
		FT_MKRANGE(FT_1G - FT_64K - 1, 2 * FT_64K + 2),
		FT_MKRANGE(FT_1G + FT_64K + 1, FT_64K - 1),
	};

	ft_exec_with_ranges(fte, test_stat_write_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects write-punch to modify file's stat's size & blocks attributes
 * properly. Performs sequential write, followed by fallocate-punch on same
 * data region.
 */
static void test_stat_punch_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = -1 };
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	void *buf = ft_new_buf_rands(fte, len);
	const char *path = ft_new_path_unique(fte);
	blkcnt_t bcnt_min = 0;
	blkcnt_t bcnt_max = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, 0);
	ft_expect_eq(st.st_blocks, 0);
	ft_pwriten(fd, buf, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)len);
	ft_calc_stat_blkcnt(off, len, &bcnt_min, &bcnt_max);
	ft_expect_ge(st.st_blocks, bcnt_min);
	ft_expect_le(st.st_blocks, bcnt_max);
	ft_fallocate(fd, mode, off, (loff_t)len);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_size, off + (loff_t)len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_stat_punch_aligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, 1),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_64K, 2 * FT_64K),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1M - FT_64K, FT_64K),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1M - FT_64K, 2 * FT_64K),
		FT_MKRANGE(FT_1G, FT_64K),
		FT_MKRANGE(FT_1G - FT_64K, 2 * FT_64K),
		FT_MKRANGE(FT_1G + FT_64K, FT_64K),
	};

	ft_exec_with_ranges(fte, test_stat_punch_, ranges);
}

static void test_stat_punch_unaligned(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(1, 2),
		FT_MKRANGE(1, FT_64K - 2),
		FT_MKRANGE(1, FT_64K + 2),
		FT_MKRANGE(1, FT_1M - 2),
		FT_MKRANGE(1, FT_1M + 2),
		FT_MKRANGE(FT_64K - 1, FT_64K + 2),
		FT_MKRANGE(FT_1M - FT_64K + 1, 2 * FT_64K + 1),
		FT_MKRANGE(FT_1M - 1, FT_64K + 11),
		FT_MKRANGE(FT_1M - FT_64K - 1, 11 * FT_64K),
		FT_MKRANGE(FT_1G - 1, FT_64K + 2),
		FT_MKRANGE(FT_1G - FT_64K - 1, 2 * FT_64K + 2),
		FT_MKRANGE(FT_1G + FT_64K + 1, FT_64K - 1),
	};

	ft_exec_with_ranges(fte, test_stat_punch_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects write to update the last data modification and last file status
 * change time-stamps, regardless of other files operation.
 */
static void test_stat_write_ctime_(struct ft_env *fte, size_t nfiles)
{
	char name[128] = "";
	struct stat st = { .st_size = -1 };
	struct stat *sts = ft_new_buf_zeros(fte, nfiles * sizeof(st));
	const char *path = ft_new_path_unique(fte);
	loff_t off = -1;
	long dif = 0;
	int dfd = -1;
	int fd = -1;

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

static void test_stat_write_ctime(struct ft_env *fte)
{
	const size_t nfiles[] = { 10, 100, 1000, 10000 };

	for (size_t i = 0; i < FT_ARRAY_SIZE(nfiles); ++i) {
		test_stat_write_ctime_(fte, nfiles[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_stat_write_aligned),
	FT_DEFTEST(test_stat_write_unaligned),
	FT_DEFTEST(test_stat_punch_aligned),
	FT_DEFTEST(test_stat_punch_unaligned),
	FT_DEFTEST(test_stat_write_ctime),
};

const struct ft_tests ft_test_stat_io = FT_DEFTESTS(ft_local_tests);
