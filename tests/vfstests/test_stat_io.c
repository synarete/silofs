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
#include "vfstests.h"


/* Common meta-info for io-tests */
struct vt_ioargs {
	loff_t off;
	size_t bsz;
	size_t cnt;
};

static const struct vt_ioargs s_aligned_ioargs[] = {
	{ 0, 1, 0 },
	{ 0, VT_BK_SIZE, 0 },
	{ 0, VT_UMEGA, 0 },
	{ VT_BK_SIZE, VT_BK_SIZE, 0 },
	{ VT_BK_SIZE, 2 * VT_BK_SIZE, 0 },
	{ VT_BK_SIZE, VT_UMEGA, 0 },
	{ VT_UMEGA - VT_BK_SIZE, VT_BK_SIZE, 0 },
	{ VT_UMEGA, VT_BK_SIZE, 0 },
	{ VT_UMEGA - VT_BK_SIZE, 2 * VT_BK_SIZE, 0 },
	{ VT_UGIGA, VT_BK_SIZE, 0 },
	{ VT_UGIGA - VT_BK_SIZE, 2 * VT_BK_SIZE, 0 },
	{ VT_UGIGA + VT_BK_SIZE, VT_BK_SIZE, 0 },
};

static const struct vt_ioargs s_unaligned_ioargs[] = {
	{ 1, 2, 0 },
	{ 1, VT_BK_SIZE - 2, 0 },
	{ 1, VT_BK_SIZE + 2, 0 },
	{ 1, VT_UMEGA - 2, 0 },
	{ 1, VT_UMEGA + 2, 0 },
	{ VT_BK_SIZE - 1, VT_BK_SIZE + 2, 0 },
	{ VT_UMEGA - VT_BK_SIZE + 1, 2 * VT_BK_SIZE + 1, 0 },
	{ VT_UMEGA - 1, VT_BK_SIZE + 11, 0 },
	{ VT_UMEGA - VT_BK_SIZE - 1, 11 * VT_BK_SIZE, 0 },
	{ VT_UGIGA - 1, VT_BK_SIZE + 2, 0 },
	{ VT_UGIGA - VT_BK_SIZE - 1, 2 * VT_BK_SIZE + 2, 0 },
	{ VT_UGIGA + VT_BK_SIZE + 1, VT_BK_SIZE - 1, 0 },
};

static blkcnt_t calc_nfrgs_of(loff_t off, loff_t len, blksize_t blksz)
{
	const loff_t frgsz = 512; /* see stat(2) */
	const loff_t beg = (off / blksz) * blksz;
	const loff_t end = ((off + len + blksz - 1) / blksz) * blksz;
	const blkcnt_t nfrgs = (blkcnt_t)(end - beg) / frgsz;

	return nfrgs;
}

static void vt_calc_stat_blkcnt(loff_t off, size_t nbytes,
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
static void test_stat_write_(struct vt_env *vte,
                             const struct vt_ioargs *ioargs)
{
	int fd = -1;
	void *buf = NULL;
	blkcnt_t bcnt_min = 0;
	blkcnt_t bcnt_max = 0;
	struct stat st = { .st_ino = 0 };
	const loff_t off = ioargs->off;
	const size_t bsz = ioargs->bsz;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);

	buf = vt_new_buf_rands(vte, bsz);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (loff_t)bsz);
	vt_calc_stat_blkcnt(off, bsz, &bcnt_min, &bcnt_max);
	vt_expect_ge(st.st_blocks, bcnt_min);
	vt_expect_le(st.st_blocks, bcnt_max);

	buf = vt_new_buf_rands(vte, bsz);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (loff_t)bsz);
	vt_calc_stat_blkcnt(off, bsz, &bcnt_min, &bcnt_max);
	vt_expect_ge(st.st_blocks, bcnt_min);
	vt_expect_le(st.st_blocks, bcnt_max);

	vt_close(fd);
	vt_unlink(path);
}

static void test_stat_write_aligned(struct vt_env *vte)
{
	for (size_t i = 0; i < VT_ARRAY_SIZE(s_aligned_ioargs); ++i) {
		test_stat_write_(vte, &s_aligned_ioargs[i]);
	}
}

static void test_stat_write_unaligned(struct vt_env *vte)
{
	for (size_t i = 0; i < VT_ARRAY_SIZE(s_unaligned_ioargs); ++i) {
		test_stat_write_(vte, &s_unaligned_ioargs[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects write-punch to modify file's stat's size & blocks attributes
 * properly. Performs sequential write, followed by fallocate-punch on same
 * data region.
 */
static void test_stat_punch_(struct vt_env *vte,
                             const struct vt_ioargs *ioargs)
{
	int fd = -1;
	blkcnt_t bcnt_min = 0;
	blkcnt_t bcnt_max = 0;
	struct stat st = { .st_ino = 0 };
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	const loff_t off = ioargs->off;
	const size_t bsz = ioargs->bsz;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (loff_t)bsz);
	vt_calc_stat_blkcnt(off, bsz, &bcnt_min, &bcnt_max);
	vt_expect_ge(st.st_blocks, bcnt_min);
	vt_expect_le(st.st_blocks, bcnt_max);
	vt_fallocate(fd, mode, off, (loff_t)bsz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + (loff_t)bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_stat_punch_aligned(struct vt_env *vte)
{
	for (size_t i = 0; i < VT_ARRAY_SIZE(s_aligned_ioargs); ++i) {
		test_stat_punch_(vte, &s_aligned_ioargs[i]);
	}
}

static void test_stat_punch_unaligned(struct vt_env *vte)
{
	for (size_t i = 0; i < VT_ARRAY_SIZE(s_unaligned_ioargs); ++i) {
		test_stat_punch_(vte, &s_unaligned_ioargs[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects write to update the last data modification and last file status
 * change time-stamps, regardless of other files operation.
 */
static void test_write_stat_(struct vt_env *vte,
                             size_t nfiles)
{
	int fd = -1;
	int dfd = -1;
	long dif;
	loff_t off;
	struct stat st;
	struct stat *sts = vt_new_buf_zeros(vte, nfiles * sizeof(st));
	const char *path = vt_new_path_unique(vte);
	char name[128] = "";

	vt_mkdir(path, 0700);
	vt_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < nfiles; ++i) {
		off = (loff_t)(i * nfiles);
		snprintf(name, sizeof(name) - 1, "%lx-%ld", i, off);
		vt_openat(dfd, name, O_CREAT | O_RDWR, 0600, &fd);
		vt_fstat(fd, &st);
		vt_pwriten(fd, name, strlen(name), off);
		vt_fstat(fd, &sts[i]);
		vt_expect_mtime_gt(&st, &sts[i]);
		vt_expect_ctime_gt(&st, &sts[i]);
		vt_close(fd);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		off = (loff_t)(i * nfiles);
		snprintf(name, sizeof(name) - 1, "%lx-%ld", i, off);
		vt_openat(dfd, name, O_RDONLY, 0600, &fd);
		vt_fstat(fd, &st);
		vt_expect_mtime_eq(&st, &sts[i]);
		/*
		 * For some unexplained reason, CTIME may change slightly every
		 * once in a million iterations. Happens only when 'nfiles' is
		 * large. Could be a deep bug in FUSE or something elsewhere
		 * -- I don't have a clue :(
		 *
		 * TODO: investigate more and change to:
		 *         vt_expect_ctime_eq(&st, sti);
		 */
		dif = vt_timespec_diff(&sts[i].st_ctim, &st.st_ctim);
		vt_expect_ge(dif, 0);
		vt_expect_lt(dif, 100000000L);
		vt_close(fd);
		vt_unlinkat(dfd, name, 0);
	}
	vt_close(dfd);
	vt_rmdir(path);
}

static void test_write_stat(struct vt_env *vte)
{
	test_write_stat_(vte, 111);
	test_write_stat_(vte, 11111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_stat_write_aligned),
	VT_DEFTEST(test_stat_write_unaligned),
	VT_DEFTEST(test_stat_punch_aligned),
	VT_DEFTEST(test_stat_punch_unaligned),
	VT_DEFTEST(test_write_stat),
};

const struct vt_tests vt_test_stat_io = VT_DEFTESTS(vt_local_tests);
