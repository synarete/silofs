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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of sequential writes followed by sequential reads.
 */
static void test_sequencial_(struct vt_env *vte, loff_t from,
                             size_t bsz, size_t cnt, int rewrite)
{
	int fd = -1;
	loff_t pos;
	size_t nwr = 0;
	size_t nrd = 0;
	void *buf1 = NULL;
	void *buf2 = vt_new_buf_zeros(vte, bsz);
	char *path = vt_new_path_unique(vte);
	const size_t nitr = rewrite ? 2 : 1;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nitr; ++i) {
		vt_llseek(fd, from, SEEK_SET, &pos);
		for (size_t j = 0; j < cnt; ++j) {
			buf1 = vt_new_buf_nums(vte, (long)j, bsz);
			vt_write(fd, buf1, bsz, &nwr);
			vt_expect_eq(nwr, bsz);
		}
		vt_llseek(fd, from, SEEK_SET, &pos);
		for (size_t j = 0; j < cnt; ++j) {
			buf1 = vt_new_buf_nums(vte, (long)j, bsz);
			vt_read(fd, buf2, bsz, &nrd);
			vt_expect_eq(nrd, bsz);
			vt_expect_eqm(buf1, buf2, bsz);
		}
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_sequencial_io(struct vt_env *vte,
                               loff_t from, size_t bsz, size_t cnt)
{
	test_sequencial_(vte, from, bsz, cnt, 0);
	test_sequencial_(vte, from, bsz, cnt, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_aligned_blk(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_BK_SIZE;

	from = 0;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - (bsz * cnt));
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)((VT_UGIGA * 2) / 2);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt));
	test_sequencial_io(vte, from, bsz, cnt);
}

static void test_sequencial_aligned_blk1(struct vt_env *vte)
{
	test_sequencial_aligned_blk(vte, 1);
}

static void test_sequencial_aligned_blk2(struct vt_env *vte)
{
	test_sequencial_aligned_blk(vte, 2);
}

static void test_sequencial_aligned_blk63(struct vt_env *vte)
{
	test_sequencial_aligned_blk(vte, 63);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_aligned_mega(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_UMEGA;

	from = 0;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_UMEGA);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_UMEGA);
	test_sequencial_io(vte, from, bsz, 2 * cnt);
	from = (loff_t)(2 * VT_UGIGA);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA / 2);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt));
	test_sequencial_io(vte, from, bsz, cnt);
}

static void test_sequencial_aligned_mega1(struct vt_env *vte)
{
	test_sequencial_aligned_mega(vte, 1);
}

static void test_sequencial_aligned_mega2(struct vt_env *vte)
{
	test_sequencial_aligned_mega(vte, 2);
}

static void test_sequencial_aligned_mega3(struct vt_env *vte)
{
	test_sequencial_aligned_mega(vte, 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_unaligned_blk(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_BK_SIZE;

	from = 1;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE - 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE + 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA - 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE - 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA - 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE - 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE + 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - (bsz * cnt) + 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA / 11);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt) - 11);
	test_sequencial_io(vte, from, bsz, cnt);
}

static void test_sequencial_unaligned_blk1(struct vt_env *vte)
{
	test_sequencial_unaligned_blk(vte, 1);
}

static void test_sequencial_unaligned_blk2(struct vt_env *vte)
{
	test_sequencial_unaligned_blk(vte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_unaligned_mega(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_UMEGA;

	from = 1;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE - 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE + 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA - 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE - 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA - 11;
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE - 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE + 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - (bsz * cnt) + 1);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA / 11);
	test_sequencial_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt) - 11);
	test_sequencial_io(vte, from, bsz, cnt);
}

static void test_sequencial_unaligned_mega1(struct vt_env *vte)
{
	test_sequencial_unaligned_mega(vte, 1);
}

static void test_sequencial_unaligned_mega2(struct vt_env *vte)
{
	test_sequencial_unaligned_mega(vte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
test_sequencial_unaligned_(struct vt_env *vte, size_t len, size_t cnt)
{
	loff_t from;

	from = 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)VT_BK_SIZE - 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)VT_BK_SIZE + 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)VT_UMEGA - 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)VT_UMEGA / 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)VT_UGIGA - 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)VT_UGIGA / 7;
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)(VT_UGIGA + (len * cnt) - 7);
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)((VT_UGIGA / 7) - 7);
	test_sequencial_io(vte, from, len, cnt);
	from = (loff_t)(VT_UTERA - (len * cnt) - 7);
	test_sequencial_io(vte, from, len, cnt);
}

static void test_sequencial_unaligned_small(struct vt_env *vte)
{
	const size_t len = 7907;

	test_sequencial_unaligned_(vte, len, 1);
	test_sequencial_unaligned_(vte, len, 7);
	test_sequencial_unaligned_(vte, len, 79);
	test_sequencial_unaligned_(vte, len, 797);
}

static void test_sequencial_unaligned_large(struct vt_env *vte)
{
	const size_t len = 66601;

	test_sequencial_unaligned_(vte, len, 1);
	test_sequencial_unaligned_(vte, len, 61);
	test_sequencial_unaligned_(vte, len, 661);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of sequential writes followed by sequential reads
 * of variable length strings
 */
static void test_sequencial_nstrings(struct vt_env *vte,
                                     loff_t start_off, size_t cnt)
{
	int fd = -1;
	int ni = 0;
	loff_t pos = -1;
	size_t nu;
	size_t nwr = 0;
	size_t nrd = 0;
	char buf1[128] = "";
	char buf2[128] = "";
	const char *path = vt_new_path_unique(vte);
	const int whence = SEEK_SET;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_llseek(fd, start_off, whence, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ni = snprintf(buf1, sizeof(buf1), "%lu", i);
		nu = (size_t)ni;
		vt_expect_eq(nu, strlen(buf1));
		vt_write(fd, buf1, nu, &nwr);
		vt_expect_eq(nu, nwr);
	}
	vt_llseek(fd, start_off, whence, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		ni = snprintf(buf1, sizeof(buf1), "%lu", i);
		nu = (size_t)ni;
		vt_expect_eq(nu, strlen(buf1));
		vt_read(fd, buf2, nu, &nrd);
		vt_expect_eq(nu, nrd);
		vt_expect_eq(0, strcmp(buf1, buf2));
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_sequencial_nstrings_(struct vt_env *vte,
                                      size_t n)
{
	test_sequencial_nstrings(vte, 0, n);
	test_sequencial_nstrings(vte, VT_BK_SIZE - 1, n);
	test_sequencial_nstrings(vte, VT_BK_SIZE, n);
	test_sequencial_nstrings(vte, VT_UMEGA - 1, n);
	test_sequencial_nstrings(vte, VT_UGIGA, n);
}

static void test_sequencial_strings10(struct vt_env *vte)
{
	test_sequencial_nstrings_(vte, 10);
}

static void test_sequencial_strings100(struct vt_env *vte)
{
	test_sequencial_nstrings_(vte, 100);
}

static void test_sequencial_strings1000(struct vt_env *vte)
{
	test_sequencial_nstrings_(vte, 1000);
}

static void test_sequencial_strings10000(struct vt_env *vte)
{
	test_sequencial_nstrings_(vte, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_sequencial_aligned_blk1),
	VT_DEFTEST(test_sequencial_aligned_blk2),
	VT_DEFTEST(test_sequencial_aligned_blk63),
	VT_DEFTEST(test_sequencial_aligned_mega1),
	VT_DEFTEST(test_sequencial_aligned_mega2),
	VT_DEFTEST(test_sequencial_aligned_mega3),
	VT_DEFTEST(test_sequencial_unaligned_blk1),
	VT_DEFTEST(test_sequencial_unaligned_blk2),
	VT_DEFTEST(test_sequencial_unaligned_mega1),
	VT_DEFTEST(test_sequencial_unaligned_mega2),
	VT_DEFTEST(test_sequencial_unaligned_small),
	VT_DEFTEST(test_sequencial_unaligned_large),
	VT_DEFTEST(test_sequencial_strings10),
	VT_DEFTEST(test_sequencial_strings100),
	VT_DEFTEST(test_sequencial_strings1000),
	VT_DEFTEST(test_sequencial_strings10000),
};

const struct vt_tests vt_test_rw_sequencial = VT_DEFTESTS(vt_local_tests);

