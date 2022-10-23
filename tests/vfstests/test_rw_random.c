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
 * Tests read-write data-consistency for a sequence of IOs at pseudo random
 * offsets.
 */
static void test_random_(struct vt_env *vte, loff_t from,
                         size_t len, size_t cnt, size_t niter)
{
	int fd = -1;
	loff_t pos = 0;
	long seed = 0;
	void *buf1 = NULL;
	void *buf2 = vt_new_buf_zeros(vte, len);
	const long *pseq = vt_new_buf_randseq(vte, cnt, 0);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0640, &fd);
	for (size_t i = 0; i < niter; ++i) {
		for (size_t j = 0; j < cnt; ++j) {
			pos = from + ((long)len * pseq[j]);
			seed = (long)(i + j) + pos;
			buf1 = vt_new_buf_nums(vte, seed, len);
			vt_pwriten(fd, buf1, len, pos);
		}
		for (size_t j = 0; j < cnt; ++j) {
			pos = from + ((long)len * pseq[j]);
			seed = (long)(i + j) + pos;
			buf1 = vt_new_buf_nums(vte, seed, len);
			vt_preadn(fd, buf2, len, pos);
			vt_expect_eqm(buf1, buf2, len);
		}
	}
	vt_close(fd);
	vt_unlink(path);
}


static void test_random_io(struct vt_env *vte, loff_t from,
                           size_t len, size_t cnt)
{
	test_random_(vte, from, len, cnt, 1);
	test_random_(vte, from, len, cnt, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_aligned_blk(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t len = VT_BK_SIZE;

	from = 0;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_BK_SIZE;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_UMEGA;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE);
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_UGIGA;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE);
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE);
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UGIGA - (len * cnt));
	test_random_io(vte, from, len, cnt);
	from = (loff_t)((VT_UGIGA) / 2);
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UTERA - (len * cnt));
	test_random_io(vte, from, len, cnt);
}

static void test_random_aligned_blk1(struct vt_env *vte)
{
	test_random_aligned_blk(vte, 1);
}

static void test_random_aligned_blk2(struct vt_env *vte)
{
	test_random_aligned_blk(vte, 2);
}

static void test_random_aligned_blk63(struct vt_env *vte)
{
	test_random_aligned_blk(vte, 63);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_aligned_mega(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_UMEGA;

	from = 0;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_UMEGA);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_UMEGA);
	test_random_io(vte, from, bsz, 2 * cnt);
	from = (loff_t)(2 * VT_UGIGA);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)((VT_UGIGA) / 2);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt));
	test_random_io(vte, from, bsz, cnt);
}

static void test_random_aligned_mega1(struct vt_env *vte)
{
	test_random_aligned_mega(vte, 1);
}

static void test_random_aligned_mega2(struct vt_env *vte)
{
	test_random_aligned_mega(vte, 2);
}

static void test_random_aligned_mega3(struct vt_env *vte)
{
	test_random_aligned_mega(vte, 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_blk(struct vt_env *vte,
                                      size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_BK_SIZE;

	from = 1;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE - 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE + 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA - 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE - 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA - 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE - 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE + 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - (bsz * cnt) + 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)((VT_UGIGA * 13) / 11);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt) - 11);
	test_random_io(vte, from, bsz, cnt);
}

static void test_random_unaligned_blk1(struct vt_env *vte)
{
	test_random_unaligned_blk(vte, 1);
}

static void test_random_unaligned_blk2(struct vt_env *vte)
{
	test_random_unaligned_blk(vte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_mega(struct vt_env *vte, size_t cnt)
{
	loff_t from;
	const size_t bsz = VT_UMEGA;

	from = 1;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE - 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_BK_SIZE + 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UMEGA - 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UMEGA - VT_BK_SIZE - 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)VT_UGIGA - 11;
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - VT_BK_SIZE - 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA + VT_BK_SIZE + 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UGIGA - (bsz * cnt) + 1);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)((VT_UGIGA * 13) / 11);
	test_random_io(vte, from, bsz, cnt);
	from = (loff_t)(VT_UTERA - (bsz * cnt) - 11);
	test_random_io(vte, from, bsz, cnt);
}

static void test_random_unaligned_mega1(struct vt_env *vte)
{
	test_random_unaligned_mega(vte, 1);
}

static void test_random_unaligned_mega2(struct vt_env *vte)
{
	test_random_unaligned_mega(vte, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_random_unaligned_(struct vt_env *vte, size_t len, size_t cnt)
{
	loff_t from;

	from = 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_BK_SIZE - 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_BK_SIZE + 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_UMEGA - 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_UMEGA / 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_UGIGA - 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)VT_UGIGA / 7;
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UGIGA + (len * cnt) - 7);
	test_random_io(vte, from, len, cnt);
	from = (loff_t)((VT_UGIGA / 7) - 7);
	test_random_io(vte, from, len, cnt);
	from = (loff_t)(VT_UTERA - (len * cnt) - 7);
	test_random_io(vte, from, len, cnt);
}

static void test_random_unaligned_small(struct vt_env *vte)
{
	const size_t len = 7907;

	test_random_unaligned_(vte, len, 1);
	test_random_unaligned_(vte, len, 7);
	test_random_unaligned_(vte, len, 79);
	test_random_unaligned_(vte, len, 797);
}

static void test_random_unaligned_large(struct vt_env *vte)
{
	const size_t len = 66601;

	test_random_unaligned_(vte, len, 1);
	test_random_unaligned_(vte, len, 61);
	test_random_unaligned_(vte, len, 661);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_random_aligned_blk1),
	VT_DEFTEST(test_random_aligned_blk2),
	VT_DEFTEST(test_random_aligned_blk63),
	VT_DEFTEST(test_random_aligned_mega1),
	VT_DEFTEST(test_random_aligned_mega2),
	VT_DEFTEST(test_random_aligned_mega3),
	VT_DEFTEST(test_random_unaligned_blk1),
	VT_DEFTEST(test_random_unaligned_blk2),
	VT_DEFTEST(test_random_unaligned_mega1),
	VT_DEFTEST(test_random_unaligned_mega2),
	VT_DEFTEST(test_random_unaligned_small),
	VT_DEFTEST(test_random_unaligned_large),
};

const struct vt_tests vt_test_rw_random = VT_DEFTESTS(vt_local_tests);
