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
 * Expects read-write data-consistency when file is opened with O_SYNC.
 */
static void test_osync_simple_(struct vt_env *vte, size_t bsz, loff_t off)
{
	void *buf0 = vt_new_buf_zeros(vte, bsz);
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);
	int fd1, fd2;

	vt_open(path, O_CREAT | O_RDWR, 0644, &fd1);
	vt_pwriten(fd1, buf1, bsz, off);
	vt_close(fd1);
	vt_open(path, O_RDONLY, 0, &fd2);
	vt_preadn(fd2, buf0, bsz, off);
	vt_expect_eqm(buf1, buf0, bsz);
	vt_open(path, O_RDWR | O_SYNC, 0, &fd1);
	vt_pwriten(fd1, buf2, bsz, off);
	vt_preadn(fd2, buf0, bsz, off);
	vt_expect_eqm(buf2, buf0, bsz);
	vt_unlink(path);
	vt_pwriten(fd1, buf1, bsz, off);
	vt_preadn(fd2, buf0, bsz, off);
	vt_expect_eqm(buf1, buf0, bsz);
	vt_close(fd1);
	vt_close(fd2);
}

static void test_osync_simple(struct vt_env *vte)
{
	test_osync_simple_(vte, VT_BK_SIZE, 0);
	test_osync_simple_(vte, VT_BK_SIZE + 1, VT_KILO);
	test_osync_simple_(vte, VT_UMEGA, VT_KILO + 1);
	test_osync_simple_(vte, 2 * VT_UMEGA - 1, VT_GIGA);
	test_osync_simple_(vte, 3 * VT_UMEGA - 3, VT_TERA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when multiple files are opened with
 * O_SYNC.
 */
static void test_osync_multi_(struct vt_env *vte, size_t bsz, loff_t off)
{
	void *buf0 = vt_new_buf_zeros(vte, bsz);
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path[16];
	int fd[16];

	for (size_t i = 0; i < VT_ARRAY_SIZE(path); ++i) {
		path[i] = vt_new_path_unique(vte);
	}
	for (size_t i = 0; i < VT_ARRAY_SIZE(fd); ++i) {
		vt_open(path[i], O_CREAT | O_RDWR | O_SYNC, 0640, &fd[i]);
		vt_pwriten(fd[i], buf1, bsz, off + (int)i);
	}
	for (size_t i = 0; i < VT_ARRAY_SIZE(fd); ++i) {
		vt_preadn(fd[i], buf0, bsz, off + (int)i);
		vt_expect_eqm(buf1, buf0, bsz);
		vt_pwriten(fd[i], buf2, bsz, off + (int)i + 1);
	}
	for (size_t i = 0; i < VT_ARRAY_SIZE(fd); ++i) {
		vt_preadn(fd[i], buf0, bsz, off + (int)i + 1);
		vt_expect_eqm(buf2, buf0, bsz);
	}
	for (size_t i = 0; i < VT_ARRAY_SIZE(fd); ++i) {
		vt_close(fd[i]);
	}
	for (size_t i = 0; i < VT_ARRAY_SIZE(path); ++i) {
		vt_unlink(path[i]);
	}
}

static void test_osync_multi(struct vt_env *vte)
{
	test_osync_multi_(vte, VT_BK_SIZE, 0);
	test_osync_multi_(vte, VT_BK_SIZE + 1, VT_KILO);
	test_osync_multi_(vte, VT_UMEGA, VT_KILO + 1);
	test_osync_multi_(vte, 2 * VT_UMEGA - 1, VT_GIGA);
	test_osync_multi_(vte, 3 * VT_UMEGA - 3, VT_TERA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_osync_simple),
	VT_DEFTEST(test_osync_multi),
};

const struct vt_tests vt_test_rw_osync = VT_DEFTESTS(vt_local_tests);
