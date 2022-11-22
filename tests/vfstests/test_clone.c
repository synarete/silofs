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
 * Expects ioctl(FICLONE) to successfully clone entire file range between two
 * files.
 */
static void test_clone_file_range_(struct vt_env *vte, size_t bsz)
{
	int fd1 = -1;
	int fd2 = -1;
	struct stat st[2];
	void *data1 = vt_new_buf_rands(vte, bsz);
	void *data2 = vt_new_buf_rands(vte, bsz);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_unique(vte);

	vt_open(path1, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path2, O_CREAT | O_RDWR, 0600, &fd2);
	vt_pwriten(fd1, data1, bsz, 0);
	vt_fstat(fd1, &st[0]);
	vt_expect_eq(bsz, st[0].st_size);
	vt_ioctl_ficlone(fd2, fd1);
	vt_fstat(fd2, &st[1]);
	vt_expect_eq(bsz, st[1].st_size);
	vt_preadn(fd1, data2, bsz, 0);
	vt_expect_eqm(data1, data2, bsz);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_close(fd1);
	vt_unlink(path1);
	vt_close(fd2);
	vt_unlink(path2);
}

static void test_clone_file_range_small(struct vt_env *vte)
{
	test_clone_file_range_(vte, VT_BK_SIZE);
	test_clone_file_range_(vte, 8 * VT_BK_SIZE);
}

static void test_clone_file_range_large(struct vt_env *vte)
{
	test_clone_file_range_(vte, VT_UMEGA);
	test_clone_file_range_(vte, 8 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTESTF(test_clone_file_range_small, VT_F_IGNORE),
	VT_DEFTESTF(test_clone_file_range_large, VT_F_IGNORE),
};

const struct vt_tests vt_test_clone = VT_DEFTESTS(vt_local_tests);
