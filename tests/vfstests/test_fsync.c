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
 * Expects fsync(3p) to return 0 after regular file write/read operation.
 */
static void test_fsync_reg(struct vt_env *vte, loff_t base_off,
                           size_t bsz, loff_t step, size_t cnt)
{
	int fd = -1;
	loff_t off = -1;
	void *buf1 = NULL;
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		off = base_off + ((loff_t)i  * step);
		buf1 = vt_new_buf_rands(vte, bsz);
		vt_pwriten(fd, buf1, bsz, off);
		vt_fsync(fd);
		vt_preadn(fd, buf2, bsz, off);
		vt_expect_eqm(buf1, buf2, bsz);
		buf2 = buf1;
	}
	vt_close(fd);
	vt_unlink(path);
}


static void test_fsync_reg_aligned(struct vt_env *vte)
{
	test_fsync_reg(vte, 0, VT_UKILO, VT_UMEGA, 64);
	test_fsync_reg(vte, VT_UMEGA, VT_BK_SIZE, VT_UGIGA,
	               64);
}

static void test_fsync_reg_unaligned(struct vt_env *vte)
{
	test_fsync_reg(vte, 1, VT_UKILO - 1, VT_UMEGA + 1, 64);
	test_fsync_reg(vte, VT_UMEGA - 1, 3 * VT_UKILO + 1, VT_UGIGA - 1, 64);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fsync(3p) to return 0 after directory operations.
 */
static void test_fsync_dir_nent(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	int dfd = -1;
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = NULL;

	vt_mkdir(path1, 0700);
	vt_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		path2 = vt_new_pathf(vte, path1, "%08x", i + 1);
		vt_creat(path2, 0640, &fd);
		vt_fsync(dfd);
		vt_close(fd);
		vt_fsync(dfd);
	}
	for (size_t j = 0; j < cnt; ++j) {
		path2 = vt_new_pathf(vte, path1, "%08x", j + 1);
		vt_unlink(path2);
		vt_fsync(dfd);
	}
	vt_close(dfd);
	vt_rmdir(path1);
}

static void test_fsync_dir(struct vt_env *vte)
{
	test_fsync_dir_nent(vte, 1024);
	test_fsync_dir_nent(vte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects syncfs(2) to return 0
 */
static void test_fsync_syncfs(struct vt_env *vte)
{
	int fd = -1;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_syncfs(fd);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_fsync_reg_aligned),
	VT_DEFTEST(test_fsync_reg_unaligned),
	VT_DEFTEST(test_fsync_dir),
	VT_DEFTEST(test_fsync_syncfs),
};

const struct vt_tests vt_test_fsync = VT_DEFTESTS(vt_local_tests);
