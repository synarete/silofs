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
 * Expects read-write data-consistency, sequential writes of single block.
 */
static void test_tmpfile_simple(struct vt_env *vte)
{
	int fd = -1;
	loff_t pos = -1;
	size_t dat = 0;
	size_t nwr = 0;
	size_t nrd = 0;
	struct stat st;
	const size_t bsz  = VT_BK_SIZE;
	void *buf  = vt_new_buf_zeros(vte, bsz);
	char *path = vt_new_path_unique(vte);

	vt_mkdir(path, 0700);
	vt_open(path, O_RDWR | O_TMPFILE | O_EXCL, 0600, &fd);
	for (size_t i = 0; i < 128; ++i) {
		dat = i;
		memcpy(buf, &dat, sizeof(dat));
		vt_write(fd, buf, bsz, &nwr);
		vt_fstat(fd, &st);
		vt_expect_eq((long)st.st_size, (long)((i + 1) * bsz));
	}
	vt_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < 128; ++i) {
		vt_read(fd, buf, bsz, &nrd);
		memcpy(&dat, buf, sizeof(dat));
		vt_expect_eq((long)i, (long)dat);
	}
	vt_close(fd);
	vt_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for buffer-size of 1M.
 */
static void test_buffer(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	void *buf1 = NULL;
	void *buf2 = NULL;
	char *path = vt_new_path_unique(vte);
	struct stat st;

	vt_mkdir(path, 0700);
	vt_open(path, O_RDWR | O_TMPFILE | O_EXCL, 0600, &fd);
	for (size_t i = 0; i < 8; ++i) {
		buf1 = vt_new_buf_rands(vte, bsz);
		vt_pwrite(fd, buf1, bsz, 0, &nwr);
		vt_fsync(fd);
		buf2 = vt_new_buf_rands(vte, bsz);
		vt_pread(fd, buf2, bsz, 0, &nrd);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, bsz);
		vt_expect_eqm(buf1, buf2, bsz);
	}
	vt_close(fd);
	vt_rmdir(path);
}

static void test_tmpfile_rdwr_1k(struct vt_env *vte)
{
	test_buffer(vte, 1024);
}

static void test_tmpfile_rdwr_8k(struct vt_env *vte)
{
	test_buffer(vte, 8 * VT_UKILO);
}

static void test_tmpfile_rdwr_1m(struct vt_env *vte)
{
	test_buffer(vte, VT_UMEGA);
}

static void test_tmpfile_rdwr_8m(struct vt_env *vte)
{
	test_buffer(vte, 8 * VT_UMEGA);
}

static void test_tmpfile_rdwr_32m(struct vt_env *vte)
{
	test_buffer(vte, 32 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTESTF(test_tmpfile_simple, VT_F_TMPFILE),
	VT_DEFTESTF(test_tmpfile_rdwr_1k, VT_F_TMPFILE),
	VT_DEFTESTF(test_tmpfile_rdwr_8k, VT_F_TMPFILE),
	VT_DEFTESTF(test_tmpfile_rdwr_1m, VT_F_TMPFILE),
	VT_DEFTESTF(test_tmpfile_rdwr_8m, VT_F_TMPFILE),
	VT_DEFTESTF(test_tmpfile_rdwr_32m, VT_F_TMPFILE),
};

const struct vt_tests vt_test_tmpfile = VT_DEFTESTS(vt_local_tests);
