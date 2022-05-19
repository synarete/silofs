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
 * Expects valid lseek(3p) with whence as SEEK_SET, SEEK_CUR and SEEK_END
 */
static void test_lseek_simple_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	loff_t pos = -1;
	size_t nrd = 0;
	size_t nwr = 0;
	uint8_t byte;
	uint8_t *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_write(fd, buf, bsz, &nwr);
	vt_expect_eq(bsz, nwr);

	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	vt_read(fd, &byte, 1, &nrd);
	vt_expect_eq(1, nrd);
	vt_expect_eq(buf[pos], byte);

	vt_llseek(fd, 2, SEEK_CUR, &pos);
	vt_expect_eq(pos, 3);
	vt_read(fd, &byte, 1, &nrd);
	vt_expect_eq(1, nrd);
	vt_expect_eq(buf[pos], byte);

	vt_llseek(fd, -1, SEEK_END, &pos);
	vt_expect_eq(pos, bsz - 1);
	vt_read(fd, &byte, 1, &nrd);
	vt_expect_eq(1, nrd);
	vt_expect_eq(buf[pos], byte);

	vt_close(fd);
	vt_unlink(path);
}

static void test_lseek_simple(struct vt_env *vte)
{
	test_lseek_simple_(vte, VT_UMEGA / 8);
	test_lseek_simple_(vte, VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid lseek(2) with SEEK_DATA
 */
static void test_lseek_data_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	loff_t from = 0;
	loff_t pos = 0;
	uint8_t byte = 0;
	const loff_t off = (loff_t)(bsz * 2);
	uint8_t *buf1 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf1, bsz, off);
	from = off - 2;
	vt_llseek(fd, from, SEEK_DATA, &pos);
	vt_expect_eq(pos, off);
	vt_readn(fd, &byte, 1);
	vt_expect_eq(buf1[0], byte);
	vt_preadn(fd, &byte, 1, pos + 1);
	vt_expect_eq(buf1[1], byte);

	vt_close(fd);
	vt_unlink(path);
}

static void test_lseek_data(struct vt_env *vte)
{
	test_lseek_data_(vte, VT_BK_SIZE);
	test_lseek_data_(vte, 2 * VT_BK_SIZE);
	test_lseek_data_(vte, VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid lseek(2) with SEEK_HOLE
 */
static void test_lseek_hole_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	loff_t from;
	loff_t off;
	loff_t pos = -1;
	size_t nrd = 0;
	uint8_t byte = 0;
	uint8_t *buf1 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	off = (loff_t)bsz;
	vt_pwriten(fd, buf1, bsz, off);
	off = (loff_t)(bsz * 100);
	vt_pwriten(fd, buf1, bsz, off);
	off = (loff_t)bsz;
	from = off - 1;
	vt_llseek(fd, from, SEEK_HOLE, &pos);
	vt_expect_eq(pos, from);
	vt_read(fd, &byte, 1, &nrd);
	vt_expect_eq(1, nrd);
	vt_expect_eq(0, byte);
	from = (loff_t)(bsz * 2) - 2;
	vt_llseek(fd, from, SEEK_HOLE, &pos);
	vt_expect_eq(pos, (loff_t)(bsz * 2));
	vt_preadn(fd, &byte, 1, pos);
	vt_expect_eq(0, byte);
	vt_close(fd);
	vt_unlink(path);
}

static void test_lseek_hole(struct vt_env *vte)
{
	test_lseek_hole_(vte, VT_BK_SIZE);
	test_lseek_hole_(vte, 2 * VT_BK_SIZE);
	test_lseek_hole_(vte, VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Tests lseek(2) with SEEK_DATA on sparse file
 */
static void test_lseek_data_sparse_(struct vt_env *vte, size_t nsteps)
{
	int fd = -1;
	loff_t off;
	loff_t pos;
	loff_t data_off;
	const size_t size = VT_BK_SIZE;
	const ssize_t ssize = (ssize_t)size;
	const size_t step = VT_UMEGA;
	const void *buf1 = vt_new_buf_rands(vte, size);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nsteps; ++i) {
		off = (loff_t)(step * (i + 1));
		data_off = off - ssize;
		vt_ftruncate(fd, off);
		vt_pwriten(fd, buf1, size, data_off);
	}
	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	for (size_t i = 0; i < nsteps; ++i) {
		off = (loff_t)(step * i);
		data_off = (loff_t)(step * (i + 1)) - ssize;
		vt_llseek(fd, off, SEEK_DATA, &pos);
		vt_expect_eq(pos, data_off);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_lseek_data_sparse(struct vt_env *vte)
{
	test_lseek_data_sparse_(vte, 16);
	test_lseek_data_sparse_(vte, 256);
}

/*
 * Tests lseek(2) with SEEK_HOLE on sparse file
 */
static void test_lseek_hole_sparse_(struct vt_env *vte, size_t nsteps)
{
	int fd = -1;
	loff_t pos = 0;
	loff_t off = 0;
	loff_t hole_off = 0;
	const size_t size = VT_BK_SIZE;
	const ssize_t ssize = (loff_t)size;
	const size_t step = VT_UMEGA;
	const void *buf1 = vt_new_buf_rands(vte, size);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < nsteps; ++i) {
		off = (loff_t)(step * i);
		vt_pwriten(fd, buf1, size, off);
	}
	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	for (size_t i = 0; i < nsteps - 1; ++i) {
		off = (loff_t)(step * i);
		hole_off = off + ssize;
		vt_llseek(fd, off, SEEK_HOLE, &pos);
		vt_expect_eq(pos, hole_off);
	}
	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	for (size_t i = 0; i < nsteps - 1; ++i) {
		off = (loff_t)(step * i) + ssize + 1;
		hole_off = off;
		vt_llseek(fd, off, SEEK_HOLE, &pos);
		vt_expect_eq(pos, hole_off);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_lseek_hole_sparse(struct vt_env *vte)
{
	test_lseek_hole_sparse_(vte, 16);
	test_lseek_hole_sparse_(vte, 256);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_lseek_simple),
	VT_DEFTEST(test_lseek_data),
	VT_DEFTEST(test_lseek_hole),
	VT_DEFTEST(test_lseek_data_sparse),
	VT_DEFTEST(test_lseek_hole_sparse),
};

const struct vt_tests vt_test_lseek = VT_DEFTESTS(vt_local_tests);

