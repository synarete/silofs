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
 * Tests data-consistency of I/O via fd where file's path is unlinked from
 * filesyatem's namespace. Data truncated to zero explicitly before close.
 */
static void test_unlinked_simple_(struct vt_env *vte,
                                  size_t bsz,
                                  size_t cnt)
{
	int fd;
	loff_t pos = -1;
	size_t nwr;
	size_t nrd;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_unlink(path);

	for (size_t i = 0; i < cnt; ++i) {
		vt_unlink_noent(path);
		vt_write(fd, buf1, bsz, &nwr);
		vt_expect_eq(nwr, bsz);
	}
	vt_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < cnt; ++i) {
		vt_unlink_noent(path);
		vt_read(fd, buf2, bsz, &nrd);
		vt_expect_eq(nrd, bsz);
		vt_expect_eqm(buf1, buf2, bsz);
	}

	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink_noent(path);
}


static void test_unlinked_simple1(struct vt_env *vte)
{
	test_unlinked_simple_(vte, 1, 1);
	test_unlinked_simple_(vte, VT_BK_SIZE, 2);
	test_unlinked_simple_(vte, VT_BK_SIZE - 3, 3);
}

static void test_unlinked_simple2(struct vt_env *vte)
{
	test_unlinked_simple_(vte, VT_BK_SIZE, VT_UKILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O via fd where file's path is unlinked from
 * filesyatem's namespace and data is truncated implicitly upon close.
 */
static void test_unlinked_complex_(struct vt_env *vte,
                                   loff_t base, size_t bsz, size_t cnt)
{
	int fd = -1;
	loff_t pos = 0;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_unlink(path);
	for (size_t i = 0; i < cnt; ++i) {
		pos = base + (loff_t)(i * bsz);
		vt_pwriten(fd, buf1, bsz, pos);
	}
	for (size_t j = 0; j < cnt; ++j) {
		pos = base + (loff_t)(j * bsz);
		vt_preadn(fd, buf2, bsz, pos);
		vt_expect_eqm(buf1, buf2, bsz);
	}
	vt_close(fd);
	vt_unlink_noent(path);
}


static void test_unlinked_complex1(struct vt_env *vte)
{
	test_unlinked_complex_(vte, 0, 1, 1);
	test_unlinked_complex_(vte, 0, VT_BK_SIZE, 2);
	test_unlinked_complex_(vte, 0, VT_BK_SIZE - 3, 3);
}

static void test_unlinked_complex2(struct vt_env *vte)
{
	test_unlinked_complex_(vte, 0, VT_BK_SIZE, VT_UKILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O via multiple fds where file's path is
 * unlinked from filesyatem's namespace.
 */
static void test_unlinked_multi(struct vt_env *vte)
{
	int fd1 = -1;
	int fd2 = -1;
	loff_t pos = 0;
	const size_t bsz = VT_BK_SIZE;
	const size_t cnt = VT_UKILO;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDONLY, 0, &fd2);
	vt_unlink(path);

	for (size_t i = 0; i < cnt; ++i) {
		pos = (loff_t)(cnt * VT_UMEGA);
		vt_pwriten(fd1, buf1, bsz, pos);
	}
	for (size_t j = 0; j < cnt; ++j) {
		pos = (loff_t)(cnt * VT_UMEGA);
		vt_preadn(fd2, buf2, bsz, pos);
		vt_expect_eqm(buf1, buf2, bsz);
	}

	vt_unlink_noent(path);
	vt_close(fd1);
	vt_close(fd2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests data-consistency of I/O after rename operations (with possible
 * implicit unlink).
 */
static void test_unlinked_rename_(struct vt_env *vte, size_t cnt)
{
	int fd1 = -1;
	int fd2 = -1;
	loff_t pos = 0;
	size_t val = 0;
	const size_t vsz = sizeof(val);
	const char *path1 = vt_new_path_unique(vte);
	const char *path2 = vt_new_path_unique(vte);

	vt_open(path1, O_CREAT | O_RDWR, 0600, &fd1);
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		val = i;
		vt_pwriten(fd1, &val, vsz, pos);
	}
	vt_rename(path1, path2);
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		vt_preadn(fd1, &val, vsz, pos);
		vt_expect_eq(i, val);
	}
	vt_open(path2, O_RDONLY, 0, &fd2);
	for (size_t i = cnt; i > 0; --i) {
		pos = (loff_t)(i * cnt);
		vt_preadn(fd2, &val, vsz, pos);
		vt_expect_eq(i, val);
	}
	vt_unlink_noent(path1);
	vt_unlink(path2);
	vt_close(fd1);
	vt_unlink_noent(path2);
	vt_close(fd2);
}

static void test_unlinked_rename(struct vt_env *vte)
{
	test_unlinked_rename_(vte, 11);
	test_unlinked_rename_(vte, 111);
	test_unlinked_rename_(vte, 1111);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests I/O over several unlinked files, all created with the same pathname.
 */
static void test_unlinked_same_path_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	int dat = -1;
	int *fds = vt_new_buf_zeros(vte, cnt * sizeof(fd));
	const char *path = vt_new_path_unique(vte);
	loff_t pos;

	for (size_t i = 0; i < cnt; ++i) {
		vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
		vt_unlink(path);
		fds[i] = fd;
		pos = (loff_t)((i * VT_UMEGA) + i);
		vt_pwriten(fd, &fd, sizeof(fd), pos);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fd = fds[i];
		pos = (loff_t)((i * VT_UMEGA) + i);
		vt_preadn(fd, &dat, sizeof(dat), pos);
		vt_expect_eq(fd, dat);
	}
	for (size_t i = 0; i < cnt; ++i) {
		vt_unlink_noent(path);
		fd = fds[i];
		vt_close(fd);
	}
}

static void test_unlinked_same_path(struct vt_env *vte)
{
	test_unlinked_same_path_(vte, 10);
	test_unlinked_same_path_(vte, 100);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_unlinked_simple1),
	VT_DEFTEST(test_unlinked_simple2),
	VT_DEFTEST(test_unlinked_complex1),
	VT_DEFTEST(test_unlinked_complex2),
	VT_DEFTEST(test_unlinked_multi),
	VT_DEFTEST(test_unlinked_rename),
	VT_DEFTEST(test_unlinked_same_path),
};

const struct vt_tests vt_test_unlinked_file = VT_DEFTESTS(vt_local_tests);
