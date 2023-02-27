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
 * Tests read-write data-consistency over sparse file.
 */
static void test_sparse_simple_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	loff_t pos = -1;
	size_t nsz = 0;
	size_t num = 0;
	size_t num2 = 0;
	const size_t step = 524287;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = (i * step);
		pos = (loff_t)num;
		nsz = sizeof(num);
		vt_pwriten(fd, &num, nsz, pos);
	}
	vt_close(fd);
	vt_open(path, O_RDONLY, 0, &fd);
	for (size_t j = 0; j < cnt; ++j) {
		num = (j * step);
		pos = (loff_t)num;
		nsz = sizeof(num2);
		vt_preadn(fd, &num2, nsz, pos);
		vt_expect_eq(num, num2);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_sparse_simple(struct vt_env *vte)
{
	test_sparse_simple_(vte, 17);
	test_sparse_simple_(vte, 7717);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file with syncs over same file
 */
static void test_sparse_rdwr_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	loff_t pos = -1;
	size_t nsz = 0;
	size_t num = 0;
	size_t num2 = 0;
	const size_t step = 524287;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_close(fd);
	for (size_t i = 0; i < 17; ++i) {
		for (size_t j = 0; j < cnt; ++j) {
			vt_open(path, O_RDWR, 0, &fd);
			num = i + (j * step);
			pos = (loff_t)num;
			nsz = sizeof(num);
			vt_pwriten(fd, &num, nsz, pos);
			vt_fdatasync(fd);
			vt_preadn(fd, &num2, nsz, pos);
			vt_expect_eq(num, num2);
			vt_close(fd);
		}
	}
	vt_unlink(path);
}

static void test_sparse_rdwr(struct vt_env *vte)
{
	test_sparse_rdwr_(vte, 11);
	test_sparse_rdwr_(vte, 127);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests read-write data-consistency over sparse file with overwrites.
 */
static void test_sparse_overwrite_(struct vt_env *vte, loff_t base_off)
{
	int fd = -1;
	loff_t off;
	uint8_t byte;
	const size_t len1 = 10037;
	const size_t len2 = 10039;
	uint8_t *buf1 = vt_new_buf_rands(vte, len1);
	uint8_t *buf2 = vt_new_buf_rands(vte, len2);
	uint8_t *buf3 = vt_new_buf_rands(vte, len1 + len2);
	char *path = vt_new_path_unique(vte);
	const loff_t offs[] = {
		737717, 280411, 10007, 31033, 42043, 53113, 161881, 375533,
		86767, 97171, 75353, 611999, 1108007, 64601, 1272211, 20323
	};
	const size_t noffs = VT_ARRAY_SIZE(offs);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < noffs; ++i) {
		off = base_off + offs[i];
		vt_pwriten(fd, buf1, len1, off);
	}
	for (size_t i = 0; i < noffs; ++i) {
		off = base_off + offs[i] + 1;
		vt_pwriten(fd, buf2, len2, off);
	}
	for (size_t i = 0; i < noffs; ++i) {
		off = base_off + offs[i];
		vt_preadn(fd, &byte, 1, off);
		vt_expect_eq(buf1[0], byte);
		vt_preadn(fd, buf3, len2, off + 1);
		vt_expect_eqm(buf2, buf3, len2);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_sparse_overwrite(struct vt_env *vte)
{
	test_sparse_overwrite_(vte, 0);
	test_sparse_overwrite_(vte, 1);
	test_sparse_overwrite_(vte, VT_UMEGA - 2);
	test_sparse_overwrite_(vte, VT_UGIGA - 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_sparse_simple),
	VT_DEFTEST(test_sparse_rdwr),
	VT_DEFTEST(test_sparse_overwrite),
};

const struct vt_tests vt_test_rw_sparse = VT_DEFTESTS(vt_local_tests);
