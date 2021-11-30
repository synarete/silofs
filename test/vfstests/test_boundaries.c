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
 * Expects read-write data-consistency when I/O at block boundaries
 */
static void test_boundaries_(struct vt_env *vte, loff_t boff)
{
	int fd;
	uint8_t byte;
	uint64_t val1;
	uint64_t val2;
	loff_t off;
	const long vsz = (long)sizeof(val1);
	const loff_t off_beg = boff - vsz - 1;
	const loff_t off_end = boff + vsz + 1;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (off = off_beg; off < off_end; ++off) {
		if (off < 1) {
			continue;
		}
		if ((off + vsz) > VT_FILESIZE_MAX) {
			break;
		}
		byte = (uint8_t)off;
		val1 = (uint64_t)off;
		vt_pwriten(fd, &val1, sizeof(val1), off);
		vt_preadn(fd, &val2, sizeof(val2), off);
		vt_expect_eq(val1, val2);
		vt_preadn(fd, &byte, sizeof(byte), off - 1);
		vt_expect_eq(byte, 0);
		vt_ftruncate(fd, off);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_boundaries_arr_(struct vt_env *vte,
                                 const loff_t *arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		test_boundaries_(vte, arr[i]);
	}
}

static void test_boundaries_write_read(struct vt_env *vte)
{
	const loff_t offs[] = {
		0, VT_KILO, VT_BK_SIZE, VT_MEGA,
		2 * VT_MEGA + 1, VT_GIGA, 7 * VT_GIGA - 7,
		VT_TERA, VT_TERA / 2 - 1,
		VT_FILESIZE_MAX / 2,
		VT_FILESIZE_MAX / 2 + 1,
		VT_FILESIZE_MAX
	};

	test_boundaries_arr_(vte, offs, VT_ARRAY_SIZE(offs));
}

static void test_boundaries_tree_levels(struct vt_env *vte)
{
	const loff_t offs[] = {
		VT_BK_SIZE,
		VT_BK_SIZE * VT_FILEMAP_NCHILD,
		VT_BK_SIZE *VT_FILEMAP_NCHILD * VT_FILEMAP_NCHILD,
		VT_BK_SIZE *VT_FILEMAP_NCHILD *
		VT_FILEMAP_NCHILD *VT_FILEMAP_NCHILD
	};

	test_boundaries_arr_(vte, offs, VT_ARRAY_SIZE(offs));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_boundaries_write_read),
	VT_DEFTEST(test_boundaries_tree_levels),
};

const struct vt_tests vt_test_boundaries = VT_DEFTESTS(vt_local_tests);
