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
#include "fftests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency when I/O at block boundaries
 */
static void test_boundaries_(struct ft_env *fte, loff_t boff)
{
	int fd;
	uint8_t byte;
	uint64_t val1;
	uint64_t val2;
	loff_t off;
	const long vsz = (long)sizeof(val1);
	const loff_t off_beg = boff - vsz - 1;
	const loff_t off_end = boff + vsz + 1;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (off = off_beg; off < off_end; ++off) {
		if (off < 1) {
			continue;
		}
		if ((off + vsz) > FT_FILESIZE_MAX) {
			break;
		}
		byte = (uint8_t)off;
		val1 = (uint64_t)off;
		ft_pwriten(fd, &val1, sizeof(val1), off);
		ft_preadn(fd, &val2, sizeof(val2), off);
		ft_expect_eq(val1, val2);
		ft_preadn(fd, &byte, sizeof(byte), off - 1);
		ft_expect_eq(byte, 0);
		ft_ftruncate(fd, off);
	}
	ft_close(fd);
	ft_unlink(path);
}

static void test_boundaries_arr_(struct ft_env *fte,
                                 const loff_t *arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		test_boundaries_(fte, arr[i]);
	}
}

static void test_boundaries_write_read(struct ft_env *fte)
{
	const loff_t offs[] = {
		0, FT_KILO, FT_BK_SIZE, FT_MEGA,
		2 * FT_MEGA + 1, FT_GIGA, 7 * FT_GIGA - 7,
		FT_TERA, FT_TERA / 2 - 1,
		FT_FILESIZE_MAX / 2,
		FT_FILESIZE_MAX / 2 + 1,
		FT_FILESIZE_MAX
	};

	test_boundaries_arr_(fte, offs, FT_ARRAY_SIZE(offs));
}

static void test_boundaries_tree_levels(struct ft_env *fte)
{
	const loff_t offs[] = {
		FT_BK_SIZE,
		FT_BK_SIZE * FT_FILEMAP_NCHILD,
		FT_BK_SIZE *FT_FILEMAP_NCHILD * FT_FILEMAP_NCHILD,
		FT_BK_SIZE *FT_FILEMAP_NCHILD *
		FT_FILEMAP_NCHILD *FT_FILEMAP_NCHILD
	};

	test_boundaries_arr_(fte, offs, FT_ARRAY_SIZE(offs));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_boundaries_write_read),
	FT_DEFTEST(test_boundaries_tree_levels),
};

const struct ft_tests ft_test_boundaries = FT_DEFTESTS(ft_local_tests);
