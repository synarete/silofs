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
 * Expects ioctl(FICLONE) to successfully clone entire file range between two
 * files.
 */
static void test_clone_file_range_(struct ft_env *fte, size_t bsz)
{
	int fd1 = -1;
	int fd2 = -1;
	struct stat st[2];
	void *data1 = ft_new_buf_rands(fte, bsz);
	void *data2 = ft_new_buf_rands(fte, bsz);
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = ft_new_path_unique(fte);

	ft_open(path1, O_CREAT | O_RDWR, 0600, &fd1);
	ft_open(path2, O_CREAT | O_RDWR, 0600, &fd2);
	ft_pwriten(fd1, data1, bsz, 0);
	ft_fstat(fd1, &st[0]);
	ft_expect_eq(bsz, st[0].st_size);
	ft_ioctl_ficlone(fd2, fd1);
	ft_fstat(fd2, &st[1]);
	ft_expect_eq(bsz, st[1].st_size);
	ft_preadn(fd1, data2, bsz, 0);
	ft_expect_eqm(data1, data2, bsz);
	ft_expect_eq(st[0].st_blocks, st[1].st_blocks);
	ft_close(fd1);
	ft_unlink(path1);
	ft_close(fd2);
	ft_unlink(path2);
}

static void test_clone_file_range_small(struct ft_env *fte)
{
	test_clone_file_range_(fte, FT_BK_SIZE);
	test_clone_file_range_(fte, 8 * FT_BK_SIZE);
}

static void test_clone_file_range_large(struct ft_env *fte)
{
	test_clone_file_range_(fte, FT_UMEGA);
	test_clone_file_range_(fte, 8 * FT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTESTF(test_clone_file_range_small, FT_F_IGNORE),
	FT_DEFTESTF(test_clone_file_range_large, FT_F_IGNORE),
};

const struct ft_tests ft_test_clone = FT_DEFTESTS(ft_local_tests);
