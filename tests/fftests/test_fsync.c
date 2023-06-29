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
 * Expects fsync(3p) to return 0 after regular file write/read operation.
 */
static void test_fsync_reg(struct ft_env *fte, loff_t base_off,
                           size_t bsz, loff_t step, size_t cnt)
{
	int fd = -1;
	loff_t off = -1;
	void *buf1 = NULL;
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		off = base_off + ((loff_t)i  * step);
		buf1 = ft_new_buf_rands(fte, bsz);
		ft_pwriten(fd, buf1, bsz, off);
		ft_fsync(fd);
		ft_preadn(fd, buf2, bsz, off);
		ft_expect_eqm(buf1, buf2, bsz);
		buf2 = buf1;
	}
	ft_close(fd);
	ft_unlink(path);
}


static void test_fsync_reg_aligned(struct ft_env *fte)
{
	test_fsync_reg(fte, 0, FT_UKILO, FT_UMEGA, 64);
	test_fsync_reg(fte, FT_UMEGA, FT_BK_SIZE, FT_UGIGA,
	               64);
}

static void test_fsync_reg_unaligned(struct ft_env *fte)
{
	test_fsync_reg(fte, 1, FT_UKILO - 1, FT_UMEGA + 1, 64);
	test_fsync_reg(fte, FT_UMEGA - 1, 3 * FT_UKILO + 1, FT_UGIGA - 1, 64);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fsync(3p) to return 0 after directory operations.
 */
static void test_fsync_dir_nent(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	int dfd = -1;
	const char *path1 = ft_new_path_unique(fte);
	const char *path2 = NULL;

	ft_mkdir(path1, 0700);
	ft_open(path1, O_DIRECTORY | O_RDONLY, 0, &dfd);
	for (size_t i = 0; i < cnt; ++i) {
		path2 = ft_new_pathf(fte, path1, "%08x", i + 1);
		ft_creat(path2, 0640, &fd);
		ft_fsync(dfd);
		ft_close(fd);
		ft_fsync(dfd);
	}
	for (size_t j = 0; j < cnt; ++j) {
		path2 = ft_new_pathf(fte, path1, "%08x", j + 1);
		ft_unlink(path2);
		ft_fsync(dfd);
	}
	ft_close(dfd);
	ft_rmdir(path1);
}

static void test_fsync_dir(struct ft_env *fte)
{
	test_fsync_dir_nent(fte, 1024);
	test_fsync_dir_nent(fte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects syncfs(2) to return 0
 */
static void test_fsync_syncfs(struct ft_env *fte)
{
	int fd = -1;
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_syncfs(fd);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_fsync_reg_aligned),
	FT_DEFTEST(test_fsync_reg_unaligned),
	FT_DEFTEST(test_fsync_dir),
	FT_DEFTEST(test_fsync_syncfs),
};

const struct ft_tests ft_test_fsync = FT_DEFTESTS(ft_local_tests);
