/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency, sequential writes of single block.
 */
static void test_tmpfile_simple(struct ft_env *fte)
{
	int fd = -1;
	loff_t pos = -1;
	size_t dat = 0;
	size_t nwr = 0;
	size_t nrd = 0;
	struct stat st;
	const size_t bsz = FT_BK_SIZE;
	void *buf = ft_new_buf_zeros(fte, bsz);
	char *path = ft_new_path_unique(fte);

	ft_mkdir(path, 0700);
	ft_open(path, O_RDWR | O_TMPFILE | O_EXCL, 0600, &fd);
	for (size_t i = 0; i < 128; ++i) {
		dat = i;
		ft_memcpy(buf, &dat, sizeof(dat));
		ft_write(fd, buf, bsz, &nwr);
		ft_fstat(fd, &st);
		ft_expect_eq((long)st.st_size, (long)((i + 1) * bsz));
	}
	ft_llseek(fd, 0, SEEK_SET, &pos);
	for (size_t i = 0; i < 128; ++i) {
		ft_read(fd, buf, bsz, &nrd);
		ft_memcpy(&dat, buf, sizeof(dat));
		ft_expect_eq((long)i, (long)dat);
	}
	ft_close(fd);
	ft_rmdir(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency for buffer-size of 1M.
 */
static void test_buffer(struct ft_env *fte, size_t bsz)
{
	int fd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	void *buf1 = NULL;
	void *buf2 = NULL;
	char *path = ft_new_path_unique(fte);
	struct stat st;

	ft_mkdir(path, 0700);
	ft_open(path, O_RDWR | O_TMPFILE | O_EXCL, 0600, &fd);
	for (size_t i = 0; i < 8; ++i) {
		buf1 = ft_new_buf_rands(fte, bsz);
		ft_pwrite(fd, buf1, bsz, 0, &nwr);
		ft_fsync(fd);
		buf2 = ft_new_buf_rands(fte, bsz);
		ft_pread(fd, buf2, bsz, 0, &nrd);
		ft_fstat(fd, &st);
		ft_expect_eq(st.st_size, bsz);
		ft_expect_eqm(buf1, buf2, bsz);
	}
	ft_close(fd);
	ft_rmdir(path);
}

static void test_tmpfile_rdwr_1k(struct ft_env *fte)
{
	test_buffer(fte, 1024);
}

static void test_tmpfile_rdwr_8k(struct ft_env *fte)
{
	test_buffer(fte, 8 * FT_1K);
}

static void test_tmpfile_rdwr_1m(struct ft_env *fte)
{
	test_buffer(fte, FT_1M);
}

static void test_tmpfile_rdwr_8m(struct ft_env *fte)
{
	test_buffer(fte, 8 * FT_1M);
}

static void test_tmpfile_rdwr_32m(struct ft_env *fte)
{
	test_buffer(fte, 32 * FT_1M);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTESTF(test_tmpfile_simple, FT_F_TMPFILE),
	FT_DEFTESTF(test_tmpfile_rdwr_1k, FT_F_TMPFILE),
	FT_DEFTESTF(test_tmpfile_rdwr_8k, FT_F_TMPFILE),
	FT_DEFTESTF(test_tmpfile_rdwr_1m, FT_F_TMPFILE),
	FT_DEFTESTF(test_tmpfile_rdwr_8m, FT_F_TMPFILE),
	FT_DEFTESTF(test_tmpfile_rdwr_32m, FT_F_TMPFILE),
};

const struct ft_tests ft_test_tmpfile = FT_DEFTESTS(ft_local_tests);
