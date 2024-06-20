/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <linux/fs.h>
#include <linux/fiemap.h>


static struct fiemap *new_fiemap(struct ft_env *fte, size_t cnt)
{
	size_t sz;
	struct fiemap *fm = NULL;

	sz = sizeof(*fm) + (cnt * sizeof(fm->fm_extents[0]));
	fm = ft_new_buf_zeros(fte, sz);
	fm->fm_extent_count = (uint32_t)cnt;

	return fm;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_fiemap_simple_(struct ft_env *fte, loff_t off, size_t bsz)
{
	const char *path = ft_new_path_unique(fte);
	void *buf = ft_new_buf_rands(fte, bsz);
	struct fiemap *fm = NULL;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_pwriten(fd, buf, bsz, off);

	fm = new_fiemap(fte, 2);
	fm->fm_start = (uint64_t)off;
	fm->fm_length = bsz;
	fm->fm_flags = FIEMAP_FLAG_SYNC;
	ft_fiemap(fd, fm);

	ft_close(fd);
	ft_unlink(path);
}

static void test_fiemap_simple(struct ft_env *fte)
{
	test_fiemap_simple_(fte, 0, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTESTF(test_fiemap_simple, FT_F_IGNORE),
};

const struct ft_tests ft_test_fiemap = FT_DEFTESTS(ft_local_tests);
