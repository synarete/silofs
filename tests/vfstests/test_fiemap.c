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
#include <linux/fs.h>
#include <linux/fiemap.h>


static struct fiemap *new_fiemap(struct vt_env *vte, size_t cnt)
{
	size_t sz;
	struct fiemap *fm = NULL;

	sz = sizeof(*fm) + (cnt * sizeof(fm->fm_extents[0]));
	fm = vt_new_buf_zeros(vte, sz);
	fm->fm_extent_count = (uint32_t)cnt;

	return fm;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_fiemap_simple_(struct vt_env *vte,
                                loff_t off, size_t bsz)
{
	int fd;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);
	struct fiemap *fm = NULL;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwriten(fd, buf, bsz, off);

	fm = new_fiemap(vte, 2);
	fm->fm_start = (uint64_t)off;
	fm->fm_length = bsz;
	fm->fm_flags = FIEMAP_FLAG_SYNC;
	vt_fiemap(fd, fm);

	vt_close(fd);
	vt_unlink(path);
}

static void test_fiemap_simple(struct vt_env *vte)
{
	test_fiemap_simple_(vte, 0, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTESTF(test_fiemap_simple, VT_IGNORE),
};

const struct vt_tests vt_test_fiemap = VT_DEFTESTS(vt_local_tests);
