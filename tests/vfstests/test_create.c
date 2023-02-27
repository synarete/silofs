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
 * Expects success for simple creat(3p)/unlink(3p) X N
 */
static void test_create_simple_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	const char *path = vt_new_path_unique(vte);

	for (size_t i = 0; i < cnt; ++i) {
		vt_creat(path, 0600, &fd);
		vt_close(fd);
		vt_unlink(path);
	}
}

static void test_create_simple(struct vt_env *vte)
{
	test_create_simple_(vte, 1);
	test_create_simple_(vte, 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects success for sequence of creat(3p)/unlink(3p) of regular files.
 */
static void test_create_unlink_(struct vt_env *vte, size_t cnt)
{
	int fd = -1;
	const char *path1 = NULL;
	const char *path0 = vt_new_path_unique(vte);

	vt_mkdir(path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		path1 = vt_new_pathf(vte, path0, "%lu", i);
		vt_creat(path1, 0600, &fd);
		vt_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		path1 = vt_new_pathf(vte, path0, "%lu", i);
		vt_unlink(path1);
	}
	vt_rmdir(path0);
}

static void test_create_unlink(struct vt_env *vte)
{
	test_create_unlink_(vte, 1);
	test_create_unlink_(vte, 2);
	test_create_unlink_(vte, 8);
	test_create_unlink_(vte, 128);
}

static void test_create_unlink_many(struct vt_env *vte)
{
	test_create_unlink_(vte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_create_simple),
	VT_DEFTEST(test_create_unlink),
	VT_DEFTEST(test_create_unlink_many),
};

const struct vt_tests vt_test_create = VT_DEFTESTS(vt_local_tests);
