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
 * Expects access(3p) to return 0 on root-dir.
 */
static void test_access_rootdir(struct vt_env *vte)
{
	const char *path = vt_new_path_name(vte, "/");

	vt_access(path, R_OK | W_OK | X_OK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return ENOENT if a component of path does not name an
 * existing file or path is an empty string.
 */
static void test_access_noent(struct vt_env *vte)
{
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);

	vt_mkdir(path0, 0755);
	vt_access(path0, F_OK);
	vt_access(path0, X_OK);
	vt_access(path0, F_OK | X_OK);

	vt_access_err(path1, R_OK, -ENOENT);
	vt_access_err(path1, F_OK, -ENOENT);
	vt_access_err(path1, F_OK | X_OK, -ENOENT);

	vt_access_err(path2, R_OK, -ENOENT);
	vt_access_err(path2, F_OK, -ENOENT);
	vt_access_err(path2, F_OK | X_OK, -ENOENT);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return EINVAL if the value of the amode argument is
 * invalid.
 */
static void test_access_inval(struct vt_env *vte)
{
	int fd = -1;
	const int mode = R_OK | W_OK | X_OK | F_OK;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0644, &fd);
	vt_access_err(path, ~mode, -EINVAL);
	vt_unlink(path);
	vt_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return EACCES when a component of the path prefix
 * denies search permission
 */
static void test_access_prefix(struct vt_env *vte)
{
	int fd = -1;
	const int mode = R_OK;
	const char *path0 = vt_new_path_unique(vte);
	const char *path1 = vt_new_path_under(vte, path0);
	const char *path2 = vt_new_path_under(vte, path1);
	const char *path3 = vt_new_path_under(vte, path2);

	vt_mkdir(path0, 0750);
	vt_mkdir(path1, 0750);
	vt_mkdir(path2, 0750);
	vt_creat(path3, 0600, &fd);
	vt_access(path3, mode);
	vt_chmod(path2, 0200);
	vt_suspends(vte, 3);
	vt_access_err(path3, mode, -EACCES);
	vt_chmod(path2, 0700);
	vt_suspends(vte, 3);
	vt_access(path3, mode);

	vt_unlink(path3);
	vt_close(fd);
	vt_rmdir(path2);
	vt_rmdir(path1);
	vt_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_access_rootdir),
	VT_DEFTEST(test_access_noent),
	VT_DEFTEST(test_access_inval),
	VT_DEFTEST(test_access_prefix)
};
const struct vt_tests vt_test_access = VT_DEFTESTS(vt_local_tests);

