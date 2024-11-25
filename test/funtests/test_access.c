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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return 0 on root-dir.
 */
static void test_access_rootdir(struct ft_env *fte)
{
	const char *path = ft_new_path_name(fte, "/");

	ft_access(path, R_OK | W_OK | X_OK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return ENOENT if a component of path does not name an
 * existing file or path is an empty string.
 */
static void test_access_noent(struct ft_env *fte)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);

	ft_mkdir(path0, 0755);
	ft_access(path0, F_OK);
	ft_access(path0, X_OK);
	ft_access(path0, F_OK | X_OK);
	ft_access_err(path1, R_OK, -ENOENT);
	ft_access_err(path1, F_OK, -ENOENT);
	ft_access_err(path1, F_OK | X_OK, -ENOENT);
	ft_access_err(path2, R_OK, -ENOENT);
	ft_access_err(path2, F_OK, -ENOENT);
	ft_access_err(path2, F_OK | X_OK, -ENOENT);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return EINVAL if the value of the amode argument is
 * invalid.
 */
static void test_access_inval(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	const int mode = R_OK | W_OK | X_OK | F_OK;
	int fd = -1;

	ft_creat(path, 0644, &fd);
	ft_access_err(path, ~mode, -EINVAL);
	ft_unlink(path);
	ft_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects access(3p) to return EACCES when a component of the path prefix
 * denies search permission
 */
static void test_access_prefix(struct ft_env *fte)
{
	const char *path0 = ft_new_path_unique(fte);
	const char *path1 = ft_new_path_under(fte, path0);
	const char *path2 = ft_new_path_under(fte, path1);
	const char *path3 = ft_new_path_under(fte, path2);
	const int mode = R_OK;
	int fd = -1;

	ft_mkdir(path0, 0750);
	ft_mkdir(path1, 0750);
	ft_mkdir(path2, 0750);
	ft_creat(path3, 0600, &fd);
	ft_access(path3, mode);
	ft_chmod(path2, 0200);
	ft_suspends(fte, 3);
	ft_access_err(path3, mode, -EACCES);
	ft_chmod(path2, 0700);
	ft_suspends(fte, 3);
	ft_access(path3, mode);
	ft_unlink(path3);
	ft_close(fd);
	ft_rmdir(path2);
	ft_rmdir(path1);
	ft_rmdir(path0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_access_rootdir), FT_DEFTEST(test_access_noent),
	FT_DEFTEST(test_access_inval), FT_DEFTEST(test_access_prefix)
};
const struct ft_tests ft_test_access = FT_DEFTESTS(ft_local_tests);
