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
 * Expects success for simple creat(3p)/unlink(3p) X N
 */
static void test_create_simple_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	const char *path = ft_new_path_unique(fte);

	for (size_t i = 0; i < cnt; ++i) {
		ft_creat(path, 0600, &fd);
		ft_close(fd);
		ft_unlink(path);
	}
}

static void test_create_simple(struct ft_env *fte)
{
	test_create_simple_(fte, 1);
	test_create_simple_(fte, 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects success for sequence of creat(3p)/unlink(3p) of regular files.
 */
static void test_create_unlink_(struct ft_env *fte, size_t cnt)
{
	int fd = -1;
	const char *path1 = NULL;
	const char *path0 = ft_new_path_unique(fte);

	ft_mkdir(path0, 0700);
	for (size_t i = 0; i < cnt; ++i) {
		path1 = ft_new_pathf(fte, path0, "%lu", i);
		ft_creat(path1, 0600, &fd);
		ft_close(fd);
	}
	for (size_t i = 0; i < cnt; ++i) {
		path1 = ft_new_pathf(fte, path0, "%lu", i);
		ft_unlink(path1);
	}
	ft_rmdir(path0);
}

static void test_create_unlink(struct ft_env *fte)
{
	test_create_unlink_(fte, 1);
	test_create_unlink_(fte, 2);
	test_create_unlink_(fte, 8);
	test_create_unlink_(fte, 128);
}

static void test_create_unlink_many(struct ft_env *fte)
{
	test_create_unlink_(fte, 4096);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_create_simple),
	FT_DEFTEST(test_create_unlink),
	FT_DEFTEST(test_create_unlink_many),
};

const struct ft_tests ft_test_create = FT_DEFTESTS(ft_local_tests);
