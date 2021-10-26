/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include "unitests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_mkdir_rmdir(struct ut_env *ute)
{
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_clone_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_create_remove(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_clone_ok(ute, dino, name);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_write_read(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	struct stat st[2];
	const char *name = UT_NAME;
	const size_t len = strlen(name);
	const loff_t off = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, name, len, off);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_clone_ok(ute, dino, name);
	ut_getattr_ok(ute, ino, &st[1]);
	ut_expect_eq_stat(&st[0], &st[1]);
	ut_read_verify(ute, ino, name, len, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_write_post(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const loff_t off = UT_BK_SIZE;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_clone_ok(ute, dino, name);
	ut_write_read_str(ute, ino, name, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_clone_overwrite(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	struct stat st[2];
	const char *name = UT_NAME;
	const size_t len = strlen(name);
	const loff_t off = 111;
	const void  *buf = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, name, len, off);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_clone_ok(ute, dino, name);
	ut_getattr_ok(ute, ino, &st[1]);
	ut_expect_eq_stat(&st[0], &st[1]);
	ut_write_read(ute, ino, buf, len, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_clone_mkdir_rmdir),
	UT_DEFTEST(ut_clone_create_remove),
	UT_DEFTEST(ut_clone_write_read),
	UT_DEFTEST(ut_clone_write_post),
	UT_DEFTEST(ut_clone_overwrite),
};

const struct ut_tests ut_test_clone = UT_MKTESTS(ut_local_tests);
