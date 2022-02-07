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
#include "unitests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_mkdir_rmdir(struct ut_env *ute)
{
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_snap_ok(ute, dino, name);
	ut_inspect_ok(ute, dino);
	ut_unrefs_ok(ute, dino, name);
	ut_inspect_ok(ute, dino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_create_remove(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_snap_ok(ute, dino, name);
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_write_read(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	time_t val = silofs_time_now();
	struct stat st[2];
	const char *name = UT_NAME;
	const loff_t off = (loff_t)(val & 0xFFFFFF);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, &val, sizeof(val), off);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_snap_ok(ute, dino, name);
	ut_getattr_ok(ute, ino, &st[1]);
	ut_expect_eq_stat(&st[0], &st[1]);
	ut_read_verify(ute, ino, &val, sizeof(val), off);
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_write_post(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const loff_t off = UT_MEGA;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_snap_ok(ute, dino, name);
	ut_write_read_str(ute, ino, name, off);
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_overwrite(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	time_t val = silofs_time_now();
	struct stat st[2];
	const char *name = UT_NAME;
	const loff_t off = UT_GIGA;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, &val, sizeof(val), off);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_snap_ok(ute, dino, name);
	ut_getattr_ok(ute, ino, &st[1]);
	ut_expect_eq_stat(&st[0], &st[1]);
	ut_read_verify(ute, ino, &val, sizeof(val), off);
	ut_read_zero(ute, ino, off - 1);
	ut_write_read(ute, ino, &val, sizeof(val), off);
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_reload(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_str(ute, ino, name, UT_KILO);
	ut_write_read_str(ute, ino, name, UT_TERA);
	ut_write_read_str(ute, ino, name, UT_MEGA);
	ut_release_ok(ute, ino);
	ut_snap_ok(ute, dino, name);
	ut_reload_fs_ok(ute);
	ut_inspect_ok(ute, dino);
	ut_open_rdonly(ute, ino);
	ut_read_verify_str(ute, ino, name, UT_MEGA);
	ut_read_verify_str(ute, ino, name, UT_KILO);
	ut_read_verify_str(ute, ino, name, UT_TERA);
	ut_read_zeros(ute, ino, UT_GIGA, 1);
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_inspect_ok(ute, dino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_snap_reload_other(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const loff_t off = UT_TERA;
	const char *name = UT_NAME;
	const char *fsname = ute->fs_env->fs_args.main_name;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read_str(ute, ino, name, off);
	ut_release_ok(ute, ino);
	ut_snap_ok(ute, dino, name);
	ute->fs_env->fs_args.rdonly = true;
	ut_reload_fs_byname_ok(ute, name);
	ut_open_rdonly(ute, ino);
	ut_read_verify_str(ute, ino, name, off);
	ut_release_ok(ute, ino);
	ute->fs_env->fs_args.rdonly = false;
	ut_reload_fs_byname_ok(ute, fsname);
	ut_open_rdonly(ute, ino);
	ut_read_verify_str(ute, ino, name, off);
	ut_remove_file(ute, dino, name, ino);
	ut_unrefs_ok(ute, dino, name);
	ut_inspect_ok(ute, dino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_snap_mkdir_rmdir),
	UT_DEFTEST(ut_snap_create_remove),
	UT_DEFTEST(ut_snap_write_read),
	UT_DEFTEST(ut_snap_write_post),
	UT_DEFTEST(ut_snap_overwrite),
	UT_DEFTEST(ut_snap_reload),
	UT_DEFTEST(ut_snap_reload_other),
};

const struct ut_testdefs ut_tdefs_snap_basic = UT_MKTESTS(ut_local_tests);
