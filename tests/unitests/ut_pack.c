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


static void ut_archive_restore_ok(struct ut_env *ute, const char *dst_name)
{
	const char *src_name = ute->args->fs_args.warm_name;
	struct statvfs stv[2];

	ut_statfs_rootd(ute, &stv[0]);
	ut_archive_ok(ute, src_name, dst_name);
	ut_restore_ok(ute, dst_name, src_name);
	ut_statfs_rootd(ute, &stv[1]);
	ut_expect_statvfs(&stv[0], &stv[1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_simple(struct ut_env *ute)
{
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_archive_restore_ok(ute, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_data_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_release_ok(ute, ino);
	ut_archive_restore_ok(ute, name);
	ut_open_rdonly(ute, ino);
	ut_read_verify(ute, ino, buf, bsz, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_data(struct ut_env *ute)
{
	ut_pack_data_(ute, 0, UT_MEGA);
	ut_pack_data_(ute, UT_KILO - 1, 2 * UT_BK_SIZE);
	ut_pack_data_(ute, UT_GIGA, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_nfiles_(struct ut_env *ute, size_t nfiles, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	loff_t off;
	const char *name = UT_NAME;
	const char *fname = NULL;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		off = (loff_t)(i * bsz + i);
		fname = ut_make_name(ute, name, i);
		ut_create_file(ute, dino, fname, &ino);
		ut_write_read(ute, ino, buf, bsz, off);
		ut_release_ok(ute, ino);
	}
	ut_archive_restore_ok(ute, name);
	for (size_t i = 0; i < nfiles; ++i) {
		off = (loff_t)(i * bsz + i);
		fname = ut_make_name(ute, name, i);
		ut_lookup_ino(ute, dino, fname, &ino);
		ut_open_rdonly(ute, ino);
		ut_read_verify(ute, ino, buf, bsz, off);
		ut_remove_file(ute, dino, fname, ino);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_nfiles(struct ut_env *ute)
{
	ut_pack_nfiles_(ute, 16, UT_MEGA);
	ut_pack_nfiles_(ute, 1024, UT_KILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_ndirs_(struct ut_env *ute, size_t ndirs)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const char *dname = NULL;

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < ndirs; ++i) {
		dname = ut_make_name(ute, name, i);
		ut_mkdir_oki(ute, dino, dname, &ino);
	}
	ut_archive_restore_ok(ute, name);
	for (size_t i = 0; i < ndirs; ++i) {
		dname = ut_make_name(ute, name, i);
		ut_lookup_ino(ute, dino, dname, &ino);
		ut_lookup_dir(ute, dino, dname, ino);
		ut_rmdir_ok(ute, dino, dname);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_ndirs(struct ut_env *ute)
{
	ut_pack_ndirs_(ute, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_pack_simple),
	UT_DEFTEST(ut_pack_data),
	UT_DEFTEST(ut_pack_nfiles),
	UT_DEFTEST(ut_pack_ndirs),
};

const struct ut_testdefs ut_tdefs_pack = UT_MKTESTS(ut_local_tests);
