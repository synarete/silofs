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


static void ut_archive_ok(struct ut_env *ute)
{
	ut_close_fs_ok(ute);
	ut_pack_fs_ok(ute);
	ut_open_fs_ok(ute);
}

static void ut_restore_ok(struct ut_env *ute)
{
	ut_close_fs_ok(ute);
	ut_unpack_fs_ok(ute);
	ut_open_fs_ok(ute);
}

static void ut_archive_restore_ok(struct ut_env *ute)
{
	struct statvfs stv[2];

	ut_statfs_rootd_ok(ute, &stv[0]);
	ut_archive_ok(ute);
	ut_restore_ok(ute);
	ut_statfs_rootd_ok(ute, &stv[1]);
	ut_expect_statvfs(&stv[0], &stv[1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_simple(struct ut_env *ute)
{
	ino_t dino;
	ino_t ino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_release_ok(ute, ino);
	ut_archive_restore_ok(ute);
	ut_unlink_file(ute, dino, name);
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
	ut_archive_restore_ok(ute);
	ut_open_rdonly(ute, ino);
	ut_read_verify(ute, ino, buf, bsz, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_data(struct ut_env *ute)
{
	ut_pack_data_(ute, 0, UT_MEGA);
	ut_pack_data_(ute, 1, SILOFS_IO_SIZE_MAX);
	ut_pack_data_(ute, UT_KILO - 1, 2 * UT_BK_SIZE);
	ut_pack_data_(ute, UT_GIGA, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_data2_(struct ut_env *ute, loff_t off1, size_t bsz1,
                           loff_t off2, size_t bsz2)
{
	ino_t ino1;
	ino_t ino2;
	ino_t dino;
	const char *name = UT_NAME;
	const char *name1 = ut_make_name(ute, "f", 1);
	const char *name2 = ut_make_name(ute, "f", 2);
	void *buf1 = ut_randbuf(ute, bsz1);
	void *buf2 = ut_randbuf(ute, bsz2);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name1, &ino1);
	ut_write_read(ute, ino1, buf1, bsz1, off1);
	ut_create_file(ute, dino, name2, &ino2);
	ut_write_read(ute, ino2, buf2, bsz2, off2);
	ut_release_ok(ute, ino1);
	ut_release_ok(ute, ino2);
	ut_archive_restore_ok(ute);
	ut_open_rdonly(ute, ino1);
	ut_open_rdonly(ute, ino2);
	ut_read_verify(ute, ino1, buf1, bsz1, off1);
	ut_read_verify(ute, ino2, buf2, bsz2, off2);
	ut_remove_file(ute, dino, name1, ino1);
	ut_remove_file(ute, dino, name2, ino2);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_data2(struct ut_env *ute)
{
	ut_pack_data2_(ute, 0, UT_MEGA, UT_GIGA, UT_MEGA);
	ut_pack_data2_(ute, UT_GIGA - 1, UT_MEGA + 3, 1, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_overwrite_(struct ut_env *ute, loff_t off1, size_t bsz1,
                               loff_t off2, size_t bsz2)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	void *buf1 = ut_randbuf(ute, bsz1);
	void *buf2 = ut_randbuf(ute, bsz2);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf1, bsz1, off1);
	ut_trunacate_file(ute, ino, off1);
	ut_write_read(ute, ino, buf2, bsz2, off2);
	ut_release_ok(ute, ino);
	ut_archive_restore_ok(ute);
	ut_open_rdonly(ute, ino);
	ut_read_verify(ute, ino, buf2, bsz2, off2);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_overwrite(struct ut_env *ute)
{
	ut_pack_overwrite_(ute, 1, UT_MEGA, 0, UT_MEGA);
	ut_pack_overwrite_(ute, 2 * UT_BK_SIZE, UT_MEGA, UT_BK_SIZE, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_truncate_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_trunacate_file(ute, ino, off + 1);
	ut_release_ok(ute, ino);
	ut_archive_restore_ok(ute);
	ut_open_rdonly(ute, ino);
	ut_read_verify(ute, ino, buf, 1, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_truncate(struct ut_env *ute)
{
	ut_pack_truncate_(ute, 0, UT_MEGA);
	ut_pack_truncate_(ute, UT_GIGA - 1, UT_MEGA + 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_nfiles_data_(struct ut_env *ute, size_t nfiles)
{
	ino_t ino;
	ino_t dino;
	loff_t off;
	uint64_t val;
	const char *name = UT_NAME;
	const char *fname = NULL;

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_create_file(ute, dino, fname, &ino);
		val = ino;
		off = (loff_t)(i * UT_KILO);
		ut_write_read(ute, ino, &val, sizeof(val), off);
		ut_release_ok(ute, ino);
	}
	ut_archive_restore_ok(ute);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_lookup_ino(ute, dino, fname, &ino);
		ut_open_rdonly(ute, ino);
		val = ino;
		off = (loff_t)(i * UT_KILO);
		ut_read_verify(ute, ino, &val, sizeof(val), off);
		ut_remove_file(ute, dino, fname, ino);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_nfiles_data(struct ut_env *ute)
{
	ut_pack_nfiles_data_(ute, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_pack_nfiles_rand_(struct ut_env *ute, size_t nfiles, size_t bsz)
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
	ut_archive_restore_ok(ute);
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

static void ut_pack_nfiles_rand(struct ut_env *ute)
{
	ut_pack_nfiles_rand_(ute, 8, UT_MEGA);
	ut_pack_nfiles_rand_(ute, 1024, UT_KILO);
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
	ut_archive_restore_ok(ute);
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

static void ut_pack_rename_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const char *name2 = "name2";
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_release_ok(ute, ino);
	ut_rename_move(ute, dino, name, dino, name2);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_release_ok(ute, ino);
	ut_rename_replace(ute, dino, name2, dino, name);
	ut_lookup_ino(ute, dino, name, &ino);
	ut_archive_restore_ok(ute);
	ut_open_rdonly(ute, ino);
	ut_read_verify(ute, ino, buf, bsz, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_pack_rename(struct ut_env *ute)
{
	ut_pack_rename_(ute, 0, UT_MEGA);
	ut_pack_rename_(ute, UT_BK_SIZE - 1, UT_MEGA + 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_pack_simple),
	UT_DEFTEST(ut_pack_data),
	UT_DEFTEST(ut_pack_data2),
	UT_DEFTEST(ut_pack_overwrite),
	UT_DEFTEST(ut_pack_truncate),
	UT_DEFTEST(ut_pack_nfiles_data),
	UT_DEFTEST(ut_pack_nfiles_rand),
	UT_DEFTEST(ut_pack_ndirs),
	UT_DEFTEST(ut_pack_rename),
};

const struct ut_testdefs ut_tdefs_pack = UT_MKTESTS(ut_local_tests);
