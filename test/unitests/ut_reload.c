/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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

static void ut_reload_nfiles_(struct ut_env *ute, size_t nfiles)
{
	ino_t ino;
	ino_t dino;
	const char *fname;
	const char *dname = UT_NAME;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_reload_fs_at(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_create_only(ute, dino, fname, &ino);
	}
	ut_reload_fs_at(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_remove_link(ute, dino, fname);
	}
	ut_reload_fs_at(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_reload_simple(struct ut_env *ute)
{
	ut_reload_nfiles_(ute, 0);
}

static void ut_reload_nfiles(struct ut_env *ute)
{
	ut_reload_nfiles_(ute, 1);
	ut_reload_nfiles_(ute, 11);
	ut_reload_nfiles_(ute, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_reload_mixed_(struct ut_env *ute, size_t nfiles)
{
	ino_t fino;
	ino_t sino;
	ino_t dino;
	ino_t tino;
	const char *name;
	const char *tname = UT_NAME;
	struct stat st;

	ut_mkdir_at_root(ute, tname, &tino);
	ut_reload_fs_at(ute, tino);
	for (size_t i = 0; i < nfiles; ++i) {
		name = ut_make_name(ute, "d", i);
		ut_mkdir2(ute, tino, name, &dino);
		name = ut_make_name(ute, "f", i);
		ut_create_only(ute, dino, name, &fino);
		name = ut_make_name(ute, "s", i);
		ut_symlink(ute, dino, name, tname, &sino);
		ut_reload_fs_at(ute, dino);
		ut_getattr_reg(ute, fino, &st);
		ut_lookup_lnk(ute, dino, name, sino);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		name = ut_make_name(ute, "d", i);
		ut_lookup_ino(ute, tino, name, &dino);
		ut_getattr_dir(ute, dino, &st);
		name = ut_make_name(ute, "f", i);
		ut_lookup_ino(ute, dino, name, &fino);
		ut_getattr_reg(ute, fino, &st);
		ut_reload_fs_at(ute, dino);
		ut_remove_link(ute, dino, name);
		name = ut_make_name(ute, "s", i);
		ut_lookup_ino(ute, dino, name, &sino);
		ut_getattr_lnk(ute, sino, &st);
		ut_remove_link(ute, dino, name);
		name = ut_make_name(ute, "d", i);
		ut_rmdir(ute, tino, name);
	}
	ut_reload_fs_at(ute, tino);
	ut_rmdir_at_root(ute, tname);
}

static void ut_reload_mixed(struct ut_env *ute)
{
	ut_reload_mixed_(ute, 1);
	ut_reload_mixed_(ute, 10);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t make_offset(size_t idx, size_t step)
{
	return (loff_t)((idx * step) + idx);
}

static void ut_reload_io_(struct ut_env *ute, size_t nfiles, size_t step)
{
	ino_t fino;
	ino_t dino;
	loff_t off;
	size_t len;
	const char *fname;
	const char *dname = UT_NAME;
	struct stat st;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_create_file(ute, dino, fname, &fino);
		len = strlen(fname);
		off = make_offset(i, step);
		ut_write_read(ute, fino, fname, len, off);
		ut_release_file(ute, fino);
	}
	ut_reload_fs_at(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_lookup_ino(ute, dino, fname, &fino);
		ut_open_rdonly(ute, fino);
		len = strlen(fname);
		off = make_offset(i, step);
		ut_read_verify(ute, fino, fname, len, off);
		/* XXX how do you truncate read-only file ? */
		ut_trunacate_file(ute, fino, off);
		ut_release_file(ute, fino);
	}
	ut_reload_fs_at(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_lookup_ino(ute, dino, fname, &fino);
		off = make_offset(i, step);
		ut_getattr_reg(ute, fino, &st);
		ut_expect_eq(st.st_size, off);
		ut_unlink(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_reload_io(struct ut_env *ute)
{
	ut_reload_io_(ute, 1, SILOFS_LBK_SIZE);
	ut_reload_io_(ute, 10, SILOFS_GIGA);
	ut_reload_io_(ute, 100, SILOFS_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_reload_unlinked_(struct ut_env *ute, size_t nfiles, size_t step)
{
	ino_t fino;
	ino_t dino;
	loff_t off;
	size_t len;
	const char *fname;
	const char *dname = UT_NAME;
	ino_t *fino_arr = ut_zalloc(ute, nfiles * sizeof(ino_t));

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_create_file(ute, dino, fname, &fino);
		fino_arr[i] = fino;
		len = strlen(fname);
		off = make_offset(i, step);
		ut_write_read(ute, fino, fname, len, off);
		ut_unlink_file(ute, dino, fname);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		fino = fino_arr[i];
		len = strlen(fname);
		off = make_offset(i, step);
		ut_read_verify(ute, fino, fname, len, off);
		ut_release_file(ute, fino);
	}
	ut_reload_fs_at(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_reload_unlinked(struct ut_env *ute)
{
	ut_reload_unlinked_(ute, 10, SILOFS_GIGA - 1);
	ut_reload_unlinked_(ute, 1000, SILOFS_MEGA - 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_reload_xattr_(struct ut_env *ute, loff_t off, size_t value_size)
{
	const char *name = UT_NAME;
	struct ut_keyval kv = {
		.name = name,
		.value = ut_randbuf(ute, value_size),
		.size = value_size,
	};
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_setxattr_create(ute, dino, &kv);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, kv.value, kv.size, off);
	ut_setxattr_create(ute, ino, &kv);
	ut_release_file(ute, ino);
	ut_reload_fs_at(ute, dino);
	ut_getxattr_value(ute, dino, &kv);
	ut_open_rdonly(ute, ino);
	ut_getxattr_value(ute, ino, &kv);
	ut_read_verify(ute, ino, kv.value, kv.size, off);
	ut_release_file(ute, ino);
	ut_unlink(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_reload_xattr(struct ut_env *ute)
{
	ut_reload_xattr_(ute, 0, UT_1K / 4);
	ut_reload_xattr_(ute, UT_1G, SILOFS_XATTR_VALUE_MAX / 2);
	ut_reload_xattr_(ute, UT_1T, SILOFS_XATTR_VALUE_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_reload_simple),   UT_DEFTEST(ut_reload_nfiles),
	UT_DEFTEST(ut_reload_mixed),    UT_DEFTEST(ut_reload_io),
	UT_DEFTEST(ut_reload_unlinked), UT_DEFTEST(ut_reload_xattr),
};

const struct ut_testdefs ut_tdefs_reload = UT_MKTESTS(ut_local_tests);
