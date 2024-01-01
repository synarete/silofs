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
#include "unitests.h"


static const char *ut_make_symname(struct ut_env *ute, size_t idx)
{
	return ut_make_name(ute, "symlink", idx);
}

static char *ut_make_symval_with(struct ut_env *ute, char c, size_t len)
{
	const size_t vsz = SILOFS_PATH_MAX;
	const size_t name_max = UT_NAME_MAX;
	char *val = NULL;

	ut_expect_le(len, vsz);
	val = ut_zerobuf(ute, vsz + 1);
	for (size_t i = 0; i < len; ++i) {
		val[i] = (i % name_max) ? c : '/';
	}
	return val;
}

static char *ut_make_symval(struct ut_env *ute, size_t len)
{
	const char *abc = "abcdefghijklmnopqrstuvwxyz";

	return ut_make_symval_with(ute, abc[len % strlen(abc)], len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_symlink_simple(struct ut_env *ute)
{
	ino_t dino = 0;
	ino_t tino = 0;
	ino_t sino = 0;
	const char *dname = UT_NAME;
	const char *tname = "target";
	const char *sname = "symlink";

	ut_mkdir_at_root(ute, dname, &dino);
	ut_mkdir_oki(ute, dino, tname, &tino);
	ut_symlink_ok(ute, dino, sname, tname, &sino);
	ut_lookup_exists(ute, dino, sname, sino, S_IFLNK);
	ut_readlink_expect(ute, sino, tname);
	ut_rmdir_ok(ute, dino, tname);
	ut_lookup_exists(ute, dino, sname, sino, S_IFLNK);
	ut_readlink_expect(ute, sino, tname);
	ut_rmdir_err(ute, UT_ROOT_INO, dname, -ENOTEMPTY);
	ut_unlink_ok(ute, dino, sname);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_symlink_length(struct ut_env *ute)
{
	ino_t dino = 0;
	ino_t sino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *dname = UT_NAME;
	const char *tname = NULL;
	const char *sname = NULL;
	const size_t nlinks = SILOFS_PATH_MAX - 1;

	ut_mkdir_oki(ute, root_ino, dname, &dino);
	for (size_t i = 1; i <= nlinks; ++i) {
		sname = ut_make_symname(ute, i);
		tname = ut_make_symval_with(ute, 'A', i);
		ut_symlink_ok(ute, dino, sname, tname, &sino);
	}
	ut_rmdir_err(ute, root_ino, dname, -ENOTEMPTY);
	for (size_t j = 1; j <= nlinks; ++j) {
		sname = ut_make_symname(ute, j);
		ut_unlink_ok(ute, dino, sname);
	}
	ut_rmdir_ok(ute, root_ino, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_symlink_nested(struct ut_env *ute)
{
	ino_t sino = 0;
	ino_t dino[128];
	const char *sname[128];
	const char *dname = UT_NAME;
	struct stat st = { .st_size = -1 };

	dino[0] = UT_ROOT_INO;
	for (size_t i = 1; i < UT_ARRAY_SIZE(dino); ++i) {
		ut_mkdir_oki(ute, dino[i - 1], dname, &dino[i]);
		sname[i] = ut_make_symname(ute, 8 * i);
		ut_symlink_ok(ute, dino[i], sname[i],
		              ut_make_symval_with(ute, 'z', i), &sino);
		ut_rmdir_err(ute, dino[i - 1], dname, -ENOTEMPTY);
	}
	for (size_t j = UT_ARRAY_SIZE(dino); j > 1; --j) {
		ut_unlink_ok(ute, dino[j - 1], sname[j - 1]);
		ut_rmdir_ok(ute, dino[j - 2], dname);
	}
	ut_getattr_ok(ute, dino[0], &st);
	ut_expect_eq(st.st_size, SILOFS_DIR_EMPTY_SIZE);
	ut_expect_eq(st.st_nlink, 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_symlink_to_reg_(struct ut_env *ute, size_t cnt)
{
	ino_t dino = 0;
	ino_t ino = 0;
	ino_t sino = 0;
	const char *dname = UT_NAME;
	const char *fname = NULL;
	const char *sname = NULL;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < cnt; ++i) {
		sname = ut_make_symname(ute, i);
		fname = ut_make_name(ute, dname, i);
		ut_create_only(ute, dino, fname, &ino);
		ut_symlink_ok(ute, dino, sname, fname, &sino);
	}
	for (size_t i = 0; i < cnt; ++i) {
		sname = ut_make_symname(ute, i);
		fname = ut_make_name(ute, dname, i);
		ut_lookup_ino(ute, dino, sname, &sino);
		ut_lookup_lnk(ute, dino, sname, sino);
		ut_readlink_expect(ute, sino, fname);
		ut_unlink_ok(ute, dino, sname);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_unlink_ok(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_symlink_to_reg(struct ut_env *ute)
{
	ut_symlink_to_reg_(ute, 64);
	ut_symlink_to_reg_(ute, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_symlink_and_io_(struct ut_env *ute, size_t cnt)
{
	loff_t off = -1;
	ino_t dino = 0;
	ino_t fino = 0;
	ino_t sino = 0;
	char *symval = NULL;
	const char *fname = NULL;
	const char *sname = NULL;
	const char *fp = "f";
	const char *sp = "s";
	const char *dname = UT_NAME;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < cnt; ++i) {
		sname = ut_make_name(ute, sp, i);
		fname = ut_make_name(ute, fp, i);
		symval = ut_make_symval(ute, i + 1);
		ut_create_file(ute, dino, fname, &fino);
		ut_symlink_ok(ute, dino, sname, symval, &sino);

		off = (loff_t)(i * UT_1M + i);
		ut_write_read_str(ute, fino, symval, off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		sname = ut_make_name(ute, sp, i);
		fname = ut_make_name(ute, fp, i);
		symval = ut_make_symval(ute, i + 1);
		ut_lookup_ino(ute, dino, sname, &sino);
		ut_readlink_expect(ute, sino, symval);

		ut_lookup_ino(ute, dino, fname, &fino);
		off = (loff_t)(i * UT_1M + i);
		ut_read_verify_str(ute, fino, symval, off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		sname = ut_make_name(ute, sp, i);
		fname = ut_make_name(ute, fp, i);

		ut_lookup_ino(ute, dino, fname, &fino);
		ut_release_file(ute, fino);
		ut_unlink_ok(ute, dino, sname);
		ut_unlink_ok(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_symlink_and_io(struct ut_env *ute)
{
	ut_symlink_and_io_(ute, 128);
	ut_symlink_and_io_(ute, SILOFS_SYMLNK_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_symlink_and_io2_(struct ut_env *ute, size_t cnt)
{
	loff_t off = -1;
	ino_t dino = 0;
	ino_t fino = 0;
	ino_t sino = 0;
	char *symval = NULL;
	const char *fname = NULL;
	const char *sname = NULL;
	const char *dname = UT_NAME;
	const char *ff = "ff";
	const char *s1 = "s1";
	const char *s2 = "s2";
	const ino_t root_ino = UT_ROOT_INO;

	ut_mkdir_oki(ute, root_ino, dname, &dino);
	for (size_t i = 0; i < cnt; ++i) {
		sname = ut_make_name(ute, s1, i);
		fname = ut_make_name(ute, ff, i);
		symval = ut_make_symval(ute, cnt);
		ut_create_file(ute, dino, fname, &fino);
		ut_symlink_ok(ute, dino, sname, symval, &sino);

		off = (loff_t)(i * cnt);
		ut_write_read_str(ute, fino, symval, off);
		ut_release_file(ute, fino);
	}
	ut_drop_caches_fully(ute);
	for (size_t j = cnt; j > 0; --j) {
		sname = ut_make_name(ute, s1, j - 1);
		fname = ut_make_name(ute, ff, j - 1);
		symval = ut_make_symval(ute, cnt);
		ut_lookup_ino(ute, dino, sname, &sino);
		ut_readlink_expect(ute, sino, symval);
		ut_lookup_ino(ute, dino, fname, &fino);

		ut_open_rdonly(ute, fino);
		off = (loff_t)((j - 1) * cnt);
		ut_read_verify_str(ute, fino, symval, off);
		ut_release_file(ute, fino);
		ut_unlink_ok(ute, dino, fname);

		sname = ut_make_name(ute, s2, j - 1);
		ut_symlink_ok(ute, dino, sname, symval, &sino);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, ff, i);
		ut_create_only(ute, dino, fname, &fino);
		sname = ut_make_name(ute, s1, i);
		ut_unlink_ok(ute, dino, sname);
		ut_lookup_file(ute, dino, fname, fino);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, ff, i);
		sname = ut_make_name(ute, s2, i);
		ut_unlink_ok(ute, dino, sname);
		ut_unlink_ok(ute, dino, fname);
	}
	ut_rmdir_ok(ute, root_ino, dname);
}

static void ut_symlink_and_io2(struct ut_env *ute)
{
	ut_symlink_and_io2_(ute, 11);
	ut_symlink_and_io2_(ute, 111);
	ut_symlink_and_io2_(ute, 1111);
	ut_symlink_and_io2_(ute, SILOFS_SYMLNK_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static blkcnt_t symval_length_to_blocks(size_t len)
{
	size_t nparts = 0;
	blkcnt_t blkcnt = 0;
	const size_t val_size = SILOFS_SYMLNK_VAL_SIZE;
	const size_t head_len = SILOFS_SYMLNK_HEAD_MAX;
	const size_t factor = val_size / 512;

	if (len > head_len) {
		nparts = silofs_div_round_up(len - head_len, val_size);
		blkcnt = (blkcnt_t)(factor * nparts);
	}
	return blkcnt;
}

static void ut_symlink_stat_(struct ut_env *ute, size_t valsize)
{
	ino_t dino = 0;
	ino_t sino = 0;
	struct stat st = { .st_size = -1 };
	const char *name = UT_NAME;
	const char *symval = ut_make_symval_with(ute, 's', valsize);
	const blkcnt_t blocks = symval_length_to_blocks(valsize);

	ut_mkdir_at_root(ute, name, &dino);
	ut_symlink_ok(ute, dino, name, symval, &sino);
	ut_lookup_exists(ute, dino, name, sino, S_IFLNK);
	ut_readlink_expect(ute, sino, symval);
	ut_getattr_lnk(ute, sino, &st);
	ut_expect_eq(st.st_size, valsize);
	ut_expect_eq(st.st_blocks, blocks);
	ut_unlink_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_symlink_stat(struct ut_env *ute)
{
	ut_symlink_stat_(ute, 1);
	ut_symlink_stat_(ute, SILOFS_SYMLNK_HEAD_MAX);
	ut_symlink_stat_(ute, SILOFS_SYMLNK_HEAD_MAX + 1);
	ut_symlink_stat_(ute, SILOFS_SYMLNK_HEAD_MAX + 1111);
	ut_symlink_stat_(ute, SILOFS_SYMLNK_MAX / 2);
	ut_symlink_stat_(ute, SILOFS_SYMLNK_MAX - 1111);
	ut_symlink_stat_(ute, SILOFS_SYMLNK_MAX - 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_symlink_simple),
	UT_DEFTEST(ut_symlink_length),
	UT_DEFTEST(ut_symlink_nested),
	UT_DEFTEST(ut_symlink_to_reg),
	UT_DEFTEST(ut_symlink_and_io),
	UT_DEFTEST(ut_symlink_and_io2),
	UT_DEFTEST(ut_symlink_stat),
};

const struct ut_testdefs ut_tdefs_symlink = UT_MKTESTS(ut_local_tests);
