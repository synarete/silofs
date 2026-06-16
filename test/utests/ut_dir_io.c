/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "utests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_mkdir_io_nfiles_(struct ut_env *ute, size_t nfiles, size_t bsz)
{
	struct stat st     = {};
	const char *dname  = UT_NAME;
	const char *dnamei = nullptr;
	const char *fnamei = nullptr;
	const void *buf    = ut_randbuf(ute, bsz);
	ino_t dino = 0, ino = 0;

	ut_mkdir_at_root(ute, dname, &dino);

	for (size_t i = 0; i < nfiles; ++i) {
		dnamei = ut_make_name(ute, dname, i);
		fnamei = ut_make_name(ute, dname, i + nfiles);

		ut_mkdir(ute, dino, dnamei, &st);
		ut_create_file(ute, dino, fnamei, &ino);
		ut_write_read(ute, ino, buf, bsz, (off_t)i);
		ut_release_file(ute, ino);
	}

	for (size_t i = 0; i < nfiles; ++i) {
		dnamei = ut_make_name(ute, dname, i);
		fnamei = ut_make_name(ute, dname, i + nfiles);

		ut_lookup_ino(ute, dino, dnamei, &ino);
		ut_lookup_ino(ute, dino, fnamei, &ino);
		ut_open_rdonly(ute, ino);
		ut_read_verify(ute, ino, buf, bsz, (off_t)i);
		ut_release_file(ute, ino);
	}

	for (size_t i = 0; i < nfiles; ++i) {
		dnamei = ut_make_name(ute, dname, i);
		fnamei = ut_make_name(ute, dname, i + nfiles);

		ut_unlink_file(ute, dino, fnamei);
		ut_rmdir(ute, dino, dnamei);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_mkdir_io_nfiles(struct ut_env *ute)
{
	ut_mkdir_io_nfiles_(ute, 10, 10);
	ut_mkdir_io_nfiles_(ute, SILOFS_BTREE_NODE_NCHILDS, UT_64K);
	ut_mkdir_io_nfiles_(ute, SILOFS_BTREE_NODE_NCHILDS + 1, UT_64K);
	ut_mkdir_io_nfiles_(ute, 2UL * SILOFS_BTREE_NODE_NCHILDS, UT_1K);
	ut_mkdir_io_nfiles_(ute, SILOFS_SPNODE_NREFS, UT_64K);
	ut_mkdir_io_nfiles_(ute, SILOFS_SPNODE_NREFS + 1, UT_4K);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_mkdir_io_nfiles),
};

const struct ut_testdefs ut_tdefs_dir_io = UT_MKTESTS(ut_local_tests);
