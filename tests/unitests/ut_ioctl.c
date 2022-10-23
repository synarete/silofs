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

static void ut_ioctl_query_version(struct ut_env *ute)
{
	struct silofs_ioc_query query = { .reserved = 0 };
	const char *name = UT_NAME;
	ino_t dino;
	ino_t ino;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_ok(ute, dino, SILOFS_QUERY_VERSION, &query);
	ut_expect_eq(query.u.version.major, silofs_version.major);
	ut_create_file(ute, dino, name, &ino);
	ut_query_ok(ute, ino, SILOFS_QUERY_VERSION, &query);
	ut_expect_eq(query.u.version.minor, silofs_version.minor);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_ioctl_query_statfsx(struct ut_env *ute)
{
	struct silofs_spacestats spst = { .btime = -1, .ctime = -1 };
	const char *name = UT_NAME;
	ino_t dino;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_spst_ok(ute, dino, &spst);
	ut_expect_gt(spst.btime, 0);
	ut_expect_gt(spst.ctime, 0);
	ut_expect_ge(spst.capacity, SILOFS_CAPACITY_SIZE_MIN);
	ut_expect_ge(spst.vspacesize, SILOFS_CAPACITY_SIZE_MIN);
	ut_expect_ge(spst.blobs.nsuper, 1);
	ut_expect_ge(spst.blobs.ndatabk, 1);
	ut_expect_ge(spst.blobs.nspnode, 3);
	ut_expect_ge(spst.blobs.nspleaf, 1);
	ut_expect_ge(spst.blobs.nitnode, 1);
	ut_expect_ge(spst.blobs.ninode, 1);
	ut_expect_ge(spst.blobs.ndtnode, 1);
	ut_expect_ge(spst.objs.nspnode, 3);
	ut_expect_ge(spst.objs.nspleaf, 4);
	ut_expect_ge(spst.bks.ndata1k, spst.bks.ndata1k);
	ut_expect_ge(spst.bks.ndata4k, spst.bks.ndata4k);
	ut_expect_ge(spst.bks.ndatabk, spst.bks.ndatabk);
	ut_expect_ge(spst.bks.nsuper, spst.bks.nsuper);
	ut_expect_ge(spst.bks.nspnode, spst.bks.nspnode);
	ut_expect_ge(spst.bks.nspleaf, spst.bks.nspleaf);
	ut_expect_ge(spst.bks.nitnode, spst.bks.nitnode);
	ut_expect_ge(spst.bks.ninode, spst.bks.ninode);
	ut_expect_ge(spst.bks.nxanode, spst.bks.nxanode);
	ut_expect_ge(spst.bks.ndtnode, spst.bks.ndtnode);
	ut_expect_ge(spst.bks.nftnode, spst.bks.nftnode);
	ut_expect_ge(spst.bks.nsymval, spst.bks.nsymval);
	ut_expect_ge(spst.objs.ndata1k, spst.objs.ndata1k);
	ut_expect_ge(spst.objs.ndata4k, spst.objs.ndata4k);
	ut_expect_ge(spst.objs.ndatabk, spst.objs.ndatabk);
	ut_expect_ge(spst.objs.nsuper, spst.objs.nsuper);
	ut_expect_ge(spst.objs.nspnode, spst.objs.nspnode);
	ut_expect_ge(spst.objs.nspleaf, spst.objs.nspleaf);
	ut_expect_ge(spst.objs.nitnode, spst.objs.nitnode);
	ut_expect_ge(spst.objs.ninode, spst.objs.ninode);
	ut_expect_ge(spst.objs.nxanode, spst.objs.nxanode);
	ut_expect_ge(spst.objs.ndtnode, spst.objs.ndtnode);
	ut_expect_ge(spst.objs.nftnode, spst.objs.nftnode);
	ut_expect_ge(spst.objs.nsymval, spst.objs.nsymval);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_query_prstats(struct ut_env *ute, ino_t ino,
                             struct silofs_query_prstats *out_prst)
{
	struct silofs_ioc_query query = { .qtype = 0 };

	ut_query_ok(ute, ino, SILOFS_QUERY_PRSTATS, &query);
	memcpy(out_prst, &query.u.prstats, sizeof(*out_prst));
}

static void ut_ioctl_query_prstats(struct ut_env *ute)
{
	struct silofs_query_prstats prst = { .uptime = -1 };
	const char *name = UT_NAME;
	size_t iopen;
	ino_t dino;
	ino_t ino;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_prstats(ute, dino, &prst);
	ut_expect_ge(prst.uptime, 0);
	ut_expect_lt(prst.iopen_cur, prst.iopen_max);
	ut_expect_eq(prst.iopen_cur, 0);
	ut_expect_lt(prst.memsz_cur, prst.memsz_max);
	iopen = prst.iopen_cur;
	ut_create_file(ute, dino, name, &ino);
	ut_query_prstats(ute, dino, &prst);
	ut_expect_eq(prst.iopen_cur, iopen + 1);
	ut_remove_file(ute, dino, name, ino);
	ut_query_prstats(ute, dino, &prst);
	ut_expect_eq(prst.iopen_cur, iopen);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_ioctl_query_version),
	UT_DEFTEST(ut_ioctl_query_statfsx),
	UT_DEFTEST(ut_ioctl_query_prstats),
};

const struct ut_testdefs ut_tdefs_ioctl = UT_MKTESTS(ut_local_tests);
