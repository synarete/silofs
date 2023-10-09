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
#include "unitests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_ioctl_query_version(struct ut_env *ute)
{
	struct silofs_ioc_query query = { .reserved = 0 };
	const char *name = UT_NAME;
	ino_t dino = 0;
	ino_t ino = 0;

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
	ino_t dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_spst_ok(ute, dino, &spst);
	ut_expect_gt(spst.btime, 0);
	ut_expect_gt(spst.ctime, 0);
	ut_expect_ge(spst.capacity, SILOFS_CAPACITY_SIZE_MIN);
	ut_expect_ge(spst.vspacesize, SILOFS_CAPACITY_SIZE_MIN);
	ut_expect_ge(spst.lexts.nsuper, 1);
	ut_expect_ge(spst.lexts.ndatabk, 1);
	ut_expect_ge(spst.lexts.nspnode, 3);
	ut_expect_ge(spst.lexts.nspleaf, 1);
	ut_expect_ge(spst.lexts.ninode, 1);
	ut_expect_ge(spst.lexts.ndtnode, 1);
	ut_expect_ge(spst.objs.nspnode, 3);
	ut_expect_ge(spst.objs.nspleaf, 4);
	ut_expect_ge(spst.bks.ndata1k, spst.bks.ndata1k);
	ut_expect_ge(spst.bks.ndata4k, spst.bks.ndata4k);
	ut_expect_ge(spst.bks.ndatabk, spst.bks.ndatabk);
	ut_expect_ge(spst.bks.nsuper, spst.bks.nsuper);
	ut_expect_ge(spst.bks.nspnode, spst.bks.nspnode);
	ut_expect_ge(spst.bks.nspleaf, spst.bks.nspleaf);
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
	ut_expect_ge(spst.objs.ninode, spst.objs.ninode);
	ut_expect_ge(spst.objs.nxanode, spst.objs.nxanode);
	ut_expect_ge(spst.objs.ndtnode, spst.objs.ndtnode);
	ut_expect_ge(spst.objs.nftnode, spst.objs.nftnode);
	ut_expect_ge(spst.objs.nsymval, spst.objs.nsymval);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ioc_query *ut_new_ioc_query(struct ut_env *ute)
{
	struct silofs_ioc_query *ioc_qry;

	ioc_qry = ut_zalloc(ute, sizeof(*ioc_qry));
	return ioc_qry;
}

static void ut_query_proc(struct ut_env *ute, ino_t ino,
                          struct silofs_ioc_query *ioc_qry)
{
	ut_query_ok(ute, ino, SILOFS_QUERY_PROC, ioc_qry);
}

static void ut_ioctl_query_proc(struct ut_env *ute)
{
	struct silofs_ioc_query *ioc_qry = ut_new_ioc_query(ute);
	struct silofs_query_proc *qpr = &ioc_qry->u.proc;
	const char *name = UT_NAME;
	size_t iopen = 0;
	ino_t dino = 0;
	ino_t ino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_proc(ute, dino, ioc_qry);
	ut_expect_ge(qpr->uptime, 0);
	ut_expect_lt(qpr->iopen_cur, qpr->iopen_max);
	ut_expect_eq(qpr->iopen_cur, 0);
	ut_expect_lt(qpr->memsz_cur, qpr->memsz_max);
	iopen = qpr->iopen_cur;
	ut_create_file(ute, dino, name, &ino);
	ut_query_proc(ute, dino, ioc_qry);
	ut_expect_eq(qpr->iopen_cur, iopen + 1);
	ut_remove_file(ute, dino, name, ino);
	ut_query_proc(ute, dino, ioc_qry);
	ut_expect_eq(qpr->iopen_cur, iopen);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_ioctl_query_version),
	UT_DEFTEST(ut_ioctl_query_statfsx),
	UT_DEFTEST(ut_ioctl_query_proc),
};

const struct ut_testdefs ut_tdefs_ioctl = UT_MKTESTS(ut_local_tests);
