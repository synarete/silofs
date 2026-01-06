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
#include "utests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_ioctl_query_version(struct ut_env *ute)
{
	struct silofs_ioc_query query = { .reserved = 0 };
	const char             *name  = UT_NAME;
	ino_t                   dino  = 0;
	ino_t                   ino   = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query(ute, dino, SILOFS_QUERY_VERSION, &query);
	ut_expect_eq(query.u.version.major, silofs_version.major);
	ut_create_file(ute, dino, name, &ino);
	ut_query(ute, ino, SILOFS_QUERY_VERSION, &query);
	ut_expect_eq(query.u.version.minor, silofs_version.minor);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_ioctl_query_statfsx(struct ut_env *ute)
{
	struct silofs_space_stats1k spst;
	const char                 *name = UT_NAME;
	ino_t                       dino = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_spst(ute, dino, &spst);
	ut_expect_gt(spst.sp_btime, 0);
	ut_expect_gt(spst.sp_ctime, 0);
	ut_expect_ge(spst.sp_capacity, SILOFS_CAPACITY_SIZE_MIN);
	ut_expect_ge(spst.sp_vspacesize, SILOFS_CAPACITY_SIZE_MIN);
	ut_expect_ge(spst.sp_lsegs.sg_nsuper, 1);
	ut_expect_ge(spst.sp_lsegs.sg_ndatabk, 1);
	ut_expect_ge(spst.sp_lsegs.sg_nspnode, 3);
	ut_expect_ge(spst.sp_lsegs.sg_nspleaf, 1);
	ut_expect_ge(spst.sp_lsegs.sg_ninode, 1);
	ut_expect_ge(spst.sp_lsegs.sg_ndtnode, 1);
	ut_expect_ge(spst.sp_objs.sg_nspnode, 3);
	ut_expect_ge(spst.sp_objs.sg_nspleaf, 4);
	ut_expect_ge(spst.sp_bks.sg_ndata1k, spst.sp_bks.sg_ndata1k);
	ut_expect_ge(spst.sp_bks.sg_ndata4k, spst.sp_bks.sg_ndata4k);
	ut_expect_ge(spst.sp_bks.sg_ndatabk, spst.sp_bks.sg_ndatabk);
	ut_expect_ge(spst.sp_bks.sg_nsuper, spst.sp_bks.sg_nsuper);
	ut_expect_ge(spst.sp_bks.sg_nspnode, spst.sp_bks.sg_nspnode);
	ut_expect_ge(spst.sp_bks.sg_nspleaf, spst.sp_bks.sg_nspleaf);
	ut_expect_ge(spst.sp_bks.sg_ninode, spst.sp_bks.sg_ninode);
	ut_expect_ge(spst.sp_bks.sg_nxanode, spst.sp_bks.sg_nxanode);
	ut_expect_ge(spst.sp_bks.sg_ndtnode, spst.sp_bks.sg_ndtnode);
	ut_expect_ge(spst.sp_bks.sg_nftnode, spst.sp_bks.sg_nftnode);
	ut_expect_ge(spst.sp_bks.sg_nsymval, spst.sp_bks.sg_nsymval);
	ut_expect_ge(spst.sp_objs.sg_ndata1k, spst.sp_objs.sg_ndata1k);
	ut_expect_ge(spst.sp_objs.sg_ndata4k, spst.sp_objs.sg_ndata4k);
	ut_expect_ge(spst.sp_objs.sg_ndatabk, spst.sp_objs.sg_ndatabk);
	ut_expect_ge(spst.sp_objs.sg_nsuper, spst.sp_objs.sg_nsuper);
	ut_expect_ge(spst.sp_objs.sg_nspnode, spst.sp_objs.sg_nspnode);
	ut_expect_ge(spst.sp_objs.sg_nspleaf, spst.sp_objs.sg_nspleaf);
	ut_expect_ge(spst.sp_objs.sg_ninode, spst.sp_objs.sg_ninode);
	ut_expect_ge(spst.sp_objs.sg_nxanode, spst.sp_objs.sg_nxanode);
	ut_expect_ge(spst.sp_objs.sg_ndtnode, spst.sp_objs.sg_ndtnode);
	ut_expect_ge(spst.sp_objs.sg_nftnode, spst.sp_objs.sg_nftnode);
	ut_expect_ge(spst.sp_objs.sg_nsymval, spst.sp_objs.sg_nsymval);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ioc_query *ut_new_ioc_query(struct ut_env *ute)
{
	struct silofs_ioc_query *ioc_qry;

	ioc_qry = ut_zalloc(ute, sizeof(*ioc_qry));
	return ioc_qry;
}

static void
ut_query_proc(struct ut_env *ute, ino_t ino, struct silofs_ioc_query *ioc_qry)
{
	ut_query(ute, ino, SILOFS_QUERY_PROC, ioc_qry);
}

static void ut_ioctl_query_proc(struct ut_env *ute)
{
	struct silofs_ioc_query  *ioc_qry = ut_new_ioc_query(ute);
	struct silofs_query_proc *qpr     = &ioc_qry->u.proc;
	const char               *name    = UT_NAME;
	size_t                    iopen   = 0;
	ino_t                     dino    = 0;
	ino_t                     ino     = 0;

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

static void
ut_query_boot(struct ut_env *ute, ino_t ino, struct silofs_ioc_query *ioc_qry)
{
	ut_query(ute, ino, SILOFS_QUERY_BOOT, ioc_qry);
}

static void ut_expect_boot_fsref(const struct silofs_fsref *fsref)
{
	ut_expect_eqs(fsref->gmeta.version, silofs_version.string);
	ut_expect_eq(fsref->gmeta.fmtvers, SILOFS_FMT_VERSION);
	ut_expect_gt(fsref->gmeta.timestamp, 0);
	ut_expect_gt(strlen(fsref->mbaddr.mba), 0);
}

static void ut_ioctl_query_boot(struct ut_env *ute)
{
	const char               *name    = UT_NAME;
	struct silofs_ioc_query  *ioc_qry = ut_new_ioc_query(ute);
	struct silofs_query_boot *qbt     = &ioc_qry->u.boot;
	ino_t                     dino    = 0;

	ut_mkdir_at_root(ute, name, &dino);
	ut_query_boot(ute, dino, ioc_qry);
	ut_expect_boot_fsref(&qbt->fsref);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_ioctl_query_version),
	UT_DEFTEST(ut_ioctl_query_statfsx),
	UT_DEFTEST(ut_ioctl_query_proc),
	UT_DEFTEST(ut_ioctl_query_boot),
};

const struct ut_testdefs ut_tdefs_ioctl = UT_MKTESTS(ut_local_tests);
