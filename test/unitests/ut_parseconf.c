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

static const char ut_mountd_conf[] = //
	"# Test mountd.conf             \n\n"
	"/mnt/foo/bar uid=1000          \n"
	"/mnt/foo/baz uid=1001          \n"
	"# Comment                      \n"
	"/mnt/qux                       \n";

static struct silofs_mntrules *ut_new_mrules(struct ut_env *ute)
{
	struct silofs_mntrules *mrules = NULL;

	mrules = ut_zalloc(ute, sizeof(*mrules));
	mrules->nrules = 0;
	return mrules;
}

static void ut_parseconf_mntrules(struct ut_env *ute)
{
	struct silofs_mntrules *mrules = ut_new_mrules(ute);
	struct silofs_alloc *alloc = silofs_default_alloc;
	int err;

	err = silofs_parse_mntrules(mrules, alloc, ut_mountd_conf);
	ut_expect_ok(err);
	ut_expect_eq(mrules->nrules, 3);
	ut_expect_eq(mrules->rules[0].uid, 1000);
	ut_expect_eq(mrules->rules[1].uid, 1001);
	silofs_release_mntrules(mrules, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char ut_fsids_conf[] = //
	"# Test fsids.conf              \n\n"
	"[users]                        \n"
	"root = 1001                    \n"
	"bin = 20002                    \n"
	"# Comment                      \n"
	"[groups]                       \n"
	"root = 300033                  \n"
	"disk = 400444                  \n"
	"users = 5500555                \n";

static struct silofs_ugids *ut_new_ugids(struct ut_env *ute)
{
	struct silofs_ugids *ugids = NULL;

	ugids = ut_zalloc(ute, sizeof(*ugids));
	ugids->users.nuids = 0;
	ugids->groups.ngids = 0;
	return ugids;
}

static void ut_parseconf_fsids(struct ut_env *ute)
{
	struct silofs_ugids *ugids = ut_new_ugids(ute);
	struct silofs_alloc *alloc = silofs_default_alloc;
	const size_t bsz = UT_1M;
	char *buf = ut_zalloc(ute, bsz);
	int err;

	err = silofs_parse_fsids(ugids, alloc, ut_fsids_conf);
	ut_expect_ok(err);
	ut_expect_eq(ugids->users.nuids, 2);
	ut_expect_eq(ugids->groups.ngids, 3);
	err = silofs_unparse_fsids(ugids, alloc, buf, bsz);
	ut_expect_ok(err);
	ut_expect_gt(strlen(buf), 50);
	silofs_release_fsids(ugids, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_parseconf_mntrules),
	UT_DEFTEST(ut_parseconf_fsids),
};

const struct ut_testdefs ut_tdefs_parseconf = UT_MKTESTS(ut_local_tests);
