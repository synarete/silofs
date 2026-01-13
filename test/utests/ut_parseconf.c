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

static const char ut_mountd_conf[] = //
	"# Test mountd.conf             \n\n"
	"/mnt/foo/bar uid=1000          \n"
	"/mnt/foo/baz uid=1001          \n"
	"# Comment                      \n"
	"/mnt/qux                       \n";

static struct silofs_mntrules *ut_new_mrules(struct ut_env *ute)
{
	struct silofs_mntrules *mrules = nullptr;

	mrules         = ut_zalloc(ute, sizeof(*mrules));
	mrules->nrules = 0;
	return mrules;
}

static void ut_parseconf_mntrules(struct ut_env *ute)
{
	struct silofs_mntrules *mrules = ut_new_mrules(ute);
	int err;

	err = silofs_parse_mntrules(mrules, nullptr, ut_mountd_conf);
	ut_expect_ok(err);
	ut_expect_eq(mrules->nrules, 3);
	ut_expect_eq(mrules->rules[0].uid, 1000);
	ut_expect_eq(mrules->rules[1].uid, 1001);
	silofs_release_mntrules(mrules, nullptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char ut_mountinfo_conf[] = //
	"76 1 253:0 / / rw,relatime shared:1                            "
	"- xfs /dev/mapper/f1 rw,seclabel,attr2                       \n"
	"40 76 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:5     "
	"- sysfs sysfs rw                                             \n"
	"47 76 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:13   "
	"- proc proc rw                                               \n"
	"48 76 0:27 / /run rw,nosuid,nodev shared:14                    "
	"- tmpfs tmpfs rw,seclabel                                    \n"
	"51 76 0:47 / /tmp rw,nosuid,nodev shared:111                   "
	"- tmpfs tmpfs rw,inode64                                     \n"
	"847 76 0:78 / /mnt/test rw,relatime shared:853                 "
	"- fuse.silofs silofs rw,user_id=1000,group_id=1000           \n";

static struct silofs_mntinfos *ut_new_mntinfos(struct ut_env *ute)
{
	struct silofs_mntinfos *minfos = nullptr;

	minfos         = ut_zalloc(ute, sizeof(*minfos));
	minfos->ninfos = 0;
	return minfos;
}

static void ut_parseconf_mntinfos(struct ut_env *ute)
{
	struct silofs_mntinfos *minfos = ut_new_mntinfos(ute);
	int err;

	err = silofs_parse_mntinfos(minfos, nullptr, ut_mountinfo_conf);
	ut_expect_ok(err);
	ut_expect_eq(minfos->ninfos, 1);
	ut_expect_eqs(minfos->infos[0].mntdir, "/mnt/test");
	silofs_release_mntinfos(minfos, nullptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_parseconf_mntrules),
	UT_DEFTEST(ut_parseconf_mntinfos),
};

const struct ut_testdefs ut_tdefs_parseconf = UT_MKTESTS(ut_local_tests);
