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
#include <silofs/cmd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>


static struct silofs_subcmd_snap *snap_args;

static const char *snap_usage[] = {
	"snap --name=NAME [options] <dirpath> ",
	"",
	"options:",
	"  -n, --name=NAME              Snapshot's name",
	NULL
};

static void snap_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("n:h", opts);
		if (opt_chr == 'n') {
			snap_args->name = optarg;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(snap_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg_or_cwd("dirpath", &snap_args->dirpath);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void snap_finalize(void)
{
	silofs_cmd_pfrees(&snap_args->dirpath_real);
	silofs_cmd_pfrees(&snap_args->dirpath);
}

static void snap_start(void)
{
	snap_args = &silofs_globals.cmd.snap;
	atexit(snap_finalize);
}

static void snap_check_dirpath(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_VERSION };
	const char *dirpath = snap_args->dirpath_real;
	int dfd = -1;
	int err;

	silofs_die_if_not_dir(dirpath, false);
	err = silofs_sys_open(dirpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "failed to open: %s", dirpath);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_QUERY, &query);
	silofs_sys_close(dfd);
	if (err) {
		silofs_die(err, "ioctl error: %s", dirpath);
	}
}

static void snap_prepare(void)
{
	snap_args->dirpath_real = silofs_cmd_realpath(snap_args->dirpath);
	silofs_die_if_illegal_fsname("name", snap_args->name);
	snap_check_dirpath();
}

static void snap_execute(void)
{
	struct silofs_ioc_snapfs snap = {
		.flags = 0,
		.name[0] = '\0'
	};
	const char *dirpath = snap_args->dirpath_real;
	const char *name = snap_args->name;
	int dfd = -1;
	int err;

	err = silofs_sys_open(dirpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "failed to open dir: %s", dirpath);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		silofs_die(err, "syncfs error: %s", dirpath);
	}
	strncpy(snap.name, name, sizeof(snap.name) - 1);
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_SNAPFS, &snap);
	if (err == -ENOTTY) {
		silofs_die(err, "ioctl error: %s", dirpath);
	} else if (err) {
		silofs_die(err, "failed to snap: %s", name);
	}
	silofs_sys_close(dfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_snap(void)
{
	/* Do all cleanups upon exits */
	snap_start();

	/* Parse command's arguments */
	snap_getopt();

	/* Verify user's arguments */
	snap_prepare();

	/* Do actual snap */
	snap_execute();

	/* Post execution cleanups */
	snap_finalize();
}

