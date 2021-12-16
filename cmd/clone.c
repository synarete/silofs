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


static struct silofs_subcmd_clone *clone_args;

static const char *clone_usage[] = {
	"clone --name=NAME [options] <dirpath> ",
	"",
	"options:",
	"  -n, --name=NAME              Snapshot's name",
	NULL
};

static void clone_getopt(void)
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
			clone_args->name = optarg;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(clone_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg_or_cwd("dirpath", &clone_args->dirpath);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void clone_finalize(void)
{
	silofs_cmd_pfrees(&clone_args->dirpath_real);
	silofs_cmd_pfrees(&clone_args->dirpath);
}

static void clone_start(void)
{
	clone_args = &silofs_globals.cmd.clone;
	atexit(clone_finalize);
}

static void clone_check_dirpath(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_VERSION };
	const char *dirpath = clone_args->dirpath_real;
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

static void clone_prepare(void)
{
	clone_args->dirpath_real = silofs_cmd_realpath(clone_args->dirpath);
	silofs_die_if_illegal_fsname("name", clone_args->name);
	clone_check_dirpath();
}

static void clone_execute(void)
{
	struct silofs_ioc_clone clone = {
		.flags = 0,
		.name[0] = '\0'
	};
	const char *dirpath = clone_args->dirpath_real;
	const char *name = clone_args->name;
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
	strncpy(clone.name, name, sizeof(clone.name) - 1);
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_CLONE, &clone);
	if (err == -ENOTTY) {
		silofs_die(err, "ioctl error: %s", dirpath);
	} else if (err) {
		silofs_die(err, "failed to clone: %s", name);
	}
	silofs_sys_close(dfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_clone(void)
{
	/* Do all cleanups upon exits */
	clone_start();

	/* Parse command's arguments */
	clone_getopt();

	/* Verify user's arguments */
	clone_prepare();

	/* Do actual clone */
	clone_execute();

	/* Post execution cleanups */
	clone_finalize();
}

