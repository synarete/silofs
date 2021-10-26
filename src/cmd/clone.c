/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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

static const char *clone_usage[] = {
	"clone --name=NAME [options] <mount-point> ",
	"",
	"options:",
	"  -n, --name=NAME              Snapshot's name",
	NULL
};

static void clone_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_getopt_subcmd("n:h", opts);
		if (opt_chr == 'n') {
			silofs_globals.cmd.clone.name = optarg;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(clone_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_globals.cmd.clone.mntpoint =
	        silofs_consume_cmdarg("mount-point", false);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void clone_finalize(void)
{
	silofs_pfree_string(&silofs_globals.cmd.clone.mntpoint_real);
}

static void clone_setup_check_params(void)
{
	silofs_globals.cmd.clone.mntpoint_real =
	        silofs_realpath_safe(silofs_globals.cmd.clone.mntpoint);
	silofs_die_if_not_mntdir(silofs_globals.cmd.clone.mntpoint_real, 0);
	silofs_die_if_illegal_name("name", silofs_globals.cmd.clone.name);
}

static void clone_execute(void)
{
	int err;
	int dfd = -1;
	const char *path;
	const char *name;
	struct silofs_ioc_clone clone = {
		.name[0] = '\0'
	};

	path = silofs_globals.cmd.clone.mntpoint_real;
	name = silofs_globals.cmd.clone.name;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "failed to open-dir: %s", path);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		silofs_die(err, "syncfs error: %s", path);
	}
	strncpy(clone.name, name, sizeof(clone.name) - 1);
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_CLONE, &clone);
	if (err == -ENOTTY) {
		silofs_die(err, "ioctl error: %s", path);
	} else if (err) {
		silofs_die(err, "failed to clone: %s", name);
	}
	silofs_sys_close(dfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_clone(void)
{
	/* Do all cleanups upon exits */
	atexit(clone_finalize);

	/* Parse command's arguments */
	clone_getopt();

	/* Verify user's arguments */
	clone_setup_check_params();

	/* Do actual clone */
	clone_execute();

	/* Post execution cleanups */
	clone_finalize();
}

