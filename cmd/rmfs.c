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


static struct silofs_subcmd_rmfs *rmfs_args;

static const char *rmfs_usage[] = {
	"rmfs --name=NAME <dirpath>",
	"",
	"options:",
	"  -n, --name=NAME              Snapshot's name",
	NULL
};

static void rmfs_getopt(void)
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
			rmfs_args->name = optarg;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(rmfs_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("dirpath", &rmfs_args->dirpath);
	silofs_cmd_endargs();
}


static void rmfs_finalize(void)
{
	silofs_cmd_pfrees(&rmfs_args->dirpath_real);
	silofs_cmd_pfrees(&rmfs_args->dirpath);
}

static void rmfs_start(void)
{
	rmfs_args = &silofs_globals.cmd.rmfs;
	atexit(rmfs_finalize);
}

static void rmfs_check_dirpath(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_VERSION };
	const char *dirpath = rmfs_args->dirpath;
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

static void rmfs_prepare(void)
{
	silofs_die_if_illegal_fsname("name", rmfs_args->name);
	rmfs_check_dirpath();
	rmfs_args->dirpath_real = silofs_cmd_realpath(rmfs_args->dirpath);
}

static void rmfs_do_ioctl_unrefs(struct silofs_ioc_unrefs *unrefs)
{
	const char *path = rmfs_args->dirpath_real;
	int fd = -1;
	int err;

	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_FS_IOC_UNREFS, unrefs);
	silofs_sys_close(fd);
	if (err) {
		silofs_die(err, "unref failed: %s", unrefs->name);
	}
}

static void rmfs_execute(void)
{
	struct silofs_ioc_unrefs unrefs = { .flags = 0 };
	const size_t len =
	        silofs_min(strlen(rmfs_args->name), sizeof(unrefs.name) - 1);

	memcpy(unrefs.name, rmfs_args->name, len);
	rmfs_do_ioctl_unrefs(&unrefs);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_execute_rmfs(void)
{
	/* Do all cleanups upon exits */
	rmfs_start();

	/* Parse command's arguments */
	rmfs_getopt();

	/* Verify user's arguments */
	rmfs_prepare();

	/* Do actual rmfs */
	rmfs_execute();

	/* Post execution cleanups */
	rmfs_finalize();
}

