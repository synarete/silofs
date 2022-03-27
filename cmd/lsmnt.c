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


static struct silofs_subcmd_lsmnt *cmd_lsmnt_args;
static char *cmd_lsmnt_mountinfo;

static const char *cmd_lsmnt_usage[] = {
	"lsmnt [options]",
	"",
	"options:",
	"  -l, --long                   Long listing format",
	NULL
};

static void cmd_lsmnt_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "long", no_argument, NULL, 'l' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("lh", opts);
		if (opt_chr == 'l') {
			cmd_lsmnt_args->long_listing = true;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(cmd_lsmnt_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_lsmnt_finalize(void)
{
	silofs_cmd_pfrees(&cmd_lsmnt_mountinfo);
	silofs_cmd_pfrees(&cmd_lsmnt_args->mntpoint_real);
}

static void cmd_lsmnt_start(void)
{
	cmd_lsmnt_args = &silofs_globals.cmd.lsmnt;
	atexit(cmd_lsmnt_finalize);
}

static void cmd_lsmnt_prepare(void)
{
	struct stat st;
	const char *path;

	path = cmd_lsmnt_args->mntpoint;
	if (path != NULL) {
		silofs_cmd_stat_ok(path, &st);
		if (!S_ISDIR(st.st_mode)) {
			silofs_die(-ENOTDIR, "bad mount-point: %s", path);
		}
		if (st.st_ino != SILOFS_INO_ROOT) {
			silofs_die(0, "not a silofs mount-point: %s", path);
		}
		silofs_cmd_realpath(path, &cmd_lsmnt_args->mntpoint_real);
	}
}

static void cmd_lsmnt_print_mntdir(const struct silofs_proc_mntinfo *mi)
{
	printf("%s\n", mi->mntdir);
}

static void cmd_lsmnt_print_mntdir_long(const struct silofs_proc_mntinfo *mi)
{
	char perm[11] = "";
	struct stat st;
	mode_t mode;
	int o_flags;
	int dfd = -1;
	int err;

	memset(perm, '?', sizeof(perm) - 1);
	o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	err = silofs_sys_openat(AT_FDCWD, mi->mntdir, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}
	err = silofs_sys_fstat(dfd, &st);
	if (err) {
		goto out;
	}
	mode = st.st_mode;
	perm[0] = S_ISDIR(mode) ? 'd' : (S_ISLNK(mode) ? 'l' : '-');
	perm[1] = (mode & S_IRUSR) ? 'r' : '-';
	perm[2] = (mode & S_IWUSR) ? 'w' : '-';
	perm[3] = (mode & S_IXUSR) ? 'x' : '-';
	perm[4] = (mode & S_IRGRP) ? 'r' : '-';
	perm[5] = (mode & S_IWGRP) ? 'w' : '-';
	perm[6] = (mode & S_IXGRP) ? 'x' : '-';
	perm[7] = (mode & S_IROTH) ? 'r' : '-';
	perm[8] = (mode & S_IWOTH) ? 'w' : '-';
	perm[9] = (mode & S_IXOTH) ? 'x' : '-';
out:
	silofs_sys_closefd(&dfd);
	printf("%s %s ", perm, mi->mntdir);
}

static void cmd_lsmnt_print_mntargs(const struct silofs_proc_mntinfo *mi)
{
	printf("%s \n", mi->mntargs);
}

static void cmd_lsmnt_execute(void)
{
	struct silofs_proc_mntinfo *mi_list = NULL;
	struct silofs_proc_mntinfo *mi_iter = NULL;

	mi_list = silofs_cmd_parse_mountinfo();
	mi_iter = mi_list;
	while (mi_iter != NULL) {
		if (cmd_lsmnt_args->long_listing) {
			cmd_lsmnt_print_mntdir_long(mi_iter);
			cmd_lsmnt_print_mntargs(mi_iter);
		} else {
			cmd_lsmnt_print_mntdir(mi_iter);
		}
		mi_iter = mi_iter->next;
	}
	silofs_cmd_free_mountinfo(mi_list);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_lsmnt(void)
{
	/* Do all cleanups upon exits */
	cmd_lsmnt_start();

	/* Parse command's arguments */
	cmd_lsmnt_getopt();

	/* Verify user's arguments */
	cmd_lsmnt_prepare();

	/* Read mount info and print */
	cmd_lsmnt_execute();

	/* Post execution cleanups */
	cmd_lsmnt_finalize();
}

