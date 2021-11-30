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


static struct silofs_subcmd_refs *refs_args;

static const char *refs_usage[] = {
	"refs [options] <pathname>",
	"",
	"options:",
	"  -l, --full                   Long format",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

static void refs_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "full", no_argument, NULL, 'l' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("lV:h", opts);
		if (opt_chr == 'l') {
			refs_args->full = true;
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(refs_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	refs_args->pathname = silofs_cmd_getarg("pathname", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void refs_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_pfree_string(&refs_args->pathname_real);
}

static void refs_start(void)
{
	refs_args = &silofs_globals.cmd.refs;
	atexit(refs_finalize);
}

static void refs_setup_check_params(void)
{
	struct stat st;

	silofs_cmd_stat_reg_or_dir(refs_args->pathname, &st);
	refs_args->pathname_real = silofs_cmd_realpath(refs_args->pathname);
}

static void refs_create_fs_env(void)
{
	const struct silofs_fs_args fs_args = {
		.repodir = refs_args->pathname_real,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.rdonly = true,
	};

	silofs_create_fse_inst(&fs_args);
}

static void refs_do_ioctl_iterfs(struct silofs_ioc_iterfs *iterfs)
{
	const char *path = refs_args->pathname_real;
	int fd = -1;
	int err;

	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_FS_IOC_ITERFS, iterfs);
	silofs_sys_close(fd);
	if (err) {
		silofs_die(err, "ioctl error: %s", path);
	}
}

static void refs_show_entry(const struct silofs_ioc_iterfs *iterfs)
{
	struct tm tm;
	char tms[128] = "";
	time_t btime = iterfs->btime;

	if (refs_args->full) {
		localtime_r(&btime, &tm);
		strftime(tms, sizeof(tms) - 1, "%b %e %Y %H:%M", &tm);
		printf("%-16s %s\n", iterfs->name, tms);
	} else {
		printf("%s\n", iterfs->name);
	}
}

static void refs_execute(void)
{
	struct silofs_ioc_iterfs iterfs = { .index = 0 };

	refs_do_ioctl_iterfs(&iterfs);
	while (iterfs.index > 0) {
		refs_show_entry(&iterfs);

		iterfs.index += 1;
		refs_do_ioctl_iterfs(&iterfs);
	}
}

static void refs_finish(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "shutdown error: %s", refs_args->pathname);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal error: %s", refs_args->pathname);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_refs(void)
{
	/* Do all cleanups upon exits */
	refs_start();

	/* Parse command's arguments */
	refs_getopt();

	/* Verify user's arguments */
	refs_setup_check_params();

	/* Prepare environment */
	refs_create_fs_env();

	/* Do actual refs listing */
	refs_execute();

	/* Post-format cleanups */
	refs_finish();

	/* Post execution cleanups */
	refs_finalize();
}


