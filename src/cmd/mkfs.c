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


static const char *mkfs_usage[] = {
	"mkfs --name=NAME [options] <repository-path>",
	"",
	"options:",
	"  -n, --name=NAME              File-system's name",
	"  -s, --size=NBYTES            Capacity size limit",
	"  -F, --force                  Force overwrite if already exists",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

static void mkfs_getopt(void)
{
	int opt_chr = 1;
	long size = 0;
	const struct option opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "size", required_argument, NULL, 's' },
		{ "force", no_argument, NULL, 'F' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_getopt_subcmd("n:s:V:Fh", opts);
		if (opt_chr == 'n') {
			silofs_globals.cmd.mkfs.name =
			        silofs_strdup_safe(optarg);
		} else if (opt_chr == 's') {
			size = silofs_parse_size(optarg);
			silofs_globals.cmd.mkfs.size = optarg;
			silofs_globals.cmd.mkfs.fs_size = size;
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'F') {
			silofs_globals.cmd.mkfs.force = true;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(mkfs_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_globals.cmd.mkfs.repodir =
	        silofs_consume_cmdarg("repository-path", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mkfs_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_pfree_string(&silofs_globals.cmd.mkfs.name);
}

static void mkfs_setup_check_params(void)
{
	silofs_die_if_missing_arg("size", silofs_globals.cmd.mkfs.size);
	silofs_require_valid_fsname("name", &silofs_globals.cmd.mkfs.name);
	silofs_die_if_not_empty_dir(silofs_globals.cmd.mkfs.repodir, true);
}

static void mkfs_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.repodir = silofs_globals.cmd.mkfs.repodir,
		.fsname = silofs_globals.cmd.mkfs.name,
		.capacity = (size_t)silofs_globals.cmd.mkfs.fs_size,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_create_fse_inst(&args);
}

static void mkfs_format_filesystem(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();

	err = silofs_fse_format(fse);
	if (err) {
		silofs_die(err, "format error: %s",
		           silofs_globals.cmd.mkfs.repodir);
	}
}

static void mkfs_finish_fs_env(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish format error: %s",
		           silofs_globals.cmd.mkfs.repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal format error: %s",
		           silofs_globals.cmd.mkfs.repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_mkfs(void)
{
	/* Do all cleanups upon exits */
	atexit(mkfs_finalize);

	/* Parse command's arguments */
	mkfs_getopt();

	/* Verify user's arguments */
	mkfs_setup_check_params();

	/* Prepare environment */
	mkfs_create_fs_env();

	/* Do actual mkfs */
	mkfs_format_filesystem();

	/* Post-format cleanups */
	mkfs_finish_fs_env();

	/* Post execution cleanups */
	mkfs_finalize();
}


