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


static struct silofs_subcmd_mkfs *cmd_mkfs_args;

static const char *mkfs_usage[] = {
	"mkfs --size=NBYTES [options] <repo/name>",
	"",
	"options:",
	"  -s, --size=NBYTES            Capacity size limit",
	"  -F, --force                  Force overwrite if already exists",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

static void cmd_mkfs_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "force", no_argument, NULL, 'F' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("s:V:Fh", opts);
		if (opt_chr == 's') {
			cmd_mkfs_args->size = optarg;
			cmd_mkfs_args->fs_size = silofs_cmd_parse_size(optarg);
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'F') {
			cmd_mkfs_args->force = true;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(mkfs_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_require_arg("size", cmd_mkfs_args->size);
	silofs_cmd_getarg("repo/name", &cmd_mkfs_args->repodir_name);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_mkfs_finalize(void)
{
	silofs_cmd_destroy_fse_inst();
	silofs_cmd_pfrees(&cmd_mkfs_args->name);
	silofs_cmd_pfrees(&cmd_mkfs_args->repodir);
	silofs_cmd_pfrees(&cmd_mkfs_args->repodir_name);
	silofs_cmd_pfrees(&cmd_mkfs_args->repodir_real);
}

static void cmd_mkfs_start(void)
{
	cmd_mkfs_args = &silofs_globals.cmd.mkfs;
	atexit(cmd_mkfs_finalize);
}

static void cmd_mkfs_prepare(void)
{
	silofs_cmd_check_notexists(cmd_mkfs_args->repodir_name);

	silofs_cmd_splitpath(cmd_mkfs_args->repodir_name,
	                     &cmd_mkfs_args->repodir,
	                     &cmd_mkfs_args->name);

	silofs_cmd_check_nonemptydir(cmd_mkfs_args->repodir, true);

	silofs_cmd_realpath(cmd_mkfs_args->repodir,
	                    &cmd_mkfs_args->repodir_real);

	silofs_cmd_check_fsname(cmd_mkfs_args->name);
}

static void cmd_mkfs_create_fs_env(void)
{
	const struct silofs_fs_args fs_args = {
		.main_repodir = cmd_mkfs_args->repodir_real,
		.main_name = cmd_mkfs_args->name,
		.capacity = (size_t)cmd_mkfs_args->fs_size,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_cmd_create_fse_inst(&fs_args);
}

static void cmd_mkfs_format_filesystem(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir = cmd_mkfs_args->repodir_real;
	int err;

	err = silofs_fse_open_repos(fse);
	if (err) {
		silofs_die(err, "failed to open repo: %s", repodir);
	}
	err = silofs_fse_close_repos(fse);
	if (err) {
		silofs_die(err, "failed to close repo: %s", repodir);
	}
	err = silofs_fse_format_fs(fse);
	if (err) {
		silofs_die(err, "failed to format fs: %s", repodir);
	}
}

static void cmd_mkfs_finish(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir = cmd_mkfs_args->repodir_real;
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "shutdown error: %s", repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal error: %s", repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_mkfs(void)
{
	/* Do all cleanups upon exits */
	cmd_mkfs_start();

	/* Parse command's arguments */
	cmd_mkfs_getopt();

	/* Verify user's arguments */
	cmd_mkfs_prepare();

	/* Prepare environment */
	cmd_mkfs_create_fs_env();

	/* Do actual mkfs */
	cmd_mkfs_format_filesystem();

	/* Post-format cleanups */
	cmd_mkfs_finish();

	/* Post execution cleanups */
	cmd_mkfs_finalize();
}


