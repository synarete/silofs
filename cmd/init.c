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


static struct silofs_subcmd_init *cmd_init_args;

static const char *cmd_init_usage[] = {
	"init <repo-dir>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

static void cmd_init_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("V:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(cmd_init_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repo-dir", &cmd_init_args->repodir);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_init_finalize(void)
{
	silofs_cmd_destroy_fse_inst();
	silofs_cmd_pfrees(&cmd_init_args->repodir_real);
	silofs_cmd_pfrees(&cmd_init_args->repodir);
}

static void cmd_init_start(void)
{
	cmd_init_args = &silofs_globals.cmd.init;
	atexit(cmd_init_finalize);
}

static void cmd_init_prepare(void)
{
	struct stat st = { .st_ino = 0 };
	const char *path = cmd_init_args->repodir;
	int err;

	err = silofs_sys_stat(path, &st);
	if (err == 0) {
		silofs_cmd_check_emptydir(path, true);
	} else if (err == -ENOENT) {
		silofs_cmd_mkdir(path, 0700);
	} else {
		silofs_die(err, "stat failure: %s", path);
	}
	silofs_cmd_realpath(path, &cmd_init_args->repodir_real);
}

static void cmd_init_create_fs_env(void)
{
	const struct silofs_fs_args fs_args = {
		.main_repodir = cmd_init_args->repodir_real,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.unimode = true,
	};

	silofs_cmd_create_fse_inst(&fs_args);
}

static void cmd_init_format_repo(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_format_repos(fse);
	if (err) {
		silofs_die(err, "format repo failed: %s",
		           cmd_init_args->repodir);
	}
}

static void cmd_init_finish(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "shutdown error: %s", cmd_init_args->repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal error: %s", cmd_init_args->repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_init(void)
{
	/* Do all cleanups upon exits */
	cmd_init_start();

	/* Parse command's arguments */
	cmd_init_getopt();

	/* Verify user's arguments */
	cmd_init_prepare();

	/* Prepare environment */
	cmd_init_create_fs_env();

	/* Do actual init */
	cmd_init_format_repo();

	/* Post-format cleanups */
	cmd_init_finish();

	/* Post execution cleanups */
	cmd_init_finalize();
}


