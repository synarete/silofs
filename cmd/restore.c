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


static struct silofs_subcmd_restore *restore_args;

static const char *restore_usage[] = {
	"restore [options] <repository-path>",
	"",
	"options:",
	"  -n, --name=NAME              Private name",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void restore_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "name", required_argument, NULL, 'n' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("V:n:P:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'n') {
			restore_args->name = optarg;
		} else if (opt_chr == 'P') {
			restore_args->passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(restore_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repository-path", &restore_args->repodir);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void restore_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_delpass(&restore_args->passphrase);
	silofs_cmd_pfrees(&restore_args->repodir);
}

static void restore_start(void)
{
	restore_args = &silofs_globals.cmd.restore;
	atexit(restore_finalize);
}

static void restore_prepare(void)
{
	silofs_die_if_not_empty_dir(restore_args->repodir, true);
	restore_args->passphrase =
	        silofs_getpass2(restore_args->passphrase_file);
}

static void restore_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.repodir = restore_args->repodir,
		.fsname = restore_args->name,
		.passwd = restore_args->passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_create_fse_inst(&args);
}

static void restore_filesystem(void)
{
	/* TODO: write me */
}

static void restore_finish(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish error: %s", restore_args->repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal error: %s", restore_args->repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_restore(void)
{
	/* Do all cleanups upon exits */
	restore_start();

	/* Parse command's arguments */
	restore_getopt();

	/* Verify user's arguments */
	restore_prepare();

	/* Prepare environment */
	restore_create_fs_env();

	/* Do actual restore */
	restore_filesystem();

	/* Post-restore cleanups */
	restore_finish();

	/* Post execution cleanups */
	restore_finalize();
}


