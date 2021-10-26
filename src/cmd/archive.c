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

static const char *archive_usage[] = {
	"archive [options] <repository-path>",
	"",
	"options:",
	"  -n, --name=NAME              Private name",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void archive_getopt(void)
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
		opt_chr = silofs_getopt_subcmd("V:n:P:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'n') {
			silofs_globals.cmd.archive.name = optarg;
		} else if (opt_chr == 'P') {
			silofs_globals.cmd.archive.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(archive_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_globals.cmd.archive.repodir =
	        silofs_consume_cmdarg("repository-path", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void archive_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_delpass(&silofs_globals.cmd.archive.passphrase);
}

static void archive_setup_check_params(void)
{
	silofs_die_if_not_empty_dir(silofs_globals.cmd.archive.repodir, true);
	silofs_globals.cmd.archive.passphrase =
	        silofs_getpass2(silofs_globals.cmd.archive.passphrase_file);
}

static void archive_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.repodir = silofs_globals.cmd.archive.repodir,
		.fsname = silofs_globals.cmd.archive.name,
		.passwd = silofs_globals.cmd.archive.passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_create_fse_inst(&args);
}

static void archive_filesystem(void)
{
	/* TODO: write me */
}

static void archive_finish_fs_env(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish format error: %s",
		           silofs_globals.cmd.archive.repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal format error: %s",
		           silofs_globals.cmd.archive.repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_archive(void)
{
	/* Do all cleanups upon exits */
	atexit(archive_finalize);

	/* Parse command's arguments */
	archive_getopt();

	/* Verify user's arguments */
	archive_setup_check_params();

	/* Prepare environment */
	archive_create_fs_env();

	/* Do actual archive */
	archive_filesystem();

	/* Post-archive cleanups */
	archive_finish_fs_env();

	/* Post execution cleanups */
	archive_finalize();
}


