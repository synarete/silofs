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


static struct silofs_subcmd_archive *archive_args;

static const char *archive_usage[] = {
	"archive --source=NAME [options] <pathname>",
	"",
	"options:",
	"  -s, --source=NAME            Source name",
	"  -t, --target=NAME            Target name",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void archive_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "source", required_argument, NULL, 's' },
		{ "target", required_argument, NULL, 't' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("s:t:P:V:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 's') {
			archive_args->source_name = optarg;
		} else if (opt_chr == 't') {
			archive_args->target_name = optarg;
		} else if (opt_chr == 'P') {
			archive_args->passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(archive_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repository-path", &archive_args->repodir);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void archive_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_delpass(&archive_args->passphrase);
	silofs_cmd_pfrees(&archive_args->repodir);
}

static void archive_start(void)
{
	archive_args = &silofs_globals.cmd.archive;
	atexit(archive_finalize);
}

static void archive_prepare(void)
{
	silofs_die_if_not_empty_dir(archive_args->repodir, true);
	archive_args->passphrase =
	        silofs_getpass2(archive_args->passphrase_file);
}

static void archive_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.repodir = archive_args->repodir,
		.fsname = archive_args->source_name,
		.passwd = archive_args->passphrase,
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

static void archive_finish(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish error: %s", archive_args->repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal error: %s", archive_args->repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_archive(void)
{
	/* Do all cleanups upon exits */
	archive_start();

	/* Parse command's arguments */
	archive_getopt();

	/* Verify user's arguments */
	archive_prepare();

	/* Prepare environment */
	archive_create_fs_env();

	/* Do actual archive */
	archive_filesystem();

	/* Post-archive cleanups */
	archive_finish();

	/* Post execution cleanups */
	archive_finalize();
}


