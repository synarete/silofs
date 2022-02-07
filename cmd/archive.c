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
	"archive [options] <main-repodir/name> <cold-repodir/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void archive_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("P:V:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'P') {
			archive_args->passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(archive_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("main-repodir/name",
	                  &archive_args->main_repodir_name);
	silofs_cmd_getarg("cold-repodir/name",
	                  &archive_args->cold_repodir_name);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void archive_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_cmd_delpass(&archive_args->passphrase);
	silofs_cmd_pfrees(&archive_args->main_repodir_name);
	silofs_cmd_pfrees(&archive_args->main_repodir);
	silofs_cmd_pfrees(&archive_args->main_repodir_real);
	silofs_cmd_pfrees(&archive_args->main_name);
	silofs_cmd_pfrees(&archive_args->cold_repodir_name);
	silofs_cmd_pfrees(&archive_args->cold_repodir);
	silofs_cmd_pfrees(&archive_args->cold_repodir_real);
	silofs_cmd_pfrees(&archive_args->cold_name);
}

static void archive_start(void)
{
	archive_args = &silofs_globals.cmd.archive;
	atexit(archive_finalize);
}

static void archive_prepare(void)
{
	/* XXX FIXME */
	/*
	silofs_cmd_getpass2(archive_args->passphrase_file,
	                    &archive_args->passphrase);
	*/

	silofs_cmd_check_notexists(archive_args->cold_repodir_name);

	silofs_cmd_splitpath(archive_args->main_repodir_name,
	                     &archive_args->main_repodir,
	                     &archive_args->main_name);
	silofs_cmd_splitpath(archive_args->cold_repodir_name,
	                     &archive_args->cold_repodir,
	                     &archive_args->cold_name);

	silofs_cmd_check_nonemptydir(archive_args->main_repodir, false);
	silofs_cmd_realpath(archive_args->main_repodir,
	                    &archive_args->main_repodir_real);
	silofs_cmd_check_fsname(archive_args->main_name);

	silofs_cmd_check_nonemptydir(archive_args->cold_repodir, true);
	silofs_cmd_realpath(archive_args->cold_repodir,
	                    &archive_args->cold_repodir_real);
	silofs_cmd_check_fsname(archive_args->cold_name);
}

static void archive_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.main_repodir = archive_args->main_repodir_real,
		.cold_repodir = archive_args->cold_repodir_real,
		.main_name = archive_args->main_name,
		.cold_name = archive_args->cold_name,
		.passwd = archive_args->passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_create_fse_inst(&args);
}

static void archive_verify_bootsec(void)
{
	struct silofs_bootsec bsec;
	struct silofs_fs_env *fse = silofs_fse_inst();
	const char *repodir = archive_args->main_repodir_real;
	const char *repodir_name = archive_args->main_repodir_name;
	struct silofs_namestr nstr;
	int fd = -1;
	int err;

	silofs_make_fsnamestr(&nstr, archive_args->main_name);
	err = silofs_fse_open_repos(fse);
	if (err) {
		silofs_die(err, "failed to open repo: %s", repodir);
	}
	err = silofs_fse_lock_boot(fse, &nstr, &fd);
	if (err) {
		silofs_die(err, "failed to lock: %s", repodir_name);
	}
	err = silofs_fse_load_boot(fse, &nstr, &bsec);
	if (err) {
		silofs_die(err, "failed to load boot: %s", repodir_name);
	}
	err = silofs_fse_unlock_boot(fse, &nstr, &fd);
	if (err) {
		silofs_die(err, "failed to unlock: %s", repodir_name);
	}
	err = silofs_fse_close_repos(fse);
	if (err) {
		silofs_die(err, "failed to close repo: %s", repodir);
	}
}

static void archive_verify_fs_env(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	const char *repodir_name = archive_args->main_repodir_name;
	const char *name = archive_args->main_name;
	int err;

	err = silofs_fse_verify(fse);
	if (err == -EUCLEAN) {
		silofs_die(0, "bad repo: %s", repodir_name);
	} else if (err == -EKEYEXPIRED) {
		silofs_die(0, "wrong passphrase: %s", repodir_name);
	} else if (err == -ENOENT) {
		silofs_die(0, "not exist: %s", name);
	} else if (err != 0) {
		silofs_die(err, "illegal repo: %s", repodir_name);
	}
}

static void archive_filesystem(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_archive(fse);
	if (err) {
		silofs_die(err, "archive failed: %s --> %s",
		           archive_args->main_repodir_name,
		           archive_args->cold_repodir_name);
	}
}

static void archive_finish(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish archive error: %s --> %s",
		           archive_args->main_repodir_name,
		           archive_args->cold_repodir_name);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal archive error: %s --> %s",
		           archive_args->main_repodir_name,
		           archive_args->cold_repodir_name);
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

	/* Require source boot sector */
	archive_verify_bootsec();

	/* Require source fs */
	archive_verify_fs_env();

	/* Do actual archive */
	archive_filesystem();

	/* Post-archive cleanups */
	archive_finish();

	/* Post execution cleanups */
	archive_finalize();
}


