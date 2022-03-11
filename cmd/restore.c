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
	"restore [options] <cold-repo/name> <main-repo/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void restore_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("V:P:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'P') {
			restore_args->passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(restore_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("cold-repo/name", &restore_args->cold_repodir_name);
	silofs_cmd_getarg("main-repo/name", &restore_args->main_repodir_name);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void restore_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_cmd_delpass(&restore_args->passphrase);
	silofs_cmd_pfrees(&restore_args->main_repodir_name);
	silofs_cmd_pfrees(&restore_args->main_repodir);
	silofs_cmd_pfrees(&restore_args->main_repodir_real);
	silofs_cmd_pfrees(&restore_args->main_name);
	silofs_cmd_pfrees(&restore_args->cold_repodir_name);
	silofs_cmd_pfrees(&restore_args->cold_repodir);
	silofs_cmd_pfrees(&restore_args->cold_repodir_real);
	silofs_cmd_pfrees(&restore_args->cold_name);
}

static void restore_start(void)
{
	restore_args = &silofs_globals.cmd.restore;
	atexit(restore_finalize);
}

static void restore_prepare(void)
{
	/* XXX FIXME */
	/*
	silofs_cmd_getpass2(archive_args->passphrase_file,
	                    &archive_args->passphrase);
	*/
	silofs_cmd_splitpath(restore_args->cold_repodir_name,
	                     &restore_args->cold_repodir,
	                     &restore_args->cold_name);

	silofs_cmd_splitpath2(restore_args->main_repodir_name,
	                      restore_args->cold_name,
	                      &restore_args->main_repodir,
	                      &restore_args->main_name);

	silofs_cmd_check_notexists2(restore_args->main_repodir,
	                            restore_args->main_name);

	silofs_cmd_check_nonemptydir(restore_args->cold_repodir, true);
	silofs_cmd_realpath(restore_args->cold_repodir,
	                    &restore_args->cold_repodir_real);
	silofs_cmd_check_fsname(restore_args->cold_name);

	silofs_cmd_check_nonemptydir(restore_args->main_repodir, false);
	silofs_cmd_realpath(restore_args->main_repodir,
	                    &restore_args->main_repodir_real);
	silofs_cmd_check_fsname(restore_args->main_name);
}

static void restore_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.main_repodir = restore_args->main_repodir_real,
		.main_name = restore_args->main_name,
		.cold_repodir = restore_args->cold_repodir_real,
		.cold_name = restore_args->cold_name,
		.passwd = restore_args->passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.restore = true,
	};

	silofs_create_fse_inst(&args);
}

static void restore_verify_bootsec(void)
{
	struct silofs_bootsec bsec;
	struct silofs_fs_env *fse = silofs_fse_inst();
	const char *repodir = restore_args->cold_repodir_real;
	const char *repodir_name = restore_args->cold_repodir_name;
	struct silofs_namestr nstr;
	int fd = -1;
	int err;

	silofs_make_fsnamestr(&nstr, restore_args->cold_name);
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

static void restore_filesystem(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_restore(fse);
	if (err) {
		silofs_die(err, "restore failed: %s --> %s",
		           restore_args->cold_repodir_name,
		           restore_args->main_repodir_name);
	}
}

static void restore_finish(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish restore error: %s --> %s",
		           restore_args->cold_repodir_name,
		           restore_args->main_repodir_name);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal restore error: %s --> %s",
		           restore_args->cold_repodir_name,
		           restore_args->main_repodir_name);
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

	/* Require source boot sector */
	restore_verify_bootsec();

	/* Do actual restore */
	restore_filesystem();

	/* Post-restore cleanups */
	restore_finish();

	/* Post execution cleanups */
	restore_finalize();
}


