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


static struct silofs_subcmd_archive *cmd_archive_args;
static int cmd_archive_warm_lock_fd = -1;

static const char *cmd_archive_usage[] = {
	"archive [options] <warm-repo/name> <cold-repo/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void cmd_archive_getopt(void)
{
	int opt_chr = 1;
	char **popt = NULL;
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
			popt = &cmd_archive_args->passphrase_file;
			silofs_cmd_getoptarg("--passphrase-file", popt);
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(cmd_archive_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("warm-repo/name",
	                  &cmd_archive_args->warm_repodir_name);
	silofs_cmd_getarg("cold-repo/name",
	                  &cmd_archive_args->cold_repodir_name);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_archive_finalize(void)
{
	silofs_cmd_destroy_fse_inst();
	silofs_cmd_pfrees(&cmd_archive_args->warm_repodir_name);
	silofs_cmd_pfrees(&cmd_archive_args->warm_repodir);
	silofs_cmd_pfrees(&cmd_archive_args->warm_repodir_real);
	silofs_cmd_pfrees(&cmd_archive_args->warm_name);
	silofs_cmd_pfrees(&cmd_archive_args->cold_repodir_name);
	silofs_cmd_pfrees(&cmd_archive_args->cold_repodir);
	silofs_cmd_pfrees(&cmd_archive_args->cold_repodir_real);
	silofs_cmd_pfrees(&cmd_archive_args->cold_name);
	silofs_cmd_pfrees(&cmd_archive_args->passphrase_file);
	silofs_cmd_delpass(&cmd_archive_args->passphrase);
	silofs_cmd_unlockf(&cmd_archive_warm_lock_fd);
}

static void cmd_archive_start(void)
{
	cmd_archive_args = &silofs_globals.cmd.archive;
	atexit(cmd_archive_finalize);
}

static void cmd_archive_prepare(void)
{
	silofs_cmd_check_reg(cmd_archive_args->warm_repodir_name, false);

	silofs_cmd_splitpath(cmd_archive_args->warm_repodir_name,
	                     &cmd_archive_args->warm_repodir,
	                     &cmd_archive_args->warm_name);

	silofs_cmd_splitpath2(cmd_archive_args->cold_repodir_name,
	                      cmd_archive_args->warm_name,
	                      &cmd_archive_args->cold_repodir,
	                      &cmd_archive_args->cold_name);

	silofs_cmd_check_notexists2(cmd_archive_args->cold_repodir,
	                            cmd_archive_args->cold_name);

	silofs_cmd_check_nonemptydir(cmd_archive_args->warm_repodir, false);

	silofs_cmd_realpath(cmd_archive_args->warm_repodir,
	                    &cmd_archive_args->warm_repodir_real);

	silofs_cmd_check_fsname(cmd_archive_args->warm_name);

	silofs_cmd_check_nonemptydir(cmd_archive_args->cold_repodir, true);

	silofs_cmd_realpath(cmd_archive_args->cold_repodir,
	                    &cmd_archive_args->cold_repodir_real);

	silofs_cmd_check_fsname(cmd_archive_args->cold_name);

	silofs_cmd_lockf(cmd_archive_args->warm_repodir_real,
	                 cmd_archive_args->warm_name,
	                 &cmd_archive_warm_lock_fd);

	silofs_cmd_getpass2(cmd_archive_args->passphrase_file,
	                    &cmd_archive_args->passphrase);
}

static void cmd_archive_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.main_repodir = cmd_archive_args->warm_repodir_real,
		.cold_repodir = cmd_archive_args->cold_repodir_real,
		.main_name = cmd_archive_args->warm_name,
		.cold_name = cmd_archive_args->cold_name,
		.passwd = cmd_archive_args->passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_cmd_create_fse_inst(&args);
}

static void cmd_archive_verify_bootsec(void)
{
	struct silofs_bootsec bsec = { .btime = 0 };
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir = cmd_archive_args->warm_repodir_real;
	const char *repodir_name = cmd_archive_args->warm_repodir_name;
	struct silofs_namestr nstr;
	int err;

	silofs_make_fsnamestr(&nstr, cmd_archive_args->warm_name);
	err = silofs_fse_open_repos(fse);
	if (err) {
		silofs_die(err, "failed to open repo: %s", repodir);
	}
	err = silofs_fse_load_boot(fse, &nstr, &bsec);
	if (err) {
		silofs_die(err, "failed to load boot: %s", repodir_name);
	}
	err = silofs_fse_close_repos(fse);
	if (err) {
		silofs_die(err, "failed to close repo: %s", repodir);
	}
}

static void cmd_archive_verify_fs_env(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir_name = cmd_archive_args->warm_repodir_name;
	const char *name = cmd_archive_args->warm_name;
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

static void cmd_archive_filesystem(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_archive(fse);
	if (err) {
		silofs_die(err, "archive failed: %s --> %s",
		           cmd_archive_args->warm_repodir_name,
		           cmd_archive_args->cold_repodir_name);
	}
}

static void cmd_archive_finish(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish archive error: %s --> %s",
		           cmd_archive_args->warm_repodir_name,
		           cmd_archive_args->cold_repodir_name);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal archive error: %s --> %s",
		           cmd_archive_args->warm_repodir_name,
		           cmd_archive_args->cold_repodir_name);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_archive(void)
{
	/* Do all cleanups upon exits */
	cmd_archive_start();

	/* Parse command's arguments */
	cmd_archive_getopt();

	/* Verify user's arguments */
	cmd_archive_prepare();

	/* Prepare environment */
	cmd_archive_create_fs_env();

	/* Require source boot sector */
	cmd_archive_verify_bootsec();

	/* Require source fs */
	cmd_archive_verify_fs_env();

	/* Do actual archive */
	cmd_archive_filesystem();

	/* Post-archive cleanups */
	cmd_archive_finish();

	/* Post execution cleanups */
	cmd_archive_finalize();
}


