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


static struct silofs_subcmd_restore *cmd_restore_args;
static int cmd_restore_cold_lock_fd = -1;

static const char *cmd_restore_usage[] = {
	"restore [options] <cold-repo/name> <warm-repo/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void cmd_restore_getopt(void)
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
		opt_chr = silofs_cmd_getopt("V:P:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'P') {
			popt = &cmd_restore_args->passphrase_file;
			silofs_cmd_getoptarg("--passphrase-file", popt);
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(cmd_restore_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("cold-repo/name",
	                  &cmd_restore_args->cold_repodir_name);
	silofs_cmd_getarg("warm-repo/name",
	                  &cmd_restore_args->warm_repodir_name);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_restore_finalize(void)
{
	silofs_cmd_destroy_fse_inst();
	silofs_cmd_pfrees(&cmd_restore_args->warm_repodir_name);
	silofs_cmd_pfrees(&cmd_restore_args->warm_repodir);
	silofs_cmd_pfrees(&cmd_restore_args->warm_repodir_real);
	silofs_cmd_pfrees(&cmd_restore_args->warm_name);
	silofs_cmd_pfrees(&cmd_restore_args->cold_repodir_name);
	silofs_cmd_pfrees(&cmd_restore_args->cold_repodir);
	silofs_cmd_pfrees(&cmd_restore_args->cold_repodir_real);
	silofs_cmd_pfrees(&cmd_restore_args->cold_name);
	silofs_cmd_pfrees(&cmd_restore_args->passphrase_file);
	silofs_cmd_delpass(&cmd_restore_args->passphrase);
	silofs_cmd_unlockf(&cmd_restore_cold_lock_fd);
}

static void cmd_restore_start(void)
{
	cmd_restore_args = &silofs_globals.cmd.restore;
	atexit(cmd_restore_finalize);
}

static void cmd_restore_prepare(void)
{
	silofs_cmd_check_reg(cmd_restore_args->cold_repodir_name, false);

	silofs_cmd_splitpath(cmd_restore_args->cold_repodir_name,
	                     &cmd_restore_args->cold_repodir,
	                     &cmd_restore_args->cold_name);

	silofs_cmd_splitpath2(cmd_restore_args->warm_repodir_name,
	                      cmd_restore_args->cold_name,
	                      &cmd_restore_args->warm_repodir,
	                      &cmd_restore_args->warm_name);

	silofs_cmd_check_notexists2(cmd_restore_args->warm_repodir,
	                            cmd_restore_args->warm_name);

	silofs_cmd_check_nonemptydir(cmd_restore_args->cold_repodir, true);

	silofs_cmd_realpath(cmd_restore_args->cold_repodir,
	                    &cmd_restore_args->cold_repodir_real);

	silofs_cmd_check_fsname(cmd_restore_args->cold_name);

	silofs_cmd_check_nonemptydir(cmd_restore_args->warm_repodir, false);

	silofs_cmd_realpath(cmd_restore_args->warm_repodir,
	                    &cmd_restore_args->warm_repodir_real);

	silofs_cmd_check_fsname(cmd_restore_args->warm_name);

	silofs_cmd_lockf(cmd_restore_args->cold_repodir_real,
	                 cmd_restore_args->cold_name,
	                 &cmd_restore_cold_lock_fd);

	silofs_cmd_getpass(cmd_restore_args->passphrase_file,
	                   &cmd_restore_args->passphrase);
}

static void cmd_restore_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.main_repodir = cmd_restore_args->warm_repodir_real,
		.main_name = cmd_restore_args->warm_name,
		.cold_repodir = cmd_restore_args->cold_repodir_real,
		.cold_name = cmd_restore_args->cold_name,
		.passwd = cmd_restore_args->passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.restore = true,
	};

	silofs_cmd_create_fse_inst(&args);
}

static void cmd_restore_verify_bootsec(void)
{
	struct silofs_bootsec bsec = { .btime = 0 };
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir = cmd_restore_args->cold_repodir_real;
	const char *repodir_name = cmd_restore_args->cold_repodir_name;
	struct silofs_namestr nstr;
	int err;

	silofs_make_fsnamestr(&nstr, cmd_restore_args->cold_name);
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

static void cmd_restore_filesystem(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_restore(fse);
	if (err) {
		silofs_die(err, "restore failed: %s --> %s",
		           cmd_restore_args->cold_repodir_name,
		           cmd_restore_args->warm_repodir_name);
	}
}

static void cmd_restore_finish(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "finish restore error: %s --> %s",
		           cmd_restore_args->cold_repodir_name,
		           cmd_restore_args->warm_repodir_name);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal restore error: %s --> %s",
		           cmd_restore_args->cold_repodir_name,
		           cmd_restore_args->warm_repodir_name);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_restore(void)
{
	/* Do all cleanups upon exits */
	cmd_restore_start();

	/* Parse command's arguments */
	cmd_restore_getopt();

	/* Verify user's arguments */
	cmd_restore_prepare();

	/* Prepare environment */
	cmd_restore_create_fs_env();

	/* Require source boot sector */
	cmd_restore_verify_bootsec();

	/* Do actual restore */
	cmd_restore_filesystem();

	/* Post-restore cleanups */
	cmd_restore_finish();

	/* Post execution cleanups */
	cmd_restore_finalize();
}


