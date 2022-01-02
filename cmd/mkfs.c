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


static struct silofs_subcmd_mkfs *mkfs_args;

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
	const struct option opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "size", required_argument, NULL, 's' },
		{ "force", no_argument, NULL, 'F' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("n:s:V:Fh", opts);
		if (opt_chr == 'n') {
			mkfs_args->name = silofs_cmd_strdup(optarg);
		} else if (opt_chr == 's') {
			mkfs_args->size = optarg;
			mkfs_args->fs_size = silofs_cmd_parse_size(optarg);
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'F') {
			mkfs_args->force = true;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(mkfs_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repository-path", &mkfs_args->repodir);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mkfs_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_cmd_pfrees(&mkfs_args->name);
	silofs_cmd_pfrees(&mkfs_args->repodir_real);
	silofs_cmd_pfrees(&mkfs_args->repodir);
}

static void mkfs_start(void)
{
	mkfs_args = &silofs_globals.cmd.mkfs;
	atexit(mkfs_finalize);
}

static void mkfs_prepare(void)
{
	silofs_die_if_missing_arg("size", mkfs_args->size);
	silofs_require_valid_fsname("name", &mkfs_args->name);
}

static void mkfs_make_repodir(void)
{
	struct stat st = { .st_ino = 0 };
	const char *path = mkfs_args->repodir;
	int err;

	err = silofs_sys_stat(path, &st);
	if (err == 0) {
		silofs_die_if_not_empty_dir(path, true);
	} else if (err == -ENOENT) {
		silofs_die_if_not_mkdir(path, 0700);
	} else {
		silofs_die(err, "stat failure: %s", path);
	}
	mkfs_args->repodir_real = silofs_cmd_realpath(path);
}

static void mkfs_create_fs_env(void)
{
	const struct silofs_fs_args fs_args = {
		.repodir = mkfs_args->repodir_real,
		.fsname = mkfs_args->name,
		.capacity = (size_t)mkfs_args->fs_size,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.lock_repo = false,
	};

	silofs_create_fse_inst(&fs_args);
}

static void mkfs_format_filesystem(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_format_repo(fse);
	if (err) {
		silofs_die(err, "format repo failed: %s", mkfs_args->repodir);
	}
	err = silofs_fse_format_fs(fse);
	if (err) {
		silofs_die(err, "format fs failed: %s", mkfs_args->repodir);
	}
}

static void mkfs_finish(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		silofs_die(err, "shutdown error: %s", mkfs_args->repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		silofs_die(err, "internal error: %s", mkfs_args->repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_mkfs(void)
{
	/* Do all cleanups upon exits */
	mkfs_start();

	/* Parse command's arguments */
	mkfs_getopt();

	/* Verify user's arguments */
	mkfs_prepare();

	/* Create new empty repo dir */
	mkfs_make_repodir();

	/* Prepare environment */
	mkfs_create_fs_env();

	/* Do actual mkfs */
	mkfs_format_filesystem();

	/* Post-format cleanups */
	mkfs_finish();

	/* Post execution cleanups */
	mkfs_finalize();
}


