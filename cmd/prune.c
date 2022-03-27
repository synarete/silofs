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


static struct silofs_subcmd_prune *cmd_prune_args;

static const char *cmd_prune_usage[] = {
	"prune [options] <repo-path>",
	"",
	"options:",
	"  -v, --version                Show version and exit",
	NULL
};

static void cmd_prune_getopt(void)
{
	int c = 1;
	int opt_index;
	int argc;
	char **argv;
	const struct option opts[] = {
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	argc = silofs_globals.cmd_argc;
	argv = silofs_globals.cmd_argv;
	while (c > 0) {
		opt_index = 0;
		c = getopt_long(argc, argv, "vh", opts, &opt_index);
		if (c == -1) {
			break;
		}
		if (c == 'v') {
			silofs_print_version_and_exit(NULL);
		} else if (c == 'h') {
			silofs_print_help_and_exit(cmd_prune_usage);
		} else {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repo-path", &cmd_prune_args->repodir);
	silofs_cmd_endargs();
}


static void cmd_prune_finalize(void)
{
	silofs_cmd_destroy_fse_inst();
	silofs_cmd_pfrees(&cmd_prune_args->repodir_real);
	silofs_cmd_pfrees(&cmd_prune_args->repodir);
}

static void cmd_prune_start(void)
{
	cmd_prune_args = &silofs_globals.cmd.prune;
	atexit(cmd_prune_finalize);
}

static void cmd_prune_prepare(void)
{
	silofs_cmd_check_nonemptydir(cmd_prune_args->repodir, true);
	silofs_cmd_realpath(cmd_prune_args->repodir,
	                    &cmd_prune_args->repodir_real);
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_cmd_execute_prune(void)
{
	/* Do all cleanups upon exits */
	cmd_prune_start();

	/* Parse command's arguments */
	cmd_prune_getopt();

	/* Verify user's arguments */
	cmd_prune_prepare();

	/* TODO: execute logic... */

	/* Post execution cleanups */
	cmd_prune_finalize();
}

