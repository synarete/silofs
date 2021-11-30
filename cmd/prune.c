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


static const char *silofs_prune_usage[] = {
	"prune [options] <repo-path>",
	"",
	"options:",
	"  -v, --version                Show version and exit",
	NULL
};

static void prune_getopt(void)
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
			silofs_show_version_and_exit(NULL);
		} else if (c == 'h') {
			silofs_show_help_and_exit(silofs_prune_usage);
		} else {
			silofs_die_unsupported_opt();
		}
	}
	if (optind >= argc) {
		silofs_die(0, "missing repo path");
	}
	silofs_globals.cmd.prune.repodir = argv[optind++];
	silofs_die_if_redundant_arg();
}


static void prune_finalize(void)
{
	silofs_destroy_fse_inst();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_execute_prune(void)
{
	/* Do all cleanups upon exits */
	atexit(prune_finalize);

	/* Parse command's arguments */
	prune_getopt();

	/* TODO: FSCK... */

	/* Post execution cleanups */
	prune_finalize();
}

