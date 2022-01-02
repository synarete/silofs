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
#include "unitests.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <locale.h>
#include <getopt.h>

/* Local variables */
struct ut_globals ut_globals;

/* Local functions */
static void ut_setup_globals(int argc, char *argv[]);
static void ut_parse_args(void);
static void ut_setup_tracing(void);
static void ut_setup_args(void);
static void ut_init_lib(void);
static void ut_atexit(void);

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                        Silofs unit-testing program                        *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Do all cleanups upon exits */
	atexit(ut_atexit);

	/* Setup process defaults */
	ut_setup_globals(argc, argv);

	/* Allow error tracing only */
	ut_setup_tracing();

	/* Parse command-line arguments */
	ut_parse_args();

	/* Require valid test directory */
	ut_setup_args();

	/* Prepare libsilofs */
	ut_init_lib();

	/* Actual tests execution... */
	ut_execute_tests();

	/* ...and we are done! */
	return 0;
}

static void ut_setup_globals(int argc, char *argv[])
{
	ut_globals.argc = argc;
	ut_globals.argv = argv;
	ut_globals.program = program_invocation_short_name;
	ut_globals.version = silofs_version.string;

	umask(0002);
	setlocale(LC_ALL, "");
	silofs_mclock_now(&ut_globals.start_ts);
}

static void ut_setup_tracing(void)
{
	ut_globals.log_mask =
	        SILOFS_LOG_ERROR | SILOFS_LOG_CRIT | SILOFS_LOG_STDOUT;
	silofs_set_logmaskp(&ut_globals.log_mask);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_show_help_and_exit(void)
{
	printf("%s <testdir> \n\n", program_invocation_short_name);
	puts("options:");
	puts(" -v, --version         Show version info");
	exit(EXIT_SUCCESS);
}

static void ut_show_version_and_exit(void)
{
	printf("%s %s\n", ut_globals.program, ut_globals.version);
	exit(EXIT_SUCCESS);
}

static void ut_parse_args(void)
{
	int opt_chr = 1;
	int opt_index;
	struct option long_opts[] = {
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_index = 0;
		opt_chr = getopt_long(ut_globals.argc, ut_globals.argv,
		                      "vh", long_opts, &opt_index);
		if (opt_chr == 'v') {
			ut_show_version_and_exit();
		} else if (opt_chr == 'h') {
			ut_show_help_and_exit();
		} else if (opt_chr > 0) {
			error(EXIT_FAILURE, 0, "bad option 0%o", opt_chr);
		}
	}

	if (optind >= ut_globals.argc) {
		error(EXIT_FAILURE, 0, "missing test dir");
	}
	ut_globals.test_dir = ut_globals.argv[optind++];
	if (optind < ut_globals.argc) {
		error(EXIT_FAILURE, 0,
		      "redundant: %s", ut_globals.argv[optind]);
	}
}

static void ut_setup_args(void)
{
	int err;
	struct stat st;

	ut_globals.test_dir_real = realpath(ut_globals.test_dir, NULL);
	if (ut_globals.test_dir_real == NULL) {
		error(EXIT_FAILURE, errno,
		      "no realpath: %s", ut_globals.test_dir);
	}
	err = silofs_sys_stat(ut_globals.test_dir_real, &st);
	if (err) {
		error(EXIT_FAILURE, errno,
		      "stat failure: %s", ut_globals.test_dir_real);
	}
	if (!S_ISDIR(st.st_mode)) {
		error(EXIT_FAILURE, ENOTDIR,
		      "invalid: %s", ut_globals.test_dir_real);
	}
	err = silofs_sys_access(ut_globals.test_dir_real, R_OK | W_OK | X_OK);
	if (err) {
		error(EXIT_FAILURE, -err,
		      "no access: %s", ut_globals.test_dir_real);
	}
}

static void ut_init_lib(void)
{
	int err;

	err = silofs_boot_lib();
	if (err) {
		error(EXIT_FAILURE, -err, "failed to init libsilofs");
	}
}

static void ut_pfree(char **pp)
{
	if (*pp != NULL) {
		free(*pp);
		*pp = NULL;
	}
}

static void ut_atexit(void)
{
	ut_pfree(&ut_globals.test_dir_real);
}


