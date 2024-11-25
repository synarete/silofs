/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include "funtests.h"
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>

struct ft_global_settings {
	struct silofs_log_params log_params;
	int argc;
	char **argv;
	char *curr_workdir;
	char *testdir_path;
	char *testdir_real;
	char *test_name;
	long repeat_count;
	int tests_mask;
	int tests_xmask;
	bool quiet_mode;
	bool without_statvfs;
	bool without_flaky;
	bool random_order;
	bool list_tests;
};

/* Global settings */
static struct ft_global_settings ft_globals;

/* Real-path resolved buffer */
static char ft_dirpath_buf[PATH_MAX];

/* Execution environment context */
static struct ft_env *ft_g_env;

/* Local functions */
static void ft_setup_globals(int argc, char *argv[]);
static void ft_parse_args(void);
static void ft_verify_args(void);
static void ft_pre_execute(void);
static void ft_post_execute(void);
static void ft_execute_all(void);
static void ft_register_sigactions(void);
static void ft_show_program_version(void);

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *            Silofs' file-system functional testing ("black-box")           *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Setup process defaults */
	ft_setup_globals(argc, argv);

	/* Parse command-line arguments */
	ft_parse_args();

	/* Check program's parameters */
	ft_verify_args();

	/* Signal handling (ignored) */
	ft_register_sigactions();

	/* Prepare execution */
	ft_pre_execute();

	/* Actual tests execution */
	ft_execute_all();

	/* Final cleanups */
	ft_post_execute();

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ft_error_print_progname(void)
{
	FILE *fp = stderr;

	fprintf(fp, "%s: ", program_invocation_short_name);
	fflush(fp);
}

static void ft_atexit_cleanup(void)
{
	ft_g_env = NULL;
	memset(&ft_globals, 0, sizeof(ft_globals));
}

static void ft_setup_globals(int argc, char *argv[])
{
	umask(0002);
	setlocale(LC_ALL, "");
	atexit(ft_atexit_cleanup);
	error_print_progname = ft_error_print_progname;

	ft_globals.argc = argc;
	ft_globals.argv = argv;
	ft_globals.repeat_count = 1;
	ft_globals.log_params.level = SILOFS_LOG_INFO;
	ft_globals.log_params.flags = SILOFS_LOGF_STDOUT |
				      SILOFS_LOGF_PROGNAME;
	silofs_set_global_log_params(&ft_globals.log_params);
}

static void ft_tests_mask(int *out_mask, int *out_xmask)
{
	*out_mask = FT_F_NORMAL;
	*out_xmask = 0;

	if (ft_globals.without_statvfs) {
		*out_xmask |= FT_F_STATVFS;
	} else {
		*out_mask |= FT_F_STATVFS;
	}
	if (ft_globals.without_flaky) {
		*out_xmask |= FT_F_FLAKY;
	} else {
		*out_mask |= FT_F_FLAKY;
	}
	if (ft_globals.random_order) {
		*out_mask |= FT_F_RANDOM;
	}
}

static void ft_pre_execute(void)
{
	ft_tests_mask(&ft_globals.tests_mask, &ft_globals.tests_xmask);

	ft_globals.curr_workdir = get_current_dir_name();
	if (ft_globals.curr_workdir == NULL) {
		error(EXIT_FAILURE, errno, "get_current_dir_name failed");
	}

	ft_g_env = (struct ft_env *)malloc(sizeof(*ft_g_env));
	if (ft_g_env == NULL) {
		error(EXIT_FAILURE, errno, "malloc %lu failed",
		      sizeof(*ft_g_env));
	}

	if (ft_globals.quiet_mode) {
		ft_globals.log_params.level = SILOFS_LOG_ERROR;
	}
}

static void ft_post_execute(void)
{
	if (ft_g_env != NULL) {
		free(ft_g_env);
		ft_g_env = NULL;
	}
	if (ft_globals.curr_workdir != NULL) {
		free(ft_globals.curr_workdir);
		ft_globals.curr_workdir = NULL;
	}
}

static void ft_execute_all(void)
{
	struct ft_params params = {
		.progname = program_invocation_short_name,
		.testdir = ft_globals.testdir_real,
		.testname = ft_globals.test_name,
		.tests_mask = ft_globals.tests_mask,
		.tests_xmask = ft_globals.tests_xmask,
		.repeatn = ft_globals.repeat_count,
		.listtests = ft_globals.list_tests,
	};

	fte_init(ft_g_env, &params);
	fte_run(ft_g_env);
	fte_fini(ft_g_env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sigaction_noop_handler(int signum)
{
	silofs_unused(signum);
}

static const struct sigaction s_sigaction_noop = {
	.sa_handler = sigaction_noop_handler
};

static void register_sigaction(int signum, const struct sigaction *sa)
{
	int err;

	err = silofs_sys_sigaction(signum, sa, NULL);
	if (err) {
		error(EXIT_FAILURE, err, "sigaction error: %d", signum);
	}
}

static void sigaction_noop(int signum)
{
	register_sigaction(signum, &s_sigaction_noop);
}

static void ft_register_sigactions(void)
{
	sigaction_noop(SIGHUP);
	sigaction_noop(SIGTRAP);
	sigaction_noop(SIGUSR1);
	sigaction_noop(SIGUSR2);
	sigaction_noop(SIGPIPE);
	sigaction_noop(SIGALRM);
	sigaction_noop(SIGCHLD);
	sigaction_noop(SIGCONT);
	sigaction_noop(SIGURG);
	sigaction_noop(SIGPROF);
	sigaction_noop(SIGWINCH);
	sigaction_noop(SIGIO);
	/* GC specifics */
	sigaction_noop(SIGPWR);
	sigaction_noop(SIGXCPU);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *const ft_usage =
	"[options] <test-dirpath>\n\n"
	"options: \n"
	" -t, --test=<name>         Run tests which contains name\n"
	" -n, --repeat=<count>      Execute tests count times\n"
	" -e, --extra               Use extra tests\n"
	" -r, --random              Run tests in random order\n"
	" -C, --nostatvfs           Do not check statvfs between tests\n"
	" -F, --noflaky             Ignore non-stable tests\n"
	" -Q, --quiet               Print only errors\n"
	" -l, --list                List tests names\n"
	" -v, --version             Show version info\n";

silofs_attr_noreturn static void show_help_and_exit(void)
{
	printf("%s %s\n", program_invocation_short_name, ft_usage);
	exit(EXIT_SUCCESS);
}

silofs_attr_noreturn static void show_version_and_exit(void)
{
	ft_show_program_version();
	exit(EXIT_SUCCESS);
}

static long ft_strtol_safe(const char *nptr)
{
	long ret = 0;
	char *endptr = NULL;

	errno = 0;
	ret = strtol(nptr, &endptr, 10);
	if ((ret == LONG_MAX) || (ret == LONG_MIN)) {
		error(EXIT_FAILURE, errno, "bad numeric: %s", nptr);
	}
	return ret;
}

static void ft_parse_args(void)
{
	int opt_chr = 1;
	int opt_index = 0;
	struct option long_opts[] = {
		{ "test", required_argument, NULL, 't' },
		{ "repeat", required_argument, NULL, 'n' },
		{ "random", no_argument, NULL, 'r' },
		{ "nostatvfs", no_argument, NULL, 'C' },
		{ "noflaky", no_argument, NULL, 'F' },
		{ "quiet", no_argument, NULL, 'Q' },
		{ "list", no_argument, NULL, 'l' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_index = 0;
		opt_chr = getopt_long(ft_globals.argc, ft_globals.argv,
				      "t:n:erQCFlvh", long_opts, &opt_index);
		if (opt_chr == 't') {
			ft_globals.test_name = optarg;
		} else if (opt_chr == 'n') {
			ft_globals.repeat_count = ft_strtol_safe(optarg);
		} else if (opt_chr == 'r') {
			ft_globals.random_order = true;
		} else if (opt_chr == 'Q') {
			ft_globals.quiet_mode = true;
		} else if (opt_chr == 'C') {
			ft_globals.without_statvfs = true;
		} else if (opt_chr == 'F') {
			ft_globals.without_flaky = true;
		} else if (opt_chr == 'l') {
			ft_globals.list_tests = true;
		} else if (opt_chr == 'v') {
			show_version_and_exit();
		} else if (opt_chr == 'h') {
			show_help_and_exit();
		} else if (opt_chr > 0) {
			error(EXIT_FAILURE, 0, "bad option 0%o", opt_chr);
		}
	}

	if (ft_globals.list_tests) {
		return;
	}
	if (optind >= ft_globals.argc) {
		error(EXIT_FAILURE, 0, "missing test-dirpath");
	}
	ft_globals.testdir_path = ft_globals.argv[optind++];
	if (optind < ft_globals.argc) {
		error(EXIT_FAILURE, 0, "redundant argument: %s",
		      ft_globals.argv[optind]);
	}
	if (!realpath(ft_globals.testdir_path, ft_dirpath_buf)) {
		error(EXIT_FAILURE, errno, "no realpath: %s",
		      ft_globals.testdir_path);
	}
	ft_globals.testdir_real = ft_dirpath_buf;
}

static void ft_verify_args(void)
{
	struct stat st = { .st_size = -1 };
	const char *base = ft_globals.testdir_path;
	int err;

	if (ft_globals.list_tests) {
		return;
	}
	err = silofs_sys_stat(base, &st);
	if (err) {
		error(EXIT_FAILURE, err, "no stat: %s", base);
	}
	if (!S_ISDIR(st.st_mode)) {
		error(EXIT_FAILURE, 0, "not a directory: %s", base);
	}
}

static void ft_show_program_version(void)
{
	const char *progname = program_invocation_short_name;

	printf("%s %s\n", progname, silofs_version.string);
}
