/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include "vfstests.h"
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <locale.h>

struct vt_globals {
	int     argc;
	int     log_mask;
	char  **argv;
	char   *workdir_root;
	char   *workdir_real;
	char   *test_name;
	long    repeat_count;
	int     tests_bitmask;
	int     no_check_statvfs;
	int     do_extra_tests;
	int     random_order;
	int     list_tests;
};

/* Global settings */
static struct vt_globals vt_g_globals;

/* Real-path resolved buffer */
static char vt_dirpath_buf[PATH_MAX];

/* Execution environment context */
static struct vt_env *vt_g_ctx;

/* Local functions */
static void vt_setup_globals(int argc, char *argv[]);
static void vt_parse_args(void);
static void vt_verify_args(void);
static void vt_pre_execute(void);
static void vt_post_execute(void);
static void vt_execute_all(void);
static void vt_register_sigactions(void);
static void vt_show_program_version(void);


/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                Silofs's file-system sanity-testing utility                *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Setup process defaults */
	vt_setup_globals(argc, argv);

	/* Parse command-line arguments */
	vt_parse_args();

	/* Check program's parameters */
	vt_verify_args();

	/* Signal handling (ignored) */
	vt_register_sigactions();

	/* Prepare execution */
	vt_pre_execute();

	/* Actual tests execution */
	vt_execute_all();

	/* Final cleanups */
	vt_post_execute();

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vt_error_print_progname(void)
{
	FILE *fp = stderr;

	fprintf(fp, "%s: ", program_invocation_short_name);
	fflush(fp);
}

static void vt_atexit_cleanup(void)
{
	vt_g_ctx = NULL;
	memset(&vt_g_globals, 0, sizeof(vt_g_globals));
}

static void vt_setup_globals(int argc, char *argv[])
{
	umask(0002);
	setlocale(LC_ALL, "");
	atexit(vt_atexit_cleanup);
	error_print_progname = vt_error_print_progname;

	vt_g_globals.argc = argc;
	vt_g_globals.argv = argv;
	vt_g_globals.repeat_count = 1;
	vt_g_globals.log_mask =
	        SILOFS_LOG_INFO | SILOFS_LOG_WARN | SILOFS_LOG_ERROR |
	        SILOFS_LOG_CRIT | SILOFS_LOG_STDOUT;
	silofs_set_logmaskp(&vt_g_globals.log_mask);
}

static int vt_tests_mask(void)
{
	int mask = VT_F_NORMAL | VT_F_STAVFS;

	if (vt_g_globals.no_check_statvfs) {
		mask &= ~VT_F_STAVFS;
		mask |= VT_F_NOSTAVFS;
	}
	if (vt_g_globals.random_order) {
		mask |= VT_F_RANDOM;
	}
	return mask;
}

static void vt_pre_execute(void)
{
	size_t size;

	size = sizeof(*vt_g_ctx);
	vt_g_ctx = (struct vt_env *)malloc(size);
	if (vt_g_ctx == NULL) {
		error(EXIT_FAILURE, errno, "malloc %lu-nbytes failed", size);
	}
	vt_g_globals.tests_bitmask = vt_tests_mask();
}

static void vt_post_execute(void)
{
	free(vt_g_ctx);
	vt_g_ctx = NULL;
}

static void vt_execute_all(void)
{
	struct vt_params params = {
		.progname = program_invocation_short_name,
		.workdir = vt_g_globals.workdir_real,
		.testname = vt_g_globals.test_name,
		.testsmask = vt_g_globals.tests_bitmask,
		.repeatn = vt_g_globals.repeat_count,
		.listtests = vt_g_globals.list_tests
	};

	vte_init(vt_g_ctx, &params);
	vte_exec(vt_g_ctx);
	vte_fini(vt_g_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sigaction_noop_handler(int signum)
{
	silofs_unused(signum);
}

static struct sigaction s_sigaction_noop = {
	.sa_handler = sigaction_noop_handler
};

static void register_sigaction(int signum, struct sigaction *sa)
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

static void vt_register_sigactions(void)
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

static const char *vt_usage =
        "[options] <dirpath>\n\n" \
        "options: \n" \
        " -t, --test=<name>         Run tests which contains name\n" \
        " -n, --repeat=<count>      Execute tests count times\n" \
        " -e, --extra               Use extra tests\n" \
        " -r, --random              Run tests in random order\n" \
        " -C, --nostatvfs           Do not check statvfs between tests\n" \
        " -l, --list                List tests names\n"
        " -v, --version             Show version info\n";

__attribute__((__noreturn__))
static void show_help_and_exit(void)
{
	printf("%s %s\n", program_invocation_short_name, vt_usage);
	exit(EXIT_SUCCESS);
}

__attribute__((__noreturn__))
static void show_version_and_exit(void)
{
	vt_show_program_version();
	exit(EXIT_SUCCESS);
}

static long vt_strtol_safe(const char *nptr)
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

static void vt_parse_args(void)
{
	int opt_chr = 1;
	int opt_index = 0;
	struct option long_opts[] = {
		{ "test", required_argument, NULL, 't' },
		{ "repeat", required_argument, NULL, 'n' },
		{ "random", no_argument, NULL, 'r' },
		{ "nostatvfs", no_argument, NULL, 'C' },
		{ "list", no_argument, NULL, 'l' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_index = 0;
		opt_chr = getopt_long(vt_g_globals.argc, vt_g_globals.argv,
		                      "t:n:erClvh", long_opts, &opt_index);
		if (opt_chr == 't') {
			vt_g_globals.test_name = optarg;
		} else if (opt_chr == 'n') {
			vt_g_globals.repeat_count = vt_strtol_safe(optarg);
		} else if (opt_chr == 'r') {
			vt_g_globals.random_order = true;
		} else if (opt_chr == 'C') {
			vt_g_globals.no_check_statvfs = true;
		} else if (opt_chr == 'l') {
			vt_g_globals.list_tests = true;
		} else if (opt_chr == 'v') {
			show_version_and_exit();
		} else if (opt_chr == 'h') {
			show_help_and_exit();
		} else if (opt_chr > 0) {
			error(EXIT_FAILURE, 0, "bad option 0%o", opt_chr);
		}
	}

	if (vt_g_globals.list_tests) {
		return;
	}
	if (optind >= vt_g_globals.argc) {
		error(EXIT_FAILURE, 0, "missing root pathname");
	}
	vt_g_globals.workdir_root = vt_g_globals.argv[optind++];
	if (optind < vt_g_globals.argc) {
		error(EXIT_FAILURE, 0, "redundant argument: %s",
		      vt_g_globals.argv[optind]);
	}
	if (!realpath(vt_g_globals.workdir_root, vt_dirpath_buf)) {
		error(EXIT_FAILURE, errno, "no realpath: %s",
		      vt_g_globals.workdir_root);
	}
	vt_g_globals.workdir_real = vt_dirpath_buf;
}

static void vt_verify_args(void)
{
	int err;
	struct stat st;
	const char *base = vt_g_globals.workdir_root;

	if (vt_g_globals.list_tests) {
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

static void vt_show_program_version(void)
{
	const char *progname = program_invocation_short_name;

	printf("%s %s\n", progname, silofs_version.string);
}

