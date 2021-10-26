/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/configs.h>
#include <silofs/fs.h>
#include <silofs/mntd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <locale.h>
#include <getopt.h>
#include <signal.h>

#define MOUNTD_LOG_MASK (SILOFS_LOG_WARN | SILOFS_LOG_ERROR | \
                         SILOFS_LOG_CRIT | SILOFS_LOG_STDOUT)

static void mountd_setup_globals(int argc, char *argv[]);
static void mountd_getopt(void);
static void mountd_init_process(void);
static void mountd_enable_signals(void);
static void mountd_boostrap_process(void);
static void mountd_create_mse_inst(void);
static void mountd_trace_start(void);
static void mound_execute_ms(void);
static void mountd_finalize(void);
static void mountd_load_mntrules(void);
static void mountd_require_cap_sys_admin(void);

/* globals */
static char *g_mountd_confpath;
static struct silofs_ms_env *g_mountd_ms_env_inst;
static struct silofs_mntrules *g_mountd_mntrules;
static int g_mountd_allow_coredump;
static int g_mountd_disable_ptrace;
static int g_mountd_argc;
static char **g_mountd_argv;
static int g_mountd_sig_halt;
static int g_mountd_sig_fatal;
static int g_mountd_log_mask = MOUNTD_LOG_MASK;


/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                         Silofs's Mounting-Daemon                          *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Setup process defaults */
	mountd_setup_globals(argc, argv);

	/* Parse command-line options */
	mountd_getopt();

	/* Common process initializations */
	mountd_init_process();

	/* Process specific bootstrap sequence */
	mountd_boostrap_process();

	/* Must have mount/umount capabilities */
	mountd_require_cap_sys_admin();

	/* Load mount-rules from config-file */
	mountd_load_mntrules();

	/* Setup environment instance */
	mountd_create_mse_inst();

	/* Say something */
	mountd_trace_start();

	/* Allow halt by signal */
	mountd_enable_signals();

	/* Execute as long as needed... */
	mound_execute_ms();

	/* Post execution cleanups */
	mountd_finalize();

	/* Goodbye ;) */
	return 0;
}


static void mountd_atexit(void)
{
	fflush(stdout);
	fflush(stderr);
}

static void mountd_setup_globals(int argc, char *argv[])
{
	g_mountd_argc = argc;
	g_mountd_argv = argv;
	g_mountd_allow_coredump = 0;
	g_mountd_disable_ptrace = 1;

	setlocale(LC_ALL, "");
	atexit(mountd_atexit);
}

static void mountd_init_process(void)
{
	int err;

	g_mountd_log_mask |=
	        SILOFS_LOG_WARN | SILOFS_LOG_ERROR | \
	        SILOFS_LOG_CRIT | SILOFS_LOG_STDOUT;

	err = silofs_boot_lib();
	if (err) {
		silofs_die(err, "unable to init lib");
	}
	silofs_set_logmaskp(&g_mountd_log_mask);
}

static void mountd_setrlimit_nocore(void)
{
	int err;
	struct rlimit rlim = { .rlim_cur = 0, .rlim_max = 0 };

	err = silofs_sys_setrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		silofs_die(err, "failed to disable core-dupms");
	}
}

static void mountd_prctl_non_dumpable(void)
{
	int err;

	err = silofs_sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (err) {
		silofs_die(err, "failed to prctl non-dumpable");
	}
}

static void mountd_boostrap_process(void)
{
	if (!g_mountd_allow_coredump) {
		mountd_setrlimit_nocore();
	}
	if (!g_mountd_disable_ptrace) {
		mountd_prctl_non_dumpable();
	}
	atexit(mountd_finalize);
}

static void mountd_require_cap_sys_admin(void)
{
	int err;
	cap_t cap;
	cap_value_t value = CAP_SYS_ADMIN;
	cap_flag_value_t flag = CAP_CLEAR;

	errno = 0;
	cap = cap_get_pid(getpid());
	if (cap == NULL) {
		silofs_die(errno, "failed to get cap");
	}
	err = cap_get_flag(cap, value, CAP_EFFECTIVE, &flag);
	if (err) {
		silofs_die(errno, "failed to get capability: value=%d", value);
	}
	cap_free(cap);

	if (flag != CAP_SET) {
		silofs_die(0, "does not have CAP_SYS_ADMIN capability");
	}
}


static void mountd_create_mse_inst(void)
{
	int err;

	err = silofs_mse_new(&g_mountd_ms_env_inst);
	if (err) {
		silofs_die(err, "failed to create instance");
	}
}

static void mountd_trace_start(void)
{
	silofs_log_meta_banner(program_invocation_short_name, 1);
}

static void mountd_trace_finish(void)
{
	silofs_log_meta_banner(program_invocation_short_name, 0);
}

static void mountd_load_mntrules(void)
{
	g_mountd_mntrules = silofs_parse_mntrules(g_mountd_confpath);
}

static void mountd_drop_mntrules(void)
{
	if (g_mountd_mntrules != NULL) {
		silofs_free_mntrules(g_mountd_mntrules);
		g_mountd_mntrules = NULL;
	}
}

static void mountd_destroy_mse_inst(void)
{
	if (g_mountd_ms_env_inst) {
		silofs_mse_del(g_mountd_ms_env_inst);
		g_mountd_ms_env_inst = NULL;
	}
}

static void mountd_finalize(void)
{
	mountd_destroy_mse_inst();
	mountd_drop_mntrules();
	mountd_trace_finish();
}

static void mound_execute_ms(void)
{
	int err;
	struct silofs_ms_env *ms_env = g_mountd_ms_env_inst;

	err = silofs_mse_serve(ms_env, g_mountd_mntrules);
	if (err) {
		silofs_die(err, "mount-service error");
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mountd_halt_by_signal(int signum)
{
	struct silofs_ms_env *ms_env = g_mountd_ms_env_inst;

	if (ms_env) {
		silofs_mse_halt(ms_env, signum);
	}
}

static void mountd_sigaction_info_handler(int signum)
{
	silofs_log_debug("signal: %d", signum);
}

static void mountd_sigaction_halt_handler(int signum)
{
	silofs_log_info("halt-signal: %d", signum);
	g_mountd_sig_halt = signum;
	mountd_halt_by_signal(signum);
}

static void mountd_sigaction_term_handler(int signum)
{
	silofs_backtrace();
	silofs_log_crit("term-signal: %d", signum);
	g_mountd_sig_halt = signum;
	g_mountd_sig_fatal = signum;
	exit(EXIT_FAILURE);
}

static void mountd_sigaction_abort_handler(int signum)
{
	if (g_mountd_sig_fatal) {
		_exit(EXIT_FAILURE);
	}

	silofs_backtrace();
	silofs_log_crit("abort-signal: %d", signum);
	g_mountd_sig_halt = signum;
	g_mountd_sig_fatal = signum;
	abort(); /* Re-raise to _exit */
}

static struct sigaction s_sigaction_info = {
	.sa_handler = mountd_sigaction_info_handler
};

static struct sigaction s_sigaction_halt = {
	.sa_handler = mountd_sigaction_halt_handler
};

static struct sigaction s_sigaction_term = {
	.sa_handler = mountd_sigaction_term_handler
};

static struct sigaction s_sigaction_abort = {
	.sa_handler = mountd_sigaction_abort_handler
};

static void register_sigaction(int signum, struct sigaction *sa)
{
	int err;

	err = silofs_sys_sigaction(signum, sa, NULL);
	if (err) {
		silofs_die(err, "sigaction error: signum=%d", signum);
	}
}

static void sigaction_info(int signum)
{
	register_sigaction(signum, &s_sigaction_info);
}

static void sigaction_halt(int signum)
{
	register_sigaction(signum, &s_sigaction_halt);
}

static void sigaction_term(int signum)
{
	register_sigaction(signum, &s_sigaction_term);
}

static void sigaction_abort(int signum)
{
	register_sigaction(signum, &s_sigaction_abort);
}

static void mountd_enable_signals(void)
{
	sigaction_info(SIGHUP);
	sigaction_halt(SIGINT);
	sigaction_halt(SIGQUIT);
	sigaction_term(SIGILL);
	sigaction_info(SIGTRAP);
	sigaction_abort(SIGABRT);
	sigaction_term(SIGBUS);
	sigaction_term(SIGFPE);
	sigaction_info(SIGUSR1);
	sigaction_term(SIGSEGV);
	sigaction_info(SIGUSR2);
	sigaction_info(SIGPIPE);
	sigaction_info(SIGALRM);
	sigaction_halt(SIGTERM);
	sigaction_term(SIGSTKFLT);
	sigaction_info(SIGCHLD);
	sigaction_info(SIGCONT);
	sigaction_halt(SIGTSTP);
	sigaction_halt(SIGTTIN);
	sigaction_halt(SIGTTOU);
	sigaction_info(SIGURG);
	sigaction_halt(SIGXCPU);
	sigaction_halt(SIGXFSZ);
	sigaction_halt(SIGVTALRM);
	sigaction_info(SIGPROF);
	sigaction_info(SIGWINCH);
	sigaction_info(SIGIO);
	sigaction_halt(SIGPWR);
	sigaction_halt(SIGSYS);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char silofs_mountd_usage[] =
        "[options] [-f conf]\n"\
        "\n"\
        "options:\n"\
        "  -f, --conf=CONF              Mount-rules config file\n"\
        "  -V, --verbose=LEVEL          Run in verbose mode (0..3)\n"\
        "  -v, --version                Show version and exit\n";

static void mountd_goodbye(void)
{
	exit(EXIT_SUCCESS);
}

static void mountd_show_usage(void)
{
	printf("%s\n", silofs_mountd_usage);
	mountd_goodbye();
}

static void mountd_show_version(void)
{
	printf("%s: %s\n", program_invocation_short_name,
	       silofs_version.string);
	mountd_goodbye();
}

static void mountd_getopt(void)
{
	int opt_chr = 1;
	int opt_index = 0;
	int argc = g_mountd_argc;
	char **argv = g_mountd_argv;
	const struct option lopts[] = {
		{ "conf", required_argument, NULL, 'f' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_index = 0;
		opt_chr = getopt_long(argc, argv, "f:V:vh", lopts, &opt_index);
		if (opt_chr == -1) {
			break;
		}
		if (opt_chr == 'f') {
			g_mountd_confpath = optarg;
		} else if (opt_chr == 'V') {
			silofs_log_mask_by_str(&g_mountd_log_mask, optarg);
		} else if (opt_chr == 'v') {
			mountd_show_version();
		} else if (opt_chr == 'h') {
			mountd_show_usage();
		} else if (opt_chr > 0) {
			silofs_die(0, "unsupported option: %s", optarg);
		}
	}
	if (optind < argc) {
		silofs_die(0, "redundant argument: %s", argv[optind]);
	}
	if (!g_mountd_confpath) {
		silofs_die(0, "missing argument: %s", "conf");
	}
}

