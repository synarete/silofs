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
#include "mountd.h"


/* local functions */
static void mountd_start(struct mountd_ctx *ctx);
static void mountd_getopt(struct mountd_ctx *ctx);
static void mountd_init_process(struct mountd_ctx *ctx);
static void mountd_boot_process(const struct mountd_ctx *ctx);
static void mountd_setup_env(struct mountd_ctx *ctx);
static void mountd_trace_start(const struct mountd_ctx *ctx);
static void mountd_trace_finish(const struct mountd_ctx *ctx);
static void mound_execute_ms(struct mountd_ctx *ctx);
static void mountd_finalize(struct mountd_ctx *ctx);
static void mountd_load_mntrules(struct mountd_ctx *ctx);
static void mountd_enable_signals(const struct mountd_ctx *ctx);
static void mountd_require_cap_sys_admin(const struct mountd_ctx *ctx);

/* execution context */
static struct mountd_ctx *mountd_ctx;

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
	struct mountd_ctx ctx = {
		.args.argc = argc,
		.args.argv = argv,
		.args.allow_coredump = false,
		.args.dumpable = false,
		.log_params.level = SILOFS_LOG_INFO,
		.log_params.flags = SILOFS_LOGF_STDOUT,
		.progname = program_invocation_short_name,
	};

	/* Do all cleanups upon exits */
	mountd_start(&ctx);

	/* Parse command-line options */
	mountd_getopt(&ctx);

	/* Common process initializations */
	mountd_init_process(&ctx);

	/* Process specific bootstrap sequence */
	mountd_boot_process(&ctx);

	/* Must have mount/umount capabilities */
	mountd_require_cap_sys_admin(&ctx);

	/* Load mount-rules from config-file */
	mountd_load_mntrules(&ctx);

	/* Setup environment instance */
	mountd_setup_env(&ctx);

	/* Say something */
	mountd_trace_start(&ctx);

	/* Allow halt by signal */
	mountd_enable_signals(&ctx);

	/* Execute as long as needed... */
	mound_execute_ms(&ctx);

	/* Say goodbye */
	mountd_trace_finish(&ctx);

	/* Post execution cleanups */
	mountd_finalize(&ctx);

	/* Goodbye ;) */
	return 0;
}

__attribute__((__noreturn__))
static void mountd_dief(int errnum, const char *restrict fmt, ...)
{
	char msg[2048] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);
	error(EXIT_FAILURE, abs(errnum), "%s", msg);
	_exit(EXIT_FAILURE); /* never gets here, but makes clang-scan happy */
}

static void mountd_init_process(struct mountd_ctx *ctx)
{
	int err;

	err = silofs_init_lib();
	if (err) {
		mountd_dief(err, "unable to init lib");
	}
	silofs_set_global_log_params(&ctx->log_params);
}

static void mountd_setrlimit_nocore(void)
{
	struct rlimit rlim = { .rlim_cur = 0, .rlim_max = 0 };
	int err;

	err = silofs_sys_setrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		mountd_dief(err, "failed to disable core-dupms");
	}
}

static void mountd_set_dumpable(unsigned int state)
{
	int err;

	err = silofs_sys_prctl(PR_SET_DUMPABLE, state, 0, 0, 0);
	if (err) {
		mountd_dief(err, "failed to prctl dumpable: state=%u", state);
	}
}

static void mountd_boot_process(const struct mountd_ctx *ctx)
{
	if (!ctx->args.allow_coredump) {
		mountd_setrlimit_nocore();
	}
	if (ctx->args.dumpable) {
		mountd_set_dumpable(1);
	} else {
		mountd_set_dumpable(0);
	}
}

static void mountd_require_cap_sys_admin(const struct mountd_ctx *ctx)
{
	cap_value_t value = CAP_SYS_ADMIN;
	cap_flag_value_t flag = CAP_CLEAR;
	cap_t cap;
	int err;

	errno = 0;
	cap = cap_get_pid(getpid());
	if (cap == NULL) {
		mountd_dief(errno, "failed to get cap");
	}
	err = cap_get_flag(cap, value, CAP_EFFECTIVE, &flag);
	if (err) {
		mountd_dief(errno, "failed to get capability: %d", value);
	}
	cap_free(cap);

	if (flag != CAP_SET) {
		mountd_dief(0, "does not have CAP_SYS_ADMIN capability");
	}
	silofs_unused(ctx);
}

static void mountd_setup_env(struct mountd_ctx *ctx)
{
	struct silofs_ms_args ms_args = {
		.runstatedir = SILOFS_RUNSTATEDIR,
		.use_abstract = true
	};
	int err;

	err = silofs_mse_new(&ms_args, &ctx->mse);
	if (err) {
		mountd_dief(err, "failed to create instance");
	}
}

static void mountd_trace_start(const struct mountd_ctx *ctx)
{
	silofs_log_meta_banner(ctx->progname, 1);
}

static void mountd_trace_finish(const struct mountd_ctx *ctx)
{
	silofs_log_meta_banner(ctx->progname, 0);
}

static void mountd_load_mntrules(struct mountd_ctx *ctx)
{
	ctx->mntrules = mountd_parse_mntrules(ctx->args.confpath);
}

static void mountd_drop_mntrules(struct mountd_ctx *ctx)
{
	if (ctx->mntrules != NULL) {
		mountd_free_mntrules(ctx->mntrules);
		ctx->mntrules = NULL;
	}
}

static void mountd_del_env(struct mountd_ctx *ctx)
{
	if (ctx->mse != NULL) {
		silofs_mse_del(ctx->mse);
		ctx->mse = NULL;
	}
}

static void mountd_finalize(struct mountd_ctx *ctx)
{
	mountd_del_env(ctx);
	mountd_drop_mntrules(ctx);
	mountd_ctx = NULL;

	silofs_burnstack();
}

static void mountd_atexit(void)
{
	if (mountd_ctx != NULL) {
		mountd_finalize(mountd_ctx);
	}
}

static void mountd_start(struct mountd_ctx *ctx)
{
	mountd_ctx = ctx;
	atexit(mountd_atexit);
	setlocale(LC_ALL, "");
}

static void mound_execute_ms(struct mountd_ctx *ctx)
{
	int err;

	err = silofs_mse_serve(ctx->mse, ctx->mntrules);
	if (err) {
		mountd_dief(err, "mount-service error");
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mountd_halt_by_signal(struct mountd_ctx *ctx, int signum)
{
	ctx->sig_halt = signum;
	if (ctx->mse) {
		silofs_mse_halt(ctx->mse, signum);
	}
}

static void mountd_sigaction_info_handler(int signum)
{
	silofs_log_debug("signal: %d", signum);
}

static void mountd_sigaction_halt_handler(int signum)
{
	struct mountd_ctx *ctx = mountd_ctx;

	silofs_log_info("halt-signal: %d", signum);
	if (ctx != NULL) {
		mountd_halt_by_signal(ctx, signum);
	}
}

__attribute__((__noreturn__))
static void mountd_sigaction_term_handler(int signum)
{
	struct mountd_ctx *ctx = mountd_ctx;

	silofs_log_crit("term-signal: %d", signum);
	if (ctx != NULL) {
		ctx->sig_halt = signum;
		ctx->sig_fatal = signum;
	}
	exit(EXIT_FAILURE);
}

__attribute__((__noreturn__))
static void mountd_sigaction_abort_handler(int signum)
{
	struct mountd_ctx *ctx = mountd_ctx;

	if (ctx && ctx->sig_fatal) {
		_exit(EXIT_FAILURE);
	}

	silofs_log_crit("abort-signal: %d", signum);
	if (ctx) {
		ctx->sig_halt = signum;
		ctx->sig_fatal = signum;
	}
	abort(); /* Re-raise to _exit */
}

static const struct sigaction s_sigaction_info = {
	.sa_handler = mountd_sigaction_info_handler
};

static const struct sigaction s_sigaction_halt = {
	.sa_handler = mountd_sigaction_halt_handler
};

static const struct sigaction s_sigaction_term = {
	.sa_handler = mountd_sigaction_term_handler
};

static const struct sigaction s_sigaction_abort = {
	.sa_handler = mountd_sigaction_abort_handler
};

static void register_sigaction(int signum, const struct sigaction *sa)
{
	int err;

	err = silofs_sys_sigaction(signum, sa, NULL);
	if (err) {
		mountd_dief(err, "sigaction error: signum=%d", signum);
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

static void mountd_enable_signals(const struct mountd_ctx *ctx)
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
	silofs_unused(ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char mountd_usage[] =
        "[options] [-f conf]\n"\
        "\n"\
        "options:\n"\
        "  -f, --conf=CONF              Mount-rules config file\n"\
        "  -V, --verbose=LEVEL          Run in verbose mode (0..3)\n"\
        "  -v, --version                Show version and exit\n";

__attribute__((__noreturn__))
static void mountd_goodbye(void)
{
	exit(EXIT_SUCCESS);
}

__attribute__((__noreturn__))
static void mountd_show_usage(void)
{
	printf("%s\n", mountd_usage);
	mountd_goodbye();
}

__attribute__((__noreturn__))
static void mountd_show_version(void)
{
	printf("%s: %s\n", program_invocation_short_name,
	       silofs_version.string);
	mountd_goodbye();
}

static void mountd_getopt(struct mountd_ctx *ctx)
{
	int opt_chr = 1;
	int opt_index = 0;
	int argc = ctx->args.argc;
	char **argv = ctx->args.argv;
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
			ctx->args.confpath = optarg;
		} else if (opt_chr == 'V') {
			silofs_log_params_by_str(&ctx->log_params, optarg);
		} else if (opt_chr == 'v') {
			mountd_show_version();
		} else if (opt_chr == 'h') {
			mountd_show_usage();
		} else if (opt_chr > 0) {
			mountd_dief(0, "unsupported option: %s", optarg);
		}
	}
	if (optind < argc) {
		mountd_dief(0, "redundant argument: %s", argv[optind]);
	}
	if (ctx->args.confpath == NULL) {
		mountd_dief(0, "missing argument: %s", "conf");
	}
}

