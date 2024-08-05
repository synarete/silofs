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
#define _GNU_SOURCE 1
#include <signal.h>
#include "cmd.h"

static void (*silofs_signal_callback_hook)(int) = NULL;

static void sigaction_info_handler(int signum)
{
	silofs_log_debug("signal: %d", signum);
}

static void sigaction_halt_handler(int signum)
{
	silofs_log_info("halt-signal: %d", signum);
	cmd_globals.sig_halt = signum;
	if (silofs_signal_callback_hook != NULL) {
		/* Call sub-program specific logic */
		silofs_signal_callback_hook(signum);
	} else {
		/* Force re-wake-up */
		raise(SIGHUP);
	}
}

__attribute__((__noreturn__))
static void sigaction_term_handler(int signum)
{
	silofs_backtrace();
	silofs_log_crit("term-signal: %d", signum);
	cmd_globals.sig_halt = signum;
	cmd_globals.sig_fatal = signum;
	exit(EXIT_FAILURE);
}

__attribute__((__noreturn__))
static void sigaction_abort_handler(int signum)
{
	if (cmd_globals.sig_fatal) {
		_exit(EXIT_FAILURE);
	}

	silofs_backtrace();
	silofs_log_crit("abort-signal: %d", signum);
	cmd_globals.sig_halt = signum;
	cmd_globals.sig_fatal = signum;
	abort(); /* Re-raise to _exit */
}

static const struct sigaction s_sigaction_ignore = {
	.sa_handler = SIG_IGN,
};

static const struct sigaction s_sigaction_info = {
	.sa_handler = sigaction_info_handler
};

static const struct sigaction s_sigaction_halt = {
	.sa_handler = sigaction_halt_handler
};

static const struct sigaction s_sigaction_term = {
	.sa_handler = sigaction_term_handler
};

static const struct sigaction s_sigaction_abort = {
	.sa_handler = sigaction_abort_handler
};

static void register_sigaction(int signum, const struct sigaction *sa)
{
	int err;

	err = silofs_sys_sigaction(signum, sa, NULL);
	if (err) {
		cmd_die(err, "sigaction error: signum=%d", signum);
	}
}

static void sigaction_ignore(int signum)
{
	register_sigaction(signum, &s_sigaction_ignore);
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

void cmd_register_sigactions(void (*sig_hook_fn)(int))
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
	sigaction_term(SIGPIPE);
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
	sigaction_ignore(SIGWINCH);
	sigaction_info(SIGIO);
	sigaction_halt(SIGPWR);
	sigaction_halt(SIGSYS);
	silofs_signal_callback_hook = sig_hook_fn;
}
