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
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <unistd.h>
#include <error.h>
#include <locale.h>
#include <time.h>
#include "cmd.h"

/* Local functions forward declarations */
static void cmd_setup_globals(int argc, char *argv[]);
static void cmd_parse_global_args(void);
static void cmd_init_libsilofs(void);
static void cmd_resolve_caps(void);
static void cmd_execute_sub(void);
static void cmd_clean_postexec(void);

/* Global process' variables */
struct cmd_globals cmd_globals;

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                           The Silo File System                            *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Setup process defaults */
	cmd_setup_globals(argc, argv);

	/* Parse top-level arguments */
	cmd_parse_global_args();

	/* Common library initializations */
	cmd_init_libsilofs();

	/* Resolve process capabilities */
	cmd_resolve_caps();

	/* Execute sub-command by hook */
	cmd_execute_sub();

	/* Post execution cleanup */
	cmd_clean_postexec();

	/* Goodbye ;) */
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_error_print_progname(void)
{
	FILE *fp = stderr;
	const char *name = cmd_globals.name;
	const char *subcmd = cmd_globals.cmd_name;

	if (subcmd && (subcmd[0] != '-')) {
		fprintf(fp, "%s %s: ", name, subcmd);
	} else {
		fprintf(fp, "%s: ", name);
	}
	fflush(fp);
}

static void cmd_setup_globals(int argc, char *argv[])
{
	SILOFS_STATICASSERT_LT(sizeof(cmd_globals), 1024);

	cmd_globals.version = silofs_version.string;
	cmd_globals.name = program_invocation_short_name;
	cmd_globals.prog = program_invocation_name;
	cmd_globals.argc = argc;
	cmd_globals.argv = argv;
	cmd_globals.cmd_argc = argc;
	cmd_globals.cmd_argv = argv;
	cmd_globals.cmd_name = NULL;
	cmd_globals.pid = getpid();
	cmd_globals.uid = getuid();
	cmd_globals.gid = getgid();
	cmd_globals.umsk = 0022;
	cmd_globals.dont_daemonize = false;
	cmd_globals.allow_coredump = false;
	cmd_globals.dumpable = true; /* XXX */
	cmd_globals.log_params.level = SILOFS_LOG_INFO;
	cmd_globals.log_params.flags =
	        SILOFS_LOGF_STDOUT | SILOFS_LOGF_PROGNAME;

	umask(cmd_globals.umsk);
	setlocale(LC_ALL, "");
	error_print_progname = cmd_error_print_progname;
}

static void cmd_init_libsilofs(void)
{
	int err;

	err = silofs_init_lib();
	if (err) {
		cmd_dief(err, "unable to init libsilofs");
	}
	silofs_set_global_log_params(&cmd_globals.log_params);
}

static void cmd_resolve_caps(void)
{
	cap_t cap;
	cap_flag_value_t flag = CAP_CLEAR;
	int err = 1;

	cap = cap_get_pid(getpid());
	if (cap != NULL) {
		err = cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &flag);
		cap_free(cap);
	}
	cmd_globals.cap_sys_admin = (!err && (flag == CAP_SET));
}

static void cmd_clean_postexec(void)
{
	silofs_burnstack();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define DEFCMD(cmd_)    { #cmd_, cmd_execute_##cmd_ }

static const struct cmd_info g_cmd_info[] = {
	DEFCMD(init),
	DEFCMD(mkfs),
	DEFCMD(mount),
	DEFCMD(umount),
	DEFCMD(lsmnt),
	DEFCMD(show),
	DEFCMD(snap),
	DEFCMD(sync),
	DEFCMD(tune),
	DEFCMD(rmfs),
	DEFCMD(prune),
	DEFCMD(fsck),
	DEFCMD(bmaps),
};

static bool equals(const char *s1, const char *s2)
{
	return (s1 && s2 && !strcmp(s1, s2));
}

static bool equals2(const char *s, const char *s1, const char *s2)
{
	return equals(s, s1) || equals(s, s2);
}

static const struct cmd_info *cmt_info_of(const char *cmd_name)
{
	const struct cmd_info *cmdi = NULL;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(g_cmd_info); ++i) {
		cmdi = &g_cmd_info[i];
		if (equals(cmd_name, cmdi->name)) {
			return cmdi;
		}
	}
	return NULL;
}

__attribute__((__noreturn__))
static void show_main_help_and_exit(int exit_code)
{
	printf("%s <command> [options]\n\n", cmd_globals.name);
	printf("main commands: \n");
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(g_cmd_info); ++i) {
		printf("  %s\n", g_cmd_info[i].name);
	}
	exit(exit_code);
}

static void silofs_grab_args(void)
{
	if (cmd_globals.argc <= 1) {
		show_main_help_and_exit(1);
	}
	cmd_globals.cmd_name = cmd_globals.argv[1];
	cmd_globals.cmd_argc = cmd_globals.argc - 1;
	cmd_globals.cmd_argv = cmd_globals.argv + 1;
}

__attribute__((__noreturn__))
static void cmd_print_version_and_exit(void)
{
	printf("%s %s\n", cmd_globals.name, cmd_globals.version);
	exit(0);
}

static void cmd_parse_global_args(void)
{
	const char *cmd_name = NULL;

	silofs_grab_args();
	cmd_name = cmd_globals.cmd_name;
	if (equals2(cmd_name, "-v", "--version")) {
		cmd_print_version_and_exit();
	}
	if (equals2(cmd_name, "-h", "--help")) {
		show_main_help_and_exit(0);
	}
	cmd_globals.cmdi = cmt_info_of(cmd_name);
}

static void cmd_execute_sub(void)
{
	const struct cmd_info *cmdi = cmd_globals.cmdi;

	if (cmdi == NULL) {
		show_main_help_and_exit(1);
	} else if (cmdi->action_hook != NULL) {
		cmdi->action_hook();
	}
}

