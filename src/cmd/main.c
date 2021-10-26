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
#include <silofs/cmd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <unistd.h>
#include <error.h>
#include <locale.h>
#include <time.h>


/* Local functions forward declarations */
static void silofs_parse_global_args(void);
static void silofs_exec_subcmd(void);


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
	silofs_setup_globals(argc, argv);

	/* Parse top-level arguments */
	silofs_parse_global_args();

	/* Common process initializations */
	silofs_init_process();

	/* Execute sub-command by hook */
	silofs_exec_subcmd();

	/* Post execution cleanup */
	silofs_burnstack();

	/* Goodbye ;) */
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define DEFCMD(cmd_)    { #cmd_, silofs_execute_##cmd_ }

static const struct silofs_cmd_info g_cmd_info[] = {
	DEFCMD(mkfs),
	DEFCMD(mount),
	DEFCMD(umount),
	DEFCMD(fsck),
	DEFCMD(show),
	DEFCMD(clone),
	DEFCMD(archive),
	DEFCMD(lsmnt),
};

static bool equals(const char *s1, const char *s2)
{
	return (s1 && s2 && !strcmp(s1, s2));
}

static bool equals2(const char *s, const char *s1, const char *s2)
{
	return equals(s, s1) || equals(s, s2);
}

static const struct silofs_cmd_info *cmt_info_of(const char *cmd_name)
{
	const struct silofs_cmd_info *cmdi = NULL;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(g_cmd_info); ++i) {
		cmdi = &g_cmd_info[i];
		if (equals(cmd_name, cmdi->name)) {
			return cmdi;
		}
	}
	return NULL;
}

static void show_main_help_and_exit(int exit_code)
{
	printf("%s <command> [options]\n\n", silofs_globals.name);
	printf("main commands: \n");
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(g_cmd_info); ++i) {
		printf("  %s\n", g_cmd_info[i].name);
	}
	exit(exit_code);
}

static void silofs_grab_args(void)
{
	if (silofs_globals.argc <= 1) {
		show_main_help_and_exit(1);
	}
	silofs_globals.cmd_name = silofs_globals.argv[1];
	silofs_globals.cmd_argc = silofs_globals.argc - 1;
	silofs_globals.cmd_argv = silofs_globals.argv + 1;
}

static void silofs_parse_global_args(void)
{
	const char *cmd_name = NULL;

	silofs_grab_args();
	cmd_name = silofs_globals.cmd_name;

	if (equals2(cmd_name, "-v", "--version")) {
		silofs_show_version_and_exit(NULL);
	}
	if (equals2(cmd_name, "-h", "--help")) {
		show_main_help_and_exit(0);
	}
	silofs_globals.cmdi = cmt_info_of(cmd_name);
}

static void silofs_exec_subcmd(void)
{
	const struct silofs_cmd_info *cmdi = silofs_globals.cmdi;

	if (cmdi == NULL) {
		show_main_help_and_exit(1);
	} else if (cmdi->action_hook != NULL) {
		cmdi->action_hook();
	}
}
