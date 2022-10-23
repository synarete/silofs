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
#include "cmd.h"

static const char *cmd_restore_help_desc[] = {
	"restore <atticdir/archive> <repodir/name>",
	"",
	"options:",
	"  -V, --verbose=level          Run in verbose mode (0..3)",
	"  -P, --password-file=file     Passphrase file (unsafe)",
	NULL
};

struct cmd_restore_in_args {
	char   *atticdir_name;
	char   *atticdir;
	char   *atticdir_real;
	char   *arname;
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *password;
	char   *password_file;
};

struct cmd_restore_ctx {
	struct cmd_restore_in_args      in_args;
	struct silofs_fs_args           fs_args;
	struct silofs_fs_env           *fs_env;
	int                             lock_fd;
};

static struct cmd_restore_ctx *cmd_restore_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_getopt(struct cmd_restore_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "password", required_argument, NULL, 'p' },
		{ "password-file", required_argument, NULL, 'P' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("p:P:V:h", opts);
		if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'P') {
			cmd_getoptarg("--password-file",
			              &ctx->in_args.password_file);
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_restore_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("atticdir/archive", &ctx->in_args.atticdir_name);
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_finalize(struct cmd_restore_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
	cmd_reset_fs_cargs(&ctx->fs_args.ca);
	cmd_pstrfree(&ctx->in_args.atticdir_name);
	cmd_pstrfree(&ctx->in_args.atticdir);
	cmd_pstrfree(&ctx->in_args.atticdir_real);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.password_file);
	cmd_delpass(&ctx->in_args.password);
	cmd_unlockf(&ctx->lock_fd);
	cmd_restore_ctx = NULL;
}

static void cmd_restore_atexit(void)
{
	if (cmd_restore_ctx != NULL) {
		cmd_restore_finalize(cmd_restore_ctx);
	}
}

static void cmd_restore_start(struct cmd_restore_ctx *ctx)
{
	cmd_restore_ctx = ctx;
	atexit(cmd_restore_atexit);
}

static void cmd_restore_prepare(struct cmd_restore_ctx *ctx)
{
	struct cmd_restore_in_args *args = &ctx->in_args;

	cmd_check_isreg(args->atticdir_name, false);
	cmd_split_path(args->atticdir_name, &args->atticdir, &args->arname);
	cmd_realpath(args->atticdir, &args->atticdir_real);
	cmd_check_nonemptydir(args->atticdir_real, false);
	cmd_check_fsname(args->arname);

	cmd_check_notexists(args->repodir_name);
	cmd_split_path(args->repodir_name, &args->repodir, &args->name);
	cmd_realpath(args->repodir, &args->repodir_real);
	cmd_check_nonemptydir(args->repodir_real, true);
	cmd_check_fsname(args->name);
	cmd_check_notexists2(args->repodir_real, args->name);

	cmd_check_not_same(args->atticdir_real, args->repodir_real);
}

static void cmd_restore_lock_src_fs(struct cmd_restore_ctx *ctx)
{
	const struct cmd_restore_in_args *args = &ctx->in_args;

	cmd_lockf(args->atticdir_real, args->arname, &ctx->lock_fd);
}

static void cmd_restore_getpass(struct cmd_restore_ctx *ctx)
{
	struct cmd_restore_in_args *args = &ctx->in_args;

	if (args->password == NULL) {
		cmd_getpass(args->password_file, &args->password);
	}
}

static void cmd_restore_setup_fs_args(struct cmd_restore_ctx *ctx)
{
	const struct cmd_restore_in_args *args = &ctx->in_args;
	struct silofs_fs_cargs *fsca = &ctx->fs_args.ca;

	cmd_init_fs_args(&ctx->fs_args);
	cmd_load_fs_cargs_for(fsca, true, args->atticdir_real, args->arname);
	ctx->fs_args.atticdir = args->atticdir_real;
	ctx->fs_args.arname = args->arname;
	ctx->fs_args.repodir = args->repodir_real;
	ctx->fs_args.name = args->name;
	ctx->fs_args.passwd = args->password;
	ctx->fs_args.restore_forced = false;
}

static void cmd_restore_setup_fs_env(struct cmd_restore_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}

static void cmd_restore_open_repo(struct cmd_restore_ctx *ctx)
{
	cmd_open_repo(ctx->fs_env);
}

static void cmd_restore_require_bsec(struct cmd_restore_ctx *ctx)
{
	cmd_require_fs(ctx->fs_env, false, &ctx->fs_args.ca.uuid);
}

static void cmd_restore_unpack_fs(struct cmd_restore_ctx *ctx)
{
	cmd_unpack_fs(ctx->fs_env, &ctx->fs_args.ca.uuid,
	              &ctx->fs_args.ca.uuid);
}

static void cmd_restore_save_fs_cargs(struct cmd_restore_ctx *ctx)
{
	const struct cmd_restore_in_args *args = &ctx->in_args;

	ctx->fs_args.ca.pack = false;
	cmd_save_fs_cargs2(&ctx->fs_args.ca, args->repodir_real, args->name);
}

static void cmd_restore_close_repo(struct cmd_restore_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_restore(void)
{
	struct cmd_restore_ctx ctx = {
		.fs_env = NULL,
		.lock_fd = -1,
	};

	/* Do all cleanups upon exits */
	cmd_restore_start(&ctx);

	/* Parse command's arguments */
	cmd_restore_getopt(&ctx);

	/* Verify user's arguments */
	cmd_restore_prepare(&ctx);

	/* Acquire source lock */
	cmd_restore_lock_src_fs(&ctx);

	/* Get user's password */
	cmd_restore_getpass(&ctx);

	/* Load source boot-params */
	cmd_restore_setup_fs_args(&ctx);

	/* Print-out common debugging info */
	cmd_trace_debug_info();

	/* Prepare environment */
	cmd_restore_setup_fs_env(&ctx);

	/* Open repositories */
	cmd_restore_open_repo(&ctx);

	/* Load-verify source bootsec */
	cmd_restore_require_bsec(&ctx);

	/* Do actual restore-unpacking */
	cmd_restore_unpack_fs(&ctx);

	/* Save warm meta boot config */
	cmd_restore_save_fs_cargs(&ctx);

	/* Close repositories */
	cmd_restore_close_repo(&ctx);

	/* Post execution cleanups */
	cmd_restore_finalize(&ctx);
}
