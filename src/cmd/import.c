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
#include "cmd.h"

static const char *cmd_import_help_desc[] = {
	"import [options] <repodir/name>",
	"",
	"options:",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_import_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
};

struct cmd_import_ctx {
	struct cmd_import_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	FILE *in_fp;
	bool has_lockfile;
};

static struct cmd_import_ctx *cmd_import_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_import_getopt(struct cmd_import_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "password", required_argument, NULL, 'p' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("p:L:h", opts);
		if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_import_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_import_acquire_lockfile(struct cmd_import_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lockfile_acquire1(ctx->in_args.repodir_real,
		                      ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_import_release_lockfile(struct cmd_import_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_lockfile_release(ctx->in_args.repodir_real,
		                     ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_import_destroy_fs_ctx(struct cmd_import_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_import_finalize(struct cmd_import_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_bconf_reset(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_import_ctx = NULL;
}

static void cmd_import_atexit(void)
{
	if (cmd_import_ctx != NULL) {
		cmd_import_release_lockfile(cmd_import_ctx);
		cmd_import_finalize(cmd_import_ctx);
	}
}

static void cmd_import_start(struct cmd_import_ctx *ctx)
{
	cmd_import_ctx = ctx;
	atexit(cmd_import_atexit);
}

static void cmd_import_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_import_prepare(struct cmd_import_ctx *ctx)
{
	cmd_check_exists(ctx->in_args.repodir_name);
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, false);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_import_setup_fs_args(struct cmd_import_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.name);
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
}

static void cmd_import_load_bconf(struct cmd_import_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_import_setup_fs_ctx(struct cmd_import_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_import_open_repo(struct cmd_import_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_import_close_repo(struct cmd_import_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_import_execute(struct cmd_import_ctx *ctx)
{
	/* TODO: impl */
	(void)ctx;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_import(void)
{
	struct cmd_import_ctx ctx = {
		.fs_ctx = NULL,
		.in_fp = stdin,
	};

	/* Do all cleanups upon exits */
	cmd_import_start(&ctx);

	/* Parse command's arguments */
	cmd_import_getopt(&ctx);

	/* Verify user's arguments */
	cmd_import_prepare(&ctx);

	/* Run with signals */
	cmd_import_enable_signals();

	/* Setup input arguments */
	cmd_import_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_import_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_import_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_import_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_import_open_repo(&ctx);

	/* Do actual import */
	cmd_import_execute(&ctx);

	/* Close repository */
	cmd_import_close_repo(&ctx);

	/* Release lock */
	cmd_import_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_import_destroy_fs_ctx(&ctx);

	/* Post execution cleanups */
	cmd_import_finalize(&ctx);
}

