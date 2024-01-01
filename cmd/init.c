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

static const char *cmd_init_help_desc[] = {
	"init <repodir>",
	"",
	"options:",
	"  -L, --loglevel=LEVEL         Logging level (rfc5424)",
	NULL
};

struct cmd_init_in_args {
	char   *repodir;
	char   *repodir_real;
};

struct cmd_init_ctx {
	struct cmd_init_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
};

static struct cmd_init_ctx *cmd_init_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_getopt(struct cmd_init_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("L:h", opts);
		if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_init_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir", &ctx->in_args.repodir);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_finalize(struct cmd_init_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_iconf_reset(&ctx->fs_args.iconf);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_init_ctx = NULL;
}

static void cmd_init_atexit(void)
{
	if (cmd_init_ctx != NULL) {
		cmd_init_finalize(cmd_init_ctx);
	}
}

static void cmd_init_start(struct cmd_init_ctx *ctx)
{
	cmd_init_ctx = ctx;
	atexit(cmd_init_atexit);
}

static void cmd_init_prepare(struct cmd_init_ctx *ctx)
{
	struct stat st;
	int err;

	err = silofs_sys_stat(ctx->in_args.repodir, &st);
	if (err == 0) {
		cmd_check_emptydir(ctx->in_args.repodir, true);
	} else if (err == -ENOENT) {
		cmd_mkdir(ctx->in_args.repodir, 0700);
	} else {
		cmd_dief(err, "stat failure: %s", ctx->in_args.repodir);
	}
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
}

static void cmd_init_setup_fs_args(struct cmd_init_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;
	const char *name = "silofs";

	cmd_init_fs_args(fs_args);
	cmd_iconf_set_name(&fs_args->iconf, name);
	ctx->fs_args.repodir = ctx->in_args.repodir_real;
	ctx->fs_args.name = name;
}

static void cmd_init_setup_fs_ctx(struct cmd_init_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_init_format_repo(const struct cmd_init_ctx *ctx)
{
	cmd_format_repo(ctx->fs_ctx);
}

static void cmd_init_close_repo(const struct cmd_init_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_init(void)
{
	struct cmd_init_ctx ctx = { .fs_ctx = NULL };

	/* Do all cleanups upon exits */
	cmd_init_start(&ctx);

	/* Parse command's arguments */
	cmd_init_getopt(&ctx);

	/* Verify user's arguments */
	cmd_init_prepare(&ctx);

	/* Setup input arguments */
	cmd_init_setup_fs_args(&ctx);

	/* Prepare environment */
	cmd_init_setup_fs_ctx(&ctx);

	/* Format repository layout */
	cmd_init_format_repo(&ctx);

	/* Post-format cleanups */
	cmd_init_close_repo(&ctx);

	/* Post execution cleanups */
	cmd_init_finalize(&ctx);
}

