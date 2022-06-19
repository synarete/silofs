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

static const char *cmd_unrefs_help_desc[] = {
	"unrefs <repo/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

struct cmd_unrefs_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
};

struct cmd_unrefs_ctx {
	struct cmd_unrefs_args  args;
	struct silofs_bootlink  blnk;
	int lock_fd;
};

static struct cmd_unrefs_ctx *cmd_unrefs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_unrefs_getopt(struct cmd_unrefs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("V:h", opts);
		if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_unrefs_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repo/name", &ctx->args.repodir_name);
	cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_unrefs_finalize(struct cmd_unrefs_ctx *ctx)
{
	cmd_pstrfree(&ctx->args.repodir_name);
	cmd_pstrfree(&ctx->args.repodir);
	cmd_pstrfree(&ctx->args.repodir_real);
	cmd_pstrfree(&ctx->args.name);
	cmd_unlock_bpath(&ctx->blnk.bpath, &ctx->lock_fd);
}

static void cmd_unrefs_atexit(void)
{
	if (cmd_unrefs_ctx != NULL) {
		cmd_unrefs_finalize(cmd_unrefs_ctx);
	}
}

static void cmd_unrefs_start(struct cmd_unrefs_ctx *ctx)
{
	cmd_unrefs_ctx = ctx;
	atexit(cmd_unrefs_atexit);
}

static void cmd_unrefs_prepare(struct cmd_unrefs_ctx *ctx)
{
	cmd_check_reg(ctx->args.repodir_name, false);
	cmd_split_path(ctx->args.repodir_name,
	               &ctx->args.repodir, &ctx->args.name);
	cmd_check_nonemptydir(ctx->args.repodir, true);
	cmd_realpath(ctx->args.repodir, &ctx->args.repodir_real);
	cmd_check_fsname(ctx->args.name);
	cmd_setup_bpath(&ctx->blnk.bpath,
	                ctx->args.repodir_real, ctx->args.name);
	cmd_lock_bpath(&ctx->blnk.bpath, &ctx->lock_fd);
}

static void cmd_unrefs_execute(struct cmd_unrefs_ctx *ctx)
{
	cmd_load_bsec(&ctx->blnk.bpath, &ctx->blnk.bsec);
	cmd_unref_bsec(&ctx->blnk.bpath);
}

static void cmd_unrefs_finish(struct cmd_unrefs_ctx *ctx)
{
	silofs_sys_syncfs(ctx->lock_fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_unrefs(void)
{
	struct cmd_unrefs_ctx ctx = {
		.lock_fd = -1,
	};

	/* Do all cleanups upon exits */
	cmd_unrefs_start(&ctx);

	/* Parse command's arguments */
	cmd_unrefs_getopt(&ctx);

	/* Verify user's arguments */
	cmd_unrefs_prepare(&ctx);

	/* Do actual unrefs */
	cmd_unrefs_execute(&ctx);

	/* Post-unrefs cleanups */
	cmd_unrefs_finish(&ctx);

	/* Post execution cleanups */
	cmd_unrefs_finalize(&ctx);
}
