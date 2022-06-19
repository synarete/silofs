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

static const char *cmd_fsck_help_desc[] = {
	"fsck [options] <repo-path>",
	"",
	"options:",
	"  -v, --version                Show version and exit",
	NULL
};

struct cmd_fsck_args {
	char   *repodir;
	char   *repodir_real;
};

struct cmd_fsck_ctx {
	struct cmd_fsck_args    args;
	struct silofs_fs_env   *fse;
};

static struct cmd_fsck_ctx *cmd_fsck_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_getopt(struct cmd_fsck_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {

		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("h", opts);
		if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_fsck_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir", &ctx->args.repodir);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_finalize(struct cmd_fsck_ctx *ctx)
{
	cmd_del_env(&ctx->fse);
	cmd_pstrfree(&ctx->args.repodir_real);
	cmd_pstrfree(&ctx->args.repodir);
	cmd_fsck_ctx = NULL;
}

static void cmd_fsck_atexit(void)
{
	if (cmd_fsck_ctx != NULL) {
		cmd_fsck_finalize(cmd_fsck_ctx);
	}
}

static void cmd_fsck_start(struct cmd_fsck_ctx *ctx)
{
	cmd_fsck_ctx = ctx;
	atexit(cmd_fsck_atexit);
}

static void cmd_fsck_prepare(struct cmd_fsck_ctx *ctx)
{
	cmd_check_nonemptydir(ctx->args.repodir, true);
	cmd_realpath(ctx->args.repodir, &ctx->args.repodir_real);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_fsck(void)
{
	struct cmd_fsck_ctx ctx = {
		.fse = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_fsck_start(&ctx);

	/* Parse command's arguments */
	cmd_fsck_getopt(&ctx);

	/* Verify user's arguments */
	cmd_fsck_prepare(&ctx);

	/* TODO: execute logic... */

	/* Post execution cleanups */
	cmd_fsck_finalize(&ctx);
}

