/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "cmd.h"

static const char *cmd_prune_help_desc =
	"prune [options] <repodir>                                       \n"
	"                                                                \n";

struct cmd_prune_in_args {
	char *repodir;
	char *repodir_real;
};

struct cmd_prune_ctx {
	struct cmd_prune_in_args in_args;
	struct silofs_fsenv *fsenv;
};

static struct cmd_prune_ctx *cmd_prune_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_prune_parse_optargs(struct cmd_prune_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "help", 'h', 0 },
		{ NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'h':
			cmd_print_help_and_exit(cmd_prune_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	ctx->in_args.repodir = cmd_optargs_getarg(&opa, "repodir");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_prune_finalize(struct cmd_prune_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_prune_ctx = NULL;
}

static void cmd_prune_atexit(void)
{
	if (cmd_prune_ctx != NULL) {
		cmd_prune_finalize(cmd_prune_ctx);
	}
}

static void cmd_prune_start(struct cmd_prune_ctx *ctx)
{
	cmd_prune_ctx = ctx;
	atexit(cmd_prune_atexit);
}

static void cmd_prune_prepare(struct cmd_prune_ctx *ctx)
{
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir(ctx->in_args.repodir_real);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*
 * TODO-0050: Implement prune
 *
 * Prune repository under full locking.
 */

void cmd_execute_prune(void)
{
	struct cmd_prune_ctx ctx = {
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_prune_start(&ctx);

	/* Parse command's arguments */
	cmd_prune_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_prune_prepare(&ctx);

	/* TODO: execute logic... */

	/* Post execution cleanups */
	cmd_prune_finalize(&ctx);
}
