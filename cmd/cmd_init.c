/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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

static const char *const cmd_init_help_desc =
	"init [<repodir>]                                              \n"
	"                                                              \n"
	"options:                                                      \n"
	"  -L, --loglevel=level         Logging level (rfc5424)        \n";

struct cmd_init_in_args {
	char *repodir;
	char *repodir_real;
};

struct cmd_init_ctx {
	struct cmd_init_in_args in_args;
	struct silofs_spec spec;
	struct silofs_env *env;
};

static struct cmd_init_ctx *cmd_init_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_parse_optargs(struct cmd_init_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "developer-mode", 'X', 0 }, //
		{ "loglevel", 'L', 1 },       //
		{ "help", 'h', 0 },           //
		{ nullptr, 0, 0 },            //
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'X':
			cmd_global_params.developer_mode = true;
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_init_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	ctx->in_args.repodir = cmd_optargs_getarg2(&opa, "repodir", ".");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_finalize(struct cmd_init_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_spec_reset(&ctx->spec);
	cmd_init_ctx_p = nullptr;
}

static void cmd_init_atexit(void)
{
	struct cmd_init_ctx *ctx = cmd_init_ctx_p;

	if (ctx != nullptr) {
		cmd_init_finalize(ctx);
	}
}

static void cmd_init_start(struct cmd_init_ctx *ctx)
{
	cmd_init_ctx_p = ctx;
	cmd_atexit(cmd_init_atexit);
}

static void cmd_init_prepare_repodir(const struct cmd_init_ctx *ctx)
{
	struct stat st = { .st_mode = 0 };
	int err;

	err = silofs_sys_stat(ctx->in_args.repodir, &st);
	if (err == -ENOENT) {
		cmd_mkdir(ctx->in_args.repodir, 0700);
	} else if (err != 0) {
		cmd_die(err, "stat failure: %s", ctx->in_args.repodir);
	}
}

static void cmd_init_prepare(struct cmd_init_ctx *ctx)
{
	cmd_init_prepare_repodir(ctx);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_emptydir(ctx->in_args.repodir_real, true);
	cmd_check_repopath(ctx->in_args.repodir_real);
}

static void cmd_init_restrict_process(struct cmd_init_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, true);
}

static void cmd_init_setup_spec(struct cmd_init_ctx *ctx)
{
	cmd_spec_setup2(&ctx->spec, SILOFS_F_NOPASSWD);
	cmd_spec_set_baseref(&ctx->spec, ctx->in_args.repodir_real, nullptr);
}

static void cmd_init_setup_env(struct cmd_init_ctx *ctx)
{
	cmd_env_setup(&ctx->spec, &ctx->env);
}

static void cmd_init_format_repo(const struct cmd_init_ctx *ctx)
{
	cmd_format_repo(ctx->env, &ctx->spec);
}

static void cmd_init_close_repo(const struct cmd_init_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_init(void)
{
	struct cmd_init_ctx ctx = { .env = nullptr };

	/* Do all cleanups upon exits */
	cmd_init_start(&ctx);

	/* Parse command's arguments */
	cmd_init_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_init_prepare(&ctx);

	/* Restrict process access */
	cmd_init_restrict_process(&ctx);

	/* Setup input arguments */
	cmd_init_setup_spec(&ctx);

	/* Prepare environment */
	cmd_init_setup_env(&ctx);

	/* Format repository layout */
	cmd_init_format_repo(&ctx);

	/* Post-format cleanups */
	cmd_init_close_repo(&ctx);

	/* Post execution cleanups */
	cmd_init_finalize(&ctx);
}
