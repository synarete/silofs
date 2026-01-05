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

static const char *const cmd_view_help_desc =
	"view <repodir/fsname>                                           \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_view_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *password;
	char *outfile;
	bool  no_prompt;
};

struct cmd_view_ctx {
	struct cmd_view_in_args in_args;
	struct silofs_fsref     fsref;
	struct silofs_env_args  env_args;
	struct silofs_env      *env;
	FILE                   *out_fp;
	bool                    has_lockfile;
};

static struct cmd_view_ctx *cmd_view_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_view_parse_optargs(struct cmd_view_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "password", 'p', 1 }, { "no-prompt", 'P', 0 },
		{ "loglevel", 'L', 1 }, { "help", 'h', 0 },
		{ nullptr, 0, 0 },
	};
	struct cmd_optargs opa;
	int                opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'P':
			ctx->in_args.no_prompt = true;
			break;
		case 'p':
			ctx->in_args.password = cmd_optargs_getpass(&opa);
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_view_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}

	ctx->in_args.repodir_fsname =
		cmd_optargs_getarg(&opa, "repodir/fsname");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_view_acquire_lockfile(struct cmd_view_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = true;
	}
}

static void cmd_view_release_lockfile(struct cmd_view_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = false;
	}
}

static void cmd_view_destroy_env(struct cmd_view_ctx *ctx)
{
	cmd_del_env(&ctx->env);
}

static void cmd_view_finalize(struct cmd_view_ctx *ctx)
{
	cmd_del_env(&ctx->env);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.outfile);
	cmd_delpass(&ctx->in_args.password);
	cmd_destroy_env_args(&ctx->env_args);
	cmd_view_ctx_p = nullptr;
}

static void cmd_view_atexit(void)
{
	struct cmd_view_ctx *ctx = cmd_view_ctx_p;

	if (ctx != nullptr) {
		cmd_view_release_lockfile(ctx);
		cmd_view_finalize(ctx);
	}
}

static void cmd_view_start(struct cmd_view_ctx *ctx)
{
	cmd_view_ctx_p = ctx;
	cmd_atexit(cmd_view_atexit);
}

static void cmd_view_enable_signals(void)
{
	cmd_register_sigactions(nullptr);
}

static void cmd_view_prepare(struct cmd_view_ctx *ctx)
{
	cmd_check_exists(ctx->in_args.repodir_fsname);
	cmd_check_isreg(ctx->in_args.repodir_fsname);
	cmd_split_path(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
}

static void cmd_view_restrict_process(struct cmd_view_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, false);
}

static void cmd_view_getpass(struct cmd_view_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_view_setup_env_args(struct cmd_view_ctx *ctx)
{
	struct silofs_env_args *env_args = &ctx->env_args;

	cmd_setup_env_args(env_args);
	env_args->boot_args.ref[0].repodir = ctx->in_args.repodir_real;
	env_args->boot_args.ref[0].refname = ctx->in_args.fsname;
	env_args->boot_args.passwd         = ctx->in_args.password;
}

static void cmd_view_load_fsids(struct cmd_view_ctx *ctx)
{
	cmd_fsids_load(&ctx->env_args.fsids, &ctx->env_args.boot_args.ref[0]);
}

static void cmd_view_load_fsref(struct cmd_view_ctx *ctx)
{
	cmd_fsref_load(&ctx->fsref, &ctx->env_args.boot_args.ref[0]);
}

static void cmd_view_setup_env(struct cmd_view_ctx *ctx)
{
	cmd_new_env(&ctx->env_args, &ctx->env);
	cmd_fsids_clear(&ctx->env_args.fsids);
	cmd_delpass(&ctx->in_args.password);
}

static void cmd_view_open_repo(struct cmd_view_ctx *ctx)
{
	cmd_open_repo(ctx->env);
}

static void cmd_view_close_repo(struct cmd_view_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

static void cmd_view_sense_fs(struct cmd_view_ctx *ctx)
{
	cmd_sense_fs(ctx->env, &ctx->fsref);
}

static void cmd_view_open_fs(struct cmd_view_ctx *ctx)
{
	cmd_open_fs(ctx->env, &ctx->fsref);
}

static void cmd_view_close_fs(struct cmd_view_ctx *ctx)
{
	cmd_close_fs(ctx->env);
}

static void cmd_view_execute(struct cmd_view_ctx *ctx)
{
	cmd_inspect_fs(ctx->env, true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_view(void)
{
	struct cmd_view_ctx ctx = {
		.env    = nullptr,
		.out_fp = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_view_start(&ctx);

	/* Parse command's arguments */
	cmd_view_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_view_prepare(&ctx);

	/* Restrict process access */
	cmd_view_restrict_process(&ctx);

	/* Require password */
	cmd_view_getpass(&ctx);

	/* Run with signals */
	cmd_view_enable_signals();

	/* Setup input arguments */
	cmd_view_setup_env_args(&ctx);

	/* Load fs-ids mapping */
	cmd_view_load_fsids(&ctx);

	/* Require fs boot-reference */
	cmd_view_load_fsref(&ctx);

	/* Setup execution environment */
	cmd_view_setup_env(&ctx);

	/* Acquire lock */
	cmd_view_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_view_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_view_sense_fs(&ctx);

	/* Open file-system */
	cmd_view_open_fs(&ctx);

	/* Do actual view */
	cmd_view_execute(&ctx);

	/* Close file-system */
	cmd_view_close_fs(&ctx);

	/* Close repository */
	cmd_view_close_repo(&ctx);

	/* Release lock */
	cmd_view_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_view_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_view_finalize(&ctx);
}
