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

static const char *const cmd_fsck_help_desc =
	"fsck <repodir/name>                                             \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_fsck_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *password;
	bool no_prompt;
};

struct cmd_fsck_ctx {
	struct cmd_fsck_in_args in_args;
	struct silofs_spec spec;
	struct silofs_env *env;
	bool has_lockfile;
};

static struct cmd_fsck_ctx *cmd_fsck_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_parse_optargs(struct cmd_fsck_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "no-prompt", 'P', 0 },
		{ "loglevel", 'L', 1 },
		{ "help", 'h', 0 },
		{ nullptr, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'P':
			ctx->in_args.no_prompt = true;
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_fsck_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}

	ctx->in_args.repodir_name = cmd_optargs_getarg(&opa, "repodir/name");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_destroy_env(struct cmd_fsck_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
}

static void cmd_fsck_finalize(struct cmd_fsck_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
	cmd_spec_reset(&ctx->spec);
	cmd_fsck_ctx_p = nullptr;
}

static void cmd_fsck_acquire_lockfile(struct cmd_fsck_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_fsck_release_lockfile(struct cmd_fsck_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_fsck_atexit(void)
{
	struct cmd_fsck_ctx *ctx = cmd_fsck_ctx_p;

	if (ctx != nullptr) {
		cmd_fsck_release_lockfile(ctx);
		cmd_fsck_finalize(ctx);
	}
}

static void cmd_fsck_start(struct cmd_fsck_ctx *ctx)
{
	cmd_fsck_ctx_p = ctx;
	cmd_atexit(cmd_fsck_atexit);
}

static void cmd_fsck_prepare(struct cmd_fsck_ctx *ctx)
{
	cmd_check_exists(ctx->in_args.repodir_name);
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_path_split(ctx->in_args.repodir_name, &ctx->in_args.repodir,
	               &ctx->in_args.name);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_fsck_getpass(struct cmd_fsck_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_fsck_setup_spec(struct cmd_fsck_ctx *ctx)
{
	cmd_spec_setup(&ctx->spec);
	cmd_spec_own_passwd(&ctx->spec, &ctx->in_args.password);
	cmd_spec_set_baseref(&ctx->spec, ctx->in_args.repodir_real,
	                     ctx->in_args.name);
}

static void cmd_fsck_load_spec(struct cmd_fsck_ctx *ctx)
{
	cmd_spec_jload(&ctx->spec);
}

static void cmd_fsck_setup_env(struct cmd_fsck_ctx *ctx)
{
	cmd_env_setup(&ctx->spec, &ctx->env);
	cmd_spec_reset(&ctx->spec);
}

static void cmd_fsck_sense_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_sense_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_fsck_reload_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_reload_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_fsck_unload_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_unload_fs(ctx->env);
}

static void cmd_fsck_execute(struct cmd_fsck_ctx *ctx)
{
	cmd_inspect_fs(ctx->env, false);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_fsck(void)
{
	struct cmd_fsck_ctx ctx = {
		.env = nullptr,
	};

	/* Do all cleanups upon exits */
	cmd_fsck_start(&ctx);

	/* Parse command's arguments */
	cmd_fsck_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_fsck_prepare(&ctx);

	/* Require password */
	cmd_fsck_getpass(&ctx);

	/* Setup input arguments */
	cmd_fsck_setup_spec(&ctx);

	/* Load fs spec */
	cmd_fsck_load_spec(&ctx);

	/* Setup execution environment */
	cmd_fsck_setup_env(&ctx);

	/* Acquire lock */
	cmd_fsck_acquire_lockfile(&ctx);

	/* Require source boot-record */
	cmd_fsck_sense_fs(&ctx);

	/* Open file-system */
	cmd_fsck_reload_fs(&ctx);

	/* Do actual fsck */
	cmd_fsck_execute(&ctx);

	/* Close file-system and caches */
	cmd_fsck_unload_fs(&ctx);

	/* Release lock */
	cmd_fsck_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_fsck_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_fsck_finalize(&ctx);
}
