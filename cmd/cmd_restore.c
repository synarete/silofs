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

static const char *const cmd_restore_help_desc =
	"restore <repodir/fsname> --from=<arname>                        \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -n, --from=arname            Source archive name              \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_restore_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *arname;
	char *password;
	bool  no_prompt;
};

struct cmd_restore_ctx {
	struct cmd_restore_in_args in_args;
	struct silofs_env_args     env_args;
	struct silofs_mbref        ar_mbref;
	struct silofs_mbref        fs_mbref;
	struct silofs_env         *env;
	bool                       has_lockfile;
};

static struct cmd_restore_ctx *cmd_restore_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_parse_optargs(struct cmd_restore_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "from", 'n', 1 },      //
		{ "password", 'p', 1 },  //
		{ "no-prompt", 'P', 0 }, //
		{ "loglevel", 'L', 1 },  //
		{ "help", 'h', 0 },      //
		{ nullptr, 0, 0 },       //
	};
	struct cmd_optargs opa;
	int                opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'n':
			ctx->in_args.arname = cmd_strdup(optarg);
			break;
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
			cmd_print_help_and_exit(cmd_restore_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	cmd_require_arg("arname", ctx->in_args.arname);

	ctx->in_args.repodir_fsname =
		cmd_optargs_getarg(&opa, "repodir/fsname");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_acquire_lockfile(struct cmd_restore_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.arname);
		ctx->has_lockfile = true;
	}
}

static void cmd_restore_release_lockfile(struct cmd_restore_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = false;
	}
}

static void cmd_restore_destroy_env(struct cmd_restore_ctx *ctx)
{
	cmd_del_env(&ctx->env);
}

static void cmd_restore_finalize(struct cmd_restore_ctx *ctx)
{
	cmd_del_env(&ctx->env);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_delpass(&ctx->in_args.password);
	cmd_destroy_env_args(&ctx->env_args);
	cmd_restore_ctx_p = nullptr;
}

static void cmd_restore_atexit(void)
{
	struct cmd_restore_ctx *ctx = cmd_restore_ctx_p;

	if (ctx != nullptr) {
		cmd_restore_release_lockfile(ctx);
		cmd_restore_finalize(ctx);
	}
}

static void cmd_restore_start(struct cmd_restore_ctx *ctx)
{
	cmd_restore_ctx_p = ctx;
	cmd_atexit(cmd_restore_atexit);
}

static void cmd_restore_enable_signals(void)
{
	cmd_register_sigactions(nullptr);
}

static void cmd_restore_prepare(struct cmd_restore_ctx *ctx)
{
	cmd_split_path(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_check_fsname(ctx->in_args.fsname);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.arname);
	cmd_check_isreg2(ctx->in_args.repodir_real, ctx->in_args.arname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.fsname);
}

static void cmd_restore_getpass(struct cmd_restore_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_restore_setup_env_args(struct cmd_restore_ctx *ctx)
{
	struct silofs_env_args *env_args = &ctx->env_args;

	cmd_setup_env_args(env_args);
	env_args->boot_args.repodir = ctx->in_args.repodir_real;
	env_args->boot_args.fs_name = ctx->in_args.fsname;
	env_args->boot_args.ar_name = ctx->in_args.arname;
	env_args->boot_args.passwd  = ctx->in_args.password;
}

static void cmd_restore_load_ar_blobid(struct cmd_restore_ctx *ctx)
{
	cmd_load_ar_metaref(&ctx->env_args.boot_args, &ctx->ar_mbref);
}

static void cmd_restore_setup_env(struct cmd_restore_ctx *ctx)
{
	cmd_new_env(&ctx->env_args, &ctx->env);
}

static void cmd_restore_open_repo(struct cmd_restore_ctx *ctx)
{
	cmd_open_repo(ctx->env);
}

static void cmd_restore_close_repo(struct cmd_restore_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

static void cmd_restore_sense_archive(struct cmd_restore_ctx *ctx)
{
	cmd_sense_ar(ctx->env, &ctx->ar_mbref);
}

static void cmd_restore_execute(struct cmd_restore_ctx *ctx)
{
	struct silofs_boot_args boot_args = {
		.repodir = ctx->in_args.repodir_real,
		.fs_name = ctx->in_args.fsname,
		.ar_name = ctx->in_args.arname,
	};

	cmd_restore_fs(ctx->env, &ctx->ar_mbref, &ctx->fs_mbref);
	cmd_save_fs_metaref(&boot_args, &ctx->fs_mbref);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_restore(void)
{
	struct cmd_restore_ctx ctx = {
		.env = nullptr,
	};

	/* Do all cleanups upon exits */
	cmd_restore_start(&ctx);

	/* Parse command's arguments */
	cmd_restore_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_restore_prepare(&ctx);

	/* Require password */
	cmd_restore_getpass(&ctx);

	/* Run with signals */
	cmd_restore_enable_signals();

	/* Setup input arguments */
	cmd_restore_setup_env_args(&ctx);

	/* Load archive boot-reference */
	cmd_restore_load_ar_blobid(&ctx);

	/* Setup execution environment */
	cmd_restore_setup_env(&ctx);

	/* Acquire lock */
	cmd_restore_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_restore_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_restore_sense_archive(&ctx);

	/* Do actual restore */
	cmd_restore_execute(&ctx);

	/* Close repository */
	cmd_restore_close_repo(&ctx);

	/* Release lock */
	cmd_restore_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_restore_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_restore_finalize(&ctx);
}
