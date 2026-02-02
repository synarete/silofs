/*\ SPDX-License-Identifier: GPL-3.0-or-later */
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

static const char *const cmd_preserve_help_desc =
	"preserve <repodir/fsname> --into=<arname>                        \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -n, --into=arname            Result preserve name              \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_preserve_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *arname;
	char *password;
	bool no_prompt;
};

struct cmd_preserve_ctx {
	struct cmd_preserve_in_args in_args;
	struct silofs_spec spec;
	struct silofs_fsref ar_fsref;
	struct silofs_env *env;
	bool has_lockfile;
};

static struct cmd_preserve_ctx *cmd_preserve_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_preserve_parse_optargs(struct cmd_preserve_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "into", 'n', 1 },      //
		{ "password", 'p', 1 },  //
		{ "no-prompt", 'P', 0 }, //
		{ "loglevel", 'L', 1 },  //
		{ "help", 'h', 0 },      //
		{ nullptr, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'n':
			ctx->in_args.arname =
				cmd_optarg_getcurr2(&opa, "into");
			break;
		case 'p':
			ctx->in_args.password = cmd_optargs_getpass(&opa);
			break;
		case 'P':
			ctx->in_args.no_prompt = true;
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_preserve_help_desc);
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

static void cmd_preserve_acquire_lockfile(struct cmd_preserve_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = true;
	}
}

static void cmd_preserve_release_lockfile(struct cmd_preserve_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = false;
	}
}

static void cmd_preserve_destroy_env(struct cmd_preserve_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
}

static void cmd_preserve_finalize(struct cmd_preserve_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_delpass(&ctx->in_args.password);
	cmd_spec_reset(&ctx->spec);
	cmd_preserve_ctx_p = nullptr;
}

static void cmd_preserve_atexit(void)
{
	struct cmd_preserve_ctx *ctx = cmd_preserve_ctx_p;

	if (ctx != nullptr) {
		cmd_preserve_release_lockfile(ctx);
		cmd_preserve_finalize(ctx);
	}
}

static void cmd_preserve_start(struct cmd_preserve_ctx *ctx)
{
	cmd_preserve_ctx_p = ctx;
	cmd_atexit(cmd_preserve_atexit);
}

static void cmd_preserve_enable_signals(void)
{
	cmd_register_sigactions(nullptr);
}

static void cmd_preserve_prepare(struct cmd_preserve_ctx *ctx)
{
	cmd_check_fsname(ctx->in_args.arname);
	cmd_check_isreg(ctx->in_args.repodir_fsname);
	cmd_path_split(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.arname);
}

static void cmd_preserve_getpass(struct cmd_preserve_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_preserve_setup_spec(struct cmd_preserve_ctx *ctx)
{
	cmd_spec_setup(&ctx->spec);
	cmd_spec_own_passwd(&ctx->spec, &ctx->in_args.password);
	cmd_spec_set_baseref(&ctx->spec, ctx->in_args.repodir_real,
	                     ctx->in_args.fsname);
	cmd_spec_set_baseref2(&ctx->spec, ctx->in_args.repodir_real,
	                      ctx->in_args.arname);
}

static void cmd_preserve_load_spec(struct cmd_preserve_ctx *ctx)
{
	cmd_spec_jload(&ctx->spec);
}

static void cmd_preserve_setup_env(struct cmd_preserve_ctx *ctx)
{
	cmd_env_setup(&ctx->spec, &ctx->env);
}

static void cmd_preserve_sense_fs(struct cmd_preserve_ctx *ctx)
{
	cmd_sense_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_preserve_reload_fs(struct cmd_preserve_ctx *ctx)
{
	cmd_reload_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_preserve_unload_fs(struct cmd_preserve_ctx *ctx)
{
	cmd_unload_fs(ctx->env);
}

static void cmd_preserve_execute(struct cmd_preserve_ctx *ctx)
{
	cmd_preserve_fs(ctx->env, &ctx->spec.fsref, &ctx->ar_fsref);
}

static void cmd_preserve_save_spec(struct cmd_preserve_ctx *ctx)
{
	cmd_spec_update_fsref(&ctx->spec, &ctx->ar_fsref);
	cmd_spec_jsave2(&ctx->spec);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_preserve(void)
{
	struct cmd_preserve_ctx ctx = {
		.env = nullptr,
	};

	/* Do all cleanups upon exits */
	cmd_preserve_start(&ctx);

	/* Parse command's arguments */
	cmd_preserve_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_preserve_prepare(&ctx);

	/* Require password */
	cmd_preserve_getpass(&ctx);

	/* Run with signals */
	cmd_preserve_enable_signals();

	/* Setup input arguments */
	cmd_preserve_setup_spec(&ctx);

	/* Load fs spec */
	cmd_preserve_load_spec(&ctx);

	/* Setup execution environment */
	cmd_preserve_setup_env(&ctx);

	/* Acquire lock */
	cmd_preserve_acquire_lockfile(&ctx);

	/* Require valid boot-record */
	cmd_preserve_sense_fs(&ctx);

	/* Open file-system */
	cmd_preserve_reload_fs(&ctx);

	/* Do actual preserve */
	cmd_preserve_execute(&ctx);

	/* Save new fs spec */
	cmd_preserve_save_spec(&ctx);

	/* Unload file-system */
	cmd_preserve_unload_fs(&ctx);

	/* Release lock */
	cmd_preserve_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_preserve_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_preserve_finalize(&ctx);
}
