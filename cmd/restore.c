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
#define _GNU_SOURCE 1
#include "cmd.h"

static const char *cmd_restore_help_desc =
	"restore <repodir/name> --from=<arname>                          \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -n, --from=arname            Source archive name              \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_restore_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *arname;
	char *password;
	bool no_prompt;
};

struct cmd_restore_ctx {
	struct cmd_restore_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	bool has_lockfile;
};

static struct cmd_restore_ctx *cmd_restore_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_parse_optargs(struct cmd_restore_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "from", 'n', 1 },      { "password", 'p', 1 },
		{ "no-prompt", 'P', 0 }, { "loglevel", 'L', 1 },
		{ "help", 'h', 0 },      { NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

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

	ctx->in_args.repodir_name = cmd_optargs_getarg(&opa, "repodir/name");
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
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_restore_destroy_fsenv(struct cmd_restore_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_restore_finalize(struct cmd_restore_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
	cmd_fini_fs_args(&ctx->fs_args);
	cmd_restore_ctx = NULL;
}

static void cmd_restore_atexit(void)
{
	if (cmd_restore_ctx != NULL) {
		cmd_restore_release_lockfile(cmd_restore_ctx);
		cmd_restore_finalize(cmd_restore_ctx);
	}
}

static void cmd_restore_start(struct cmd_restore_ctx *ctx)
{
	cmd_restore_ctx = ctx;
	atexit(cmd_restore_atexit);
}

static void cmd_restore_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_restore_prepare(struct cmd_restore_ctx *ctx)
{
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
	               &ctx->in_args.name);
	cmd_check_fsname(ctx->in_args.name);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.arname);
	cmd_check_isreg2(ctx->in_args.repodir_real, ctx->in_args.arname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_restore_getpass(struct cmd_restore_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_restore_setup_fs_args(struct cmd_restore_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init(fs_args);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = ctx->in_args.arname;
	fs_args->bref.passwd = ctx->in_args.password;
}

static void cmd_restore_load_bref(struct cmd_restore_ctx *ctx)
{
	cmd_bootref_load_ar(&ctx->fs_args.bref);
}

static void cmd_restore_setup_fsenv(struct cmd_restore_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_restore_open_repo(struct cmd_restore_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_restore_close_repo(struct cmd_restore_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_restore_poke_archive(struct cmd_restore_ctx *ctx)
{
	cmd_poke_archive(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_restore_execute(struct cmd_restore_ctx *ctx)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };

	cmd_restore_fs(ctx->fsenv, &caddr);
	cmd_bootref_resave(&ctx->fs_args.bref, &caddr, ctx->in_args.name);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_restore(void)
{
	struct cmd_restore_ctx ctx = {
		.fsenv = NULL,
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
	cmd_restore_setup_fs_args(&ctx);

	/* Load archive boot-reference */
	cmd_restore_load_bref(&ctx);

	/* Setup execution environment */
	cmd_restore_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_restore_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_restore_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_restore_poke_archive(&ctx);

	/* Do actual restore */
	cmd_restore_execute(&ctx);

	/* Close repository */
	cmd_restore_close_repo(&ctx);

	/* Release lock */
	cmd_restore_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_restore_destroy_fsenv(&ctx);

	/* Post execution cleanups */
	cmd_restore_finalize(&ctx);
}
