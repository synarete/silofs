/*\ SPDX-License-Identifier: GPL-3.0-or-later */
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

static const char *cmd_archive_help_desc[] = {
	"archive <repodir/name> --into=<arname>",
	"",
	"options:",
	"  -n, --into=archivename       Result archive name",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_archive_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *arname;
	char *password;
	bool no_prompt;
};

struct cmd_archive_ctx {
	struct cmd_archive_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	bool has_lockfile;
};

static struct cmd_archive_ctx *cmd_archive_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_archive_parse_optargs(struct cmd_archive_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "into", 'n', 1 },      { "password", 'p', 1 },
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
			ctx->in_args.arname =
				cmd_optarg_dupoptarg(&opa, "into");
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
			cmd_print_help_and_exit(cmd_archive_help_desc);
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

static void cmd_archive_acquire_lockfile(struct cmd_archive_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_archive_release_lockfile(struct cmd_archive_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_archive_destroy_fsenv(struct cmd_archive_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_archive_finalize(struct cmd_archive_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_delpass(&ctx->in_args.password);
	cmd_fini_fs_args(&ctx->fs_args);
	cmd_archive_ctx = NULL;
}

static void cmd_archive_atexit(void)
{
	if (cmd_archive_ctx != NULL) {
		cmd_archive_release_lockfile(cmd_archive_ctx);
		cmd_archive_finalize(cmd_archive_ctx);
	}
}

static void cmd_archive_start(struct cmd_archive_ctx *ctx)
{
	cmd_archive_ctx = ctx;
	atexit(cmd_archive_atexit);
}

static void cmd_archive_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_archive_prepare(struct cmd_archive_ctx *ctx)
{
	cmd_check_fsname(ctx->in_args.arname);
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
		       &ctx->in_args.name);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.arname);
}

static void cmd_archive_getpass(struct cmd_archive_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
				   &ctx->in_args.password);
	}
}

static void cmd_archive_setup_fs_args(struct cmd_archive_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init(fs_args);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = ctx->in_args.name;
	fs_args->bref.passwd = ctx->in_args.password;
}

static void cmd_archive_setup_fs_ids(struct cmd_archive_ctx *ctx)
{
	cmd_fs_ids_load(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

static void cmd_archive_load_bref(struct cmd_archive_ctx *ctx)
{
	cmd_bootref_load(&ctx->fs_args.bref);
}

static void cmd_archive_setup_fsenv(struct cmd_archive_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_archive_open_repo(struct cmd_archive_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_archive_close_repo(struct cmd_archive_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_archive_poke_fs(struct cmd_archive_ctx *ctx)
{
	cmd_poke_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_archive_open_fs(struct cmd_archive_ctx *ctx)
{
	cmd_open_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_archive_close_fs(struct cmd_archive_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

static void cmd_archive_execute(struct cmd_archive_ctx *ctx)
{
	struct silofs_caddr caddr;

	cmd_archive_fs(ctx->fsenv, &caddr);
	cmd_bootref_resave(&ctx->fs_args.bref, &caddr, ctx->in_args.arname);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_archive(void)
{
	struct cmd_archive_ctx ctx = {
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_archive_start(&ctx);

	/* Parse command's arguments */
	cmd_archive_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_archive_prepare(&ctx);

	/* Require password */
	cmd_archive_getpass(&ctx);

	/* Run with signals */
	cmd_archive_enable_signals();

	/* Setup input arguments */
	cmd_archive_setup_fs_args(&ctx);

	/* Load local fs ids */
	cmd_archive_setup_fs_ids(&ctx);

	/* Load fs boot-reference */
	cmd_archive_load_bref(&ctx);

	/* Setup execution environment */
	cmd_archive_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_archive_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_archive_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_archive_poke_fs(&ctx);

	/* Open file-system */
	cmd_archive_open_fs(&ctx);

	/* Do actual archive */
	cmd_archive_execute(&ctx);

	/* Close file-system */
	cmd_archive_close_fs(&ctx);

	/* Close repository */
	cmd_archive_close_repo(&ctx);

	/* Release lock */
	cmd_archive_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_archive_destroy_fsenv(&ctx);

	/* Post execution cleanups */
	cmd_archive_finalize(&ctx);
}
