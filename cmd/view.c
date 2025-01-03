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

static const char *cmd_view_help_desc =
	"view <repodir/name>                                             \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_view_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *password;
	char *outfile;
	bool no_prompt;
};

struct cmd_view_ctx {
	struct cmd_view_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	FILE *out_fp;
	bool has_lockfile;
};

static struct cmd_view_ctx *cmd_view_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_view_parse_optargs(struct cmd_view_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "password", 'p', 1 }, { "no-prompt", 'P', 0 },
		{ "loglevel", 'L', 1 }, { "help", 'h', 0 },
		{ NULL, 0, 0 },
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

	ctx->in_args.repodir_name = cmd_optargs_getarg(&opa, "repodir/name");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_view_acquire_lockfile(struct cmd_view_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_view_release_lockfile(struct cmd_view_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_view_destroy_fsenv(struct cmd_view_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_view_finalize(struct cmd_view_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.outfile);
	cmd_delpass(&ctx->in_args.password);
	cmd_fini_fs_args(&ctx->fs_args);
	cmd_view_ctx = NULL;
}

static void cmd_view_atexit(void)
{
	if (cmd_view_ctx != NULL) {
		cmd_view_release_lockfile(cmd_view_ctx);
		cmd_view_finalize(cmd_view_ctx);
	}
}

static void cmd_view_start(struct cmd_view_ctx *ctx)
{
	cmd_view_ctx = ctx;
	atexit(cmd_view_atexit);
}

static void cmd_view_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_view_prepare(struct cmd_view_ctx *ctx)
{
	cmd_check_exists(ctx->in_args.repodir_name);
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
	               &ctx->in_args.name);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_view_getpass(struct cmd_view_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_view_setup_fs_args(struct cmd_view_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init(fs_args);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = ctx->in_args.name;
	fs_args->bref.passwd = ctx->in_args.password;
}

static void cmd_view_setup_fs_ids(struct cmd_view_ctx *ctx)
{
	cmd_fs_ids_load(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

static void cmd_view_load_bref(struct cmd_view_ctx *ctx)
{
	cmd_bootref_load(&ctx->fs_args.bref);
}

static void cmd_view_setup_fsenv(struct cmd_view_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_view_open_repo(struct cmd_view_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_view_close_repo(struct cmd_view_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_view_poke_fs(struct cmd_view_ctx *ctx)
{
	cmd_poke_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_view_open_fs(struct cmd_view_ctx *ctx)
{
	cmd_open_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_view_close_fs(struct cmd_view_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

static void cmd_view_show_laddr(const struct cmd_view_ctx *ctx,
                                const struct silofs_laddr *laddr)
{
	struct silofs_strbuf sbuf;
	FILE *fp = ctx->out_fp;

	silofs_laddr_to_ascii(laddr, &sbuf);
	fputs(sbuf.str, fp);
	fputs("\n", fp);
	fflush(fp);
}

static int cmd_view_cb(void *user_ctx, const struct silofs_laddr *laddr)
{
	cmd_view_show_laddr(user_ctx, laddr);
	return 0;
}

static void cmd_view_execute(struct cmd_view_ctx *ctx)
{
	cmd_inspect_fs(ctx->fsenv, cmd_view_cb, ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_view(void)
{
	struct cmd_view_ctx ctx = {
		.fsenv = NULL,
		.out_fp = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_view_start(&ctx);

	/* Parse command's arguments */
	cmd_view_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_view_prepare(&ctx);

	/* Require password */
	cmd_view_getpass(&ctx);

	/* Run with signals */
	cmd_view_enable_signals();

	/* Setup input arguments */
	cmd_view_setup_fs_args(&ctx);

	/* Load fs-ids mapping */
	cmd_view_setup_fs_ids(&ctx);

	/* Require fs boot-reference */
	cmd_view_load_bref(&ctx);

	/* Setup execution environment */
	cmd_view_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_view_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_view_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_view_poke_fs(&ctx);

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
	cmd_view_destroy_fsenv(&ctx);

	/* Post execution cleanups */
	cmd_view_finalize(&ctx);
}
