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
#include "cmd.h"

static const char *cmd_view_help_desc[] = {
	"view <repodir/name>",
	"",
	"options:",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_view_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *password;
	char   *outfile;
	bool    no_prompt;
};

struct cmd_view_ctx {
	struct cmd_view_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	FILE *out_fp;
	bool has_lockfile;
};

static struct cmd_view_ctx *cmd_view_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_view_getopt(struct cmd_view_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "password", required_argument, NULL, 'p' },
		{ "no-prompt", no_argument, NULL, 'P' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("p:PL:h", opts);
		if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'P') {
			ctx->in_args.no_prompt = true;
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_view_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_getopt_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_view_acquire_lockfile(struct cmd_view_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real,
		            ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_view_release_lockfile(struct cmd_view_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real,
		              ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_view_destroy_fs_ctx(struct cmd_view_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_view_finalize(struct cmd_view_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_bconf_reset(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.outfile);
	cmd_delpass(&ctx->in_args.password);
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
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, false);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
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

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.name);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
}

static void cmd_view_load_bconf(struct cmd_view_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_view_setup_fs_ctx(struct cmd_view_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_view_open_repo(struct cmd_view_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_view_close_repo(struct cmd_view_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_view_require_brec(struct cmd_view_ctx *ctx)
{
	cmd_require_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_view_boot_fs(struct cmd_view_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_view_open_fs(struct cmd_view_ctx *ctx)
{
	cmd_open_fs(ctx->fs_ctx);
}

static void cmd_view_close_fs(struct cmd_view_ctx *ctx)
{
	cmd_close_fs(ctx->fs_ctx);
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

static void cmd_view_cb(void *user_ctx, const struct silofs_laddr *laddr)
{

	cmd_view_show_laddr(user_ctx, laddr);
}

static void cmd_view_execute(struct cmd_view_ctx *ctx)
{
	cmd_inspect_fs(ctx->fs_ctx, cmd_view_cb, ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_view(void)
{
	struct cmd_view_ctx ctx = {
		.fs_ctx = NULL,
		.out_fp = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_view_start(&ctx);

	/* Parse command's arguments */
	cmd_view_getopt(&ctx);

	/* Verify user's arguments */
	cmd_view_prepare(&ctx);

	/* Require password */
	cmd_view_getpass(&ctx);

	/* Run with signals */
	cmd_view_enable_signals();

	/* Setup input arguments */
	cmd_view_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_view_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_view_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_view_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_view_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_view_require_brec(&ctx);

	/* Require boot-able file-system */
	cmd_view_boot_fs(&ctx);

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
	cmd_view_destroy_fs_ctx(&ctx);

	/* Post execution cleanups */
	cmd_view_finalize(&ctx);
}
