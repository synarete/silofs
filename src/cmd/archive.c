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

static const char *cmd_archive_help_desc[] = {
	"archive <repodir/srcname> <packdir/dstname>",
	"",
	"options:",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_archive_in_args {
	char   *repodir_srcname;
	char   *repodir;
	char   *repodir_real;
	char   *srcname;
	char   *packdir_dstname;
	char   *packdir;
	char   *packdir_real;
	char   *dstname;
	char   *password;
	bool    no_prompt;
};

struct cmd_archive_ctx {
	struct cmd_archive_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	bool has_lockfile;
};

static struct cmd_archive_ctx *cmd_archive_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_archive_getopt(struct cmd_archive_ctx *ctx)
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
			cmd_print_help_and_exit(cmd_archive_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_getopt_getarg("repodir/srcname", &ctx->in_args.repodir_srcname);
	cmd_getopt_getarg("packdir/dstname", &ctx->in_args.packdir_dstname);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_archive_acquire_lockfile(struct cmd_archive_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real,
		            ctx->in_args.srcname);
		ctx->has_lockfile = true;
	}
}

static void cmd_archive_release_lockfile(struct cmd_archive_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real,
		              ctx->in_args.srcname);
		ctx->has_lockfile = false;
	}
}

static void cmd_archive_destroy_fs_ctx(struct cmd_archive_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_archive_finalize(struct cmd_archive_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_bconf_reset_ids(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_srcname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.srcname);
	cmd_pstrfree(&ctx->in_args.packdir_dstname);
	cmd_pstrfree(&ctx->in_args.packdir);
	cmd_pstrfree(&ctx->in_args.packdir_real);
	cmd_pstrfree(&ctx->in_args.dstname);
	cmd_delpass(&ctx->in_args.password);
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
	cmd_check_isreg(ctx->in_args.repodir_srcname);
	cmd_split_path(ctx->in_args.repodir_srcname,
	               &ctx->in_args.repodir, &ctx->in_args.srcname);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.srcname);
	cmd_split_path(ctx->in_args.packdir_dstname,
	               &ctx->in_args.packdir, &ctx->in_args.dstname);
	cmd_realpath_dir(ctx->in_args.packdir, &ctx->in_args.packdir_real);
	cmd_check_notexists2(ctx->in_args.packdir_real, ctx->in_args.dstname);
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

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.srcname);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.srcname;
}

static void cmd_archive_load_bconf(struct cmd_archive_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_archive_setup_fs_ctx(struct cmd_archive_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_archive_open_repo(struct cmd_archive_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_archive_close_repo(struct cmd_archive_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_archive_require_brec(struct cmd_archive_ctx *ctx)
{
	cmd_require_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_archive_boot_fs(struct cmd_archive_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_archive_open_fs(struct cmd_archive_ctx *ctx)
{
	cmd_open_fs(ctx->fs_ctx);
}

static void cmd_archive_close_fs(struct cmd_archive_ctx *ctx)
{
	cmd_close_fs(ctx->fs_ctx);
}

static void cmd_archive_execute(struct cmd_archive_ctx *ctx)
{
	struct silofs_fs_bconf bconf;

	cmd_bconf_assign(&bconf, &ctx->fs_args.bconf);
	cmd_bconf_set_name(&bconf, ctx->in_args.dstname);
	cmd_archive_fs(ctx->fs_ctx, ctx->in_args.packdir_real, &bconf.pack_id);
	cmd_bconf_save(&bconf, ctx->in_args.packdir_real);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_archive(void)
{
	struct cmd_archive_ctx ctx = {
		.fs_ctx = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_archive_start(&ctx);

	/* Parse command's arguments */
	cmd_archive_getopt(&ctx);

	/* Verify user's arguments */
	cmd_archive_prepare(&ctx);

	/* Require password */
	cmd_archive_getpass(&ctx);

	/* Run with signals */
	cmd_archive_enable_signals();

	/* Setup input arguments */
	cmd_archive_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_archive_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_archive_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_archive_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_archive_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_archive_require_brec(&ctx);

	/* Require boot-able file-system */
	cmd_archive_boot_fs(&ctx);

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
	cmd_archive_destroy_fs_ctx(&ctx);

	/* Post execution cleanups */
	cmd_archive_finalize(&ctx);
}

