/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

static const char *cmd_rmfs_help_desc[] = {
	"rmfs <repodir/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

struct cmd_rmfs_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *password;
};

struct cmd_rmfs_ctx {
	struct cmd_rmfs_in_args in_args;
	struct silofs_fs_args     fs_args;
	struct silofs_fs_env     *fs_env;
	int                       lock_fd;
};

static struct cmd_rmfs_ctx *cmd_rmfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_rmfs_getopt(struct cmd_rmfs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "password", required_argument, NULL, 'p' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("p:V:h", opts);
		if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_rmfs_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_rmfs_prepare(struct cmd_rmfs_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, true);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_rmfs_getpass(struct cmd_rmfs_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass(NULL, &ctx->in_args.password);
	}
}

static void cmd_rmfs_lock_fs(struct cmd_rmfs_ctx *ctx)
{
	cmd_lockf(ctx->in_args.repodir_real,
	          ctx->in_args.name, &ctx->lock_fd);
}

static void cmd_rmfs_setup_fs_args(struct cmd_rmfs_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
	fs_args->passwd = ctx->in_args.password;
}

static void cmd_rmfs_load_ids(struct cmd_rmfs_ctx *ctx)
{
	cmd_load_fs_uuid(&ctx->fs_args.uuid,
	                 ctx->in_args.repodir_real, ctx->in_args.name);
	cmd_reset_ids(&ctx->fs_args.ids);
	cmd_load_fs_idsmap(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

static void cmd_rmfs_setup_fs_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}

static void cmd_rmfs_open_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_open_repo(ctx->fs_env);
}

static void cmd_rmfs_close_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

static void cmd_rmfs_require_bsec(struct cmd_rmfs_ctx *ctx)
{
	cmd_require_fs(ctx->fs_env, &ctx->fs_args.uuid);
}

static void cmd_rmfs_execute(struct cmd_rmfs_ctx *ctx)
{
	cmd_unref_fs(ctx->fs_env, &ctx->fs_args.uuid);
}

static void cmd_rmfs_unlink_fsargs(struct cmd_rmfs_ctx *ctx)
{
	cmd_unlink_fs_uuid(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_rmfs_destroy_fs_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
}

static void cmd_rmfs_finalize(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_destroy_fs_env(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_unlockf(&ctx->lock_fd);
	cmd_rmfs_ctx = NULL;
}

static void cmd_rmfs_atexit(void)
{
	if (cmd_rmfs_ctx != NULL) {
		cmd_rmfs_finalize(cmd_rmfs_ctx);
	}
}

static void cmd_rmfs_start(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_ctx = ctx;
	atexit(cmd_rmfs_atexit);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_rmfs(void)
{
	struct cmd_rmfs_ctx ctx = {
		.lock_fd = -1,
	};

	/* Do all cleanups upon exits */
	cmd_rmfs_start(&ctx);

	/* Parse command's arguments */
	cmd_rmfs_getopt(&ctx);

	/* Verify user's arguments */
	cmd_rmfs_prepare(&ctx);

	/* Require password */
	cmd_rmfs_getpass(&ctx);

	/* Require lockable */
	cmd_rmfs_lock_fs(&ctx);

	/* Setup input arguments */
	cmd_rmfs_setup_fs_args(&ctx);

	/* Require ids-map */
	cmd_rmfs_load_ids(&ctx);

	/* Setup execution context */
	cmd_rmfs_setup_fs_env(&ctx);

	/* Open-validate repository */
	cmd_rmfs_open_repo(&ctx);

	/* Require valid reference */
	cmd_rmfs_require_bsec(&ctx);

	/* Do actual blobs deletion*/
	cmd_rmfs_execute(&ctx);

	/* Unlink boot-configuration */
	cmd_rmfs_unlink_fsargs(&ctx);

	/* Close repository */
	cmd_rmfs_close_repo(&ctx);

	/* Post execution cleanups */
	cmd_rmfs_finalize(&ctx);
}
