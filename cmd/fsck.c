/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

static const char *cmd_fsck_help_desc[] = {
	"fsck <repodir/name>",
	"",
	"options:",
	"  -V, --verbose=level          Run in verbose mode (0..3)",
	NULL
};

struct cmd_fsck_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
};

struct cmd_fsck_ctx {
	struct cmd_fsck_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_env   *fs_env;
};

static struct cmd_fsck_ctx *cmd_fsck_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_getopt(struct cmd_fsck_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("h", opts);
		if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_fsck_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_destroy_fs_env(struct cmd_fsck_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
}

static void cmd_fsck_finalize(struct cmd_fsck_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
	cmd_reset_fs_cargs(&ctx->fs_args.ca);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_fsck_ctx = NULL;
}

static void cmd_fsck_atexit(void)
{
	if (cmd_fsck_ctx != NULL) {
		cmd_fsck_finalize(cmd_fsck_ctx);
	}
}

static void cmd_fsck_start(struct cmd_fsck_ctx *ctx)
{
	cmd_fsck_ctx = ctx;
	atexit(cmd_fsck_atexit);
}

static void cmd_fsck_prepare(struct cmd_fsck_ctx *ctx)
{
	struct cmd_fsck_in_args *args = &ctx->in_args;

	cmd_check_exists(args->repodir_name);
	cmd_check_isreg(args->repodir_name, false);
	cmd_split_path(args->repodir_name, &args->repodir, &args->name);
	cmd_check_nonemptydir(args->repodir, false);
	cmd_realpath(args->repodir, &args->repodir_real);
	cmd_check_repopath(args->repodir_real);
	cmd_check_fsname(args->name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_setup_fs_args(struct cmd_fsck_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;
	const char *repodir = ctx->in_args.repodir_real;
	const char *name = ctx->in_args.name;

	cmd_init_fs_args(fs_args);
	cmd_load_fs_cargs_for(&fs_args->ca, false, repodir, name);
	fs_args->repodir = repodir;
	fs_args->name = name;
}

static void cmd_fsck_setup_fs_env(struct cmd_fsck_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}


static void cmd_fsck_open_repo(struct cmd_fsck_ctx *ctx)
{
	cmd_open_repo(ctx->fs_env);
}

static void cmd_fsck_require_bsec(struct cmd_fsck_ctx *ctx)
{
	cmd_require_fs(ctx->fs_env, true, &ctx->fs_args.ca.uuid);
}

static void cmd_fsck_boot_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_env, &ctx->fs_args.ca.uuid);
}

static void cmd_fsck_open_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_open_fs(ctx->fs_env);
}

static void cmd_fsck_execute(struct cmd_fsck_ctx *ctx)
{
	cmd_inspect_fs(ctx->fs_env);
}

static void cmd_fsck_close_repo(struct cmd_fsck_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_fsck(void)
{
	struct cmd_fsck_ctx ctx = {
		.fs_env = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_fsck_start(&ctx);

	/* Parse command's arguments */
	cmd_fsck_getopt(&ctx);

	/* Verify user's arguments */
	cmd_fsck_prepare(&ctx);

	/* Load-require boot-params */
	cmd_fsck_setup_fs_args(&ctx);

	/* Setup execution environment */
	cmd_fsck_setup_fs_env(&ctx);

	/* Open repository */
	cmd_fsck_open_repo(&ctx);

	/* Require source bootsec */
	cmd_fsck_require_bsec(&ctx);

	/* Require boot + lock-able file-system */
	cmd_fsck_boot_fs(&ctx);

	/* Open file-system */
	cmd_fsck_open_fs(&ctx);

	/* Do actual fsck */
	cmd_fsck_execute(&ctx);

	/* Close repository */
	cmd_fsck_close_repo(&ctx);

	/* Destroy environment instance */
	cmd_fsck_destroy_fs_env(&ctx);

	/* Post execution cleanups */
	cmd_fsck_finalize(&ctx);
}

