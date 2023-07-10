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
	char   *password;
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
		{ "password", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("p:h", opts);
		if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'V') {
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
	cmd_iconf_reset(&ctx->fs_args.iconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
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
	cmd_check_exists(ctx->in_args.repodir_name);
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, false);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_fsck_getpass(struct cmd_fsck_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass(NULL, &ctx->in_args.password);
	}
}

static void cmd_fsck_setup_fs_args(struct cmd_fsck_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_iconf_setname(&fs_args->iconf, ctx->in_args.name);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
}

static void cmd_fsck_load_iconf(struct cmd_fsck_ctx *ctx)
{
	cmd_iconf_load(&ctx->fs_args.iconf, ctx->in_args.repodir_real);
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
	cmd_require_fs(ctx->fs_env, &ctx->fs_args.iconf.uuid);
}

static void cmd_fsck_boot_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_env, &ctx->fs_args.iconf.uuid);
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

	/* Require password */
	cmd_fsck_getpass(&ctx);

	/* Setup input arguments */
	cmd_fsck_setup_fs_args(&ctx);

	/* Require ids-map */
	cmd_fsck_load_iconf(&ctx);

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

