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

static const char *cmd_fsck_help_desc[] = {
	"fsck <repodir/name>", "",
	"options:", "  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_fsck_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *password;
	bool no_prompt;
};

struct cmd_fsck_ctx {
	struct cmd_fsck_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	bool has_lockfile;
};

static struct cmd_fsck_ctx *cmd_fsck_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fsck_parse_optargs(struct cmd_fsck_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "no-prompt", 'P', 0 },
		{ "loglevel", 'L', 1 },
		{ "help", 'h', 0 },
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
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_fsck_help_desc);
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

static void cmd_fsck_destroy_fsenv(struct cmd_fsck_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_fsck_finalize(struct cmd_fsck_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
	cmd_fini_fs_args(&ctx->fs_args);
	cmd_fsck_ctx = NULL;
}

static void cmd_fsck_acquire_lockfile(struct cmd_fsck_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_fsck_release_lockfile(struct cmd_fsck_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_fsck_atexit(void)
{
	if (cmd_fsck_ctx != NULL) {
		cmd_fsck_release_lockfile(cmd_fsck_ctx);
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
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
		       &ctx->in_args.name);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_fsck_getpass(struct cmd_fsck_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
				   &ctx->in_args.password);
	}
}

static void cmd_fsck_setup_fs_args(struct cmd_fsck_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init(fs_args);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = ctx->in_args.name;
	fs_args->bref.passwd = ctx->in_args.password;
}

static void cmd_fsck_setup_fs_ids(struct cmd_fsck_ctx *ctx)
{
	cmd_fs_ids_load(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

static void cmd_fsck_load_bref(struct cmd_fsck_ctx *ctx)
{
	cmd_bootref_load(&ctx->fs_args.bref);
}

static void cmd_fsck_setup_fsenv(struct cmd_fsck_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_fsck_open_repo(struct cmd_fsck_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_fsck_poke_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_poke_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_fsck_open_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_open_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_fsck_close_fs(struct cmd_fsck_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

static void cmd_fsck_execute(struct cmd_fsck_ctx *ctx)
{
	cmd_inspect_fs(ctx->fsenv, NULL, NULL);
}

static void cmd_fsck_close_repo(struct cmd_fsck_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_fsck(void)
{
	struct cmd_fsck_ctx ctx = {
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_fsck_start(&ctx);

	/* Parse command's arguments */
	cmd_fsck_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_fsck_prepare(&ctx);

	/* Require password */
	cmd_fsck_getpass(&ctx);

	/* Setup input arguments */
	cmd_fsck_setup_fs_args(&ctx);

	/* Load fs-ids mapping */
	cmd_fsck_setup_fs_ids(&ctx);

	/* Load fs boot-reference */
	cmd_fsck_load_bref(&ctx);

	/* Setup execution environment */
	cmd_fsck_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_fsck_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_fsck_open_repo(&ctx);

	/* Require source boot-record */
	cmd_fsck_poke_fs(&ctx);

	/* Open file-system */
	cmd_fsck_open_fs(&ctx);

	/* Do actual fsck */
	cmd_fsck_execute(&ctx);

	/* Close file-system and caches */
	cmd_fsck_close_fs(&ctx);

	/* Close repository */
	cmd_fsck_close_repo(&ctx);

	/* Release lock */
	cmd_fsck_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_fsck_destroy_fsenv(&ctx);

	/* Post execution cleanups */
	cmd_fsck_finalize(&ctx);
}
