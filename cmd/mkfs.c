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

static const char *cmd_mkfs_help_desc[] = {
	"mkfs --size=nbytes [options] <repodir/name>",
	"",
	"options:",
	"  -s, --size=nbytes            Capacity size limit",
	"  -u, --user=username          Make username the owner of root-dir",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_mkfs_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *password;
	char *username;
	long fs_size;
};

struct cmd_mkfs_ctx {
	struct cmd_mkfs_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	bool has_lockfile;
};

static struct cmd_mkfs_ctx *cmd_mkfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_parse_optargs(struct cmd_mkfs_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "size", 's', 1 },     { "user", 'u', 1 },
		{ "password", 'p', 1 }, { "loglevel", 'L', 1 },
		{ "help", 'h', 0 },     { NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 's':
			ctx->in_args.fs_size = cmd_optargs_curr_as_size(&opa);
			break;
		case 'u':
			ctx->in_args.username =
				cmd_optarg_dupoptarg(&opa, "user");
			break;
		case 'p':
			ctx->in_args.password = cmd_optargs_getpass(&opa);
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_mkfs_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	cmd_require_arg_size("size", ctx->in_args.fs_size);

	ctx->in_args.repodir_name = cmd_optargs_getarg(&opa, "repodir/name");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_destroy_fsenv(struct cmd_mkfs_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_mkfs_finalize(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_destroy_fsenv(ctx);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.username);
	cmd_delpass(&ctx->in_args.password);
	cmd_fini_fs_args(&ctx->fs_args);
	cmd_mkfs_ctx = NULL;
}

static void cmd_mkfs_acquire_lockfile(struct cmd_mkfs_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_mkfs_release_lockfile(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_mkfs_atexit(void)
{
	if (cmd_mkfs_ctx != NULL) {
		cmd_mkfs_release_lockfile(cmd_mkfs_ctx);
		cmd_mkfs_finalize(cmd_mkfs_ctx);
	}
}

static void cmd_mkfs_start(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_ctx = ctx;
	atexit(cmd_mkfs_atexit);
}

static void cmd_mkfs_prepare(struct cmd_mkfs_ctx *ctx)
{
	cmd_check_notdir(ctx->in_args.repodir_name);
	cmd_check_notexists(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
		       &ctx->in_args.name);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_mkfs_require_owner(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->in_args.username == NULL) {
		ctx->in_args.username = cmd_getusername();
	}
}

static void cmd_mkfs_getpass(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass2(NULL, true, &ctx->in_args.password);
	}
}

static void cmd_mkfs_setup_fs_args(struct cmd_mkfs_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init(fs_args);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = ctx->in_args.name;
	fs_args->bref.passwd = ctx->in_args.password;
	fs_args->capacity = (size_t)ctx->in_args.fs_size;
}

static void cmd_mkfs_setup_fs_ids(struct cmd_mkfs_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;
	struct silofs_fs_ids *ids = &fs_args->ids;
	const char *username = ctx->in_args.username;

	cmd_fs_ids_load(ids, ctx->in_args.repodir_real);
	cmd_require_uidgid(ids, username, &fs_args->uid, &fs_args->gid);
}

static void cmd_mkfs_setup_fsenv(struct cmd_mkfs_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_mkfs_open_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_mkfs_close_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_mkfs_format_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_format_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_mkfs_save_bref(struct cmd_mkfs_ctx *ctx)
{
	cmd_bootref_save(&ctx->fs_args.bref);
}

static void cmd_mkfs_close_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mkfs(void)
{
	struct cmd_mkfs_ctx ctx = {
		.in_args = { .fs_size = -1, },
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_mkfs_start(&ctx);

	/* Parse command's arguments */
	cmd_mkfs_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_mkfs_prepare(&ctx);

	/* Have proper file-system owner username */
	cmd_mkfs_require_owner(&ctx);

	/* Require password */
	cmd_mkfs_getpass(&ctx);

	/* Setup input arguments */
	cmd_mkfs_setup_fs_args(&ctx);

	/* Setup fs owner and ids */
	cmd_mkfs_setup_fs_ids(&ctx);

	/* Prepare environment */
	cmd_mkfs_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_mkfs_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_mkfs_open_repo(&ctx);

	/* Format file-system layer */
	cmd_mkfs_format_fs(&ctx);

	/* Save top-level fs boot-ref */
	cmd_mkfs_save_bref(&ctx);

	/* Post-format cleanups */
	cmd_mkfs_close_fs(&ctx);

	/* Close repository */
	cmd_mkfs_close_repo(&ctx);

	/* Release lock */
	cmd_mkfs_release_lockfile(&ctx);

	/* Post execution cleanups */
	cmd_mkfs_finalize(&ctx);
}
