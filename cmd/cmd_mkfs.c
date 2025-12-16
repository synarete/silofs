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

static const char *const cmd_mkfs_help_desc =
	"mkfs --size=nbytes [options] <repodir/fsname>                   \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -s, --size=nbytes            Capacity size limit              \n"
	"  -u, --user=username          Set username owner of root-dir   \n"
	"  -N, --no-utf8-names          Do not force UTF8 file names     \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_mkfs_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *password;
	char *username;
	long  fs_size;
	bool  no_utf8_names;
};

struct cmd_mkfs_ctx {
	struct cmd_mkfs_in_args in_args;
	struct silofs_env_args  env_args;
	struct silofs_blobid    fs_blobid;
	struct silofs_env      *env;
	bool                    has_lockfile;
};

static struct cmd_mkfs_ctx *cmd_mkfs_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_parse_optargs(struct cmd_mkfs_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "size", 's', 1 },           //
		{ "user", 'u', 1 },           //
		{ "password", 'p', 1 },       //
		{ "no-utf8-names", 'N', 0 },  //
		{ "developer-mode", 'X', 0 }, //
		{ "loglevel", 'L', 1 },       //
		{ "help", 'h', 0 },           //
		{ nullptr, 0, 0 },            //
	};
	struct cmd_optargs opa;
	int                opt_chr = 1;

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
		case 'N':
			ctx->in_args.no_utf8_names = true;
			break;
		case 'X':
			cmd_global_params.developer_mode = true;
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

	ctx->in_args.repodir_fsname = cmd_optargs_getarg(&opa, "repodir/name");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_destroy_env(struct cmd_mkfs_ctx *ctx)
{
	cmd_del_env(&ctx->env);
}

static void cmd_mkfs_finalize(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_destroy_env(ctx);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.username);
	cmd_delpass(&ctx->in_args.password);
	cmd_destroy_env_args(&ctx->env_args);
	cmd_mkfs_ctx_p = nullptr;
}

static void cmd_mkfs_acquire_lockfile(struct cmd_mkfs_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = true;
	}
}

static void cmd_mkfs_release_lockfile(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = false;
	}
}

static void cmd_mkfs_atexit(void)
{
	struct cmd_mkfs_ctx *ctx = cmd_mkfs_ctx_p;

	if (ctx != nullptr) {
		cmd_mkfs_release_lockfile(ctx);
		cmd_mkfs_finalize(ctx);
	}
}

static void cmd_mkfs_start(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_ctx_p = ctx;
	cmd_atexit(cmd_mkfs_atexit);
}

static void cmd_mkfs_prepare(struct cmd_mkfs_ctx *ctx)
{
	cmd_check_notdir(ctx->in_args.repodir_fsname);
	cmd_check_notexists(ctx->in_args.repodir_fsname);
	cmd_split_path(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.fsname);
}

static void cmd_mkfs_restrict_process(struct cmd_mkfs_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, false);
}

static void cmd_mkfs_require_owner(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->in_args.username == nullptr) {
		ctx->in_args.username = cmd_getusername();
	}
}

static void cmd_mkfs_getpass(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass2(nullptr, true, &ctx->in_args.password);
	}
}

static void cmd_mkfs_setup_env_args(struct cmd_mkfs_ctx *ctx)
{
	struct silofs_env_args *env_args = &ctx->env_args;

	cmd_setup_env_args(env_args);
	env_args->boot_args.repodir = ctx->in_args.repodir_real;
	env_args->boot_args.fs_name = ctx->in_args.fsname;
	env_args->boot_args.passwd  = ctx->in_args.password;
	env_args->capacity          = (size_t)ctx->in_args.fs_size;
	env_args->no_utf8_names     = ctx->in_args.no_utf8_names;
}

static void cmd_mkfs_setup_fs_ids(struct cmd_mkfs_ctx *ctx)
{
	struct silofs_env_args *env_args = &ctx->env_args;
	struct silofs_ugids    *ids      = &env_args->ugids;
	const char             *username = ctx->in_args.username;

	cmd_load_fsids(ids, ctx->in_args.repodir_real);
	cmd_require_uidgid(ids, username, &env_args->uid, &env_args->gid);
}

static void cmd_mkfs_setup_env(struct cmd_mkfs_ctx *ctx)
{
	cmd_new_env(&ctx->env_args, &ctx->env);
}

static void cmd_mkfs_open_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_open_repo(ctx->env);
}

static void cmd_mkfs_close_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

static void cmd_mkfs_format_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_format_fs(ctx->env, &ctx->fs_blobid);
}

static void cmd_mkfs_save_blobid(struct cmd_mkfs_ctx *ctx)
{
	cmd_save_fs_metaref(&ctx->env_args.boot_args, &ctx->fs_blobid);
}

static void cmd_mkfs_close_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_close_fs(ctx->env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mkfs(void)
{
	struct cmd_mkfs_ctx ctx = {
		.in_args = {
			.fs_size = -1,
			.no_utf8_names = false,
		},
		.env = nullptr,
	};

	/* Do all cleanups upon exits */
	cmd_mkfs_start(&ctx);

	/* Parse command's arguments */
	cmd_mkfs_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_mkfs_prepare(&ctx);

	/* Restrict process access */
	cmd_mkfs_restrict_process(&ctx);

	/* Have proper file-system owner username */
	cmd_mkfs_require_owner(&ctx);

	/* Require password */
	cmd_mkfs_getpass(&ctx);

	/* Setup input arguments */
	cmd_mkfs_setup_env_args(&ctx);

	/* Setup fs owner and ids */
	cmd_mkfs_setup_fs_ids(&ctx);

	/* Prepare environment */
	cmd_mkfs_setup_env(&ctx);

	/* Acquire lock */
	cmd_mkfs_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_mkfs_open_repo(&ctx);

	/* Format file-system layer */
	cmd_mkfs_format_fs(&ctx);

	/* Save top-level fs boot-ref */
	cmd_mkfs_save_blobid(&ctx);

	/* Post-format cleanups */
	cmd_mkfs_close_fs(&ctx);

	/* Close repository */
	cmd_mkfs_close_repo(&ctx);

	/* Release lock */
	cmd_mkfs_release_lockfile(&ctx);

	/* Post execution cleanups */
	cmd_mkfs_finalize(&ctx);
}
