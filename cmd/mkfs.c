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

static const char *cmd_mkfs_help_desc[] = {
	"mkfs --size=nbytes [options] <repodir/name>",
	"",
	"options:",
	"  -s, --size=nbytes            Capacity size limit",
	"  -u, --uid=suid               Map owner uid to suid",
	"  -g, --gid=suid               Map owner gid to sgid",
	"  -F, --force                  Force overwrite if already exists",
	"  -V, --verbose=level          Run in verbose mode (0..3)",
	NULL
};

struct cmd_mkfs_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *size;
	long    fs_size;
	uid_t   suid;
	gid_t   sgid;
	bool    force;
};

struct cmd_mkfs_ctx {
	struct cmd_mkfs_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_env   *fs_env;
};

static struct cmd_mkfs_ctx *cmd_mkfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_getopt(struct cmd_mkfs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "suid", required_argument, NULL, 'U' },
		{ "sgid", required_argument, NULL, 'G' },
		{ "force", no_argument, NULL, 'F' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	ctx->in_args.suid = getuid();
	ctx->in_args.sgid = getgid();
	while (opt_chr > 0) {
		opt_chr = cmd_getopt("s:U:G:V:Fh", opts);
		if (opt_chr == 's') {
			ctx->in_args.size = optarg;
			ctx->in_args.fs_size = cmd_parse_str_as_size(optarg);
		} else if (opt_chr == 'U') {
			ctx->in_args.suid = cmd_parse_str_as_uid(optarg);
		} else if (opt_chr == 'G') {
			ctx->in_args.sgid = cmd_parse_str_as_gid(optarg);
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'F') {
			ctx->in_args.force = true;
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_mkfs_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_require_arg("size", ctx->in_args.size);
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_destroy_fs_env(struct cmd_mkfs_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
}

static void cmd_mkfs_finalize(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_destroy_fs_env(ctx);
	cmd_reset_fs_cargs(&ctx->fs_args.ca);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_mkfs_ctx = NULL;
}

static void cmd_mkfs_atexit(void)
{
	if (cmd_mkfs_ctx != NULL) {
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
	struct cmd_mkfs_in_args *args = &ctx->in_args;

	cmd_check_notdir(args->repodir_name);
	cmd_check_notexists(args->repodir_name);
	cmd_split_path(args->repodir_name, &args->repodir, &args->name);
	cmd_check_nonemptydir(args->repodir, true);
	cmd_realpath(args->repodir, &args->repodir_real);
	cmd_check_repopath(args->repodir_real);
	cmd_check_fsname(args->name);
}

static void cmd_mkfs_setup_fs_args(struct cmd_mkfs_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_setup_fs_cargs(&fs_args->ca, ctx->in_args.suid, ctx->in_args.sgid);
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
	fs_args->capacity = (size_t)ctx->in_args.fs_size;
}

static void cmd_mkfs_setup_fs_env(struct cmd_mkfs_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}

static void cmd_mkfs_open_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_open_repo(ctx->fs_env);
}

static void cmd_mkfs_close_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

static void cmd_mkfs_format_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_format_fs(ctx->fs_env, &ctx->fs_args.ca.uuid);
}

static void cmd_mkfs_save_fs_cargs(struct cmd_mkfs_ctx *ctx)
{
	const struct cmd_mkfs_in_args *args = &ctx->in_args;

	cmd_save_fs_cargs2(&ctx->fs_args.ca, args->repodir_real, args->name);
}

static void cmd_mkfs_shutdown_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_close_fs(ctx->fs_env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mkfs(void)
{
	struct cmd_mkfs_ctx ctx = {
		.fs_env = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_mkfs_start(&ctx);

	/* Parse command's arguments */
	cmd_mkfs_getopt(&ctx);

	/* Verify user's arguments */
	cmd_mkfs_prepare(&ctx);

	/* Setup input arguments */
	cmd_mkfs_setup_fs_args(&ctx);

	/* Prepare environment */
	cmd_mkfs_setup_fs_env(&ctx);

	/* Open repository */
	cmd_mkfs_open_repo(&ctx);

	/* Do actual mkfs */
	cmd_mkfs_format_fs(&ctx);

	/* Save top-level boot-params */
	cmd_mkfs_save_fs_cargs(&ctx);

	/* Post-format cleanups */
	cmd_mkfs_shutdown_fs(&ctx);

	/* Close repository */
	cmd_mkfs_close_repo(&ctx);

	/* Post execution cleanups */
	cmd_mkfs_finalize(&ctx);
}
