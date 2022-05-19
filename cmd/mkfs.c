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

static const char *cmd_mkfs_usage[] = {
	"mkfs --size=NBYTES [options] <repo/name>",
	"",
	"options:",
	"  -s, --size=NBYTES            Capacity size limit",
	"  -F, --force                  Force overwrite if already exists",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

struct cmd_mkfs_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *size;
	long    fs_size;
	bool    force;
};

struct cmd_mkfs_ctx {
	struct cmd_mkfs_args    args;
	struct silofs_bootpath  bpath;
	struct silofs_bootsec   bsec;
	struct silofs_fs_env   *fse;
};

static struct cmd_mkfs_ctx *cmd_mkfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_getopt(struct cmd_mkfs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "force", no_argument, NULL, 'F' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("s:V:Fh", opts);
		if (opt_chr == 's') {
			ctx->args.size = optarg;
			ctx->args.fs_size = cmd_parse_size(optarg);
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'F') {
			ctx->args.force = true;
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_mkfs_usage);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_require_arg("size", ctx->args.size);
	cmd_getarg("repo/name", &ctx->args.repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_finalize(struct cmd_mkfs_ctx *ctx)
{
	cmd_del_env(&ctx->fse);
	cmd_pstrfree(&ctx->args.name);
	cmd_pstrfree(&ctx->args.repodir);
	cmd_pstrfree(&ctx->args.repodir_name);
	cmd_pstrfree(&ctx->args.repodir_real);
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
	cmd_check_notdir(ctx->args.repodir_name);
	cmd_check_notexists(ctx->args.repodir_name);
	cmd_split_path(ctx->args.repodir_name,
	               &ctx->args.repodir, &ctx->args.name);
	cmd_check_nonemptydir(ctx->args.repodir, true);
	cmd_realpath(ctx->args.repodir, &ctx->args.repodir_real);
	cmd_check_fsname(ctx->args.name);
	cmd_setup_bpath(&ctx->bpath, ctx->args.repodir_real, ctx->args.name);
}

static void cmd_mkfs_setup_env(struct cmd_mkfs_ctx *ctx)
{
	const struct silofs_fs_args fs_args = {
		.warm_repodir = ctx->args.repodir_real,
		.warm_name = ctx->args.name,
		.capacity = (size_t)ctx->args.fs_size,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	cmd_new_env(&ctx->fse, &fs_args);
}

static void cmd_mkfs_verify_repo(const struct cmd_mkfs_ctx *ctx)
{
	cmd_open_repo(ctx->fse);
	cmd_close_repo(ctx->fse);
}

static void cmd_mkfs_format_filesystem(struct cmd_mkfs_ctx *ctx)
{
	cmd_format_fs(ctx->fse, &ctx->bsec);
	cmd_save_bsec(&ctx->bpath, &ctx->bsec);
}

static void cmd_mkfs_finish(const struct cmd_mkfs_ctx *ctx)
{
	cmd_shutdown_fs(ctx->fse);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mkfs(void)
{
	struct cmd_mkfs_ctx ctx = {
		.fse = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_mkfs_start(&ctx);

	/* Parse command's arguments */
	cmd_mkfs_getopt(&ctx);

	/* Verify user's arguments */
	cmd_mkfs_prepare(&ctx);

	/* Prepare environment */
	cmd_mkfs_setup_env(&ctx);

	/* Ensure access to repository */
	cmd_mkfs_verify_repo(&ctx);

	/* Do actual mkfs */
	cmd_mkfs_format_filesystem(&ctx);

	/* Post-format cleanups */
	cmd_mkfs_finish(&ctx);

	/* Post execution cleanups */
	cmd_mkfs_finalize(&ctx);
}
