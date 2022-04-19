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

static const char *cmd_restore_usage[] = {
	"restore [options] <cold-repo/name> <warm-repo/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

struct cmd_restore_args {
	char   *warm_repodir_name;
	char   *warm_repodir;
	char   *warm_repodir_real;
	char   *warm_name;
	char   *cold_repodir_name;
	char   *cold_repodir;
	char   *cold_repodir_real;
	char   *cold_name;
	char   *passphrase;
	char   *passphrase_file;
};

struct cmd_restore_ctx {
	struct cmd_restore_args args;
	struct silofs_bootlink  src_blnk;
	struct silofs_bootlink  dst_blnk;
	struct silofs_fs_env   *fse;
	int                     src_lock_fd;
};

static struct cmd_restore_ctx *cmd_restore_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_getopt(struct cmd_restore_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("V:P:h", opts);
		if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'P') {
			cmd_getoptarg("--passphrase-file",
			              &ctx->args.passphrase_file);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_restore_usage);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("cold-repo/name", &ctx->args.cold_repodir_name);
	cmd_getarg("warm-repo/name", &ctx->args.warm_repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_finalize(struct cmd_restore_ctx *ctx)
{
	cmd_del_env(&ctx->fse);
	cmd_pstrfree(&ctx->args.warm_repodir_name);
	cmd_pstrfree(&ctx->args.warm_repodir);
	cmd_pstrfree(&ctx->args.warm_repodir_real);
	cmd_pstrfree(&ctx->args.warm_name);
	cmd_pstrfree(&ctx->args.cold_repodir_name);
	cmd_pstrfree(&ctx->args.cold_repodir);
	cmd_pstrfree(&ctx->args.cold_repodir_real);
	cmd_pstrfree(&ctx->args.cold_name);
	cmd_pstrfree(&ctx->args.passphrase_file);
	cmd_delpass(&ctx->args.passphrase);
	cmd_unlock_bpath(&ctx->src_blnk.bpath, &ctx->src_lock_fd);
	cmd_restore_ctx = NULL;
}

static void cmd_restore_atexit(void)
{
	if (cmd_restore_ctx != NULL) {
		cmd_restore_finalize(cmd_restore_ctx);
	}
}

static void cmd_restore_start(struct cmd_restore_ctx *ctx)
{
	cmd_restore_ctx = ctx;
	atexit(cmd_restore_atexit);
}

static void cmd_restore_prepare(struct cmd_restore_ctx *ctx)
{
	cmd_check_reg(ctx->args.cold_repodir_name, false);
	cmd_split_path(ctx->args.cold_repodir_name,
	               &ctx->args.cold_repodir, &ctx->args.cold_name);
	cmd_split_path2(ctx->args.warm_repodir_name, ctx->args.cold_name,
	                &ctx->args.warm_repodir, &ctx->args.warm_name);
	cmd_check_notexists2(ctx->args.warm_repodir, ctx->args.warm_name);
	cmd_check_nonemptydir(ctx->args.cold_repodir, true);
	cmd_realpath(ctx->args.cold_repodir, &ctx->args.cold_repodir_real);
	cmd_check_fsname(ctx->args.cold_name);
	cmd_check_nonemptydir(ctx->args.warm_repodir, false);
	cmd_realpath(ctx->args.warm_repodir, &ctx->args.warm_repodir_real);
	cmd_check_fsname(ctx->args.warm_name);
	cmd_check_diff(ctx->args.warm_repodir_name,
	               ctx->args.cold_repodir_name);
	cmd_setup_bpath(&ctx->src_blnk.bpath,
	                ctx->args.cold_repodir_real, ctx->args.cold_name);
	cmd_setup_bpath(&ctx->dst_blnk.bpath,
	                ctx->args.warm_repodir_real, ctx->args.warm_name);
	cmd_lock_bpath(&ctx->src_blnk.bpath, &ctx->src_lock_fd);
	cmd_getpass(ctx->args.passphrase_file, &ctx->args.passphrase);
}

static void cmd_restore_setup_env(struct cmd_restore_ctx *ctx)
{
	const struct silofs_fs_args fs_args = {
		.main_repodir = ctx->args.warm_repodir_real,
		.main_name = ctx->args.warm_name,
		.cold_repodir = ctx->args.cold_repodir_real,
		.cold_name = ctx->args.cold_name,
		.passwd = ctx->args.passphrase,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.restore = true,
	};

	cmd_new_env(&ctx->fse, &fs_args);
}

static void cmd_restore_filesystem(struct cmd_restore_ctx *ctx)
{
	cmd_load_bsec(&ctx->src_blnk.bpath, &ctx->src_blnk.bsec);
	cmd_restore_fs(ctx->fse, &ctx->src_blnk, &ctx->dst_blnk);
	cmd_save_bsec(&ctx->dst_blnk.bpath, &ctx->dst_blnk.bsec);
}

static void cmd_restore_finish(struct cmd_restore_ctx *ctx)
{
	cmd_shutdown_fs(ctx->fse);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_restore(void)
{
	struct cmd_restore_ctx ctx = {
		.fse = NULL,
		.src_lock_fd = -1,
	};

	/* Do all cleanups upon exits */
	cmd_restore_start(&ctx);

	/* Parse command's arguments */
	cmd_restore_getopt(&ctx);

	/* Verify user's arguments */
	cmd_restore_prepare(&ctx);

	/* Prepare environment */
	cmd_restore_setup_env(&ctx);

	/* Do actual restore */
	cmd_restore_filesystem(&ctx);

	/* Post-restore cleanups */
	cmd_restore_finish(&ctx);

	/* Post execution cleanups */
	cmd_restore_finalize(&ctx);
}
