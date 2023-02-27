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

static const char *cmd_init_help_desc[] = {
	"init <repodir>",
	"",
	"options:",
	"  -u, --uid=suid               Map owner uid to suid",
	"  -g, --gid=suid               Map owner gid to sgid",
	"  -R, --no-root                Ignore root user",
	"  -V, --verbose=level          Run in verbose mode (0..3)",
	NULL
};

struct cmd_init_in_args {
	char   *repodir;
	char   *repodir_real;
	uid_t   suid;
	gid_t   sgid;
	bool    no_root;
};

struct cmd_init_ctx {
	struct cmd_init_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_env   *fs_env;
};

static struct cmd_init_ctx *cmd_init_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_getopt(struct cmd_init_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "uid", required_argument, NULL, 'u' },
		{ "gid", required_argument, NULL, 'g' },
		{ "no-root", no_argument, NULL, 'R' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	ctx->in_args.suid = getuid();
	ctx->in_args.sgid = getgid();
	while (opt_chr > 0) {
		opt_chr = cmd_getopt("u:g:RV:h", opts);
		if (opt_chr == 'u') {
			ctx->in_args.suid = cmd_parse_str_as_uid(optarg);
		} else if (opt_chr == 'g') {
			ctx->in_args.sgid = cmd_parse_str_as_gid(optarg);
		} else if (opt_chr == 'R') {
			ctx->in_args.no_root = true;
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_init_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir", &ctx->in_args.repodir);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_finalize(struct cmd_init_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
	cmd_reset_fs_ids(&ctx->fs_args.ids);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_init_ctx = NULL;
}

static void cmd_init_atexit(void)
{
	if (cmd_init_ctx != NULL) {
		cmd_init_finalize(cmd_init_ctx);
	}
}

static void cmd_init_start(struct cmd_init_ctx *ctx)
{
	cmd_init_ctx = ctx;
	atexit(cmd_init_atexit);
}

static void cmd_init_prepare(struct cmd_init_ctx *ctx)
{
	struct stat st;
	int err;

	err = silofs_sys_stat(ctx->in_args.repodir, &st);
	if (err == 0) {
		cmd_check_emptydir(ctx->in_args.repodir, true);
	} else if (err == -ENOENT) {
		cmd_mkdir(ctx->in_args.repodir, 0700);
	} else {
		cmd_dief(err, "stat failure: %s", ctx->in_args.repodir);
	}
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
}

static void cmd_init_setup_fs_args(struct cmd_init_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_setup_fs_ids(&fs_args->ids, ctx->in_args.suid,
	                 ctx->in_args.sgid, ctx->in_args.no_root);
	ctx->fs_args.repodir = ctx->in_args.repodir_real;
	ctx->fs_args.name = "silofs";
}

static void cmd_init_setup_fs_env(struct cmd_init_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}

static void cmd_init_format_repo(const struct cmd_init_ctx *ctx)
{
	cmd_format_repo(ctx->fs_env);
}

static void cmd_init_close_repo(const struct cmd_init_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

static void cmd_init_save_idmap(const struct cmd_init_ctx *ctx)
{
	cmd_save_fs_idsmap(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_init(void)
{
	struct cmd_init_ctx ctx = {
		.fs_env = NULL
	};

	/* Do all cleanups upon exits */
	cmd_init_start(&ctx);

	/* Parse command's arguments */
	cmd_init_getopt(&ctx);

	/* Verify user's arguments */
	cmd_init_prepare(&ctx);

	/* Setup input arguments */
	cmd_init_setup_fs_args(&ctx);

	/* Prepare environment */
	cmd_init_setup_fs_env(&ctx);

	/* Format repository layout */
	cmd_init_format_repo(&ctx);

	/* Post-format cleanups */
	cmd_init_close_repo(&ctx);

	/* Store ids-map configuration file */
	cmd_init_save_idmap(&ctx);

	/* Post execution cleanups */
	cmd_init_finalize(&ctx);
}

