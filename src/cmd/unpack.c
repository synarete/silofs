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
#include "cmd.h"

static const char *cmd_unpack_help_desc[] = {
	"unpack -n <name> <repodir/arname>",
	"",
	"options:",
	"  -n, --name=fsname            Restored file-system name",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_unpack_in_args {
	char   *repodir_arname;
	char   *repodir;
	char   *repodir_real;
	char   *arname;
	char   *name;
	char   *password;
	bool    no_prompt;
};

struct cmd_unpack_ctx {
	struct cmd_unpack_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fsenv    *fsenv;
	bool has_lockfile;
};

static struct cmd_unpack_ctx *cmd_unpack_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_unpack_getopt(struct cmd_unpack_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "password", required_argument, NULL, 'p' },
		{ "no-prompt", no_argument, NULL, 'P' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("n:p:PL:h", opts);
		if (opt_chr == 'n') {
			ctx->in_args.name = cmd_strdup(optarg);
		} else if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'P') {
			ctx->in_args.no_prompt = true;
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_unpack_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_require_arg("name", ctx->in_args.name);
	cmd_getopt_getarg("repodir/arname", &ctx->in_args.repodir_arname);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_unpack_acquire_lockfile(struct cmd_unpack_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.arname);
		ctx->has_lockfile = true;
	}
}

static void cmd_unpack_release_lockfile(struct cmd_unpack_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_unpack_destroy_fs_ctx(struct cmd_unpack_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_unpack_finalize(struct cmd_unpack_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_bconf_fini(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_arname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
	cmd_unpack_ctx = NULL;
}

static void cmd_unpack_atexit(void)
{
	if (cmd_unpack_ctx != NULL) {
		cmd_unpack_release_lockfile(cmd_unpack_ctx);
		cmd_unpack_finalize(cmd_unpack_ctx);
	}
}

static void cmd_unpack_start(struct cmd_unpack_ctx *ctx)
{
	cmd_unpack_ctx = ctx;
	atexit(cmd_unpack_atexit);
}

static void cmd_unpack_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_unpack_prepare(struct cmd_unpack_ctx *ctx)
{
	cmd_check_fsname(ctx->in_args.name);
	cmd_split_path(ctx->in_args.repodir_arname,
	               &ctx->in_args.repodir, &ctx->in_args.arname);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.arname);
	cmd_check_isreg2(ctx->in_args.repodir_real, ctx->in_args.arname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_unpack_getpass(struct cmd_unpack_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_unpack_setup_fs_args(struct cmd_unpack_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.arname);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.arname;
}

static void cmd_unpack_load_bconf(struct cmd_unpack_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_unpack_setup_fs_ctx(struct cmd_unpack_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_unpack_open_repo(struct cmd_unpack_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_unpack_close_repo(struct cmd_unpack_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_unpack_require_brec(struct cmd_unpack_ctx *ctx)
{
	cmd_require_fs(ctx->fsenv, &ctx->fs_args.bconf);
}

static void cmd_unpack_execute(struct cmd_unpack_ctx *ctx)
{
	struct silofs_fs_bconf bconf;

	cmd_bconf_assign(&bconf, &ctx->fs_args.bconf);
	cmd_bconf_set_name(&bconf, ctx->in_args.arname);
	cmd_unpack_fs(ctx->fsenv, &bconf.pack_ref);
	cmd_bconf_set_name(&bconf, ctx->in_args.name);
	cmd_bconf_save_rdonly(&bconf, ctx->in_args.repodir_real);
	cmd_bconf_fini(&bconf);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_unpack(void)
{
	struct cmd_unpack_ctx ctx = {
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_unpack_start(&ctx);

	/* Parse command's arguments */
	cmd_unpack_getopt(&ctx);

	/* Verify user's arguments */
	cmd_unpack_prepare(&ctx);

	/* Require password */
	cmd_unpack_getpass(&ctx);

	/* Run with signals */
	cmd_unpack_enable_signals();

	/* Setup input arguments */
	cmd_unpack_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_unpack_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_unpack_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_unpack_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_unpack_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_unpack_require_brec(&ctx);

	/* Do actual unpack */
	cmd_unpack_execute(&ctx);

	/* Close repository */
	cmd_unpack_close_repo(&ctx);

	/* Release lock */
	cmd_unpack_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_unpack_destroy_fs_ctx(&ctx);

	/* Post execution cleanups */
	cmd_unpack_finalize(&ctx);
}
