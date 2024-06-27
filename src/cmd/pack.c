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

static const char *cmd_pack_help_desc[] = {
	"pack -n <arname> <repodir/name>",
	"",
	"options:",
	"  -n, --name=packname       Result pack name",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_pack_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *arname;
	char   *password;
	bool    no_prompt;
};

struct cmd_pack_ctx {
	struct cmd_pack_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fsenv    *fsenv;
	bool has_lockfile;
};

static struct cmd_pack_ctx *cmd_pack_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_pack_getopt(struct cmd_pack_ctx *ctx)
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
			ctx->in_args.arname = cmd_strdup(optarg);
		} else if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'P') {
			ctx->in_args.no_prompt = true;
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_pack_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_require_arg("arname", ctx->in_args.arname);
	cmd_getopt_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_pack_acquire_lockfile(struct cmd_pack_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_pack_release_lockfile(struct cmd_pack_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_pack_destroy_fs_ctx(struct cmd_pack_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_pack_finalize(struct cmd_pack_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_bconf_fini(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_delpass(&ctx->in_args.password);
	cmd_pack_ctx = NULL;
}

static void cmd_pack_atexit(void)
{
	if (cmd_pack_ctx != NULL) {
		cmd_pack_release_lockfile(cmd_pack_ctx);
		cmd_pack_finalize(cmd_pack_ctx);
	}
}

static void cmd_pack_start(struct cmd_pack_ctx *ctx)
{
	cmd_pack_ctx = ctx;
	atexit(cmd_pack_atexit);
}

static void cmd_pack_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_pack_prepare(struct cmd_pack_ctx *ctx)
{
	cmd_check_fsname(ctx->in_args.arname);
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.name);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.arname);
}

static void cmd_pack_getpass(struct cmd_pack_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_pack_setup_fs_args(struct cmd_pack_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.name);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
}

static void cmd_pack_load_bconf(struct cmd_pack_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_pack_setup_fs_ctx(struct cmd_pack_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_pack_open_repo(struct cmd_pack_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_pack_close_repo(struct cmd_pack_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_pack_require_brec(struct cmd_pack_ctx *ctx)
{
	cmd_require_fs(ctx->fsenv, &ctx->fs_args.bconf);
}

static void cmd_pack_boot_fs(struct cmd_pack_ctx *ctx)
{
	cmd_boot_fs(ctx->fsenv, &ctx->fs_args.bconf);
}

static void cmd_pack_open_fs(struct cmd_pack_ctx *ctx)
{
	cmd_open_fs(ctx->fsenv);
}

static void cmd_pack_close_fs(struct cmd_pack_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

static void cmd_pack_execute(struct cmd_pack_ctx *ctx)
{
	struct silofs_fs_bconf bconf;

	cmd_bconf_assign(&bconf, &ctx->fs_args.bconf);
	cmd_bconf_set_name(&bconf, ctx->in_args.arname);
	cmd_pack_fs(ctx->fsenv, &bconf.pack_ref);
	cmd_bconf_save_rdonly(&bconf, ctx->in_args.repodir_real);
	cmd_bconf_fini(&bconf);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_pack(void)
{
	struct cmd_pack_ctx ctx = {
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_pack_start(&ctx);

	/* Parse command's arguments */
	cmd_pack_getopt(&ctx);

	/* Verify user's arguments */
	cmd_pack_prepare(&ctx);

	/* Require password */
	cmd_pack_getpass(&ctx);

	/* Run with signals */
	cmd_pack_enable_signals();

	/* Setup input arguments */
	cmd_pack_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_pack_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_pack_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_pack_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_pack_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_pack_require_brec(&ctx);

	/* Require boot-able file-system */
	cmd_pack_boot_fs(&ctx);

	/* Open file-system */
	cmd_pack_open_fs(&ctx);

	/* Do actual pack */
	cmd_pack_execute(&ctx);

	/* Close file-system */
	cmd_pack_close_fs(&ctx);

	/* Close repository */
	cmd_pack_close_repo(&ctx);

	/* Release lock */
	cmd_pack_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_pack_destroy_fs_ctx(&ctx);

	/* Post execution cleanups */
	cmd_pack_finalize(&ctx);
}
