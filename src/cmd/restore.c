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

static const char *cmd_restore_help_desc[] = {
	"restore <repodir/name> --from=<arname>",
	"",
	"options:",
	"  -n, --from=arname            Source archive name",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_restore_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *arname;
	char   *password;
	bool    no_prompt;
};

struct cmd_restore_ctx {
	struct cmd_restore_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fsenv    *fsenv;
	bool has_lockfile;
};

static struct cmd_restore_ctx *cmd_restore_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_getopt(struct cmd_restore_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "from", required_argument, NULL, 'n' },
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
			cmd_print_help_and_exit(cmd_restore_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_require_arg("arname", ctx->in_args.arname);
	cmd_getopt_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_restore_acquire_lockfile(struct cmd_restore_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.arname);
		ctx->has_lockfile = true;
	}
}

static void cmd_restore_release_lockfile(struct cmd_restore_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_restore_destroy_fsenv(struct cmd_restore_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_restore_finalize(struct cmd_restore_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_bconf_fini(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.arname);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
	cmd_restore_ctx = NULL;
}

static void cmd_restore_atexit(void)
{
	if (cmd_restore_ctx != NULL) {
		cmd_restore_release_lockfile(cmd_restore_ctx);
		cmd_restore_finalize(cmd_restore_ctx);
	}
}

static void cmd_restore_start(struct cmd_restore_ctx *ctx)
{
	cmd_restore_ctx = ctx;
	atexit(cmd_restore_atexit);
}

static void cmd_restore_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_restore_prepare(struct cmd_restore_ctx *ctx)
{
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_fsname(ctx->in_args.name);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.arname);
	cmd_check_isreg2(ctx->in_args.repodir_real, ctx->in_args.arname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_restore_getpass(struct cmd_restore_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_restore_setup_fs_args(struct cmd_restore_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.arname);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.arname;
}

static void cmd_restore_load_bconf(struct cmd_restore_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_restore_setup_fsenv(struct cmd_restore_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_restore_open_repo(struct cmd_restore_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_restore_close_repo(struct cmd_restore_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_restore_poke_archive(struct cmd_restore_ctx *ctx)
{
	cmd_poke_archive(ctx->fsenv, &ctx->fs_args.bconf);
}

static void cmd_restore_execute(struct cmd_restore_ctx *ctx)
{
	struct silofs_fs_bconf bconf;

	cmd_bconf_assign(&bconf, &ctx->fs_args.bconf);
	cmd_bconf_set_name(&bconf, ctx->in_args.arname);
	cmd_restore_fs(ctx->fsenv, &bconf.pack_ref);
	cmd_bconf_set_name(&bconf, ctx->in_args.name);
	cmd_bconf_save_rdonly(&bconf, ctx->in_args.repodir_real);
	cmd_bconf_fini(&bconf);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_restore(void)
{
	struct cmd_restore_ctx ctx = {
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_restore_start(&ctx);

	/* Parse command's arguments */
	cmd_restore_getopt(&ctx);

	/* Verify user's arguments */
	cmd_restore_prepare(&ctx);

	/* Require password */
	cmd_restore_getpass(&ctx);

	/* Run with signals */
	cmd_restore_enable_signals();

	/* Setup input arguments */
	cmd_restore_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_restore_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_restore_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_restore_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_restore_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_restore_poke_archive(&ctx);

	/* Do actual restore */
	cmd_restore_execute(&ctx);

	/* Close repository */
	cmd_restore_close_repo(&ctx);

	/* Release lock */
	cmd_restore_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_restore_destroy_fsenv(&ctx);

	/* Post execution cleanups */
	cmd_restore_finalize(&ctx);
}
