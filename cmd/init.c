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

static const char *cmd_init_help_desc[] = {
	"init [--user=<username>] [<repodir>]",
	"",
	"options:",
	"  -u, --user=username          Primary fs-owner user-name",
	"  -G, --sup-groups             Allow owner's supplementary groups",
	"  -R, --allow-root             Allow root user and group",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_init_in_args {
	char *repodir;
	char *repodir_real;
	char *username;
	bool with_sup_groups;
	bool with_root_user;
};

struct cmd_init_ctx {
	struct cmd_init_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
};

static struct cmd_init_ctx *cmd_init_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_parse_optargs(struct cmd_init_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "user", 'u', 1 },       { "sup-groups", 'G', 0 },
		{ "allow-root", 'R', 0 }, { "loglevel", 'L', 1 },
		{ "help", 'h', 0 },       { NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'u':
			ctx->in_args.username =
				cmd_optarg_dupoptarg(&opa, "user");
			break;
		case 'G':
			ctx->in_args.with_sup_groups = true;
			break;
		case 'R':
			ctx->in_args.with_root_user = true;
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_init_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	ctx->in_args.repodir = cmd_optargs_getarg2(&opa, "repodir", ".");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_init_finalize(struct cmd_init_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
	cmd_fs_ids_fini(&ctx->fs_args.ids);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.username);
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

static void cmd_init_prepare_repodir(const struct cmd_init_ctx *ctx)
{
	struct stat st = { .st_mode = 0 };
	int err;

	err = silofs_sys_stat(ctx->in_args.repodir, &st);
	if (err == -ENOENT) {
		cmd_mkdir(ctx->in_args.repodir, 0700);
	} else if (err != 0) {
		cmd_die(err, "stat failure: %s", ctx->in_args.repodir);
	}
}

static void cmd_init_prepare(struct cmd_init_ctx *ctx)
{
	cmd_init_prepare_repodir(ctx);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_emptydir(ctx->in_args.repodir_real, true);
	cmd_check_repopath(ctx->in_args.repodir_real);
}

static void cmd_init_resolve_owner(struct cmd_init_ctx *ctx)
{
	if (ctx->in_args.username == NULL) {
		ctx->in_args.username = cmd_getusername();
	}
}

static void cmd_init_setup_fs_args(struct cmd_init_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;
	const char *username = ctx->in_args.username;

	cmd_fs_args_init(fs_args);
	cmd_resolve_uidgid(username, &fs_args->uid, &fs_args->gid);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = "silofs";
}

static void cmd_init_setup_fs_ids(struct cmd_init_ctx *ctx)
{
	struct silofs_fs_ids *ids = &ctx->fs_args.ids;
	const char *username = ctx->in_args.username;
	const bool with_sup_groups = ctx->in_args.with_sup_groups;
	const bool with_root_user = ctx->in_args.with_root_user;
	char *rootname = cmd_getpwuid(0);

	cmd_fs_ids_add_user(ids, username, with_sup_groups);
	if (with_root_user && strcmp(rootname, username)) {
		cmd_fs_ids_add_user(ids, rootname, false);
	}
	cmd_pstrfree(&rootname);
}

static void cmd_init_setup_fsenv(struct cmd_init_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_init_format_repo(const struct cmd_init_ctx *ctx)
{
	cmd_format_repo(ctx->fsenv);
}

static void cmd_init_close_repo(const struct cmd_init_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_init_save_idsconf(const struct cmd_init_ctx *ctx)
{
	cmd_fs_ids_save(&ctx->fs_args.ids, ctx->fs_args.bref.repodir);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_init(void)
{
	struct cmd_init_ctx ctx = { .fsenv = NULL };

	/* Do all cleanups upon exits */
	cmd_init_start(&ctx);

	/* Parse command's arguments */
	cmd_init_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_init_prepare(&ctx);

	/* Have proper file-system owner username */
	cmd_init_resolve_owner(&ctx);

	/* Setup input arguments */
	cmd_init_setup_fs_args(&ctx);

	/* Setup users/groups ids */
	cmd_init_setup_fs_ids(&ctx);

	/* Prepare environment */
	cmd_init_setup_fsenv(&ctx);

	/* Format repository layout */
	cmd_init_format_repo(&ctx);

	/* Post-format cleanups */
	cmd_init_close_repo(&ctx);

	/* Save ids-config file */
	cmd_init_save_idsconf(&ctx);

	/* Post execution cleanups */
	cmd_init_finalize(&ctx);
}
