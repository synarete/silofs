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

static const char *cmd_mkfs_help_desc[] = {
	"mkfs --size=nbytes [options] <repodir/name>",
	"",
	"options:",
	"  -s, --size=nbytes            Capacity size limit",
	"  -u, --user=username          Make username the owner of root-dir",
	"  -G, --sup-groups             Allow owner's supplementary groups",
	"  -r, --allow-root             Allow root user and group",
	"  -F, --force                  Force overwrite if already exists",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_mkfs_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *size;
	char   *password;
	char   *username;
	long    fs_size;
	bool    allow_root;
	bool    with_sup_groups;
	bool    force;
};

struct cmd_mkfs_ctx {
	struct cmd_mkfs_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fsenv    *fsenv;
	bool has_lockfile;
};

static struct cmd_mkfs_ctx *cmd_mkfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_getopt(struct cmd_mkfs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "user", required_argument, NULL, 'u' },
		{ "sup-groups", no_argument, NULL, 'G' },
		{ "allow-root", no_argument, NULL, 'r' },
		{ "force", no_argument, NULL, 'F' },
		{ "password", required_argument, NULL, 'p' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("s:u:GrFp:L:h", opts);
		if (opt_chr == 's') {
			ctx->in_args.size = optarg;
			ctx->in_args.fs_size = cmd_parse_str_as_size(optarg);
		} else if (opt_chr == 'u') {
			ctx->in_args.username = cmd_strdup(optarg);
		} else if (opt_chr == 'G') {
			ctx->in_args.with_sup_groups = true;
		} else if (opt_chr == 'r') {
			ctx->in_args.allow_root = true;
		} else if (opt_chr == 'F') {
			ctx->in_args.force = true;
		} else if (opt_chr == 'p') {
			cmd_getoptarg_pass(&ctx->in_args.password);
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_mkfs_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_require_arg("size", ctx->in_args.size);
	cmd_getopt_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_destroy_fsenv(struct cmd_mkfs_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_mkfs_finalize(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_destroy_fsenv(ctx);
	cmd_bconf_fini(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.username);
	cmd_delpass(&ctx->in_args.password);
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
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
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
	uid_t uid;
	gid_t gid;

	cmd_resolve_uidgid(ctx->in_args.username, &uid, &gid);
	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.name);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
	fs_args->capacity = (size_t)ctx->in_args.fs_size;
	fs_args->uid = uid;
	fs_args->gid = gid;
}

static void cmd_mkfs_update_bconf(struct cmd_mkfs_ctx *ctx)
{
	struct silofs_fs_bconf *bconf = &ctx->fs_args.bconf;
	const char *username = ctx->in_args.username;
	bool with_sup_groups = ctx->in_args.with_sup_groups;
	char *selfname = NULL;
	char *rootname = NULL;

	selfname = cmd_getpwuid(getuid());
	rootname = cmd_getpwuid(0);
	if (ctx->in_args.allow_root && strcmp(rootname, username)) {
		cmd_bconf_add_user(bconf, rootname, false);
	}
	if (strcmp(selfname, username)) {
		cmd_bconf_add_user(bconf, selfname, false);
	}
	if (strlen(username)) {
		cmd_bconf_add_user(bconf, username, with_sup_groups);
	}
	cmd_pstrfree(&selfname);
	cmd_pstrfree(&rootname);
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
	cmd_format_fs(ctx->fsenv, &ctx->fs_args.bconf);
}

static void cmd_mkfs_save_bconf(struct cmd_mkfs_ctx *ctx)
{
	cmd_bconf_save(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_mkfs_close_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mkfs(void)
{
	struct cmd_mkfs_ctx ctx = {
		.in_args = { .fs_size = 0, },
		.fsenv = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_mkfs_start(&ctx);

	/* Parse command's arguments */
	cmd_mkfs_getopt(&ctx);

	/* Verify user's arguments */
	cmd_mkfs_prepare(&ctx);

	/* Have proper file-system owner username */
	cmd_mkfs_require_owner(&ctx);

	/* Require password */
	cmd_mkfs_getpass(&ctx);

	/* Setup input arguments */
	cmd_mkfs_setup_fs_args(&ctx);

	/* Add user-ids configuration */
	cmd_mkfs_update_bconf(&ctx);

	/* Prepare environment */
	cmd_mkfs_setup_fsenv(&ctx);

	/* Acquire lock */
	cmd_mkfs_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_mkfs_open_repo(&ctx);

	/* Do actual mkfs */
	cmd_mkfs_format_fs(&ctx);

	/* Save top-level fs-uuid */
	cmd_mkfs_save_bconf(&ctx);

	/* Post-format cleanups */
	cmd_mkfs_close_fs(&ctx);

	/* Close repository */
	cmd_mkfs_close_repo(&ctx);

	/* Release lock */
	cmd_mkfs_release_lockfile(&ctx);

	/* Post execution cleanups */
	cmd_mkfs_finalize(&ctx);
}
