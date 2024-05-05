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

static const char *cmd_rmfs_help_desc[] = {
	"rmfs <repodir/name>",
	"",
	"options:",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_rmfs_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *password;
	bool    no_prompt;
};

struct cmd_rmfs_ctx {
	struct silofs_ioc_query   ioc_qry;
	long                      pad;
	struct cmd_rmfs_in_args   in_args;
	struct silofs_fs_args     fs_args;
	struct silofs_fs_ctx     *fs_ctx;
	bool has_lockfile;
};

static struct cmd_rmfs_ctx *cmd_rmfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_rmfs_getopt(struct cmd_rmfs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "no-prompt", no_argument, NULL, 'P' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("PL:h", opts);
		if (opt_chr == 'P') {
			ctx->in_args.no_prompt = true;
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_rmfs_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_getopt_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_getopt_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_rmfs_prepare(struct cmd_rmfs_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_rmfs_getpass(struct cmd_rmfs_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_rmfs_check_nomnt_at(struct cmd_rmfs_ctx *ctx,
                                    const struct cmd_proc_mntinfo *mi)
{
	struct stat st[2];
	char *path[2] = { NULL, NULL };
	char *repodir = NULL;
	char *name = NULL;
	struct silofs_ioc_query *qry = &ctx->ioc_qry;
	int o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	int dfd = -1;
	int err = 0;

	err = silofs_sys_openat(AT_FDCWD, mi->mntdir, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_REPO;
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	repodir = cmd_strdup(qry->u.repo.path);

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_BOOT;
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	name = cmd_strdup(qry->u.boot.name);

	cmd_join_path(repodir, name, &path[0]);
	err = silofs_sys_stat(path[0], &st[0]);
	if (err) {
		goto out;
	}

	cmd_join_path(ctx->in_args.repodir_real, ctx->in_args.name, &path[1]);
	err = silofs_sys_stat(path[1], &st[1]);
	if (err) {
		goto out;
	}

	if ((st[0].st_ino == st[1].st_ino) &&
	    (st[0].st_dev == st[1].st_dev)) {
		cmd_dief(EBUSY, "currently mounted at: %s", mi->mntdir);
	}
out:
	silofs_sys_closefd(&dfd);
	cmd_pstrfree(&path[0]);
	cmd_pstrfree(&path[1]);
	cmd_pstrfree(&name);
	cmd_pstrfree(&repodir);
}

static void cmd_rmfs_check_nomnt(struct cmd_rmfs_ctx *ctx)
{
	struct cmd_proc_mntinfo *mi_list = NULL;
	const struct cmd_proc_mntinfo *mi_iter = NULL;

	mi_list = cmd_parse_mountinfo();
	for (mi_iter = mi_list; mi_iter != NULL; mi_iter = mi_iter->next) {
		cmd_rmfs_check_nomnt_at(ctx, mi_iter);
	}
	cmd_free_mountinfo(mi_list);
}

static void cmd_rmfs_setup_fs_args(struct cmd_rmfs_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.name);
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
	fs_args->passwd = ctx->in_args.password;
}

static void cmd_rmfs_load_bconf(struct cmd_rmfs_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_rmfs_setup_fs_ctx(struct cmd_rmfs_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_rmfs_open_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_rmfs_close_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_rmfs_require_brec(struct cmd_rmfs_ctx *ctx)
{
	cmd_require_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_rmfs_execute(struct cmd_rmfs_ctx *ctx)
{
	cmd_unref_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_rmfs_unlink_bconf(struct cmd_rmfs_ctx *ctx)
{
	cmd_bconf_unlink(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_rmfs_destroy_fs_ctx(struct cmd_rmfs_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_rmfs_acquire_lockfile(struct cmd_rmfs_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real,
		            ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_rmfs_release_lockfile(struct cmd_rmfs_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real,
		              ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_rmfs_finalize(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_destroy_fs_ctx(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_rmfs_ctx = NULL;
}

static void cmd_rmfs_atexit(void)
{
	if (cmd_rmfs_ctx != NULL) {
		cmd_rmfs_release_lockfile(cmd_rmfs_ctx);
		cmd_rmfs_finalize(cmd_rmfs_ctx);
	}
}

static void cmd_rmfs_start(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_ctx = ctx;
	atexit(cmd_rmfs_atexit);
}

static void cmd_rmfs_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_rmfs(void)
{
	struct cmd_rmfs_ctx ctx = {
		.ioc_qry.qtype = -1
	};

	/* Do all cleanups upon exits */
	cmd_rmfs_start(&ctx);

	/* Parse command's arguments */
	cmd_rmfs_getopt(&ctx);

	/* Verify user's arguments */
	cmd_rmfs_prepare(&ctx);

	/* Ensure not and active mount */
	cmd_rmfs_check_nomnt(&ctx);

	/* Require password */
	cmd_rmfs_getpass(&ctx);

	/* Run with signals */
	cmd_rmfs_enable_signals();

	/* Setup input arguments */
	cmd_rmfs_setup_fs_args(&ctx);

	/* Require boot-config */
	cmd_rmfs_load_bconf(&ctx);

	/* Setup execution context */
	cmd_rmfs_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_rmfs_acquire_lockfile(&ctx);

	/* Open-validate repository */
	cmd_rmfs_open_repo(&ctx);

	/* Require existing boot-record */
	cmd_rmfs_require_brec(&ctx);

	/* Do actual lsegs deletion*/
	cmd_rmfs_execute(&ctx);

	/* Unlink boot-configuration */
	cmd_rmfs_unlink_bconf(&ctx);

	/* Close repository */
	cmd_rmfs_close_repo(&ctx);

	/* Release lock */
	cmd_rmfs_release_lockfile(&ctx);

	/* Post execution cleanups */
	cmd_rmfs_finalize(&ctx);
}
