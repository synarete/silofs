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

static const char *cmd_rmfs_help_desc[] = {
	"rmfs <repodir/name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

struct cmd_rmfs_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *password;
};

struct cmd_rmfs_ctx {
	struct silofs_ioc_query   ioc_qry;
	long                      pad;
	struct cmd_rmfs_in_args   in_args;
	struct silofs_fs_args     fs_args;
	struct silofs_fs_env     *fs_env;
};

static struct cmd_rmfs_ctx *cmd_rmfs_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_rmfs_getopt(struct cmd_rmfs_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "password", required_argument, NULL, 'p' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("p:V:h", opts);
		if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_rmfs_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_rmfs_prepare(struct cmd_rmfs_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, true);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_rmfs_getpass(struct cmd_rmfs_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass(NULL, &ctx->in_args.password);
	}
}

static void cmd_rmfs_check_nomnt_at(struct cmd_rmfs_ctx *ctx,
                                    const struct cmd_proc_mntinfo *mi)
{
	struct stat st[2];
	char *path[2] = { NULL, NULL };
	struct silofs_ioc_query *qry = &ctx->ioc_qry;
	int o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	int dfd = -1;
	int err = 0;

	err = silofs_sys_openat(AT_FDCWD, mi->mntdir, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}
	qry->qtype = SILOFS_QUERY_BOOTSEC;
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	cmd_join_path(qry->u.bootrec.repo, qry->u.bootrec.name, &path[0]);
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
	cmd_iconf_setname(&fs_args->iconf, ctx->in_args.name);
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
	fs_args->passwd = ctx->in_args.password;
}

static void cmd_rmfs_load_iconf(struct cmd_rmfs_ctx *ctx)
{
	cmd_iconf_load(&ctx->fs_args.iconf, ctx->in_args.repodir_real);
}

static void cmd_rmfs_setup_fs_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}

static void cmd_rmfs_open_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_open_repo(ctx->fs_env);
}

static void cmd_rmfs_close_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

static void cmd_rmfs_require_brec(struct cmd_rmfs_ctx *ctx)
{
	cmd_require_fs(ctx->fs_env, &ctx->fs_args.iconf.uuid);
}

static void cmd_rmfs_execute(struct cmd_rmfs_ctx *ctx)
{
	cmd_unref_fs(ctx->fs_env, &ctx->fs_args.iconf.uuid);
}

static void cmd_rmfs_unlink_iconf(struct cmd_rmfs_ctx *ctx)
{
	cmd_iconf_unlink(&ctx->fs_args.iconf, ctx->in_args.repodir_real);
}

static void cmd_rmfs_destroy_fs_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
}

static void cmd_rmfs_finalize(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_destroy_fs_env(ctx);
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
		cmd_rmfs_finalize(cmd_rmfs_ctx);
	}
}

static void cmd_rmfs_start(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_ctx = ctx;
	atexit(cmd_rmfs_atexit);
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

	/* Setup input arguments */
	cmd_rmfs_setup_fs_args(&ctx);

	/* Require ids-map */
	cmd_rmfs_load_iconf(&ctx);

	/* Setup execution context */
	cmd_rmfs_setup_fs_env(&ctx);

	/* Open-validate repository */
	cmd_rmfs_open_repo(&ctx);

	/* Require existing boot-record */
	cmd_rmfs_require_brec(&ctx);

	/* Do actual blobs deletion*/
	cmd_rmfs_execute(&ctx);

	/* Unlink boot-configuration */
	cmd_rmfs_unlink_iconf(&ctx);

	/* Close repository */
	cmd_rmfs_close_repo(&ctx);

	/* Post execution cleanups */
	cmd_rmfs_finalize(&ctx);
}
