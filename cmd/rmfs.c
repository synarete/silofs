/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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

static const char *const cmd_rmfs_help_desc = {
	"rmfs <repodir/fsname>                                           \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n"
};

struct cmd_rmfs_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *password;
	bool no_prompt;
};

struct cmd_rmfs_ctx {
	struct silofs_ioc_query ioc_qry;
	struct cmd_rmfs_in_args in_args;
	struct silofs_env_args env_args;
	struct silofs_xref fs_xref;
	struct silofs_env *env;
	bool has_lockfile;
};

static struct cmd_rmfs_ctx *cmd_rmfs_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_rmfs_parse_optargs(struct cmd_rmfs_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "password", 'p', 1 },  //
		{ "no-prompt", 'P', 0 }, //
		{ "loglevel", 'L', 1 },  //
		{ "help", 'h', 0 },      //
		{ NULL, 0, 0 },          //
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'P':
			ctx->in_args.no_prompt = true;
			break;
		case 'p':
			ctx->in_args.password = cmd_optargs_getpass(&opa);
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_rmfs_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}

	ctx->in_args.repodir_fsname =
		cmd_optargs_getarg(&opa, "repodir/fsname");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_rmfs_prepare(struct cmd_rmfs_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_fsname);
	cmd_split_path(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
}

static void cmd_rmfs_restrict_process(struct cmd_rmfs_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, false);
}

static void cmd_rmfs_getpass(struct cmd_rmfs_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_rmfs_check_nomnt_at(struct cmd_rmfs_ctx *ctx, const char *mntp)
{
	struct stat st[2];
	char *path[2] = { NULL, NULL };
	char *repodir = NULL;
	char *name = NULL;
	struct silofs_ioc_query *qry = &ctx->ioc_qry;
	int o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	int dfd = -1;
	int err = 0;

	err = silofs_sys_openat(AT_FDCWD, mntp, o_flags, 0, &dfd);
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

	cmd_join_path(ctx->in_args.repodir_real, ctx->in_args.fsname,
	              &path[1]);
	err = silofs_sys_stat(path[1], &st[1]);
	if (err) {
		goto out;
	}

	if ((st[0].st_ino == st[1].st_ino) && (st[0].st_dev == st[1].st_dev)) {
		cmd_die(EBUSY, "currently mounted at: %s", mntp);
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
	struct silofs_mntinfos *minfos = NULL;

	minfos = cmd_parse_mountinfo();
	for (size_t i = 0; i < minfos->ninfos; ++i) {
		cmd_rmfs_check_nomnt_at(ctx, minfos->infos[i].mntdir);
	}
	cmd_free_mountinfo(minfos);
}

static void cmd_rmfs_setup_env_args(struct cmd_rmfs_ctx *ctx)
{
	struct silofs_env_args *env_args = &ctx->env_args;

	cmd_setup_env_args(env_args);
	env_args->boot_args.repodir = ctx->in_args.repodir_real;
	env_args->boot_args.fs_name = ctx->in_args.fsname;
	env_args->boot_args.passwd = ctx->in_args.password;
}

static void cmd_rmfs_setup_fs_ids(struct cmd_rmfs_ctx *ctx)
{
	cmd_load_fsids(&ctx->env_args.ugids, ctx->in_args.repodir_real);
}

static void cmd_rmfs_load_fs_xref(struct cmd_rmfs_ctx *ctx)
{
	cmd_load_fs_xref(&ctx->env_args.boot_args, &ctx->fs_xref);
}

static void cmd_rmfs_setup_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_new_env(&ctx->env_args, &ctx->env);
}

static void cmd_rmfs_open_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_open_repo(ctx->env);
}

static void cmd_rmfs_close_repo(struct cmd_rmfs_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

static void cmd_rmfs_sense_fs(struct cmd_rmfs_ctx *ctx)
{
	cmd_sense_fs(ctx->env, &ctx->fs_xref);
}

static void cmd_rmfs_execute(struct cmd_rmfs_ctx *ctx)
{
	cmd_remove_fs(ctx->env, &ctx->fs_xref);
}

static void cmd_rmfs_unlink_xref(struct cmd_rmfs_ctx *ctx)
{
	cmd_unlink_fs_xref(&ctx->env_args.boot_args);
}

static void cmd_rmfs_destroy_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_del_env(&ctx->env);
}

static void cmd_rmfs_acquire_lockfile(struct cmd_rmfs_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = true;
	}
}

static void cmd_rmfs_release_lockfile(struct cmd_rmfs_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = false;
	}
}

static void cmd_rmfs_finalize(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_destroy_env(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_rmfs_ctx_p = NULL;
}

static void cmd_rmfs_atexit(void)
{
	struct cmd_rmfs_ctx *ctx = cmd_rmfs_ctx_p;

	if (ctx != NULL) {
		cmd_rmfs_release_lockfile(ctx);
		cmd_rmfs_finalize(ctx);
	}
}

static void cmd_rmfs_start(struct cmd_rmfs_ctx *ctx)
{
	cmd_rmfs_ctx_p = ctx;
	cmd_atexit(cmd_rmfs_atexit);
}

static void cmd_rmfs_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_rmfs(void)
{
	struct cmd_rmfs_ctx ctx = { .ioc_qry.qtype = -1 };

	/* Do all cleanups upon exits */
	cmd_rmfs_start(&ctx);

	/* Parse command's arguments */
	cmd_rmfs_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_rmfs_prepare(&ctx);

	/* Ensure not and active mount */
	cmd_rmfs_check_nomnt(&ctx);

	/* Restrict process access */
	cmd_rmfs_restrict_process(&ctx);

	/* Require password */
	cmd_rmfs_getpass(&ctx);

	/* Run with signals */
	cmd_rmfs_enable_signals();

	/* Setup input arguments */
	cmd_rmfs_setup_env_args(&ctx);

	/* Load fs-ids mapping */
	cmd_rmfs_setup_fs_ids(&ctx);

	/* Load fs boot-reference */
	cmd_rmfs_load_fs_xref(&ctx);

	/* Setup execution context */
	cmd_rmfs_setup_env(&ctx);

	/* Acquire lock */
	cmd_rmfs_acquire_lockfile(&ctx);

	/* Open-validate repository */
	cmd_rmfs_open_repo(&ctx);

	/* Require existing boot-record */
	cmd_rmfs_sense_fs(&ctx);

	/* Do actual lsegs deletion*/
	cmd_rmfs_execute(&ctx);

	/* Unlink boot-configuration */
	cmd_rmfs_unlink_xref(&ctx);

	/* Close repository */
	cmd_rmfs_close_repo(&ctx);

	/* Release lock */
	cmd_rmfs_release_lockfile(&ctx);

	/* Post execution cleanups */
	cmd_rmfs_finalize(&ctx);
}
