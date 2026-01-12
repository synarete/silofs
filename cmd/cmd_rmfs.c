/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
	bool  no_prompt;
};

struct cmd_rmfs_ctx {
	struct silofs_ioc_query ioc_qry;
	struct cmd_rmfs_in_args in_args;
	struct silofs_args      args;
	struct silofs_env      *env;
	bool                    has_lockfile;
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
		{ nullptr, 0, 0 },       //
	};
	struct cmd_optargs opa;
	int                opt_chr = 1;

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
	cmd_path_split(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
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
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_rmfs_check_nomnt_at(struct cmd_rmfs_ctx *ctx, const char *mntp)
{
	struct stat              st[2];
	char                    *path[2] = { nullptr, nullptr };
	char                    *repodir = nullptr;
	char                    *name    = nullptr;
	struct silofs_ioc_query *qry     = &ctx->ioc_qry;
	int o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	int dfd     = -1;
	int err     = 0;

	err = silofs_sys_openat(AT_FDCWD, mntp, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_REPO;
	err        = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	repodir = cmd_strvdup(qry->u.repo.path);

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_BOOT;
	err        = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	name = cmd_strvdup(qry->u.boot.name);

	path[0] = cmd_path_join(repodir, name);
	err     = silofs_sys_stat(path[0], &st[0]);
	if (err) {
		goto out;
	}

	path[1] =
		cmd_path_join(ctx->in_args.repodir_real, ctx->in_args.fsname);
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
	struct silofs_mntinfos *minfos = nullptr;

	minfos = cmd_parse_mountinfo();
	for (size_t i = 0; i < minfos->ninfos; ++i) {
		cmd_rmfs_check_nomnt_at(ctx, minfos->infos[i].mntdir);
	}
	cmd_free_mountinfo(minfos);
}

static void cmd_rmfs_setup_args(struct cmd_rmfs_ctx *ctx)
{
	struct silofs_args *args = &ctx->args;

	cmd_setup_args(args);
	args->bref[0].repodir = ctx->in_args.repodir_real;
	args->bref[0].refname = ctx->in_args.fsname;
	args->passwd          = ctx->in_args.password;
}

static void cmd_rmfs_load_spec(struct cmd_rmfs_ctx *ctx)
{
	cmd_spec_load(&ctx->args.spec, &ctx->args.bref[0]);
	cmd_fsids_need_self(&ctx->args.spec.fsids);
}

static void cmd_rmfs_setup_env(struct cmd_rmfs_ctx *ctx)
{
	cmd_new_env(&ctx->args, &ctx->env);
	cmd_spec_clear_fsids(&ctx->args.spec);
	cmd_delpass(&ctx->in_args.password);
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
	cmd_sense_fs(ctx->env, &ctx->args.spec.fsref);
}

static void cmd_rmfs_execute(struct cmd_rmfs_ctx *ctx)
{
	cmd_remove_fs(ctx->env, &ctx->args.spec.fsref);
}

static void cmd_rmfs_unlink_blobid(struct cmd_rmfs_ctx *ctx)
{
	cmd_spec_unlink(&ctx->args.bref[0]);
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
	cmd_rmfs_ctx_p = nullptr;
}

static void cmd_rmfs_atexit(void)
{
	struct cmd_rmfs_ctx *ctx = cmd_rmfs_ctx_p;

	if (ctx != nullptr) {
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
	cmd_register_sigactions(nullptr);
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
	cmd_rmfs_setup_args(&ctx);

	/* Load fs spec */
	cmd_rmfs_load_spec(&ctx);

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
	cmd_rmfs_unlink_blobid(&ctx);

	/* Close repository */
	cmd_rmfs_close_repo(&ctx);

	/* Release lock */
	cmd_rmfs_release_lockfile(&ctx);

	/* Post execution cleanups */
	cmd_rmfs_finalize(&ctx);
}
