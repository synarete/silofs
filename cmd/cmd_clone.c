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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "cmd.h"

static const char *const cmd_clone_help_desc =
	"clone -n <forkname> [<pathname>]                                \n"
	"clone -n <forkname> --offline <repodir/fsname>                  \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -n, --name=forkname          Result fork name                 \n"
	"  -X, --offline                Operate on non-mounted fs        \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_clone_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *forkname;
	char *dirpath;
	char *dirpath_real;
	char *password;
	bool offline;
	bool no_prompt;
};

struct cmd_clone_ctx {
	struct cmd_clone_in_args in_args;
	struct silofs_args args;
	struct silofs_fsrefs fsrefs;
	struct silofs_env *env;
	union silofs_ioc_u *ioc;
};

/* local functions */
static void
cmd_clone_ioctl_query(const char *path, struct silofs_ioc_query *qry);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct cmd_clone_ctx *cmd_clone_ctx_p;

static struct cmd_clone_ctx *cmd_clone_new_ctx(void)
{
	struct cmd_clone_ctx *ctx = cmd_clone_ctx_p;

	if (ctx == nullptr) {
		ctx = cmd_clone_ctx_p = cmd_zalloc(sizeof(*ctx));
	}
	return ctx;
}

static void cmd_clone_del_ctx(struct cmd_clone_ctx *ctx)
{
	if ((ctx != nullptr) && (ctx == cmd_clone_ctx_p)) {
		cmd_zfree(ctx, sizeof(*ctx));
		cmd_clone_ctx_p = nullptr;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_clone_parse_optargs(struct cmd_clone_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "name", 'n', 1 },      //
		{ "offline", 'X', 0 },   //
		{ "no-prompt", 'P', 0 }, //
		{ "password", 'p', 1 },  //
		{ "loglevel", 'L', 1 },  //
		{ "help", 'h', 0 },      //
		{ nullptr, 0, 0 },       //
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'n':
			ctx->in_args.forkname =
				cmd_optarg_getcurr2(&opa, "name");
			break;
		case 'X':
			ctx->in_args.offline = true;
			break;
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
			cmd_print_help_and_exit(cmd_clone_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	cmd_require_arg("name", ctx->in_args.forkname);

	if (ctx->in_args.offline) {
		ctx->in_args.repodir_fsname =
			cmd_optargs_getarg(&opa, "repodir/fsname");
	} else {
		ctx->in_args.dirpath = cmd_optargs_getarg(&opa, "pathname");
	}
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_clone_destroy_env(struct cmd_clone_ctx *ctx)
{
	cmd_del_env(&ctx->env);
}

static void cmd_clone_finalize(struct cmd_clone_ctx *ctx)
{
	cmd_clone_destroy_env(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.forkname);
	cmd_pstrfree(&ctx->in_args.dirpath);
	cmd_pstrfree(&ctx->in_args.dirpath_real);
	cmd_del_iocp(&ctx->ioc);
	cmd_destroy_args(&ctx->args);
	cmd_clone_del_ctx(ctx);
}

static void cmd_clone_atexit(void)
{
	struct cmd_clone_ctx *ctx = cmd_clone_ctx_p;

	if (ctx != nullptr) {
		cmd_clone_finalize(ctx);
	}
}

static void cmd_clone_start(struct cmd_clone_ctx **pctx)
{
	cmd_atexit(cmd_clone_atexit);
	*pctx        = cmd_clone_new_ctx();
	(*pctx)->ioc = cmd_new_ioc();
}

static void cmd_clone_prepare_by_query(struct cmd_clone_ctx *ctx)
{
	struct silofs_ioc_query ioc_qry;
	struct silofs_ioc_query *qry   = &ioc_qry;
	struct cmd_clone_in_args *args = &ctx->in_args;

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_REPO;
	cmd_clone_ioctl_query(args->dirpath_real, qry);
	args->repodir = cmd_strvdup(qry->u.repo.path);

	qry->qtype = SILOFS_QUERY_BOOT;
	cmd_clone_ioctl_query(args->dirpath_real, qry);
	args->fsname = cmd_strvdup(qry->u.boot.name);
}

static void cmd_clone_prepare_online(struct cmd_clone_ctx *ctx)
{
	cmd_realpath_dir(ctx->in_args.dirpath, &ctx->in_args.dirpath_real);
	cmd_check_fsname(ctx->in_args.forkname);
	cmd_check_fusefs(ctx->in_args.dirpath_real);
	cmd_clone_prepare_by_query(ctx);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.forkname);
}

static void cmd_clone_prepare_offline(struct cmd_clone_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_fsname);
	cmd_path_split(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_check_nonemptydir(ctx->in_args.repodir, true);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
	cmd_check_fsname(ctx->in_args.forkname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.forkname);
}

static void cmd_clone_prepare(struct cmd_clone_ctx *ctx)
{
	if (ctx->in_args.offline) {
		cmd_clone_prepare_offline(ctx);
	} else {
		cmd_clone_prepare_online(ctx);
	}
}

static void cmd_clone_restrict_process(struct cmd_clone_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, false);
}

static void cmd_clone_getpass(struct cmd_clone_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void
cmd_clone_ioctl_query(const char *path, struct silofs_ioc_query *qry)
{
	int dfd = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_die(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		cmd_die(err, "ioctl error: %s", path);
	}
	silofs_sys_closefd(&dfd);
}

static void cmd_clone_do_ioctl_forkfs(struct cmd_clone_ctx *ctx)
{
	union silofs_ioc_u *ioc = ctx->ioc;
	const char *dirpath     = ctx->in_args.dirpath_real;
	int dfd                 = -1;
	int err;

	cmd_reset_ioc(ctx->ioc);
	err = silofs_sys_opendir(dirpath, &dfd);
	if (err) {
		cmd_die(err, "failed to open dir: %s", dirpath);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		cmd_die(err, "syncfs error: %s", dirpath);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_FORKFS, &ioc->forkfs);
	silofs_sys_close(dfd);
	if (err == -ENOTTY) {
		cmd_die(err, "ioctl error: %s", dirpath);
	} else if (err) {
		cmd_die(err, "failed to clone: %s",
		        ctx->in_args.repodir_fsname);
	}
	memcpy(&ctx->fsrefs, &ioc->forkfs.fsrefs, sizeof(ctx->fsrefs));
}

static void cmd_clone_do_ioctl_syncfs(struct cmd_clone_ctx *ctx)
{
	const char *dirpath = ctx->in_args.dirpath_real;
	int dfd             = -1;
	int err;

	cmd_reset_ioc(ctx->ioc);
	err = silofs_sys_open(dirpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_die(err, "failed to open: %s", dirpath);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_SYNCFS, &ctx->ioc->syncfs);
	if (err) {
		cmd_die(err, "ioctl error: %s", dirpath);
	}
	silofs_sys_close(dfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_clone_setup_args(struct cmd_clone_ctx *ctx)
{
	struct silofs_args *args = &ctx->args;

	cmd_setup_args(args);
	args->bref[0].repodir = ctx->in_args.repodir_real;
	args->bref[0].refname = ctx->in_args.fsname;
	args->passwd          = ctx->in_args.password;
}

static void cmd_clone_load_spec(struct cmd_clone_ctx *ctx)
{
	cmd_spec_load(&ctx->args.spec, &ctx->args.bref[0]);
}

static void cmd_clone_setup_env(struct cmd_clone_ctx *ctx)
{
	cmd_new_env(&ctx->args, &ctx->env);
	cmd_spec_clear_fsids(&ctx->args.spec);
	cmd_delpass(&ctx->in_args.password);
}

static void cmd_clone_open_repo(struct cmd_clone_ctx *ctx)
{
	cmd_open_repo(ctx->env);
}

static void cmd_clone_close_repo(struct cmd_clone_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

static void cmd_clone_sense_fs(struct cmd_clone_ctx *ctx)
{
	cmd_sense_fs(ctx->env, &ctx->args.spec.fsref);
}

static void cmd_clone_open_fs(struct cmd_clone_ctx *ctx)
{
	cmd_reload_fs(ctx->env, &ctx->args.spec.fsref);
}

static void cmd_clone_do_clonefs(struct cmd_clone_ctx *ctx)
{
	cmd_fork_fs(ctx->env, &ctx->fsrefs);
}

static void cmd_clone_close_fs(struct cmd_clone_ctx *ctx)
{
	cmd_close_fs(ctx->env);
}

static void cmd_clone_save_fork(struct cmd_clone_ctx *ctx)
{
	const struct silofs_baseref baseref = {
		.repodir = ctx->in_args.repodir_real,
		.refname = ctx->in_args.forkname,
	};

	cmd_spec_resave(&ctx->args.spec, &ctx->fsrefs.fork, &baseref);
}

static void cmd_clone_save_main(struct cmd_clone_ctx *ctx)
{
	const struct silofs_baseref baseref = {
		.repodir = ctx->in_args.repodir_real,
		.refname = ctx->in_args.fsname,
	};

	cmd_spec_resave(&ctx->args.spec, &ctx->fsrefs.main, &baseref);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_clone_online(struct cmd_clone_ctx *ctx)
{
	/* Clone fs on server side via ioctl request */
	cmd_clone_do_ioctl_forkfs(ctx);

	/* Trigger another flush-sync on new file-system */
	cmd_clone_do_ioctl_syncfs(ctx);
}

static void cmd_clone_offline(struct cmd_clone_ctx *ctx)
{
	/* Open file-system */
	cmd_clone_open_fs(ctx);

	/* Fork and clone */
	cmd_clone_do_clonefs(ctx);

	/* Shut down file-system environment */
	cmd_clone_close_fs(ctx);
}

static void cmd_clone_execute(struct cmd_clone_ctx *ctx)
{
	if (ctx->in_args.offline) {
		/* Execute clone directly on off-line file-system */
		cmd_clone_offline(ctx);
	} else {
		/* Execute clone via ioctl to live file-system */
		cmd_clone_online(ctx);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_clone(void)
{
	struct cmd_clone_ctx *ctx = nullptr;

	/* Setup context */
	cmd_clone_start(&ctx);

	/* Parse command's arguments */
	cmd_clone_parse_optargs(ctx);

	/* Verify user's arguments */
	cmd_clone_prepare(ctx);

	/* Restrict process access */
	cmd_clone_restrict_process(ctx);

	/* Require password (off-line mode) */
	cmd_clone_getpass(ctx);

	/* Setup input arguments */
	cmd_clone_setup_args(ctx);

	/* Load fs spec */
	cmd_clone_load_spec(ctx);

	/* Setup execution environment */
	cmd_clone_setup_env(ctx);

	/* Open repository */
	cmd_clone_open_repo(ctx);

	/* Require source boot-record */
	cmd_clone_sense_fs(ctx);

	/* Do actual clone (offline|online) */
	cmd_clone_execute(ctx);

	/* Close repository */
	cmd_clone_close_repo(ctx);

	/* Save new clone spec */
	cmd_clone_save_fork(ctx);

	/* Re-save (overwrite) original spec */
	cmd_clone_save_main(ctx);

	/* Delete environment */
	cmd_clone_destroy_env(ctx);

	/* Post execution cleanups */
	cmd_clone_finalize(ctx);
}
