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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "cmd.h"

static const char *const cmd_fork_help_desc =
	"fork -n <forkname> [<pathname>]                                 \n"
	"fork -n <forkname> --offline <repodir/fsname>                   \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -n, --name=forkname          Result forkshot name             \n"
	"  -X, --offline                Operate on non-mounted fs        \n"
	"  -L, --loglevel=level         Logging level (rfc5424)          \n";

struct cmd_fork_in_args {
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

struct cmd_fork_ctx {
	struct cmd_fork_in_args in_args;
	struct silofs_args env_args;
	struct silofs_env *env;
	union silofs_ioc_u *ioc;
	struct silofs_xref xref_new;
	struct silofs_xref xref_alt;
};

static struct cmd_fork_ctx *cmd_fork_ctx_p;

/* local functions */
static void
cmd_fork_ioctl_query(const char *path, struct silofs_ioc_query *qry);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fork_parse_optargs(struct cmd_fork_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "name", 'n', 1 },      //
		{ "offline", 'X', 0 },   //
		{ "no-prompt", 'P', 0 }, //
		{ "password", 'p', 1 },  //
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
		case 'n':
			ctx->in_args.forkname =
				cmd_optarg_dupoptarg(&opa, "name");
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
			cmd_print_help_and_exit(cmd_fork_help_desc);
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

static void cmd_fork_destroy_env(struct cmd_fork_ctx *ctx)
{
	cmd_del_env(&ctx->env);
}

static void cmd_fork_finalize(struct cmd_fork_ctx *ctx)
{
	cmd_fork_destroy_env(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.forkname);
	cmd_pstrfree(&ctx->in_args.dirpath);
	cmd_pstrfree(&ctx->in_args.dirpath_real);
	cmd_del_iocp(&ctx->ioc);
	cmd_destroy_env_args(&ctx->env_args);
	cmd_fork_ctx_p = NULL;
}

static void cmd_fork_atexit(void)
{
	struct cmd_fork_ctx *ctx = cmd_fork_ctx_p;

	if (ctx != NULL) {
		cmd_fork_finalize(ctx);
	}
}

static void cmd_fork_start(struct cmd_fork_ctx *ctx)
{
	ctx->ioc = cmd_new_ioc();
	cmd_fork_ctx_p = ctx;
	cmd_atexit(cmd_fork_atexit);
}

static void cmd_fork_prepare_by_query(struct cmd_fork_ctx *ctx)
{
	struct silofs_ioc_query ioc_qry;
	struct silofs_ioc_query *qry = &ioc_qry;
	struct cmd_fork_in_args *args = &ctx->in_args;

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_REPO;
	cmd_fork_ioctl_query(args->dirpath_real, qry);
	args->repodir = cmd_strdup(qry->u.repo.path);

	qry->qtype = SILOFS_QUERY_BOOT;
	cmd_fork_ioctl_query(args->dirpath_real, qry);
	args->fsname = cmd_strdup(qry->u.boot.name);
}

static void cmd_fork_prepare_online(struct cmd_fork_ctx *ctx)
{
	cmd_realpath_dir(ctx->in_args.dirpath, &ctx->in_args.dirpath_real);
	cmd_check_fsname(ctx->in_args.forkname);
	cmd_check_fusefs(ctx->in_args.dirpath_real);
	cmd_fork_prepare_by_query(ctx);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.forkname);
}

static void cmd_fork_prepare_offline(struct cmd_fork_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_fsname);
	cmd_split_path(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_check_nonemptydir(ctx->in_args.repodir, true);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
	cmd_check_fsname(ctx->in_args.forkname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.forkname);
}

static void cmd_fork_prepare(struct cmd_fork_ctx *ctx)
{
	if (ctx->in_args.offline) {
		cmd_fork_prepare_offline(ctx);
	} else {
		cmd_fork_prepare_online(ctx);
	}
}

static void cmd_fork_getpass(struct cmd_fork_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void
cmd_fork_ioctl_query(const char *path, struct silofs_ioc_query *qry)
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

static void cmd_fork_do_ioctl_forkfs(struct cmd_fork_ctx *ctx)
{
	struct silofs_ioc_forkfs *cl = &ctx->ioc->forkfs;
	const char *dirpath = ctx->in_args.dirpath_real;
	int dfd = -1;
	int err;

	SILOFS_STATICASSERT_EQ(sizeof(ctx->xref_new.s), sizeof(cl->xref_new));
	SILOFS_STATICASSERT_EQ(sizeof(ctx->xref_alt.s), sizeof(cl->xref_alt));

	cmd_reset_ioc(ctx->ioc);
	err = silofs_sys_opendir(dirpath, &dfd);
	if (err) {
		cmd_die(err, "failed to open dir: %s", dirpath);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		cmd_die(err, "syncfs error: %s", dirpath);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_FORKFS, cl);
	silofs_sys_close(dfd);
	if (err == -ENOTTY) {
		cmd_die(err, "ioctl error: %s", dirpath);
	} else if (err) {
		cmd_die(err, "failed to fork: %s",
		        ctx->in_args.repodir_fsname);
	}

	memcpy(ctx->xref_new.s, cl->xref_new, sizeof(ctx->xref_new.s));
	memcpy(ctx->xref_alt.s, cl->xref_alt, sizeof(ctx->xref_alt.s));
}

static void cmd_fork_do_ioctl_syncfs(struct cmd_fork_ctx *ctx)
{
	const char *dirpath = ctx->in_args.dirpath_real;
	int dfd = -1;
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

static void cmd_fork_setup_env_args(struct cmd_fork_ctx *ctx)
{
	struct silofs_args *env_args = &ctx->env_args;

	cmd_setup_env_args(env_args);
	env_args->boot.repodir = ctx->in_args.repodir_real;
	env_args->boot.fsname = ctx->in_args.fsname;
	env_args->boot.passwd = ctx->in_args.password;
}

static void cmd_fork_setup_fs_ids(struct cmd_fork_ctx *ctx)
{
	cmd_fs_ids_load(&ctx->env_args.ids, ctx->in_args.repodir_real);
}

static void cmd_fork_load_xref(struct cmd_fork_ctx *ctx)
{
	cmd_load_fs_xref(&ctx->env_args.boot);
}

static void cmd_fork_setup_env(struct cmd_fork_ctx *ctx)
{
	cmd_new_env(&ctx->env_args, &ctx->env);
}

static void cmd_fork_open_repo(struct cmd_fork_ctx *ctx)
{
	cmd_open_repo(ctx->env);
}

static void cmd_fork_close_repo(struct cmd_fork_ctx *ctx)
{
	cmd_close_repo(ctx->env);
}

static void cmd_fork_sense_fs(struct cmd_fork_ctx *ctx)
{
	cmd_sense_fs(ctx->env);
}

static void cmd_fork_open_fs(struct cmd_fork_ctx *ctx)
{
	cmd_open_fs(ctx->env);
}

static void cmd_fork_do_forkfs(struct cmd_fork_ctx *ctx)
{
	cmd_fork_fs(ctx->env, &ctx->xref_new, &ctx->xref_alt);
}

static void cmd_fork_close_fs(struct cmd_fork_ctx *ctx)
{
	cmd_close_fs(ctx->env);
}

static void cmd_fork_save_fork_xref(struct cmd_fork_ctx *ctx)
{
	struct silofs_boot_args boot_args = {
		.repodir = ctx->in_args.repodir_real,
		.fsname = ctx->in_args.forkname,
	};

	memcpy(&boot_args.xref, &ctx->xref_alt, sizeof(boot_args.xref));
	cmd_save_fs_xref(&boot_args);
}

static void cmd_fork_save_curr_xref(struct cmd_fork_ctx *ctx)
{
	struct silofs_boot_args boot_args = {
		.repodir = ctx->in_args.repodir_real,
		.fsname = ctx->in_args.fsname,
	};

	memcpy(&boot_args.xref, &ctx->xref_new, sizeof(boot_args.xref));
	cmd_save_fs_xref(&boot_args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_fork_online(struct cmd_fork_ctx *ctx)
{
	/* Clone fs on server side via ioctl request */
	cmd_fork_do_ioctl_forkfs(ctx);

	/* Trigger another flush-sync on new file-system */
	cmd_fork_do_ioctl_syncfs(ctx);
}

static void cmd_fork_offline(struct cmd_fork_ctx *ctx)
{
	/* Open file-system */
	cmd_fork_open_fs(ctx);

	/* Fork and clone */
	cmd_fork_do_forkfs(ctx);

	/* Shut down file-system environment */
	cmd_fork_close_fs(ctx);
}

static void cmd_fork_execute(struct cmd_fork_ctx *ctx)
{
	if (ctx->in_args.offline) {
		/* Execute fork directly on off-line file-system */
		cmd_fork_offline(ctx);
	} else {
		/* Execute fork via ioctl to live file-system */
		cmd_fork_online(ctx);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_fork(void)
{
	struct cmd_fork_ctx ctx = {
		.env = NULL,
		.ioc = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_fork_start(&ctx);

	/* Parse command's arguments */
	cmd_fork_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_fork_prepare(&ctx);

	/* Require password (off-line mode) */
	cmd_fork_getpass(&ctx);

	/* Setup input arguments */
	cmd_fork_setup_env_args(&ctx);

	/* Load fs boot-reference */
	cmd_fork_load_xref(&ctx);

	/* Load fs-ids mapping */
	cmd_fork_setup_fs_ids(&ctx);

	/* Setup execution environment */
	cmd_fork_setup_env(&ctx);

	/* Open repository */
	cmd_fork_open_repo(&ctx);

	/* Require source boot-record */
	cmd_fork_sense_fs(&ctx);

	/* Do actual fork (offline|online) */
	cmd_fork_execute(&ctx);

	/* Close repository */
	cmd_fork_close_repo(&ctx);

	/* Save new fork bconf */
	cmd_fork_save_fork_xref(&ctx);

	/* Re-save (overwrite) original bconf */
	cmd_fork_save_curr_xref(&ctx);

	/* Delete environment */
	cmd_fork_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_fork_finalize(&ctx);
}
