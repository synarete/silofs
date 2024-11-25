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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "cmd.h"

static const char *cmd_snap_help_desc[] = {
	"snap -n <snapname> [<pathname>]",
	"snap -n <snapname> --offline <repodir/name>",
	"",
	"options:",
	"  -n, --name=snapname          Result snapshot name",
	"  -X, --offline                Operate on non-mounted file-system",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_snap_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *snapname;
	char *dirpath;
	char *dirpath_real;
	char *password;
	bool offline;
	bool no_prompt;
};

struct cmd_snap_ctx {
	struct cmd_snap_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	union silofs_ioc_u *ioc;
	struct silofs_caddr boot_new;
	struct silofs_caddr boot_alt;
};

static struct cmd_snap_ctx *cmd_snap_ctx;

/* local functions */
static void
cmd_snap_ioctl_query(const char *path, struct silofs_ioc_query *qry);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_parse_optargs(struct cmd_snap_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "name", 'n', 1 },      { "offline", 'X', 0 },
		{ "no-prompt", 'P', 0 }, { "password", 'p', 1 },
		{ "loglevel", 'L', 1 },  { "help", 'h', 0 },
		{ NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'n':
			ctx->in_args.snapname =
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
			cmd_print_help_and_exit(cmd_snap_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	cmd_require_arg("name", ctx->in_args.snapname);

	if (ctx->in_args.offline) {
		ctx->in_args.repodir_name =
			cmd_optargs_getarg(&opa, "repodir/name");
	} else {
		ctx->in_args.dirpath = cmd_optargs_getarg(&opa, "pathname");
	}
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_destroy_env(struct cmd_snap_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_snap_finalize(struct cmd_snap_ctx *ctx)
{
	cmd_snap_destroy_env(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.snapname);
	cmd_pstrfree(&ctx->in_args.dirpath);
	cmd_pstrfree(&ctx->in_args.dirpath_real);
	cmd_del_iocp(&ctx->ioc);
	cmd_fini_fs_args(&ctx->fs_args);
	cmd_snap_ctx = NULL;
}

static void cmd_snap_atexit(void)
{
	if (cmd_snap_ctx != NULL) {
		cmd_snap_finalize(cmd_snap_ctx);
	}
}

static void cmd_snap_start(struct cmd_snap_ctx *ctx)
{
	ctx->ioc = cmd_new_ioc();
	cmd_snap_ctx = ctx;
	atexit(cmd_snap_atexit);
}

static void cmd_snap_prepare_by_query(struct cmd_snap_ctx *ctx)
{
	struct silofs_ioc_query ioc_qry;
	struct silofs_ioc_query *qry = &ioc_qry;
	struct cmd_snap_in_args *args = &ctx->in_args;

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_REPO;
	cmd_snap_ioctl_query(args->dirpath_real, qry);
	args->repodir = cmd_strdup(qry->u.repo.path);

	qry->qtype = SILOFS_QUERY_BOOT;
	cmd_snap_ioctl_query(args->dirpath_real, qry);
	args->name = cmd_strdup(qry->u.boot.name);
}

static void cmd_snap_prepare_online(struct cmd_snap_ctx *ctx)
{
	cmd_realpath_dir(ctx->in_args.dirpath, &ctx->in_args.dirpath_real);
	cmd_check_fsname(ctx->in_args.snapname);
	cmd_check_fusefs(ctx->in_args.dirpath_real);
	cmd_snap_prepare_by_query(ctx);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.snapname);
}

static void cmd_snap_prepare_offline(struct cmd_snap_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
		       &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, true);
	cmd_realpath_dir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
	cmd_check_fsname(ctx->in_args.snapname);
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.snapname);
}

static void cmd_snap_prepare(struct cmd_snap_ctx *ctx)
{
	if (ctx->in_args.offline) {
		cmd_snap_prepare_offline(ctx);
	} else {
		cmd_snap_prepare_online(ctx);
	}
}

static void cmd_snap_getpass(struct cmd_snap_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
				   &ctx->in_args.password);
	}
}

static void
cmd_snap_ioctl_query(const char *path, struct silofs_ioc_query *qry)
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

static void cmd_snap_do_ioctl_clone(struct cmd_snap_ctx *ctx)
{
	struct silofs_strbuf name;
	struct silofs_ioc_clone *cl = &ctx->ioc->clone;
	const char *dirpath = ctx->in_args.dirpath_real;
	int dfd = -1;
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
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_CLONE, cl);
	silofs_sys_close(dfd);
	if (err == -ENOTTY) {
		cmd_die(err, "ioctl error: %s", dirpath);
	} else if (err) {
		cmd_die(err, "failed to snap: %s", ctx->in_args.repodir_name);
	}

	silofs_strbuf_setup_by(&name, cl->boot_new);
	silofs_caddr_by_name(&ctx->boot_new, &name);

	silofs_strbuf_setup_by(&name, cl->boot_alt);
	silofs_caddr_by_name(&ctx->boot_alt, &name);
}

static void cmd_snap_do_ioctl_syncfs(struct cmd_snap_ctx *ctx)
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

static void cmd_snap_setup_fs_args(struct cmd_snap_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init(fs_args);
	fs_args->bref.repodir = ctx->in_args.repodir_real;
	fs_args->bref.name = ctx->in_args.name;
	fs_args->bref.passwd = ctx->in_args.password;
}

static void cmd_snap_setup_fs_ids(struct cmd_snap_ctx *ctx)
{
	cmd_fs_ids_load(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

static void cmd_snap_load_bref(struct cmd_snap_ctx *ctx)
{
	cmd_bootref_load(&ctx->fs_args.bref);
}

static void cmd_snap_setup_fsenv(struct cmd_snap_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_snap_open_repo(struct cmd_snap_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_snap_close_repo(struct cmd_snap_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_snap_poke_fs(struct cmd_snap_ctx *ctx)
{
	cmd_poke_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_snap_open_fs(struct cmd_snap_ctx *ctx)
{
	cmd_open_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_snap_fork_fs(struct cmd_snap_ctx *ctx)
{
	cmd_fork_fs(ctx->fsenv, &ctx->boot_new, &ctx->boot_alt);
}

static void cmd_snap_close_fs(struct cmd_snap_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

static void cmd_snap_save_snap_bref(struct cmd_snap_ctx *ctx)
{
	struct silofs_fs_bref bref;

	silofs_bootref_init(&bref);
	silofs_bootref_assign(&bref, &ctx->fs_args.bref);
	silofs_bootref_update(&bref, &ctx->boot_alt, ctx->in_args.snapname);
	cmd_bootref_save(&bref);
	silofs_bootref_fini(&bref);
}

static void cmd_snap_save_orig_bref(struct cmd_snap_ctx *ctx)
{
	struct silofs_fs_bref bref;

	silofs_bootref_init(&bref);
	silofs_bootref_assign(&bref, &ctx->fs_args.bref);
	silofs_bootref_update(&bref, &ctx->boot_new, ctx->in_args.name);
	cmd_bootref_save(&bref);
	silofs_bootref_fini(&bref);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_online(struct cmd_snap_ctx *ctx)
{
	/* Clone fs on server side via ioctl request */
	cmd_snap_do_ioctl_clone(ctx);

	/* Trigger another flush-sync on new file-system */
	cmd_snap_do_ioctl_syncfs(ctx);
}

static void cmd_snap_offline(struct cmd_snap_ctx *ctx)
{
	/* Open file-system */
	cmd_snap_open_fs(ctx);

	/* Fork and clone */
	cmd_snap_fork_fs(ctx);

	/* Shut down file-system environment */
	cmd_snap_close_fs(ctx);
}

static void cmd_snap_execute(struct cmd_snap_ctx *ctx)
{
	if (ctx->in_args.offline) {
		/* Execute snap directly on off-line file-system */
		cmd_snap_offline(ctx);
	} else {
		/* Execute snap via ioctl to live file-system */
		cmd_snap_online(ctx);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_snap(void)
{
	struct cmd_snap_ctx ctx = {
		.fsenv = NULL,
		.ioc = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_snap_start(&ctx);

	/* Parse command's arguments */
	cmd_snap_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_snap_prepare(&ctx);

	/* Require password (off-line mode) */
	cmd_snap_getpass(&ctx);

	/* Setup input arguments */
	cmd_snap_setup_fs_args(&ctx);

	/* Load fs boot-reference */
	cmd_snap_load_bref(&ctx);

	/* Load fs-ids mapping */
	cmd_snap_setup_fs_ids(&ctx);

	/* Setup execution environment */
	cmd_snap_setup_fsenv(&ctx);

	/* Open repository */
	cmd_snap_open_repo(&ctx);

	/* Require source boot-record */
	cmd_snap_poke_fs(&ctx);

	/* Do actual snap (offline|online) */
	cmd_snap_execute(&ctx);

	/* Close repository */
	cmd_snap_close_repo(&ctx);

	/* Save new snap bconf */
	cmd_snap_save_snap_bref(&ctx);

	/* Re-save (overwrite) original bconf */
	cmd_snap_save_orig_bref(&ctx);

	/* Delete environment */
	cmd_snap_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_snap_finalize(&ctx);
}
