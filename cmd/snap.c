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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include "cmd.h"

static const char *cmd_snap_help_desc[] = {
	"snap -n <snapname> [<pathname>]",
	"snap -n <snapname> --offline <repodir/name>",
	"",
	"options:",
	"  -n, --name=snapname          Result snapshot name",
	"  -X, --offline                Operate on non-mounted file-system",
	"  -V, --verbose=level          Run in verbose mode (0..3)",
	NULL
};

struct cmd_snap_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *snapname;
	char   *dirpath;
	char   *dirpath_real;
	char   *password;
	bool    offline;
};

struct cmd_snap_ctx {
	struct cmd_snap_in_args  in_args;
	struct silofs_fs_args    fs_args;
	struct silofs_fs_ctx    *fs_ctx;
	union silofs_ioc_u      *ioc;
	struct silofs_lvid       lvid_new;
	struct silofs_lvid       lvid_alt;
};

static struct cmd_snap_ctx *cmd_snap_ctx;

/* local functions */
static void
cmd_snap_ioctl_query(const char *path, struct silofs_ioc_query *qry);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_getopt(struct cmd_snap_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "offline", no_argument, NULL, 'X' },
		{ "password", required_argument, NULL, 'p' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("n:XV:h", opts);
		if (opt_chr == 'n') {
			ctx->in_args.snapname = cmd_strdup(optarg);
		} else if (opt_chr == 'X') {
			ctx->in_args.offline = true;
		} else if (opt_chr == 'p') {
			cmd_getoptarg_pass(&ctx->in_args.password);
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_snap_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_require_arg("name", ctx->in_args.snapname);
	if (ctx->in_args.offline) {
		cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	} else {
		cmd_getarg_or_cwd("pathname", &ctx->in_args.dirpath);
	}
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_destroy_env(struct cmd_snap_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_snap_finalize(struct cmd_snap_ctx *ctx)
{
	cmd_snap_destroy_env(ctx);
	cmd_delpass(&ctx->in_args.password);
	cmd_iconf_reset(&ctx->fs_args.iconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.snapname);
	cmd_pstrfree(&ctx->in_args.dirpath);
	cmd_pstrfree(&ctx->in_args.dirpath_real);
	cmd_del_iocp(&ctx->ioc);
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

static void cmd_snap_prepare_online(struct cmd_snap_ctx *ctx)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_BOOT };
	struct cmd_snap_in_args *args = &ctx->in_args;

	cmd_check_isdir(args->dirpath, false);
	cmd_realpath(args->dirpath, &args->dirpath_real);
	cmd_check_fsname(args->snapname);
	cmd_check_fusefs(args->dirpath_real);
	cmd_snap_ioctl_query(args->dirpath_real, &query);
	args->repodir = cmd_strdup(query.u.bootrec.repo);
	args->name = cmd_strdup(query.u.bootrec.name);
	cmd_realpath(args->repodir, &args->repodir_real);
	cmd_check_isdir(args->repodir_real, true);
	cmd_check_fsname(args->name);
	cmd_check_notexists2(args->repodir_real, args->snapname);
}

static void cmd_snap_prepare_offline(struct cmd_snap_ctx *ctx)
{
	struct cmd_snap_in_args *args = &ctx->in_args;

	cmd_check_isreg(args->repodir_name, false);
	cmd_split_path(args->repodir_name, &args->repodir, &args->name);
	cmd_check_nonemptydir(args->repodir, true);
	cmd_realpath(args->repodir, &args->repodir_real);
	cmd_check_fsname(args->name);
	cmd_check_fsname(args->snapname);
	cmd_check_notexists2(args->repodir_real, args->snapname);
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
		cmd_getpass(NULL, &ctx->in_args.password);
	}
}

static void
cmd_snap_ioctl_query(const char *path, struct silofs_ioc_query *qry)
{
	int dfd = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_dief(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		cmd_dief(err, "ioctl error: %s", path);
	}
	silofs_sys_closefd(&dfd);
}

static void cmd_snap_do_ioctl_clone(struct cmd_snap_ctx *ctx)
{
	const char *dirpath = ctx->in_args.dirpath_real;
	int dfd = -1;
	int err;

	cmd_reset_ioc(ctx->ioc);
	err = silofs_sys_opendir(dirpath, &dfd);
	if (err) {
		cmd_dief(err, "failed to open dir: %s", dirpath);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		cmd_dief(err, "syncfs error: %s", dirpath);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_CLONE, &ctx->ioc->clone);
	silofs_sys_close(dfd);
	if (err == -ENOTTY) {
		cmd_dief(err, "ioctl error: %s", dirpath);
	} else if (err) {
		cmd_dief(err, "failed to snap: %s",
		         ctx->in_args.repodir_name);
	}
	silofs_lvid_assign(&ctx->lvid_new, &ctx->ioc->clone.lvid_new);
	silofs_lvid_assign(&ctx->lvid_alt, &ctx->ioc->clone.lvid_alt);
}

static void cmd_snap_do_ioctl_syncfs(struct cmd_snap_ctx *ctx)
{
	const char *dirpath = ctx->in_args.dirpath_real;
	int dfd = -1;
	int err;

	cmd_reset_ioc(ctx->ioc);
	err = silofs_sys_open(dirpath, O_RDONLY, 0, &dfd);
	if (err) {
		cmd_dief(err, "failed to open: %s", dirpath);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_SYNCFS, &ctx->ioc->syncfs);
	if (err) {
		cmd_dief(err, "ioctl error: %s", dirpath);
	}
	silofs_sys_close(dfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_setup_fs_args(struct cmd_snap_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_iconf_set_name(&fs_args->iconf, ctx->in_args.name);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
}

static void cmd_snap_load_iconf(struct cmd_snap_ctx *ctx)
{
	cmd_iconf_load(&ctx->fs_args.iconf, ctx->in_args.repodir_real);
}

static void cmd_snap_setup_fs_ctx(struct cmd_snap_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_snap_open_repo(struct cmd_snap_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_snap_close_repo(struct cmd_snap_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_snap_require_brec(struct cmd_snap_ctx *ctx)
{
	cmd_require_fs(ctx->fs_ctx, &ctx->fs_args.iconf);
}

static void cmd_snap_boot_fs(struct cmd_snap_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_ctx, &ctx->fs_args.iconf);
}

static void cmd_snap_open_fs(struct cmd_snap_ctx *ctx)
{
	cmd_open_fs(ctx->fs_ctx);
}

static void cmd_snap_fork_fs(struct cmd_snap_ctx *ctx)
{
	cmd_fork_fs(ctx->fs_ctx, &ctx->lvid_new, &ctx->lvid_alt);
}

static void cmd_snap_close_fs(struct cmd_snap_ctx *ctx)
{
	cmd_close_fs(ctx->fs_ctx);
}

static void cmd_snap_save_snap_iconf(struct cmd_snap_ctx *ctx)
{
	struct silofs_iconf snap_iconf;

	cmd_iconf_assign(&snap_iconf, &ctx->fs_args.iconf);
	cmd_iconf_set_lvid_by(&snap_iconf, &ctx->lvid_alt);
	cmd_iconf_set_name(&snap_iconf,  ctx->in_args.snapname);
	cmd_iconf_save(&snap_iconf, ctx->in_args.repodir_real);
	cmd_iconf_reset(&snap_iconf);
}

static void cmd_snap_save_orig_iconf(struct cmd_snap_ctx *ctx)
{
	struct silofs_iconf orig_iconf;

	cmd_iconf_assign(&orig_iconf, &ctx->fs_args.iconf);
	cmd_iconf_set_lvid_by(&orig_iconf, &ctx->lvid_new);
	cmd_iconf_set_name(&orig_iconf,  ctx->in_args.name);
	cmd_iconf_save(&orig_iconf, ctx->in_args.repodir_real);
	cmd_iconf_reset(&orig_iconf);
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
	/* Boot and lock file-system */
	cmd_snap_boot_fs(ctx);

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
		.fs_ctx = NULL,
		.ioc = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_snap_start(&ctx);

	/* Parse command's arguments */
	cmd_snap_getopt(&ctx);

	/* Verify user's arguments */
	cmd_snap_prepare(&ctx);

	/* Require password (off-line mode) */
	cmd_snap_getpass(&ctx);

	/* Setup input arguments */
	cmd_snap_setup_fs_args(&ctx);

	/* Require ids-map */
	cmd_snap_load_iconf(&ctx);

	/* Setup execution environment */
	cmd_snap_setup_fs_ctx(&ctx);

	/* Open repository */
	cmd_snap_open_repo(&ctx);

	/* Require source boot-record */
	cmd_snap_require_brec(&ctx);

	/* Do actual snap (offline|online) */
	cmd_snap_execute(&ctx);

	/* Close repository */
	cmd_snap_close_repo(&ctx);

	/* Save new snap iconf */
	cmd_snap_save_snap_iconf(&ctx);

	/* Re-save (overwrite) original iconf */
	cmd_snap_save_orig_iconf(&ctx);

	/* Delete environment */
	cmd_snap_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_snap_finalize(&ctx);
}

