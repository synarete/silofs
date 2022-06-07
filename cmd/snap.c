/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

static const char *cmd_snap_usage[] = {
	"snap <repo/src-name> <repo/dst-name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

struct cmd_snap_args {
	char   *src_repodir_name;
	char   *src_repodir;
	char   *src_repodir_real;
	char   *src_name;
	char   *dst_repodir_name;
	char   *dst_repodir;
	char   *dst_repodir_real;
	char   *dst_name;
};

struct cmd_snap_ctx {
	struct cmd_snap_args    args;
	struct silofs_bootlink  src_blnk;
	struct silofs_bootpath  dst_bpath;
	struct silofs_bootsecs  dst_bsecs;
	struct silofs_ioc_clone ioc_clone;
	struct silofs_fs_env   *fse;
	char                   *src_mntdir;
	int                     src_lock_fd;
};

static struct cmd_snap_ctx *cmd_snap_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_getopt(struct cmd_snap_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("V:h", opts);
		if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_snap_usage);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repo/src-name", &ctx->args.src_repodir_name);
	cmd_getarg("repo/dst-name", &ctx->args.dst_repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_snap_finalize(struct cmd_snap_ctx *ctx)
{
	cmd_del_env(&ctx->fse);
	cmd_pstrfree(&ctx->args.src_repodir_name);
	cmd_pstrfree(&ctx->args.src_repodir);
	cmd_pstrfree(&ctx->args.src_repodir_real);
	cmd_pstrfree(&ctx->args.src_name);
	cmd_pstrfree(&ctx->args.dst_repodir_name);
	cmd_pstrfree(&ctx->args.dst_repodir_name);
	cmd_pstrfree(&ctx->args.dst_repodir_real);
	cmd_pstrfree(&ctx->args.dst_repodir_real);
	cmd_pstrfree(&ctx->src_mntdir);
	cmd_unlock_bpath(&ctx->src_blnk.bpath, &ctx->src_lock_fd);
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
	cmd_snap_ctx = ctx;
	atexit(cmd_snap_atexit);
}

static void cmd_snap_prepare(struct cmd_snap_ctx *ctx)
{
	cmd_check_reg(ctx->args.src_repodir_name, false);
	cmd_check_notexists(ctx->args.dst_repodir_name);
	cmd_split_path(ctx->args.src_repodir_name,
	               &ctx->args.src_repodir, &ctx->args.src_name);
	cmd_split_path(ctx->args.dst_repodir_name,
	               &ctx->args.dst_repodir, &ctx->args.dst_name);
	cmd_check_nonemptydir(ctx->args.src_repodir, false);
	cmd_check_nonemptydir(ctx->args.dst_repodir, true);
	cmd_realpath(ctx->args.src_repodir, &ctx->args.src_repodir_real);
	cmd_check_fsname(ctx->args.src_name);
	cmd_realpath(ctx->args.dst_repodir, &ctx->args.dst_repodir_real);
	cmd_check_fsname(ctx->args.dst_name);
	cmd_setup_bpath(&ctx->src_blnk.bpath,
	                ctx->args.src_repodir_real, ctx->args.src_name);
	cmd_setup_bpath(&ctx->dst_bpath,
	                ctx->args.dst_repodir_real, ctx->args.dst_name);
}

static bool cmd_snap_stat_samedir(const char *path1, const char *path2)
{
	struct stat st1;
	struct stat st2;

	cmd_stat_dir(path1, &st1);
	cmd_stat_dir(path2, &st2);
	return (st1.st_ino == st2.st_ino) && (st1.st_dev == st2.st_dev);
}

static void cmd_snap_check_samerepo(const struct cmd_snap_ctx *ctx)
{
	const char *src = ctx->args.src_repodir_real;
	const char *dst = ctx->args.dst_repodir_real;

	if (!cmd_snap_stat_samedir(src, dst)) {
		cmd_dief(0, "not on same repository: %s %s", src, dst);
	}
}

static void cmd_snap_ioctl_query(const char *path,
                                 struct silofs_ioc_query *qry)
{
	int dfd = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_dief(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_QUERY, qry);
	if (err) {
		cmd_dief(err, "ioctl error: %s", path);
	}
	silofs_sys_closefd(&dfd);
}

static bool cmd_snap_is_src_mntdir(struct cmd_snap_ctx *ctx,
                                   const char *mntdir)
{
	struct silofs_ioc_query query = {
		.qtype = SILOFS_QUERY_BOOTSEC,
	};
	bool ret;

	cmd_snap_ioctl_query(mntdir, &query);
	ret = cmd_snap_stat_samedir(query.u.bootsec.repo,
	                            ctx->args.src_repodir_real);
	return ret && !strcmp(query.u.bootsec.name, ctx->args.src_name);
}

static void cmd_snap_resolve_src_mntdir(struct cmd_snap_ctx *ctx)
{
	struct silofs_proc_mntinfo *mi_list = NULL;
	struct silofs_proc_mntinfo *mi_iter = NULL;

	mi_list = cmd_parse_mountinfo();
	mi_iter = mi_list;
	while (mi_iter && !ctx->src_mntdir) {
		if (cmd_snap_is_src_mntdir(ctx, mi_iter->mntdir)) {
			cmd_realpath(mi_iter->mntdir, &ctx->src_mntdir);
		}
		mi_iter = mi_iter->next;
	}
	cmd_free_mountinfo(mi_list);

	if (!ctx->src_mntdir) {
		cmd_dief(0, "failed to resolve mount point of: %s",
		         ctx->args.src_repodir_name);
	}
}

static void cmd_snap_by_ioctl_clone(struct cmd_snap_ctx *ctx)
{
	struct silofs_ioc_clone *clone = &ctx->ioc_clone;
	int dfd = -1;
	int err;

	err = silofs_sys_opendir(ctx->src_mntdir, &dfd);
	if (err) {
		cmd_dief(err, "failed to open dir: %s", ctx->src_mntdir);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		cmd_dief(err, "syncfs error: %s", ctx->src_mntdir);
	}

	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_CLONE, clone);
	silofs_sys_close(dfd);
	if (err == -ENOTTY) {
		cmd_dief(err, "ioctl error: %s", ctx->src_mntdir);
	} else if (err) {
		cmd_dief(err, "failed to snap: %s",
		         ctx->args.dst_repodir_name);
	}

	silofs_bsec1k_parse(&clone->bsec[0], &ctx->dst_bsecs.bsec[0]);
	silofs_bsec1k_parse(&clone->bsec[1], &ctx->dst_bsecs.bsec[1]);
}

static void cmd_snap_resave_bsecs(struct cmd_snap_ctx *ctx)
{
	cmd_save_bsec(&ctx->src_blnk.bpath, &ctx->dst_bsecs.bsec[0]);
	cmd_save_bsec(&ctx->dst_bpath, &ctx->dst_bsecs.bsec[1]);
}

static void cmd_snap_online(struct cmd_snap_ctx *ctx)
{
	cmd_snap_resolve_src_mntdir(ctx);
	cmd_snap_by_ioctl_clone(ctx);
	cmd_snap_resave_bsecs(ctx);
}

static void cmd_snap_setup_env(struct cmd_snap_ctx *ctx)
{
	const struct silofs_fs_args fs_args = {
		.main_repodir = ctx->args.src_repodir_real,
		.main_name = ctx->args.src_name,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};
	cmd_new_env(&ctx->fse, &fs_args);
}

static void cmd_snap_by_exec_fse(struct cmd_snap_ctx *ctx)
{
	cmd_load_bsec(&ctx->src_blnk.bpath, &ctx->src_blnk.bsec);
	cmd_snap_fs(ctx->fse, &ctx->src_blnk.bsec, &ctx->dst_bsecs);
}

static void cmd_snap_offline(struct cmd_snap_ctx *ctx)
{
	cmd_snap_setup_env(ctx);
	cmd_snap_by_exec_fse(ctx);
	cmd_snap_resave_bsecs(ctx);
}

static bool cmd_snap_need_online(struct cmd_snap_ctx *ctx)
{
	return !cmd_trylock_bpath(&ctx->src_blnk.bpath, &ctx->src_lock_fd);
}

static void cmd_snap_execute(struct cmd_snap_ctx *ctx)
{
	if (cmd_snap_need_online(ctx)) {
		cmd_snap_online(ctx);
	} else {
		cmd_snap_offline(ctx);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_snap(void)
{
	struct cmd_snap_ctx ctx = {
		.fse = NULL,
		.src_lock_fd = -1,
	};

	/* Do all cleanups upon exits */
	cmd_snap_start(&ctx);

	/* Parse command's arguments */
	cmd_snap_getopt(&ctx);

	/* Verify user's arguments */
	cmd_snap_prepare(&ctx);

	/* Require single repo mode */
	cmd_snap_check_samerepo(&ctx);

	/* Do actual snap */
	cmd_snap_execute(&ctx);

	/* Post execution cleanups */
	cmd_snap_finalize(&ctx);
}

