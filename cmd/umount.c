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
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include "cmd.h"

static const char *cmd_umount_help_desc[] = {
	"umount [options] <mountpoint>",
	"",
	"options:",
	"  -l, --lazy                   Detach mode",
	"  -f, --force                  Forced mode",
	NULL
};

struct cmd_umount_in_args {
	char   *mntpoint;
	char   *mntpoint_real;
	int     force;
	int     lazy;
};

struct cmd_umount_ctx {
	struct cmd_umount_in_args in_args;
	long pad;
};

static struct cmd_umount_ctx *cmd_umount_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_umount_getopt(struct cmd_umount_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "lazy", no_argument, NULL, 'l' },
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("lfh", opts);
		if (opt_chr == 'l') {
			ctx->in_args.lazy = 1;
		} else if (opt_chr == 'f') {
			ctx->in_args.force = 1;
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_umount_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("mountpoint", &ctx->in_args.mntpoint);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_umount_finalize(struct cmd_umount_ctx *ctx)
{
	cmd_pstrfree(&ctx->in_args.mntpoint_real);
	cmd_pstrfree(&ctx->in_args.mntpoint);
	cmd_umount_ctx = NULL;
}

static void cmd_umount_atexit(void)
{
	if (cmd_umount_ctx != NULL) {
		cmd_umount_finalize(cmd_umount_ctx);
	}
}

static void cmd_umount_start(struct cmd_umount_ctx *ctx)
{
	cmd_umount_ctx = ctx;
	atexit(cmd_umount_atexit);
}

static void cmd_umount_prepare(struct cmd_umount_ctx *ctx)
{
	struct stat st;
	int err;

	cmd_check_mntsrv_conn();
	err = silofs_sys_stat(ctx->in_args.mntpoint, &st);
	if ((err == -ENOTCONN) && ctx->in_args.force) {
		silofs_log_debug("transport endpoint not connected: %s",
		                 ctx->in_args.mntpoint);
		return;
	}
	cmd_realpath(ctx->in_args.mntpoint, &ctx->in_args.mntpoint_real);
	cmd_check_mntdir(ctx->in_args.mntpoint_real, false);
}

static const char *cmd_umount_dirpath(const struct cmd_umount_ctx *ctx)
{
	return (ctx->in_args.mntpoint_real != NULL) ?
	       ctx->in_args.mntpoint_real : ctx->in_args.mntpoint;
}

static uint32_t cmd_umount_mnt_flags(const struct cmd_umount_ctx *ctx)
{
	uint32_t mnt_flags = 0;

	if (ctx->in_args.lazy) {
		mnt_flags |= MNT_DETACH;
	}
	if (ctx->in_args.force) {
		mnt_flags |= MNT_FORCE;
	}
	return mnt_flags;
}

static void cmd_umount_send_recv(const struct cmd_umount_ctx *ctx)
{
	const char *mntpath = cmd_umount_dirpath(ctx);
	const uid_t uid = getuid();
	const gid_t gid = getgid();
	uint32_t mnt_flags;
	int err;

	mnt_flags = cmd_umount_mnt_flags(ctx);
	err = silofs_mntrpc_umount(mntpath, uid, gid, mnt_flags);
	if (err) {
		cmd_dief(err, "umount failed: %s lazy=%d force=%d",
		         mntpath, ctx->in_args.lazy, ctx->in_args.force);
	}
}

static void cmd_umount_probe_statvfs(const struct cmd_umount_ctx *ctx)
{
	struct statfs stfs;
	const char *path = cmd_umount_dirpath(ctx);
	long fstype;
	int err;

	for (size_t i = 0; i < 4; ++i) {
		sleep(1);
		memset(&stfs, 0, sizeof(stfs));
		err = silofs_sys_statfs(path, &stfs);
		if (err) {
			break;
		}
		fstype = stfs.f_type;
		if (fstype && !silofs_is_fuse_fstype(fstype)) {
			break;
		}
		/*
		 * TODO-0023: Fix FUSE statfs/statvfs
		 *
		 * It appears that FUSE forces zero value for 'statvfs.f_fsid'.
		 * Need to check why and if possible to fix.
		 */
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_umount(void)
{
	struct cmd_umount_ctx ctx = {
		.pad = 0,
	};

	/* Do all cleanups upon exits */
	cmd_umount_start(&ctx);

	/* Parse command's arguments */
	cmd_umount_getopt(&ctx);

	/* Verify user's arguments */
	cmd_umount_prepare(&ctx);

	/* Do actual umount */
	cmd_umount_send_recv(&ctx);

	/* Post-umount checks */
	cmd_umount_probe_statvfs(&ctx);

	/* Post execution cleanups */
	cmd_umount_finalize(&ctx);
}


