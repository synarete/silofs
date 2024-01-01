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
#define _GNU_SOURCE 1
#include <fcntl.h>
#include "cmd.h"

struct cmd_lockfile_ctx {
	char lockname[SILOFS_NAME_MAX + 1];
	char tempname[SILOFS_NAME_MAX + 1];
	char data[256];
	const char *repodir;
	const char *name;
	size_t  retry;
	time_t  now;
	pid_t   pid;
	int     dfd;
};


static int do_fstatat(int dirfd, const char *pathname, struct stat *st)
{
	return silofs_sys_fstatat(dirfd, pathname, st, 0);
}

static void cmd_lockfile_closedir(struct cmd_lockfile_ctx *lf_ctx)
{
	silofs_sys_closefd(&lf_ctx->dfd);
}

static void
cmd_lockfile_init(struct cmd_lockfile_ctx *lf_ctx,
                  const char *repodir, const char *name, size_t retry)
{
	memset(lf_ctx, 0, sizeof(*lf_ctx));
	lf_ctx->repodir = repodir;
	lf_ctx->name = name;
	lf_ctx->now = silofs_time_now();
	lf_ctx->retry = retry;
	lf_ctx->pid = getpid();
	lf_ctx->dfd = -1;
}

static void cmd_lockfile_fini(struct cmd_lockfile_ctx *lf_ctx)
{
	cmd_lockfile_closedir(lf_ctx);
	memset(lf_ctx, 0, sizeof(*lf_ctx));
}

static void cmd_lockfile_mknames(struct cmd_lockfile_ctx *lf_ctx)
{
	snprintf(lf_ctx->lockname, sizeof(lf_ctx->lockname) - 1,
	         ".%s.lock", lf_ctx->name);
	snprintf(lf_ctx->tempname, sizeof(lf_ctx->tempname) - 1,
	         ".%s_%08x.lock~", lf_ctx->name, (int)lf_ctx->now);
}

static void cmd_lockfile_mkdata(struct cmd_lockfile_ctx *lf_ctx)
{
	snprintf(lf_ctx->data, sizeof(lf_ctx->data) - 1, "%d\n", lf_ctx->pid);
}

static void cmd_lockfile_opendir(struct cmd_lockfile_ctx *lf_ctx)
{
	int err;

	err = silofs_sys_opendir(lf_ctx->repodir, &lf_ctx->dfd);
	if (err) {
		cmd_dief(err, "failed to open repodir: %s", lf_ctx->repodir);
	}
}

static void
cmd_lockfile_setup(struct cmd_lockfile_ctx *lf_ctx,
                   const char *repodir, const char *name, size_t retry)
{
	cmd_lockfile_init(lf_ctx, repodir, name, retry);
	cmd_lockfile_mknames(lf_ctx);
	cmd_lockfile_mkdata(lf_ctx);
	cmd_lockfile_opendir(lf_ctx);
}

static void cmd_lockfile_wait_noent(const struct cmd_lockfile_ctx *lf_ctx)
{
	struct stat st = { .st_size = -1 };
	size_t retry = 0;
	int err = 0;

	while (retry++ < lf_ctx->retry) {
		err = do_fstatat(lf_ctx->dfd, lf_ctx->lockname, &st);
		if (err) {
			break;
		}
		silofs_suspend_secs(2);
	}

	if (!err) {
		cmd_dief(0, "lock-file exists: %s/%s",
		         lf_ctx->repodir, lf_ctx->lockname);
	} else if (err != -ENOENT) {
		cmd_dief(err, "fail to stat lock-file: %s/%s",
		         lf_ctx->repodir, lf_ctx->lockname);
	}
}

static void cmd_lockfile_mktemp(const struct cmd_lockfile_ctx *lf_ctx)
{
	int fd = -1;
	int err;

	err = silofs_sys_openat(lf_ctx->dfd, lf_ctx->tempname,
	                        O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		cmd_dief(err, "failed to create temp lock-file: %s/%s",
		         lf_ctx->repodir, lf_ctx->tempname);
	}
	err = silofs_sys_writen(fd, lf_ctx->data, strlen(lf_ctx->data));
	if (err) {
		silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->tempname, 0);
		cmd_dief(err, "failed to write temp lock-file: %s/%s",
		         lf_ctx->repodir, lf_ctx->tempname);
	}
	silofs_sys_closefd(&fd);
}

static void cmd_lockfile_mklock(const struct cmd_lockfile_ctx *lf_ctx)
{
	int err = 0;

	err = silofs_sys_renameat2(lf_ctx->dfd, lf_ctx->tempname,
	                           lf_ctx->dfd, lf_ctx->lockname,
	                           RENAME_NOREPLACE);
	if (err) {
		silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->tempname, 0);
		cmd_dief(err, "failed to rename lock-file: %s/%s --> %s",
		         lf_ctx->repodir, lf_ctx->tempname, lf_ctx->lockname);
	}
}

static void cmd_lockfile_unlinkall(const struct cmd_lockfile_ctx *lf_ctx)
{
	silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->tempname, 0);
	silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->lockname, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_lockfile_acquire(const char *repodir,
                                 const char *name, size_t retry)
{
	struct cmd_lockfile_ctx lf_ctx;

	cmd_lockfile_setup(&lf_ctx, repodir, name, retry);
	cmd_lockfile_wait_noent(&lf_ctx);
	cmd_lockfile_mktemp(&lf_ctx);
	cmd_lockfile_mklock(&lf_ctx);
	cmd_lockfile_fini(&lf_ctx);
}

void cmd_lockfile_acquire1(const char *repodir, const char *name)
{
	cmd_lockfile_acquire(repodir, name, 1);
}

void cmd_lockfile_acquire4(const char *repodir, const char *name)
{
	cmd_lockfile_acquire(repodir, name, 4);
}

void cmd_lockfile_release(const char *repodir, const char *name)
{
	struct cmd_lockfile_ctx lf_ctx;

	cmd_lockfile_setup(&lf_ctx, repodir, name, 1);
	cmd_lockfile_unlinkall(&lf_ctx);
	cmd_lockfile_fini(&lf_ctx);
}
