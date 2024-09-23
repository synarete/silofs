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

static void cmd_lockfile_init(struct cmd_lockfile_ctx *lf_ctx,
                              const char *repodir, const char *name)
{
	memset(lf_ctx, 0, sizeof(*lf_ctx));
	lf_ctx->repodir = repodir;
	lf_ctx->name = name;
	lf_ctx->now = silofs_time_now();
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
		cmd_die(err, "failed to open repodir: %s", lf_ctx->repodir);
	}
}

static void cmd_lockfile_setup(struct cmd_lockfile_ctx *lf_ctx,
                               const char *repodir, const char *name)
{
	cmd_lockfile_init(lf_ctx, repodir, name);
	cmd_lockfile_mknames(lf_ctx);
	cmd_lockfile_mkdata(lf_ctx);
	cmd_lockfile_opendir(lf_ctx);
}

static int cmd_lockfile_trystat(const struct cmd_lockfile_ctx *lf_ctx)
{
	struct stat st = { .st_size = -1 };
	int err;

	err = do_fstatat(lf_ctx->dfd, lf_ctx->lockname, &st);
	if (err) {
		return err;
	}
	if (S_ISDIR(st.st_mode)) {
		return -EISDIR;
	}
	if (!S_ISREG(st.st_mode)) {
		return -EINVAL;
	}
	return 0;
}

static void
cmd_lockfile_wait_noent(const struct cmd_lockfile_ctx *lf_ctx, int retry_max)
{
	int err = 0;

	for (int retry = 0; retry < retry_max; ++retry) {
		err = cmd_lockfile_trystat(lf_ctx);
		if (err) {
			break;
		}
		silofs_suspend_secs(2);
	}

	if (!err) {
		cmd_die(-EEXIST, "lock-file exists: %s/%s",
		        lf_ctx->repodir, lf_ctx->lockname);
	} else if (err != -ENOENT) {
		cmd_die(err, "fail to stat lock-file: %s/%s",
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
		cmd_die(err, "failed to create temp lock-file: %s/%s",
		        lf_ctx->repodir, lf_ctx->tempname);
	}
	err = silofs_sys_writen(fd, lf_ctx->data, strlen(lf_ctx->data));
	if (err) {
		silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->tempname, 0);
		cmd_die(err, "failed to write temp lock-file: %s/%s",
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
		cmd_die(err, "failed to rename lock-file: %s/%s --> %s",
		        lf_ctx->repodir, lf_ctx->tempname, lf_ctx->lockname);
	}
}

static void cmd_lockfile_unlinkall(const struct cmd_lockfile_ctx *lf_ctx)
{
	silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->tempname, 0);
	silofs_sys_unlinkat(lf_ctx->dfd, lf_ctx->lockname, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_lock_fs(const char *repodir, const char *name)
{
	struct cmd_lockfile_ctx lf_ctx;

	cmd_lockfile_setup(&lf_ctx, repodir, name);
	cmd_lockfile_wait_noent(&lf_ctx, 10);
	cmd_lockfile_mktemp(&lf_ctx);
	cmd_lockfile_mklock(&lf_ctx);
	cmd_lockfile_fini(&lf_ctx);
}

void cmd_unlock_fs(const char *repodir, const char *name)
{
	struct cmd_lockfile_ctx lf_ctx;

	cmd_lockfile_setup(&lf_ctx, repodir, name);
	cmd_lockfile_unlinkall(&lf_ctx);
	cmd_lockfile_fini(&lf_ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_repo_lockpath(const char *repodir, char **out_path)
{
	char *dotsdir = NULL;

	cmd_join_path(repodir, SILOFS_REPO_DOTS_DIRNAME, &dotsdir);
	cmd_join_path(dotsdir, SILOFS_REPO_LOCK_FILENAME, out_path);
	cmd_pstrfree(&dotsdir);
}

static void cmd_open_repo_lock(const char *path, int *out_fd)
{
	struct stat st = { .st_size = 0 };
	int fd = -1;
	int err;

	err = silofs_sys_open(path, O_RDWR, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open repo lock: %s", path);
	}
	err = silofs_sys_fstat(fd, &st);
	if (err) {
		cmd_die(err, "failed to stat repo lock: %s", path);
	}
	if (st.st_size != SILOFS_REPO_METAFILE_SIZE) {
		cmd_die(0, "bad repo lock: %s", path);
	}
	*out_fd = fd;
}

static void cmd_close_repo_lock(const char *path, int *pfd)
{
	int err;

	err = silofs_sys_close(*pfd);
	if (err) {
		cmd_die(err, "failed to close repo lock: %s", path);
	}
	*pfd = -1;
}

static void cmd_acquire_repo_lock(const char *path, int fd, bool wrlck)
{
	struct stat st = { .st_size = 0 };
	struct flock fl = { .l_type = wrlck ? F_WRLCK : F_RDLCK };
	int err;

	err = silofs_sys_fstat(fd, &st);
	if (err) {
		cmd_die(err, "failed to stat repo lock: %s", path);
	}
	fl.l_len = st.st_size;
	err = silofs_sys_fcntl_flock(fd, F_OFD_SETLK, &fl);
	if (err) {
		cmd_die(err, "failed to acquire repo lock: %s", path);
	}
}

static void cmd_release_repo_lock(const char *path, int fd)
{
	struct stat st = { .st_size = 0 };
	struct flock fl = { .l_type = F_UNLCK };
	int err;

	err = silofs_sys_fstat(fd, &st);
	if (err) {
		cmd_die(err, "failed to stat repo lock: %s", path);
	}
	fl.l_len = st.st_size;
	err = silofs_sys_fcntl_flock(fd, F_OFD_SETLK, &fl);
	if (err) {
		cmd_die(err, "failed to release repo lock: %s", path);
	}
}

static void cmd_do_lock_repo(const char *lockfile, bool wrlck, int *out_fd)
{
	cmd_open_repo_lock(lockfile, out_fd);
	cmd_acquire_repo_lock(lockfile, *out_fd, wrlck);
}

static void cmd_do_unlock_repo(const char *lockfile, int *pfd)
{
	cmd_release_repo_lock(lockfile, *pfd);
	cmd_close_repo_lock(lockfile, pfd);
}

static void cmd_lock_repo(const char *repodir, bool wrlck, int *out_fd)
{
	char *lockfile = NULL;

	cmd_repo_lockpath(repodir, &lockfile);
	cmd_do_lock_repo(lockfile, wrlck, out_fd);
	cmd_pstrfree(&lockfile);
}

void cmd_wrlock_repo(const char *repodir, int *pfd)
{
	cmd_lock_repo(repodir, true, pfd);
}

void cmd_rdlock_repo(const char *repodir, int *pfd)
{
	cmd_lock_repo(repodir, false, pfd);
}

void cmd_unlock_repo(const char *repodir, int *pfd)
{
	char *lockfile = NULL;

	if (repodir && pfd && (*pfd > 0)) {
		cmd_repo_lockpath(repodir, &lockfile);
		cmd_do_unlock_repo(lockfile, pfd);
		cmd_pstrfree(&lockfile);
	}
}
