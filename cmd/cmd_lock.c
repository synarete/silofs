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

static void cmd_fslock_mkname(const char *fsname, char *buf, size_t bsz)
{
	memset(buf, 0, bsz);
	snprintf(buf, bsz - 1, ".%s.lock", fsname);
}

static void cmd_fslock_mkdata(char *buf, size_t bsz)
{
	memset(buf, 0, bsz);
	snprintf(buf, bsz - 1, "%s-%s:%ld\n", cmd_global_params.name,
	         cmd_global_params.version, (long)getpid());
}

static void cmd_fslock_opendir(const char *repodir, int *out_dfd)
{
	int err;

	err = silofs_sys_opendir(repodir, out_dfd);
	if (err) {
		cmd_die(err, "failed to open directory: %s", repodir);
	}
}

static void cmd_fslock_closedir(const char *repodir, int *pdfd)
{
	int err;

	err = silofs_sys_closefd(pdfd);
	if (err) {
		cmd_die(err, "failed to close directory: %s", repodir);
	}
}

static void
cmd_fslock_open_with(int dfd, const char *fsname, int o_flags, int *out_fd)
{
	char lkname[NAME_MAX + 1];
	const mode_t mode = S_IRUSR | S_IWUSR;
	int err;

	cmd_fslock_mkname(fsname, lkname, sizeof(lkname));
	err = silofs_sys_openat(dfd, lkname, o_flags, mode, out_fd);
	if (err) {
		cmd_die(err, "failed to open fs-lock: %s", fsname);
	}
}

static void
cmd_fslock_open_at(int dfd, const char *fsname, bool excl, int *out_fd)
{
	const int o_xflags = excl ? O_EXCL : 0;

	cmd_fslock_open_with(dfd, fsname, O_CREAT | O_RDWR | o_xflags, out_fd);
}

static void cmd_fslock_assign(int fd, const char *fsname)
{
	char dat[256];
	size_t len;
	int err;

	cmd_fslock_mkdata(dat, sizeof(dat));
	len = strlen(dat);
	err = silofs_sys_pwriten(fd, dat, len, 0);
	if (err) {
		cmd_die(err, "failed to assign fs-lock: %s", fsname);
	}
	err = silofs_sys_ftruncate(fd, (off_t)len);
	if (err) {
		cmd_die(err, "failed to truncate fs-lock: %s", fsname);
	}
}

static void cmd_fslock_acquire_flock(int fd, const char *fsname)
{
	struct flock fl = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0, /* whole file */
	};
	int err;

	err = silofs_sys_fcntl_flock(fd, F_OFD_SETLK, &fl);
	if (err) {
		cmd_die(err, "failed to acquire fs-lock: %s", fsname);
	}
}

static void cmd_fslock_release_flock(int fd, const char *fsname)
{
	struct flock fl = {
		.l_type   = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0, /* whole file */
	};
	int err;

	err = silofs_sys_fcntl_flock(fd, F_OFD_SETLK, &fl);
	if (err) {
		cmd_die(err, "failed to release fs-lock: %s", fsname);
	}
}

static void cmd_fslock_do_acquire(const char *repodir, const char *fsname,
                                  bool excl, int *out_fd)
{
	int dfd = -1;

	cmd_fslock_opendir(repodir, &dfd);
	cmd_fslock_open_at(dfd, fsname, excl, out_fd);
	cmd_fslock_closedir(repodir, &dfd);
	cmd_fslock_acquire_flock(*out_fd, fsname);
	cmd_fslock_assign(*out_fd, fsname);
}

void cmd_fslock_acquirex(const char *repodir, const char *fsname, int *out_fd)
{
	cmd_fslock_do_acquire(repodir, fsname, true, out_fd);
}

void cmd_fslock_acquire(const char *repodir, const char *fsname, int *out_fd)
{
	cmd_fslock_do_acquire(repodir, fsname, false, out_fd);
}

static void cmd_fslock_unlink_at(int dfd, const char *fsname)
{
	char lkname[NAME_MAX + 1];

	cmd_fslock_mkname(fsname, lkname, sizeof(lkname));
	silofs_sys_unlinkat(dfd, lkname, 0);
}

static void cmd_fslock_closefd(int *pfd, const char *fsname)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		cmd_die(err, "failed to close fs-lock: %s", fsname);
	}
}

static void
cmd_fslock_do_release(const char *repodir, const char *fsname, int *pfd)
{
	int dfd = -1;

	cmd_fslock_opendir(repodir, &dfd);
	cmd_fslock_unlink_at(dfd, fsname);
	cmd_fslock_release_flock(*pfd, fsname);
	cmd_fslock_closefd(pfd, fsname);
	cmd_fslock_closedir(repodir, &dfd);
}

void cmd_fslock_release(const char *repodir, const char *fsname, int *pfd)
{
	if ((pfd != nullptr) && (*pfd >= 0)) {
		cmd_fslock_do_release(repodir, fsname, pfd);
	}
}
