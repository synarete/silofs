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
#define _GNU_SOURCE 1
#include <linux/landlock.h>
#include <linux/prctl.h>
#include "cmd.h"

static int open_dirfd(const char *dirpath)
{
	const int o_flags = O_PATH | O_CLOEXEC | O_DIRECTORY;
	int       dirfd   = -1;
	int       err;

	err = silofs_sys_open(dirpath, o_flags, 0, &dirfd);
	if (err) {
		cmd_die(err, "failed to open directory: %s", dirpath);
	}
	return dirfd;
}

static void clode_dirfd(int dirfd)
{
	silofs_sys_close(dirfd);
}

static void create_ruleset(int *out_ruleset_fd)
{
	const struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
		                     LANDLOCK_ACCESS_FS_WRITE_FILE |
		                     LANDLOCK_ACCESS_FS_READ_FILE |
		                     LANDLOCK_ACCESS_FS_READ_DIR |
		                     LANDLOCK_ACCESS_FS_REMOVE_DIR |
		                     LANDLOCK_ACCESS_FS_REMOVE_FILE |
		                     LANDLOCK_ACCESS_FS_MAKE_CHAR |
		                     LANDLOCK_ACCESS_FS_MAKE_DIR |
		                     LANDLOCK_ACCESS_FS_MAKE_REG |
		                     LANDLOCK_ACCESS_FS_MAKE_SOCK |
		                     LANDLOCK_ACCESS_FS_MAKE_FIFO |
		                     LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		                     LANDLOCK_ACCESS_FS_MAKE_SYM,
	};
	int err;

	err = silofs_sys_landlock_create_ruleset(&attr, sizeof(attr),
	                                         out_ruleset_fd);
	if (err) {
		cmd_die(err, "failed to create landlock ruleset");
	}
}

static void restrict_beneath(int ruleset_fd, const char *dirpath,
                             uint64_t allowed_access_mask)
{
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = allowed_access_mask,
		.parent_fd      = -1,
	};
	int err;

	path_beneath.parent_fd = open_dirfd(dirpath);
	err = silofs_sys_landlock_add_rule_beneath(ruleset_fd, &path_beneath);
	if (err) {
		cmd_die(err, "failed to add landlock rule");
	}
	clode_dirfd(path_beneath.parent_fd);
}

static void restrict_fsroot(int ruleset_fd)
{
	const uint64_t allowed_access_mask =   //
		LANDLOCK_ACCESS_FS_READ_FILE | //
		LANDLOCK_ACCESS_FS_READ_DIR;

	restrict_beneath(ruleset_fd, "/", allowed_access_mask);
}

static void restrict_devfs(int ruleset_fd)
{
	const uint64_t allowed_access_mask =    //
		LANDLOCK_ACCESS_FS_WRITE_FILE | //
		LANDLOCK_ACCESS_FS_READ_FILE;

	restrict_beneath(ruleset_fd, "/dev", allowed_access_mask);
}

static void
restrict_repo(int ruleset_fd, const char *repodir, bool allow_mkdir)
{
	const uint64_t allowed_access_mask =     //
		LANDLOCK_ACCESS_FS_WRITE_FILE |  //
		LANDLOCK_ACCESS_FS_READ_FILE |   //
		LANDLOCK_ACCESS_FS_READ_DIR |    //
		LANDLOCK_ACCESS_FS_REMOVE_FILE | //
		LANDLOCK_ACCESS_FS_MAKE_REG |    //
		(allow_mkdir ? LANDLOCK_ACCESS_FS_MAKE_DIR : 0);

	restrict_beneath(ruleset_fd, repodir, allowed_access_mask);
}

static void apply_ruleset(int *ruleset_fd)
{
	int err;

	err = silofs_sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (err) {
		cmd_die(err, "failed to restrict privileges");
	}
	err = silofs_sys_landlock_restrict_self(*ruleset_fd, 0);
	if (err) {
		cmd_die(err, "failed to enforce ruleset");
	}
	silofs_sys_closefd(ruleset_fd);
}

static void restrict_process_at(const char *repodir, bool allow_mkdir)
{
	int ruleset_fd = -1;

	create_ruleset(&ruleset_fd);
	restrict_fsroot(ruleset_fd);
	restrict_devfs(ruleset_fd);
	if (repodir != nullptr) {
		restrict_repo(ruleset_fd, repodir, allow_mkdir);
	}
	apply_ruleset(&ruleset_fd);
}

static bool has_landlock(void)
{
	int abi_vers = -1;
	int err;

	err = silofs_sys_landlock_abi_version(&abi_vers);
	if (err || (abi_vers <= 0)) {
		silofs_log_debug("landlock not supported: abi_vers=%d err=%d",
		                 abi_vers, err);
		return false;
	}
	return true;
}

void cmd_restrict_process(const char *repodir, bool allow_mkdir)
{
	if (!cmd_global_params.developer_mode && has_landlock()) {
		restrict_process_at(repodir, allow_mkdir);
	}
}
