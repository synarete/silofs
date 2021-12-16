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
#include <silofs/cmd.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/mount.h>

static struct silofs_subcmd_umount *umount_args;

static const char *umount_usage[] = {
	"umount [options] <mount-point>",
	"",
	"options:",
	"  -l, --lazy                   Detach umount",
	"  -f, --force                  Forced umount",
	NULL
};

static void umount_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "lazy", no_argument, NULL, 'l' },
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("lfh", opts);
		if (opt_chr == 'l') {
			umount_args->lazy = true;
		} else if (opt_chr == 'f') {
			umount_args->force = true;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(umount_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("mount-point", &umount_args->mntpoint);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void umount_finalize(void)
{
	silofs_cmd_pfrees(&umount_args->mntpoint_real);
	silofs_cmd_pfrees(&umount_args->mntpoint);
}

static void umount_start(void)
{
	umount_args = &silofs_globals.cmd.umount;
	atexit(umount_finalize);
}

static void umount_prepare(void)
{
	struct stat st;
	int err;

	silofs_die_if_no_mountd();

	err = silofs_sys_stat(umount_args->mntpoint, &st);
	if ((err == -ENOTCONN) && umount_args->force) {
		silofs_log_debug("transport endpoint "
		                 "not connected: %s", umount_args->mntpoint);
	} else {
		umount_args->mntpoint_real =
		        silofs_cmd_realpath(umount_args->mntpoint);
		silofs_die_if_not_mntdir(umount_args->mntpoint_real, false);
	}
}

static const char *umount_dirpath(void)
{
	return (umount_args->mntpoint_real != NULL) ?
	       umount_args->mntpoint_real : umount_args->mntpoint;
}

static void umount_send_recv(void)
{
	const char *path = umount_dirpath();
	int mnt_flags = 0;
	int err;

	if (umount_args->lazy) {
		mnt_flags |= MNT_DETACH;
	}
	if (umount_args->force) {
		mnt_flags |= MNT_FORCE;
	}
	err = silofs_rpc_umount(path, getuid(), getgid(), mnt_flags);
	if (err) {
		silofs_die(err, "umount failed: %s lazy=%d force=%d", path,
		           (int)umount_args->lazy,
		           (int)umount_args->force);
	}
}

static void umount_probe_statvfs(void)
{
	int err;
	long fstype;
	struct statfs stfs;
	const char *path = umount_dirpath();

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

void silofs_execute_umount(void)
{
	/* Do all cleanups upon exits */
	umount_start();

	/* Parse command's arguments */
	umount_getopt();

	/* Verify user's arguments */
	umount_prepare();

	/* Do actual umount */
	umount_send_recv();

	/* Post-umount checks */
	umount_probe_statvfs();

	/* Post execution cleanups */
	umount_finalize();
}


