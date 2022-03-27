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


static struct silofs_subcmd_snap *cmd_snap_args;
static char *cmd_snap_src_mntdir;
static int cmd_snap_src_lock_fd = -1;

static const char *cmd_snap_usage[] = {
	"snap <repo/src-name> <repo/dst-name>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

static void cmd_snap_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("V:h", opts);
		if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(cmd_snap_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repo/src-name",
	                  &cmd_snap_args->src_repodir_name);
	silofs_cmd_getarg("repo/dst-name",
	                  &cmd_snap_args->dst_repodir_name);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_snap_finalize(void)
{
	silofs_cmd_destroy_fse_inst();
	silofs_cmd_pfrees(&cmd_snap_args->src_repodir_name);
	silofs_cmd_pfrees(&cmd_snap_args->src_repodir);
	silofs_cmd_pfrees(&cmd_snap_args->src_repodir_real);
	silofs_cmd_pfrees(&cmd_snap_args->src_name);
	silofs_cmd_pfrees(&cmd_snap_args->dst_repodir_name);
	silofs_cmd_pfrees(&cmd_snap_args->dst_repodir_name);
	silofs_cmd_pfrees(&cmd_snap_args->dst_repodir_real);
	silofs_cmd_pfrees(&cmd_snap_args->dst_repodir_real);
	silofs_cmd_pfrees(&cmd_snap_src_mntdir);
	silofs_cmd_unlockf(&cmd_snap_src_lock_fd);
}

static void cmd_snap_start(void)
{
	cmd_snap_args = &silofs_globals.cmd.snap;
	atexit(cmd_snap_finalize);
}

static void cmd_snap_check_samerepo(void)
{
	struct stat src_st;
	struct stat dst_st;

	silofs_cmd_stat_dir(cmd_snap_args->src_repodir_real, &src_st);
	silofs_cmd_stat_dir(cmd_snap_args->dst_repodir_real, &dst_st);
	if ((src_st.st_ino != dst_st.st_ino) ||
	    (src_st.st_dev != dst_st.st_dev)) {
		silofs_die(0, "not on same repository: %s %s",
		           cmd_snap_args->src_repodir_name,
		           cmd_snap_args->dst_repodir_name);
	}
}

static void cmd_snap_prepare(void)
{
	silofs_cmd_check_reg(cmd_snap_args->src_repodir_name, false);

	silofs_cmd_check_notexists(cmd_snap_args->dst_repodir_name);

	silofs_cmd_splitpath(cmd_snap_args->src_repodir_name,
	                     &cmd_snap_args->src_repodir,
	                     &cmd_snap_args->src_name);

	silofs_cmd_splitpath(cmd_snap_args->dst_repodir_name,
	                     &cmd_snap_args->dst_repodir,
	                     &cmd_snap_args->dst_name);

	silofs_cmd_check_nonemptydir(cmd_snap_args->src_repodir, false);

	silofs_cmd_check_nonemptydir(cmd_snap_args->dst_repodir, true);

	silofs_cmd_realpath(cmd_snap_args->src_repodir,
	                    &cmd_snap_args->src_repodir_real);

	silofs_cmd_check_fsname(cmd_snap_args->src_name);

	silofs_cmd_realpath(cmd_snap_args->dst_repodir,
	                    &cmd_snap_args->dst_repodir_real);

	silofs_cmd_check_fsname(cmd_snap_args->dst_name);

	cmd_snap_check_samerepo();
}

static void cmd_snap_ioctl_query(const char *path,
                                 struct silofs_ioc_query *qry)
{
	int dfd = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_QUERY, qry);
	if (err) {
		silofs_die(err, "ioctl error: %s", path);
	}
	silofs_sys_closefd(&dfd);
}

static bool cmd_snap_stat_samedir(const char *path0, const char *path1)
{
	struct stat st[2];
	int err;

	err = silofs_sys_stat(path0, &st[0]);
	if (err) {
		silofs_die(err, "stat error: %s", path0);
	}
	err = silofs_sys_stat(path1, &st[1]);
	if (err) {
		silofs_die(err, "stat error: %s", path1);
	}
	return S_ISDIR(st[0].st_mode) &&
	       (st[0].st_ino == st[1].st_ino) &&
	       (st[0].st_dev == st[1].st_dev);
}

static bool cmd_snap_is_src_mntdir(const char *mntdir)
{
	struct silofs_ioc_query query = { .reserved = 0 };
	bool ret = false;

	query.qtype = SILOFS_QUERY_VERSION;
	cmd_snap_ioctl_query(mntdir, &query);

	query.qtype = SILOFS_QUERY_REPO;
	cmd_snap_ioctl_query(mntdir, &query);

	ret = cmd_snap_stat_samedir(query.u.repo.r_path,
	                            cmd_snap_args->src_repodir_real);
	if (ret) {
		query.qtype = SILOFS_QUERY_FSNAME;
		cmd_snap_ioctl_query(mntdir, &query);
		ret = !strcmp(query.u.fsname.f_name, cmd_snap_args->src_name);
	}
	return ret;
}

static void cmd_snap_resolve_mntdir(void)
{
	struct silofs_proc_mntinfo *mi_list = NULL;
	struct silofs_proc_mntinfo *mi_iter = NULL;

	mi_list = silofs_cmd_parse_mountinfo();
	mi_iter = mi_list;
	while (mi_iter && !cmd_snap_src_mntdir) {
		if (cmd_snap_is_src_mntdir(mi_iter->mntdir)) {
			silofs_cmd_realpath(mi_iter->mntdir,
			                    &cmd_snap_src_mntdir);
		}
		mi_iter = mi_iter->next;
	}
	silofs_cmd_free_mountinfo(mi_list);

	if (cmd_snap_src_mntdir == NULL) {
		silofs_die(0, "failed to resolve mount point of: %s",
		           cmd_snap_args->src_repodir_name);
	}
}

static void cmd_snap_by_ioctl_clone(void)
{
	struct silofs_ioc_clone clone = { .name[0] = '\0' };
	const char *dirpath = cmd_snap_src_mntdir;
	const char *name = cmd_snap_args->dst_name;
	int dfd = -1;
	int err;

	err = silofs_sys_open(dirpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "failed to open dir: %s", dirpath);
	}
	err = silofs_sys_syncfs(dfd);
	if (err) {
		silofs_die(err, "syncfs error: %s", dirpath);
	}
	strncpy(clone.name, name, sizeof(clone.name) - 1);
	err = silofs_sys_ioctlp(dfd, SILOFS_FS_IOC_CLONE, &clone);
	silofs_sys_close(dfd);
	if (err == -ENOTTY) {
		silofs_die(err, "ioctl error: %s", dirpath);
	} else if (err) {
		silofs_die(err, "failed to snap: %s", name);
	}
}

static void cmd_snap_online(void)
{
	cmd_snap_resolve_mntdir();
	cmd_snap_by_ioctl_clone();
}

static void cmd_snap_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.main_repodir = cmd_snap_args->src_repodir_real,
		.main_name = cmd_snap_args->src_name,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	silofs_cmd_create_fse_inst(&args);
}

static void cmd_snap_by_exec_fse(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_snap(fse, cmd_snap_args->dst_name);
	if (err) {
		silofs_die(err, "snap failed: %s --> %s",
		           cmd_snap_args->src_repodir_name,
		           cmd_snap_args->dst_repodir_name);
	}
}

static void cmd_snap_offline(void)
{
	cmd_snap_create_fs_env();
	cmd_snap_by_exec_fse();
}

static bool cmd_snap_need_online(void)
{
	return !silofs_cmd_trylockf(cmd_snap_args->src_repodir,
	                            cmd_snap_args->src_name,
	                            &cmd_snap_src_lock_fd);
}

static void cmd_snap_execute(void)
{
	if (cmd_snap_need_online()) {
		cmd_snap_online();
	} else {
		cmd_snap_offline();
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_snap(void)
{
	/* Do all cleanups upon exits */
	cmd_snap_start();

	/* Parse command's arguments */
	cmd_snap_getopt();

	/* Verify user's arguments */
	cmd_snap_prepare();

	/* Do actual snap */
	cmd_snap_execute();

	/* Post execution cleanups */
	cmd_snap_finalize();
}

