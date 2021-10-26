/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>



static const char *mount_usage[] = {
	"mount --name=NAME [options] <repo-path> <mount-point>",
	"",
	"options:",
	"  -n, --name                   File-system's name",
	"  -r, --rdonly                 Mount in read-only mode",
	"  -x, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"      --nodev                  Do not allow access to device files",
	"      --kcopy                  Use kernel-copy for user data",
	"  -o  --options                Additional mount options",
	"  -A  --allow-other            Allow other users to access fs",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	NULL
};

static void mount_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "rdonly", no_argument, NULL, 'r' },
		{ "noexec", no_argument, NULL, 'x' },
		{ "nosuid", no_argument, NULL, 'S' },
		{ "nodev", no_argument, NULL, 'Z' },
		{ "kcopy", no_argument, NULL, 'K' },
		{ "options", required_argument, NULL, 'o' },
		{ "allow-other", no_argument, NULL, 'A' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_getopt_subcmd("n:rxSZKo:ADV:Ch", opts);
		if (opt_chr == 'n') {
			silofs_globals.cmd.mount.name =
			        silofs_strdup_safe(optarg);
		} else if (opt_chr == 'r') {
			silofs_globals.cmd.mount.rdonly = true;
		} else if (opt_chr == 'x') {
			silofs_globals.cmd.mount.noexec = true;
		} else if (opt_chr == 'S') {
			silofs_globals.cmd.mount.nosuid = true;
		} else if (opt_chr == 'Z') {
			silofs_globals.cmd.mount.nodev = true;
		} else if (opt_chr == 'K') {
			silofs_globals.cmd.mount.kcopy = true;
		} else if (opt_chr == 'o') {
			/* currently, only for xfstests */
			silofs_globals.cmd.mount.options = optarg;
		} else if (opt_chr == 'A') {
			silofs_globals.cmd.mount.allowother = true;
		} else if (opt_chr == 'D') {
			silofs_globals.dont_daemonize = true;
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'C') {
			silofs_globals.allow_coredump = true;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(mount_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_globals.cmd.mount.repodir =
	        silofs_consume_cmdarg("repo-path", false);
	silofs_globals.cmd.mount.mntpoint =
	        silofs_consume_cmdarg("mount-point", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mount_create_fs_env(void)
{
	const struct silofs_fs_args args = {
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.repodir = silofs_globals.cmd.mount.repodir_real,
		.fsname = silofs_globals.cmd.mount.name,
		.mntdir = silofs_globals.cmd.mount.mntpoint_real,
		.allowother = silofs_globals.cmd.mount.allowother,
		.lazytime = silofs_globals.cmd.mount.lazytime,
		.noexec = silofs_globals.cmd.mount.noexec,
		.nosuid = silofs_globals.cmd.mount.nosuid,
		.nodev = silofs_globals.cmd.mount.nodev,
		.rdonly = silofs_globals.cmd.mount.rdonly,
		.kcopy_mode = silofs_globals.cmd.mount.kcopy,
		.pedantic = false,
		.with_fuseq = true,

	};

	silofs_create_fse_inst(&args);
}

static void mount_destroy_fs_env(void)
{
	silofs_destroy_fse_inst();
}

static void mount_halt_by_signal(int signum)
{
	struct silofs_fs_env *fse = silofs_fse_inst();

	if (fse) {
		silofs_fse_halt(fse, signum);
	}
}

static void mount_enable_signals(void)
{
	silofs_register_sigactions(mount_halt_by_signal);
}

static void mount_execute_fs(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();

	err = silofs_fse_serve(fse);
	if (err) {
		silofs_die(err, "fs failure: %s %s",
		           silofs_globals.cmd.mount.repodir_real,
		           silofs_globals.cmd.mount.mntpoint_real);
	}
}

static void mount_finalize(void)
{
	mount_destroy_fs_env();
	silofs_pfree_string(&silofs_globals.cmd.mount.repodir_real);
	silofs_pfree_string(&silofs_globals.cmd.mount.mntpoint_real);
	silofs_close_syslog();
	silofs_burnstack();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mount_setup_check_mntpoint(void)
{
	silofs_require_valid_fsname("name", &silofs_globals.cmd.mount.name);
	silofs_globals.cmd.mount.mntpoint_real =
	        silofs_realpath_safe(silofs_globals.cmd.mount.mntpoint);
	silofs_die_if_not_mntdir(silofs_globals.cmd.mount.mntpoint_real, true);
	silofs_die_if_no_mountd();
}

static void mount_setup_check_repo(void)
{
	silofs_globals.cmd.mount.repodir_real =
	        silofs_realpath_safe(silofs_globals.cmd.mount.repodir);
	silofs_die_if_not_dir(silofs_globals.cmd.mount.repodir_real, true);
	silofs_die_if_not_reg3(silofs_globals.cmd.mount.repodir_real,
	                       "refs", silofs_globals.cmd.mount.name,
	                       !silofs_globals.cmd.mount.rdonly);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0015: Use inotify to monitor available mount
 *
 * Better user modern inotify interface on mount-directory instead of this
 * naive busy-loop.
 */
static int mount_probe_rootdir(void)
{
	struct stat st;
	const char *path = silofs_globals.cmd.mount.mntpoint_real;

	silofs_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		silofs_die(0, "illegal mount-point: %s", path);
	}
	return (st.st_ino == SILOFS_INO_ROOT) ? 0 : -1;
}

static void mount_finish_parent(void)
{
	int err = -1;
	size_t retry = 20;

	while (retry-- && err) {
		err = mount_probe_rootdir();
		sleep(1);
	}
	exit(err);
}

static void mount_start_daemon(void)
{
	const pid_t pre_pid = getpid();

	silofs_fork_daemon();

	if (pre_pid == getpid()) {
		/* I am the parent: wait for active mount & exit */
		mount_finish_parent();
	}
}

static void mount_boostrap_process(void)
{
	silofs_globals.log_mask |= SILOFS_LOG_INFO;

	if (!silofs_globals.dont_daemonize) {
		mount_start_daemon();
		silofs_open_syslog();
	}
	if (!silofs_globals.allow_coredump) {
		silofs_setrlimit_nocore();
	}
	if (!silofs_globals.disable_ptrace) {
		silofs_prctl_non_dumpable();
	}
}

static void mount_verify_fs_env(void)
{
	int err;
	struct silofs_fs_env *fse = silofs_fse_inst();
	const char *repodir = silofs_globals.cmd.mount.repodir_real;

	err = silofs_fse_verify(fse);
	if (err == -EUCLEAN) {
		silofs_die(0, "not a silofs volume: %s", repodir);
	} else if (err == -EKEYEXPIRED) {
		silofs_die(0, "wrong passphrase: %s", repodir);
	} else if (err != 0) {
		silofs_die(err, "illegal volume: %s", repodir);
	}
}

/*
 * Trace global setting to user. When running as daemon on systemd-based
 * environments, users should use the following command to view silofs's
 * traces:
 *
 *   $ journalctl -b -n 60 -f -t silofs
 */
static void mount_trace_start(void)
{
	silofs_log_meta_banner(silofs_globals.name, 1);
	silofs_log_info("executable: %s", silofs_globals.prog);
	silofs_log_info("mountpoint: %s",
	                silofs_globals.cmd.mount.mntpoint_real);
	silofs_log_info("repodir: %s", silofs_globals.cmd.mount.repodir_real);
	silofs_log_info("modes: rdonly=%d noexec=%d nodev=%d nosuid=%d",
	                (int)silofs_globals.cmd.mount.rdonly,
	                (int)silofs_globals.cmd.mount.noexec,
	                (int)silofs_globals.cmd.mount.nodev,
	                (int)silofs_globals.cmd.mount.nosuid);
}

static void mount_trace_finish(void)
{
	const time_t exec_time = time(NULL) - silofs_globals.start_time;

	silofs_log_info("mount done: %s",
	                silofs_globals.cmd.mount.mntpoint_real);
	silofs_log_info("execution time: %ld seconds", exec_time);
	silofs_log_meta_banner(silofs_globals.name, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_mount(void)
{
	/* Do all cleanups upon exits */
	atexit(mount_finalize);

	/* Parse command's arguments */
	mount_getopt();

	/* Require valid mount-point */
	mount_setup_check_mntpoint();

	/* Require minimal repository validity */
	mount_setup_check_repo();

	/* Setup boot environment instance */
	mount_create_fs_env();

	/* Destroy boot environment instance */
	mount_destroy_fs_env();

	/* Become daemon process */
	mount_boostrap_process();

	/* Setup main environment instance */
	mount_create_fs_env();

	/* Re-verify MBR and input arguments */
	mount_verify_fs_env();

	/* Report beginning-of-mount */
	mount_trace_start();

	/* Allow halt by signal */
	mount_enable_signals();

	/* Execute as long as needed... */
	mount_execute_fs();

	/* Report end-of-mount */
	mount_trace_finish();

	/* Destroy main environment instance */
	mount_destroy_fs_env();

	/* Post execution cleanups */
	mount_finalize();

	/* Return to main for global cleanups */
}
