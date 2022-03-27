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
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>

static struct silofs_subcmd_mount *cmd_mount_args;
static int cmd_mount_halt_signal = -1;
static int cmd_mount_lock_fd = -1;
static bool cmd_mount_clean_ending = true;

static const char *cmd_mount_usage[] = {
	"mount [options] <repo/name> <mountpoint>",
	"",
	"options:",
	"  -r, --rdonly                 Mount in read-only mode",
	"  -X, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"      --nodev                  Do not allow access to device files",
	"      --nokcopy                Do not copy data by in-kernel copy",
	"  -o  --options                Additional mount options",
	"  -a  --allow-other            Allow other users to access fs",
	"  -W  --writeback-cache        Enable write-back cache mode",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	NULL
};

static void cmd_mount_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "rdonly", no_argument, NULL, 'r' },
		{ "noexec", no_argument, NULL, 'X' },
		{ "nosuid", no_argument, NULL, 'S' },
		{ "nodev", no_argument, NULL, 'Z' },
		{ "nokcopy", no_argument, NULL, 'K' },
		{ "options", required_argument, NULL, 'o' },
		{ "allow-other", no_argument, NULL, 'a' },
		{ "writeback-cache", no_argument, NULL, 'W' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("rXSZKo:aWDV:Ch", opts);
		if (opt_chr == 'r') {
			cmd_mount_args->rdonly = true;
		} else if (opt_chr == 'x') {
			cmd_mount_args->noexec = true;
		} else if (opt_chr == 'S') {
			cmd_mount_args->nosuid = true;
		} else if (opt_chr == 'Z') {
			cmd_mount_args->nodev = true;
		} else if (opt_chr == 'K') {
			cmd_mount_args->nokcopy = true;
		} else if (opt_chr == 'o') {
			/* currently, only for xfstests */
			cmd_mount_args->options = optarg;
		} else if (opt_chr == 'a') {
			cmd_mount_args->allowother = true;
		} else if (opt_chr == 'W') {
			cmd_mount_args->wbackcache = true;
		} else if (opt_chr == 'D') {
			silofs_globals.dont_daemonize = true;
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'C') {
			silofs_globals.allow_coredump = true;
		} else if (opt_chr == 'h') {
			silofs_print_help_and_exit(cmd_mount_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg("repo/name", &cmd_mount_args->repodir_name);
	silofs_cmd_getarg("mountpoint", &cmd_mount_args->mntpoint);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_mount_create_fs_env(void)
{
	const struct silofs_fs_args fs_args = {
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.main_repodir = cmd_mount_args->repodir_real,
		.main_name = cmd_mount_args->name,
		.mntdir = cmd_mount_args->mntpoint_real,
		.withfuse = true,
		.allowother = cmd_mount_args->allowother,
		.wbackcache = cmd_mount_args->wbackcache,
		.lazytime = cmd_mount_args->lazytime,
		.noexec = cmd_mount_args->noexec,
		.nosuid = cmd_mount_args->nosuid,
		.nodev = cmd_mount_args->nodev,
		.rdonly = cmd_mount_args->rdonly,
		.kcopy = !cmd_mount_args->nokcopy,
		.concp = true,
		.pedantic = false,
	};

	silofs_cmd_create_fse_inst(&fs_args);
}

static void cmd_mount_destroy_fs_env(void)
{
	silofs_cmd_destroy_fse_inst();
}

static void cmd_mount_halt_by_signal(int signum)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();

	if (fse) {
		silofs_fse_halt(fse, signum);
	}
}

static void cmd_mount_enable_signals(void)
{
	silofs_register_sigactions(cmd_mount_halt_by_signal);
}

static void cmd_mount_execute_fs(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	int err;

	err = silofs_fse_serve(fse);
	if (err) {
		silofs_die(err, "fs failure: %s %s",
		           cmd_mount_args->repodir, cmd_mount_args->mntpoint);
	}
	cmd_mount_halt_signal = fse->fs_signum;
	cmd_mount_clean_ending = silofs_fse_served_clean(fse);
}

static void cmd_mount_finalize(void)
{
	cmd_mount_destroy_fs_env();
	silofs_cmd_pfrees(&cmd_mount_args->repodir_name);
	silofs_cmd_pfrees(&cmd_mount_args->repodir);
	silofs_cmd_pfrees(&cmd_mount_args->mntpoint);
	silofs_cmd_pfrees(&cmd_mount_args->repodir_real);
	silofs_cmd_pfrees(&cmd_mount_args->mntpoint_real);
	silofs_cmd_pfrees(&cmd_mount_args->name);
	silofs_cmd_unlockf(&cmd_mount_lock_fd);
	silofs_cmd_close_syslog();
}

static void cmd_mount_start(void)
{
	cmd_mount_args = &silofs_globals.cmd.mount;
	atexit(cmd_mount_finalize);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_prepare_mntpoint(void)
{
	silofs_cmd_realpath(cmd_mount_args->mntpoint,
	                    &cmd_mount_args->mntpoint_real);
	silofs_cmd_check_mntdir(cmd_mount_args->mntpoint_real, true);
	silofs_cmd_check_mountd();
}

static void cmd_mount_prepare_repo(void)
{
	silofs_cmd_check_exists(cmd_mount_args->repodir_name);

	silofs_cmd_check_reg(cmd_mount_args->repodir_name, false);

	silofs_cmd_splitpath(cmd_mount_args->repodir_name,
	                     &cmd_mount_args->repodir,
	                     &cmd_mount_args->name);

	silofs_cmd_check_nonemptydir(cmd_mount_args->repodir, true);

	silofs_cmd_realpath(cmd_mount_args->repodir,
	                    &cmd_mount_args->repodir_real);

	silofs_cmd_check_fsname(cmd_mount_args->name);

	silofs_cmd_lockf(cmd_mount_args->repodir_real,
	                 cmd_mount_args->name, &cmd_mount_lock_fd);

	silofs_cmd_unlockf(&cmd_mount_lock_fd);
}

static void cmd_mount_lock_repo(void)
{
	silofs_cmd_lockf(cmd_mount_args->repodir_real,
	                 cmd_mount_args->name,
	                 &cmd_mount_lock_fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_verify_bootsec(void)
{
	struct silofs_bootsec bsec = { .btime = 0 };
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir = cmd_mount_args->repodir_real;
	const char *repodir_name = cmd_mount_args->repodir_name;
	struct silofs_namestr nstr;
	int err;

	silofs_make_fsnamestr(&nstr, cmd_mount_args->name);
	err = silofs_fse_open_repos(fse);
	if (err) {
		silofs_die(err, "failed to open repo: %s", repodir);
	}
	err = silofs_fse_load_boot(fse, &nstr, &bsec);
	if (err) {
		silofs_die(err, "failed to load boot: %s", repodir_name);
	}
	err = silofs_fse_close_repos(fse);
	if (err) {
		silofs_die(err, "failed to close repo: %s", repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0015: Use inotify to monitor available mount
 *
 * Better user modern inotify interface on mount-directory instead of this
 * naive busy-loop.
 */
static int cmd_mount_probe_rootdir(void)
{
	struct stat st;

	silofs_cmd_stat_ok(cmd_mount_args->mntpoint_real, &st);
	if (!S_ISDIR(st.st_mode)) {
		silofs_die(0, "illegal mount-point: %s",
		           cmd_mount_args->mntpoint_real);
	}
	return (st.st_ino == SILOFS_INO_ROOT) ? 0 : -1;
}

static void cmd_mount_finish_parent(void)
{
	int err = -1;
	size_t retry = 20;

	while (retry-- && err) {
		err = cmd_mount_probe_rootdir();
		sleep(1);
	}
	exit(err);
}

static void cmd_mount_start_daemon(void)
{
	const pid_t pre_pid = getpid();

	silofs_cmd_fork_daemon();

	if (pre_pid == getpid()) {
		/* I am the parent: wait for active mount & exit */
		cmd_mount_finish_parent();
	}
}

static void cmd_mount_boostrap_process(void)
{
	silofs_globals.log_mask |= SILOFS_LOG_INFO;

	if (!silofs_globals.dont_daemonize) {
		cmd_mount_start_daemon();
		silofs_cmd_open_syslog();
	}
	if (!silofs_globals.allow_coredump) {
		silofs_setrlimit_nocore();
	}
	if (!silofs_globals.disable_ptrace) {
		silofs_prctl_non_dumpable();
	}
}

static void cmd_mount_verify_fs_env(void)
{
	struct silofs_fs_env *fse = silofs_cmd_fse_inst();
	const char *repodir = cmd_mount_args->repodir_real;
	const char *name = cmd_mount_args->name;
	int err;

	err = silofs_fse_verify(fse);
	if (err == -EUCLEAN) {
		silofs_die(0, "bad repo: %s", repodir);
	} else if (err == -EKEYEXPIRED) {
		silofs_die(0, "wrong passphrase: %s", repodir);
	} else if (err == -ENOENT) {
		silofs_die(0, "not exist: %s", name);
	} else if (err != 0) {
		silofs_die(err, "illegal repo: %s", repodir);
	}
}

/*
 * Trace global setting to user. When running as daemon on systemd-based
 * environments, users should use the following command to view silofs's
 * traces:
 *
 *   $ journalctl -b -n 60 -f -t silofs
 */
static void cmd_mount_trace_start(void)
{
	silofs_log_meta_banner(silofs_globals.name, 1);
	silofs_log_info("executable: %s", silofs_globals.prog);
	silofs_log_info("mountpoint: %s", cmd_mount_args->mntpoint_real);
	silofs_log_info("repodir: %s", cmd_mount_args->repodir_real);
	silofs_log_info("modes: rdonly=%d noexec=%d nodev=%d nosuid=%d",
	                (int)cmd_mount_args->rdonly,
	                (int)cmd_mount_args->noexec,
	                (int)cmd_mount_args->nodev,
	                (int)cmd_mount_args->nosuid);
}

static void cmd_mount_trace_finish(void)
{
	const time_t exec_time = time(NULL) - silofs_globals.start_time;

	silofs_log_info("mount done: %s", cmd_mount_args->mntpoint_real);
	silofs_log_info("execution time: %ld seconds", exec_time);
	silofs_log_meta_banner(silofs_globals.name, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * In case there is still a dangling mount-point due to halt-by-signal try to
 * unmount it.
 */
static void cmd_mount_post_exec_cleanup(void)
{
	const char *mntp = cmd_mount_args->mntpoint_real;
	const uid_t uid = getuid();
	const gid_t gid = getgid();
	int err;

	if (mntp && (cmd_mount_halt_signal > 0) && !cmd_mount_clean_ending) {
		err = silofs_rpc_umount(mntp, uid, gid, MNT_DETACH);
		if (err) {
			silofs_log_info("failed to umount lazily: "
			                "%s err=%d", mntp, err);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_execute_mount(void)
{
	/* Do all cleanups upon exits */
	cmd_mount_start();

	/* Parse command's arguments */
	cmd_mount_getopt();

	/* Require valid mount-point */
	cmd_mount_prepare_mntpoint();

	/* Require minimal repository validity */
	cmd_mount_prepare_repo();

	/* Setup boot environment instance */
	cmd_mount_create_fs_env();

	/* Verify valid and lock-able boot sector */
	cmd_mount_verify_bootsec();

	/* Destroy boot environment instance */
	cmd_mount_destroy_fs_env();

	/* Become daemon process */
	cmd_mount_boostrap_process();

	/* Setup main environment instance */
	cmd_mount_create_fs_env();

	/* Re-verify MBR and input arguments */
	cmd_mount_verify_fs_env();

	/* Report beginning-of-mount */
	cmd_mount_trace_start();

	/* Allow halt by signal */
	cmd_mount_enable_signals();

	/* Require repository lock */
	cmd_mount_lock_repo();

	/* Execute as long as needed... */
	cmd_mount_execute_fs();

	/* Report end-of-mount */
	cmd_mount_trace_finish();

	/* Destroy main environment instance */
	cmd_mount_destroy_fs_env();

	/* Post execution cleanups */
	cmd_mount_post_exec_cleanup();

	/* Finalize resource allocations */
	cmd_mount_finalize();

	/* Return to main for global cleanups */
}
