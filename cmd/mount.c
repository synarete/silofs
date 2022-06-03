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
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include "cmd.h"


static const char *cmd_mount_usage[] = {
	"mount [options] <repo/name> <mountpoint>",
	"",
	"options:",
	"  -r, --rdonly                 Mount in read-only mode",
	"  -X, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"      --nodev                  Do not allow access to device files",
	"      --nokcopy                Do not copy data by in-kernel copy",
	"  -a  --allow-other            Allow other users to access fs",
	"  -W  --writeback-cache        Enable write-back cache mode",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	NULL
};

struct cmd_mount_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *mntpoint;
	char   *mntpoint_real;
	bool    allowother;
	bool    wbackcache;
	bool    lazytime;
	bool    noexec;
	bool    nosuid;
	bool    nodev;
	bool    rdonly;
	bool    nokcopy;
};

struct cmd_mount_ctx {
	struct cmd_mount_args   args;
	struct silofs_bootlink  blnk;
	struct silofs_fs_env   *fse;
	time_t                  start_time;
	int                     halt_signal;
	int                     lock_fd;
	bool                    clean_ending;
};

static struct cmd_mount_ctx *cmd_mount_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_getopt(struct cmd_mount_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "rdonly", no_argument, NULL, 'r' },
		{ "noexec", no_argument, NULL, 'X' },
		{ "nosuid", no_argument, NULL, 'S' },
		{ "nodev", no_argument, NULL, 'Z' },
		{ "nokcopy", no_argument, NULL, 'K' },
		{ "allow-other", no_argument, NULL, 'a' },
		{ "writeback-cache", no_argument, NULL, 'W' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("rXSZKaWDV:Ch", opts);
		if (opt_chr == 'r') {
			ctx->args.rdonly = true;
		} else if (opt_chr == 'x') {
			ctx->args.noexec = true;
		} else if (opt_chr == 'S') {
			ctx->args.nosuid = true;
		} else if (opt_chr == 'Z') {
			ctx->args.nodev = true;
		} else if (opt_chr == 'K') {
			ctx->args.nokcopy = true;
		} else if (opt_chr == 'a') {
			ctx->args.allowother = true;
		} else if (opt_chr == 'W') {
			ctx->args.wbackcache = true;
		} else if (opt_chr == 'D') {
			cmd_globals.dont_daemonize = true;
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'C') {
			cmd_globals.allow_coredump = true;
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_mount_usage);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repo/name", &ctx->args.repodir_name);
	cmd_getarg("mountpoint", &ctx->args.mntpoint);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_setup_env(struct cmd_mount_ctx *ctx)
{
	const struct silofs_fs_args fs_args = {
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.main_repodir = ctx->args.repodir_real,
		.main_name = ctx->args.name,
		.mntdir = ctx->args.mntpoint_real,
		.withfuse = true,
		.allowother = ctx->args.allowother,
		.wbackcache = ctx->args.wbackcache,
		.lazytime = ctx->args.lazytime,
		.noexec = ctx->args.noexec,
		.nosuid = ctx->args.nosuid,
		.nodev = ctx->args.nodev,
		.rdonly = ctx->args.rdonly,
		.kcopy = !ctx->args.nokcopy,
		.concp = true,
		.pedantic = false,
	};

	cmd_new_env(&ctx->fse, &fs_args);
}

static void cmd_mount_destroy_env(struct cmd_mount_ctx *ctx)
{
	cmd_del_env(&ctx->fse);
}

static void cmd_mount_halt_by_signal(int signum)
{
	struct cmd_mount_ctx *ctx;

	ctx = cmd_mount_ctx;
	if (ctx && ctx->fse) {
		silofs_fse_halt(ctx->fse, signum);
	}
}

static void cmd_mount_enable_signals(void)
{
	cmd_register_sigactions(cmd_mount_halt_by_signal);
}

static void cmd_mount_execute_fs(struct cmd_mount_ctx *ctx)
{
	ctx->start_time = silofs_time_now();
	cmd_serve_fs(ctx->fse, &ctx->blnk.bsec);
	ctx->halt_signal = ctx->fse->fs_signum;
	ctx->clean_ending = silofs_fse_served_clean(ctx->fse);
}

static void cmd_mount_finalize(struct cmd_mount_ctx *ctx)
{
	cmd_del_env(&ctx->fse);
	cmd_pstrfree(&ctx->args.repodir_name);
	cmd_pstrfree(&ctx->args.repodir);
	cmd_pstrfree(&ctx->args.mntpoint);
	cmd_pstrfree(&ctx->args.repodir_real);
	cmd_pstrfree(&ctx->args.mntpoint_real);
	cmd_pstrfree(&ctx->args.name);
	cmd_unlock_bpath(&ctx->blnk.bpath, &ctx->lock_fd);
	cmd_close_syslog();
	cmd_mount_ctx = NULL;
}

static void cmd_mount_atexit(void)
{
	if (cmd_mount_ctx != NULL) {
		cmd_mount_finalize(cmd_mount_ctx);
	}
}

static void cmd_mount_start(struct cmd_mount_ctx *ctx)
{
	cmd_mount_ctx = ctx;
	atexit(cmd_mount_atexit);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_prepare_mntpoint(struct cmd_mount_ctx *ctx)
{
	cmd_realpath(ctx->args.mntpoint, &ctx->args.mntpoint_real);
	cmd_check_mntdir(ctx->args.mntpoint_real, true);
	cmd_check_mountd();
}

static void cmd_mount_prepare_repo(struct cmd_mount_ctx *ctx)
{
	cmd_check_exists(ctx->args.repodir_name);
	cmd_check_reg(ctx->args.repodir_name, false);
	cmd_split_path(ctx->args.repodir_name,
	               &ctx->args.repodir, &ctx->args.name);
	cmd_check_nonemptydir(ctx->args.repodir, true);
	cmd_realpath(ctx->args.repodir, &ctx->args.repodir_real);
	cmd_check_fsname(ctx->args.name);
	cmd_setup_bpath(&ctx->blnk.bpath,
	                ctx->args.repodir_real, ctx->args.name);
}

static void cmd_mount_ensure_lockable(struct cmd_mount_ctx *ctx)
{
	int fd = -1;

	cmd_lock_bpath(&ctx->blnk.bpath, &fd);
	cmd_unlock_bpath(&ctx->blnk.bpath, &fd);
}

static void cmd_mount_lock_repo(struct cmd_mount_ctx *ctx)
{
	cmd_lock_bpath(&ctx->blnk.bpath, &ctx->lock_fd);
}

static void cmd_mount_load_bootsec(struct cmd_mount_ctx *ctx)
{
	cmd_load_bsec(&ctx->blnk.bpath, &ctx->blnk.bsec);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0015: Use inotify to monitor available mount
 *
 * Better user modern inotify interface on mount-directory instead of this
 * naive busy-loop.
 */
static void cmd_mount_finish_parent(const struct cmd_mount_ctx *ctx)
{
	struct stat st = { .st_ino = 0 };
	int err = -1;

	for (size_t retry = 0; (retry < 20); ++retry) {
		cmd_stat_dir(ctx->args.mntpoint_real, &st);
		if (st.st_ino == SILOFS_INO_ROOT) {
			exit(EXIT_SUCCESS);
		}
		sleep(1);
	}
	exit(err);
}

static void cmd_mount_start_daemon(const struct cmd_mount_ctx *ctx)
{
	const pid_t pre_pid = getpid();

	cmd_fork_daemon();

	if (pre_pid == getpid()) {
		/* I am parent: wait for active mount & exit */
		cmd_mount_finish_parent(ctx);
	} else {
		/* I am child: eanble syslog */
		cmd_open_syslog();
	}
}

static void cmd_mount_set_dumpable(unsigned int state)
{
	int err;

	err = silofs_sys_prctl(PR_SET_DUMPABLE, state, 0, 0, 0);
	if (err) {
		cmd_dief(err, "failed to prctl dumpable: state=%d", state);
	}
}

static void cmd_mount_boostrap_process(const struct cmd_mount_ctx *ctx)
{
	cmd_globals.log_mask |= SILOFS_LOG_INFO;

	if (!cmd_globals.dont_daemonize) {
		cmd_mount_start_daemon(ctx);
	}
	if (!cmd_globals.allow_coredump) {
		cmd_setrlimit_nocore();
	}
	if (cmd_globals.dumpable) {
		cmd_mount_set_dumpable(1);
	} else {
		cmd_mount_set_dumpable(0);
	}
}

static void cmd_mount_verify_fs(struct cmd_mount_ctx *ctx)
{
	cmd_verify_fs(ctx->fse, &ctx->blnk.bsec);
}

/*
 * Trace global setting to user. When running as daemon on systemd-based
 * environments, users should use the following command to view silofs's
 * traces:
 *
 *   $ journalctl -b -n 60 -f -t silofs
 */
static void cmd_mount_trace_start(const struct cmd_mount_ctx *ctx)
{
	silofs_log_meta_banner(cmd_globals.name, 1);
	silofs_log_info("executable: %s", cmd_globals.prog);
	silofs_log_info("mountpoint: %s", ctx->args.mntpoint_real);
	silofs_log_info("repodir: %s", ctx->args.repodir_real);
	silofs_log_info("modes: rdonly=%d noexec=%d nodev=%d nosuid=%d",
	                (int)ctx->args.rdonly, (int)ctx->args.noexec,
	                (int)ctx->args.nodev, (int)ctx->args.nosuid);
}

static void cmd_mount_trace_finish(const struct cmd_mount_ctx *ctx)
{
	const time_t exec_time = silofs_time_now() - ctx->start_time;

	silofs_log_info("mount done: %s", ctx->args.mntpoint_real);
	silofs_log_info("execution time: %ld seconds", exec_time);
	silofs_log_meta_banner(cmd_globals.name, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * In case there is still a dangling mount-point due to halt-by-signal try to
 * unmount it.
 */
static void cmd_mount_post_exec_cleanup(const struct cmd_mount_ctx *ctx)
{
	int err;

	if ((ctx->halt_signal > 0) && !ctx->clean_ending) {
		err = silofs_rpc_umount(ctx->args.mntpoint_real,
		                        getuid(), getgid(), MNT_DETACH);
		if (err) {
			silofs_log_info("failed to umount lazily: %s err=%d",
			                ctx->args.mntpoint_real, err);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mount(void)
{
	struct cmd_mount_ctx ctx = {
		.fse = NULL,
		.halt_signal = -1,
		.lock_fd = -1,
		.clean_ending = true,
	};

	/* Do all cleanups upon exits */
	cmd_mount_start(&ctx);

	/* Parse command's arguments */
	cmd_mount_getopt(&ctx);

	/* Require valid mount-point */
	cmd_mount_prepare_mntpoint(&ctx);

	/* Require minimal repository validity */
	cmd_mount_prepare_repo(&ctx);

	/* Require lock-able boot-sec */
	cmd_mount_ensure_lockable(&ctx);

	/* Setup boot environment instance */
	cmd_mount_setup_env(&ctx);

	/* Load-verify bootsec */
	cmd_mount_load_bootsec(&ctx);

	/* Destroy boot environment instance */
	cmd_mount_destroy_env(&ctx);

	/* Become daemon process */
	cmd_mount_boostrap_process(&ctx);

	/* Setup main environment instance */
	cmd_mount_setup_env(&ctx);

	/* ReLoad-verify bootsec */
	cmd_mount_load_bootsec(&ctx);

	/* Re-verify MBR and input arguments */
	cmd_mount_verify_fs(&ctx);

	/* Report beginning-of-mount */
	cmd_mount_trace_start(&ctx);

	/* Allow halt by signal */
	cmd_mount_enable_signals();

	/* Require repository lock */
	cmd_mount_lock_repo(&ctx);

	/* Execute as long as needed... */
	cmd_mount_execute_fs(&ctx);

	/* Report end-of-mount */
	cmd_mount_trace_finish(&ctx);

	/* Destroy main environment instance */
	cmd_mount_destroy_env(&ctx);

	/* Post execution cleanups */
	cmd_mount_post_exec_cleanup(&ctx);

	/* Finalize resource allocations */
	cmd_mount_finalize(&ctx);

	/* Return to main for global cleanups */
}
