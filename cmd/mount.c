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
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include "cmd.h"

static const char *cmd_mount_help_desc[] = {
	"mount [options] <repodir/name> <mountpoint>",
	"",
	"options:",
	"  -r, --rdonly                 Mount in read-only mode",
	"  -X, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"      --nodev                  Do not allow access to device files",
	"  -i  --allow-hostids          Use local host uid/gid",
	"  -A  --no-allow-other         Do not allow other users",
	"  -W  --writeback-cache        Enable write-back cache mode",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	/*
	"  -K, --kcopy                  In-kernel data copy (devel)",
	"  -P, --noconcp                No concurrent data copy (devel)",
	*/
	NULL
};

struct cmd_mount_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *mntpoint;
	char   *mntpoint_real;
	bool    no_allowother;
	bool    allowhostids;
	bool    wbackcache;
	bool    lazytime;
	bool    noexec;
	bool    nosuid;
	bool    nodev;
	bool    rdonly;
	bool    kcopy;
	bool    noconcp;
};

struct cmd_mount_ctx {
	struct cmd_mount_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_env   *fs_env;
	pid_t                   child_pid;
	time_t                  start_time;
	int                     halt_signal;
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
		{ "allow-hostids", no_argument, NULL, 'i' },
		{ "no-allow-other", no_argument, NULL, 'A' },
		{ "writeback-cache", no_argument, NULL, 'W' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "kcopy", no_argument, NULL, 'K' },
		{ "noconcp", no_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("rXSZKPiAWDV:Ch", opts);
		if (opt_chr == 'r') {
			ctx->in_args.rdonly = true;
		} else if (opt_chr == 'x') {
			ctx->in_args.noexec = true;
		} else if (opt_chr == 'S') {
			ctx->in_args.nosuid = true;
		} else if (opt_chr == 'Z') {
			ctx->in_args.nodev = true;
		} else if (opt_chr == 'K') {
			ctx->in_args.kcopy = true;
		} else if (opt_chr == 'P') {
			ctx->in_args.noconcp = true;
		} else if (opt_chr == 'A') {
			ctx->in_args.no_allowother = true;
		} else if (opt_chr == 'i') {
			ctx->in_args.allowhostids = true;
		} else if (opt_chr == 'W') {
			ctx->in_args.wbackcache = true;
		} else if (opt_chr == 'D') {
			cmd_globals.dont_daemonize = true;
		} else if (opt_chr == 'V') {
			cmd_set_verbose_mode(optarg);
		} else if (opt_chr == 'C') {
			cmd_globals.allow_coredump = true;
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_mount_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_getarg("mountpoint", &ctx->in_args.mntpoint);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_setup_fs_args(struct cmd_mount_ctx *ctx)
{
	const struct cmd_mount_in_args *args = &ctx->in_args;
	struct silofs_fs_args *fs_args = &ctx->fs_args;
	struct silofs_fs_cargs *fsca = &ctx->fs_args.ca;

	cmd_init_fs_args(fs_args);
	cmd_load_fs_cargs_for(fsca, false, args->repodir_real, args->name);
	fs_args->repodir = args->repodir_real;
	fs_args->name = args->name;
	fs_args->mntdir = args->mntpoint_real;
	fs_args->withfuse = true;
	fs_args->allowother = !args->no_allowother;
	fs_args->allowhostids = args->allowhostids;
	fs_args->allowadmin = true;
	fs_args->wbackcache = args->wbackcache;
	fs_args->lazytime = args->lazytime;
	fs_args->noexec = args->noexec;
	fs_args->nosuid = args->nosuid;
	fs_args->nodev = args->nodev;
	fs_args->rdonly = args->rdonly;
	fs_args->kcopy = args->kcopy;
	fs_args->concp = !args->noconcp;
	fs_args->pedantic = false;
}

static void cmd_mount_setup_fs_env(struct cmd_mount_ctx *ctx)
{
	cmd_new_env(&ctx->fs_env, &ctx->fs_args);
}

static void cmd_mount_destroy_fs_env(struct cmd_mount_ctx *ctx)
{
	cmd_del_env(&ctx->fs_env);
}

static void cmd_mount_halt_by_signal(int signum)
{
	struct cmd_mount_ctx *ctx;

	ctx = cmd_mount_ctx;
	if (ctx && ctx->fs_env) {
		silofs_fse_halt(ctx->fs_env, signum);
	}
}

static void cmd_mount_enable_signals(void)
{
	cmd_register_sigactions(cmd_mount_halt_by_signal);
}

static void cmd_mount_finalize(struct cmd_mount_ctx *ctx)
{
	cmd_mount_destroy_fs_env(ctx);
	cmd_reset_fs_cargs(&ctx->fs_args.ca);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.mntpoint);
	cmd_pstrfree(&ctx->in_args.mntpoint_real);
	cmd_pstrfree(&ctx->in_args.name);
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
	cmd_realpath(ctx->in_args.mntpoint, &ctx->in_args.mntpoint_real);
	cmd_check_mntdir(ctx->in_args.mntpoint_real, true);
	cmd_check_mntsrv_conn();
	cmd_check_mntsrv_perm(ctx->in_args.mntpoint_real);
}

static void cmd_mount_prepare_repo(struct cmd_mount_ctx *ctx)
{
	struct cmd_mount_in_args *args = &ctx->in_args;

	cmd_check_exists(args->repodir_name);
	cmd_check_isreg(args->repodir_name, false);
	cmd_split_path(args->repodir_name, &args->repodir, &args->name);
	cmd_check_nonemptydir(args->repodir, true);
	cmd_realpath(args->repodir, &args->repodir_real);
	cmd_check_repopath(args->repodir_real);
	cmd_check_fsname(args->name);
}

static void cmd_mount_open_repo(struct cmd_mount_ctx *ctx)
{
	cmd_open_repo(ctx->fs_env);
}

static void cmd_mount_close_repo(struct cmd_mount_ctx *ctx)
{
	cmd_close_repo(ctx->fs_env);
}

static void cmd_mount_require_bsec(struct cmd_mount_ctx *ctx)
{
	cmd_require_fs(ctx->fs_env, true, &ctx->fs_args.ca.uuid);
}

static void cmd_mount_boot_fs(struct cmd_mount_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_env, &ctx->fs_args.ca.uuid);
}

static void cmd_mount_execute_fs(struct cmd_mount_ctx *ctx)
{
	ctx->start_time = silofs_time_now();
	cmd_exec_fs(ctx->fs_env);
	ctx->halt_signal = ctx->fs_env->fs_signum;
	ctx->clean_ending = silofs_fse_served_clean(ctx->fs_env);
}

static void cmd_mount_shutdown_fs(struct cmd_mount_ctx *ctx)
{
	cmd_close_fs(ctx->fs_env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0015: Use inotify to monitor available mount
 *
 * Better user modern inotify interface on mount-directory instead of this
 * naive busy-loop.
 */
__attribute__((__noreturn__))
static void cmd_mount_finish_parent(struct cmd_mount_ctx *ctx)
{
	struct stat st = { .st_ino = 0 };
	int err = -1;

	for (size_t retry = 0; (retry < 20); ++retry) {
		cmd_stat_dir(ctx->in_args.mntpoint_real, &st);
		if (st.st_ino == SILOFS_INO_ROOT) {
			exit(EXIT_SUCCESS);
		}
		sleep(1);
	}
	exit(err);
}

static void cmd_mount_wait_child_pid(struct cmd_mount_ctx *ctx)
{
	pid_t ret;
	int wstatus = 0;
	int exited;
	int exit_status;

	ret = waitpid(ctx->child_pid, &wstatus, WNOHANG);
	if (ret == -1) {
		exit(errno);
	}
	exited = WIFEXITED(wstatus);
	exit_status = WEXITSTATUS(wstatus);
	if (exited && exit_status) {
		exit(exit_status);
	}
}

static void cmd_mount_start_daemon(struct cmd_mount_ctx *ctx)
{
	const pid_t pre_pid = getpid();

	cmd_fork_daemon(&ctx->child_pid);
	if (pre_pid == getpid()) {
		/* I am parent: wait for active mount & exit */
		cmd_mount_wait_child_pid(ctx);
		cmd_mount_finish_parent(ctx);
	} else {
		/* I am child: enable syslog and continue boot flow*/
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

static void cmd_mount_boostrap_process(struct cmd_mount_ctx *ctx)
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

static void cmd_mount_open_fs(struct cmd_mount_ctx *ctx)
{
	cmd_open_fs(ctx->fs_env);
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
	silofs_log_info("mountpoint: %s", ctx->in_args.mntpoint_real);
	silofs_log_info("repodir: %s", ctx->in_args.repodir_real);
	silofs_log_info("modes: rdonly=%d noexec=%d nodev=%d nosuid=%d",
	                (int)ctx->in_args.rdonly, (int)ctx->in_args.noexec,
	                (int)ctx->in_args.nodev, (int)ctx->in_args.nosuid);
}

static void cmd_mount_trace_finish(const struct cmd_mount_ctx *ctx)
{
	const time_t exec_time = silofs_time_now() - ctx->start_time;

	silofs_log_info("mount done: %s", ctx->in_args.mntpoint_real);
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
		err = silofs_mntrpc_umount(ctx->in_args.mntpoint_real,
		                           getuid(), getgid(), MNT_DETACH);
		if (err) {
			silofs_log_info("failed to umount lazily: %s err=%d",
			                ctx->in_args.mntpoint_real, err);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mount(void)
{
	struct cmd_mount_ctx ctx = {
		.fs_env = NULL,
		.halt_signal = -1,
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

	/* Load and setup source boot-params */
	cmd_mount_setup_fs_args(&ctx);

	/* Setup boot environment instance */
	cmd_mount_setup_fs_env(&ctx);

	/* Open repository first time */
	cmd_mount_open_repo(&ctx);

	/* Load-verify bootsec */
	cmd_mount_require_bsec(&ctx);

	/* Require boot + lock-able file-system */
	cmd_mount_boot_fs(&ctx);

	/* Close repository */
	cmd_mount_close_repo(&ctx);

	/* Destroy boot environment instance */
	cmd_mount_destroy_fs_env(&ctx);

	/* Become daemon process */
	cmd_mount_boostrap_process(&ctx);

	/* Setup main environment instance */
	cmd_mount_setup_fs_env(&ctx);

	/* Re-open repository */
	cmd_mount_open_repo(&ctx);

	/* Re-load and verify bootsec */
	cmd_mount_require_bsec(&ctx);

	/* Re-boot and lock file-system */
	cmd_mount_boot_fs(&ctx);

	/* Open-load file-system meta-data */
	cmd_mount_open_fs(&ctx);

	/* Report beginning-of-mount */
	cmd_mount_trace_start(&ctx);

	/* Allow halt by signal */
	cmd_mount_enable_signals();

	/* Execute as long as needed... */
	cmd_mount_execute_fs(&ctx);

	/* Flush-close file-system meta-data */
	cmd_mount_shutdown_fs(&ctx);

	/* Report end-of-mount */
	cmd_mount_trace_finish(&ctx);

	/* Close repository */
	cmd_mount_close_repo(&ctx);

	/* Destroy main environment instance */
	cmd_mount_destroy_fs_env(&ctx);

	/* Post execution cleanups */
	cmd_mount_post_exec_cleanup(&ctx);

	/* Finalize resource allocations */
	cmd_mount_finalize(&ctx);

	/* Return to main for global cleanups */
}
