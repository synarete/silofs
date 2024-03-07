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
	"  -o, --opts=subopts           Comma-separated sub-options",
	"  -r, --rdonly                 Mount in read-only mode",
	"  -X, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"  -i  --allow-hostids          Use local host uid/gid",
	"  -E  --allow-xattr-acl        Enable ACL via extended attributes",
	"  -A  --no-allow-other         Do not allow other users",
	"  -W  --writeback-cache=0|1    Write-back cache mode",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	"  -M, --stdalloc               Use standard C allocator",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_mount_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *mntpoint;
	char   *mntpoint_real;
	char   *uhelper;
	char   *password;
	struct silofs_fs_cflags  flags;
	bool    explicit_log_level;
	bool    systemd_run;
};

struct cmd_mount_ctx {
	struct cmd_mount_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	pid_t                   child_pid;
	time_t                  start_time;
	int                     halt_signal;
	int                     post_exec_status;
	bool                    has_lockfile;
	bool                    with_progname; /* XXX: TODO: allow set */
};

static struct cmd_mount_ctx *cmd_mount_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum cmd_mount_subopts {
	CMD_MOUNT_OPT_RO = 0,
	CMD_MOUNT_OPT_RW,
	CMD_MOUNT_OPT_DEV,
	CMD_MOUNT_OPT_NODEV,
	CMD_MOUNT_OPT_SUID,
	CMD_MOUNT_OPT_NOSUID,
	CMD_MOUNT_OPT_EXEC,
	CMD_MOUNT_OPT_NOEXEC,
	CMD_MOUNT_OPT_HOSTIDS,
	CMD_MOUNT_OPT_PASSWD,
};

static void cmd_mount_getsubopts(struct cmd_mount_ctx *ctx)
{
	char subopts[256] = "";
	char tok_ro[] = "ro";
	char tok_rw[] = "rw";
	char tok_dev[] = "dev";
	char tok_nodev[] = "nodev";
	char tok_suid[] = "suid";
	char tok_nosuid[] = "nosuid";
	char tok_exec[] = "exec";
	char tok_noexec[] = "noexec";
	char tok_hostids[] = "hostids";
	char tok_passwd[] = "passwd";
	char *const toks[] = {
		[CMD_MOUNT_OPT_RO] = tok_ro,
		[CMD_MOUNT_OPT_RW] = tok_rw,
		[CMD_MOUNT_OPT_DEV] = tok_dev,
		[CMD_MOUNT_OPT_NODEV] = tok_nodev,
		[CMD_MOUNT_OPT_SUID] = tok_suid,
		[CMD_MOUNT_OPT_NOSUID] = tok_nosuid,
		[CMD_MOUNT_OPT_EXEC] = tok_exec,
		[CMD_MOUNT_OPT_NOEXEC] = tok_noexec,
		[CMD_MOUNT_OPT_HOSTIDS] = tok_hostids,
		[CMD_MOUNT_OPT_PASSWD] = tok_passwd,
		NULL
	};
	char *sopt = NULL;
	char *sval = NULL;
	int skey = 0;
	size_t len;

	len = strlen(optarg);
	if (len >= sizeof(subopts)) {
		cmd_dief(0, "too many sub-options: %s", optarg);
	}
	memcpy(subopts, optarg, len);
	sopt = subopts;
	while (*sopt != '\0') {
		sval = NULL;
		skey = getsubopt(&sopt, toks, &sval);
		if (skey == CMD_MOUNT_OPT_RO) {
			ctx->in_args.flags.rdonly = true;
		} else if (skey == CMD_MOUNT_OPT_RW) {
			ctx->in_args.flags.rdonly = false;
		} else if (skey == CMD_MOUNT_OPT_DEV) {
			ctx->in_args.flags.nodev = false;
		} else if (skey == CMD_MOUNT_OPT_NODEV) {
			ctx->in_args.flags.nodev = true;
		} else if (skey == CMD_MOUNT_OPT_SUID) {
			ctx->in_args.flags.nosuid = false;
		} else if (skey == CMD_MOUNT_OPT_NOSUID) {
			ctx->in_args.flags.nosuid = true;
		} else if (skey == CMD_MOUNT_OPT_EXEC) {
			ctx->in_args.flags.noexec = false;
		} else if (skey == CMD_MOUNT_OPT_NOEXEC) {
			ctx->in_args.flags.noexec = true;
		} else if (skey == CMD_MOUNT_OPT_HOSTIDS) {
			ctx->in_args.flags.allow_hostids = true;
		} else if (skey == CMD_MOUNT_OPT_PASSWD) {
			ctx->in_args.password = cmd_getpass_str(sval);
		} else {
			cmd_dief(0, "illegal sub-options: %s", optarg);
		}
	}
}

static void cmd_mount_getopt(struct cmd_mount_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "opts", required_argument, NULL, 'o' },
		{ "allow-hostids", no_argument, NULL, 'i' },
		{ "allow-xattr-acl", no_argument, NULL, 'E' },
		{ "no-allow-other", no_argument, NULL, 'A' },
		{ "writeback-cache", required_argument, NULL, 'W' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "asyncwr", required_argument, NULL, 'a' },
		{ "stdalloc", no_argument, NULL, 'M' },
		{ "password", required_argument, NULL, 'p' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "systemd-run", no_argument, NULL, 'R' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("o:iAEW:DCa:Mp:L:Rh", opts);
		if (opt_chr == 'o') {
			cmd_mount_getsubopts(ctx);
		} else if (opt_chr == 'i') {
			ctx->in_args.flags.allow_hostids = true;
		} else if (opt_chr == 'A') {
			ctx->in_args.flags.allow_other = false;
		} else if (opt_chr == 'E') {
			ctx->in_args.flags.allow_xattr_acl = true;
		} else if (opt_chr == 'W') {
			ctx->in_args.flags.writeback_cache =
			        cmd_parse_str_as_bool(optarg);
		} else if (opt_chr == 'D') {
			cmd_globals.dont_daemonize = true;
		} else if (opt_chr == 'C') {
			cmd_globals.allow_coredump = true;
		} else if (opt_chr == 'a') {
			ctx->in_args.flags.asyncwr =
			        cmd_parse_str_as_bool(optarg);
		} else if (opt_chr == 'M') {
			ctx->in_args.flags.stdalloc = true;
		} else if (opt_chr == 'p') {
			cmd_getoptarg_pass(&ctx->in_args.password);
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
			ctx->in_args.explicit_log_level = true;
		} else if (opt_chr == 'R') {
			ctx->in_args.systemd_run = true;
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
	const struct cmd_mount_in_args *in_args = &ctx->in_args;
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, in_args->name);
	memcpy(&fs_args->cflags, &in_args->flags, sizeof(fs_args->cflags));
	fs_args->passwd = in_args->password;
	fs_args->repodir = in_args->repodir_real;
	fs_args->name = in_args->name;
	fs_args->mntdir = in_args->mntpoint_real;
}

static void cmd_mount_load_bconf(struct cmd_mount_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_mount_setup_fs_ctx(struct cmd_mount_ctx *ctx)
{
	ctx->fs_args.passwd = ctx->in_args.password;
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_mount_destroy_fs_ctx(struct cmd_mount_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_mount_halt_by_signal(int signum)
{
	struct cmd_mount_ctx *ctx;

	ctx = cmd_mount_ctx;
	if (ctx && ctx->fs_ctx) {
		silofs_halt_fs(ctx->fs_ctx, signum);
	}
}

static void cmd_mount_enable_signals(void)
{
	cmd_register_sigactions(cmd_mount_halt_by_signal);
}


static void cmd_mount_acquire_lockfile(struct cmd_mount_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lockfile_acquire1(ctx->in_args.repodir_real,
		                      ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_mount_release_lockfile(struct cmd_mount_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_lockfile_release(ctx->in_args.repodir_real,
		                     ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_mount_finalize(struct cmd_mount_ctx *ctx)
{
	cmd_mount_destroy_fs_ctx(ctx);
	cmd_bconf_reset(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.mntpoint);
	cmd_pstrfree(&ctx->in_args.mntpoint_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.uhelper);
	cmd_delpass(&ctx->in_args.password);
	cmd_close_syslog();
	cmd_mount_ctx = NULL;
}

static void cmd_mount_atexit(void)
{
	if (cmd_mount_ctx != NULL) {
		cmd_mount_release_lockfile(cmd_mount_ctx);
		cmd_mount_finalize(cmd_mount_ctx);
	}
}

static void cmd_mount_start(struct cmd_mount_ctx *ctx)
{
	cmd_mount_ctx = ctx;
	atexit(cmd_mount_atexit);
}

static void cmd_mount_mkdefaults(struct cmd_mount_ctx *ctx)
{
	ctx->in_args.flags.pedantic = false;
	ctx->in_args.flags.rdonly = false;
	ctx->in_args.flags.noexec = false;
	ctx->in_args.flags.nosuid = false;
	ctx->in_args.flags.nodev = false;
	ctx->in_args.flags.with_fuse = true;
	ctx->in_args.flags.asyncwr = true;
	ctx->in_args.flags.allow_other = true;
	ctx->in_args.flags.allow_hostids = false;
	ctx->in_args.flags.allow_xattr_acl = false;
	ctx->in_args.flags.allow_admin = true;
	ctx->in_args.flags.writeback_cache = true;
	ctx->in_args.flags.lazytime = false;
	ctx->in_args.flags.stdalloc = false;
	ctx->in_args.explicit_log_level = false;
	ctx->in_args.systemd_run = false;
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
	cmd_check_exists(ctx->in_args.repodir_name);
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, true);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_mount_getpass(struct cmd_mount_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass(NULL, &ctx->in_args.password);
	}
}

static void cmd_mount_open_repo(struct cmd_mount_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_mount_close_repo(struct cmd_mount_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_mount_require_brec(struct cmd_mount_ctx *ctx)
{
	cmd_require_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_mount_boot_fs(struct cmd_mount_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_mount_execute_fs(struct cmd_mount_ctx *ctx)
{
	ctx->start_time = silofs_time_now();
	cmd_exec_fs(ctx->fs_ctx);
	ctx->halt_signal = ctx->fs_ctx->signum;
	ctx->post_exec_status = silofs_post_exec_fs(ctx->fs_ctx);
}

static void cmd_mount_close_fs(struct cmd_mount_ctx *ctx)
{
	cmd_close_fs(ctx->fs_ctx);
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

static void cmd_mount_update_log_params(const struct cmd_mount_ctx *ctx)
{
	int log_flags = cmd_globals.log_params.flags;

	/* log control flags bits-mask */
	if (!cmd_globals.dont_daemonize) { /* daemon mode */
		log_flags |= SILOFS_LOGF_SYSLOG;
		log_flags &= ~SILOFS_LOGF_STDOUT;
		log_flags &= ~SILOFS_LOGF_PROGNAME;
	} else {
		log_flags |= SILOFS_LOGF_STDOUT;
		log_flags &= ~SILOFS_LOGF_SYSLOG;
	}
	if (ctx->with_progname) {
		log_flags |= SILOFS_LOGF_PROGNAME;
	} else {
		log_flags &= ~SILOFS_LOGF_PROGNAME;
	}
	cmd_globals.log_params.flags = (enum silofs_log_flags)log_flags;

	/* log level */
	if (!ctx->in_args.explicit_log_level) {
		if (ctx->in_args.systemd_run) {
			cmd_globals.log_params.level = SILOFS_LOG_ERROR;
		} else {
			cmd_globals.log_params.level = SILOFS_LOG_INFO;
		}
	}
}

static void cmd_mount_open_fs(struct cmd_mount_ctx *ctx)
{
	cmd_open_fs(ctx->fs_ctx);
}

/*
 * Trace global setting to user. When running as daemon on systemd-based
 * environments, users should use the following command to view silofs's
 * traces:
 *
 *   $ journalctl -b -n 60 -f -t silofs
 */
#define silofs_log_iarg(fmt_, ...) silofs_log_info("inarg: " fmt_, __VA_ARGS__)

static void cmd_mount_trace_start(const struct cmd_mount_ctx *ctx)
{
	const struct silofs_fs_cflags *cflags = &ctx->in_args.flags;

	silofs_log_meta_banner(cmd_globals.name, 1);
	silofs_log_info("executable: %s", cmd_globals.prog);
	silofs_log_info("nprocs: %u", silofs_sc_nproc_onln());
	silofs_log_iarg("mountpoint=%s", ctx->in_args.mntpoint_real);
	silofs_log_iarg("repodir=%s", ctx->in_args.repodir_real);
	silofs_log_iarg("rdonly=%d", cflags->rdonly);
	silofs_log_iarg("noexec=%d", cflags->noexec);
	silofs_log_iarg("nosuid=%d", cflags->nosuid);
	silofs_log_iarg("nodev=%d", cflags->nodev);
	silofs_log_iarg("asyncwr=%d", cflags->asyncwr);
	silofs_log_iarg("allow_admin=%d", cflags->allow_admin);
	silofs_log_iarg("allow_other=%d", cflags->allow_other);
	silofs_log_iarg("allow_hostids=%d", cflags->allow_hostids);
	silofs_log_iarg("allow_xattr_acl=%d", cflags->allow_xattr_acl);
	silofs_log_iarg("writeback_cache=%d", cflags->writeback_cache);
	silofs_log_iarg("lazytime=%d", cflags->lazytime);
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

	if ((ctx->halt_signal > 0) && (ctx->post_exec_status != 0)) {
		err = silofs_mntrpc_umount(ctx->in_args.mntpoint_real,
		                           getuid(), getgid(), MNT_DETACH);
		if (err) {
			silofs_log_info("failed to umount lazily: %s err=%d",
			                ctx->in_args.mntpoint_real, err);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_exec_phase1(struct cmd_mount_ctx *ctx)
{
	/* Setup boot environment instance */
	cmd_mount_setup_fs_ctx(ctx);

	/* Acquire lock */
	cmd_mount_acquire_lockfile(ctx);

	/* Open repository first time */
	cmd_mount_open_repo(ctx);

	/* Load-verify boot-record */
	cmd_mount_require_brec(ctx);

	/* Require boot + lock-able file-system */
	cmd_mount_boot_fs(ctx);

	/* Flush-close file-system */
	cmd_mount_close_fs(ctx);

	/* Close repository */
	cmd_mount_close_repo(ctx);

	/* Release lock */
	cmd_mount_release_lockfile(ctx);

	/* Destroy boot environment instance */
	cmd_mount_destroy_fs_ctx(ctx);
}

static void cmd_mount_exec_phase2(struct cmd_mount_ctx *ctx)
{
	/* Become daemon process */
	cmd_mount_boostrap_process(ctx);

	/* Update logging */
	cmd_mount_update_log_params(ctx);

	/* Setup main environment instance */
	cmd_mount_setup_fs_ctx(ctx);

	/* Re-acquire lock */
	cmd_mount_acquire_lockfile(ctx);

	/* Re-open repository */
	cmd_mount_open_repo(ctx);

	/* Re-load and verify boot-record  */
	cmd_mount_require_brec(ctx);

	/* Re-boot and lock file-system */
	cmd_mount_boot_fs(ctx);

	/* Open-load file-system meta-data */
	cmd_mount_open_fs(ctx);

	/* Report beginning-of-mount */
	cmd_mount_trace_start(ctx);

	/* Allow halt by signal */
	cmd_mount_enable_signals();

	/* Execute as long as needed... */
	cmd_mount_execute_fs(ctx);

	/* Flush-close file-system meta-data */
	cmd_mount_close_fs(ctx);

	/* Close repository */
	cmd_mount_close_repo(ctx);

	/* Release lock */
	cmd_mount_release_lockfile(ctx);

	/* Report end-of-mount */
	cmd_mount_trace_finish(ctx);

	/* Destroy main environment instance */
	cmd_mount_destroy_fs_ctx(ctx);
}


void cmd_execute_mount(void)
{
	struct cmd_mount_ctx ctx = {
		.fs_ctx = NULL,
		.halt_signal = -1,
		.post_exec_status = 0,
	};

	/* Do all cleanups upon exits */
	cmd_mount_start(&ctx);

	/* Setup default boot-args */
	cmd_mount_mkdefaults(&ctx);

	/* Parse command's arguments */
	cmd_mount_getopt(&ctx);

	/* Require valid mount-point */
	cmd_mount_prepare_mntpoint(&ctx);

	/* Require minimal repository validity */
	cmd_mount_prepare_repo(&ctx);

	/* Require password */
	cmd_mount_getpass(&ctx);

	/* Setup input arguments */
	cmd_mount_setup_fs_args(&ctx);

	/* Require fs-uuid and ids-map */
	cmd_mount_load_bconf(&ctx);

	/* Execute pre-mount as command-line process */
	cmd_mount_exec_phase1(&ctx);

	/* Execute mount as daemon process */
	cmd_mount_exec_phase2(&ctx);

	/* Post execution cleanups */
	cmd_mount_post_exec_cleanup(&ctx);

	/* Finalize resource allocations */
	cmd_mount_finalize(&ctx);
}
