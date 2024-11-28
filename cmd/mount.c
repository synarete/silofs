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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include "cmd.h"

static const char *cmd_mount_help_desc =
	"mount [options] <repodir/name> <mountpoint>                       \n"
	"                                                                  \n"
	"options:                                                          \n"
	"  -o, --opts=subopts           Comma-separated sub-options        \n"
	"  -r, --rdonly                 Mount in read-only mode            \n"
	"  -X, --noexec                 Do not allow programs execution    \n"
	"  -S, --nosuid                 Do not honor special bits          \n"
	"  -i  --allow-hostids          Use local host uid/gid             \n"
	"  -E  --allow-xattr-acl        ACLs via extended attributes       \n"
	"  -A  --no-allow-other         Do not allow other users           \n"
	"  -W  --writeback-cache=0|1    Write-back cache mode              \n"
	"  -B  --buffer-copy-mode       Set FUSE with copy-to-buffer mode  \n"
	"  -D, --nodaemon               Do not run as daemon process       \n"
	"  -C, --coredump               Allow core-dumps upon fatal errors \n"
	"  -M, --stdalloc               Use standard C malloc/free         \n"
	"  -L, --loglevel=level         Logging level (rfc5424)            \n";

struct cmd_mount_in_args {
	char *repodir_name;
	char *repodir;
	char *repodir_real;
	char *name;
	char *mntpoint;
	char *mntpoint_real;
	char *uhelper;
	char *password;
	struct silofs_fs_cflags flags;
	bool explicit_log_level;
	bool systemd_run;
	bool no_prompt;
};

struct cmd_mount_ctx {
	struct cmd_mount_in_args in_args;
	struct silofs_fs_args fs_args;
	struct silofs_fsenv *fsenv;
	pid_t child_pid;
	time_t start_time;
	int halt_signal;
	int post_exec_status;
	bool has_lockfile;
	bool with_progname; /* XXX: TODO: allow set */
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
	char *const toks[] = { [CMD_MOUNT_OPT_RO] = tok_ro,
		               [CMD_MOUNT_OPT_RW] = tok_rw,
		               [CMD_MOUNT_OPT_DEV] = tok_dev,
		               [CMD_MOUNT_OPT_NODEV] = tok_nodev,
		               [CMD_MOUNT_OPT_SUID] = tok_suid,
		               [CMD_MOUNT_OPT_NOSUID] = tok_nosuid,
		               [CMD_MOUNT_OPT_EXEC] = tok_exec,
		               [CMD_MOUNT_OPT_NOEXEC] = tok_noexec,
		               [CMD_MOUNT_OPT_HOSTIDS] = tok_hostids,
		               [CMD_MOUNT_OPT_PASSWD] = tok_passwd,
		               NULL };
	char *sopt = NULL;
	char *sval = NULL;
	int skey = 0;
	size_t len;

	len = strlen(optarg);
	if (len >= sizeof(subopts)) {
		cmd_die(0, "too many sub-options: %s", optarg);
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
			ctx->in_args.password = cmd_duppass(sval);
		} else {
			cmd_die(0, "illegal sub-options: %s", optarg);
		}
	}
}

static void cmd_mount_parse_optargs(struct cmd_mount_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "opts", 'o', 1 },
		{ "allow-hostids", 'i', 0 },
		{ "allow-xattr-acl", 'E', 0 },
		{ "no-allow-other", 'A', 0 },
		{ "writeback-cache", 'W', 1 },
		{ "buffer-copy-mode", 'B', 0 },
		{ "nodaemon", 'D', 0 },
		{ "coredump", 'C', 0 },
		{ "asyncwr", 'a', 1 },
		{ "stdalloc", 'M', 0 },
		{ "no-prompt", 'P', 0 },
		{ "password", 'p', 1 },
		{ "loglevel", 'L', 1 },
		{ "systemd-run", 'R', 0 },
		{ "help", 'h', 0 },
		{ NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'o':
			cmd_mount_getsubopts(ctx);
			break;
		case 'i':
			ctx->in_args.flags.allow_hostids = true;
			break;
		case 'A':
			ctx->in_args.flags.allow_other = false;
			break;
		case 'E':
			ctx->in_args.flags.allow_xattr_acl = true;
			break;
		case 'W':
			ctx->in_args.flags.writeback_cache =
				cmd_optargs_curr_as_bool(&opa);
			break;
		case 'B':
			ctx->in_args.flags.may_splice = false;
			break;
		case 'D':
			cmd_globals.dont_daemonize = true;
			break;
		case 'C':
			cmd_globals.allow_coredump = true;
			break;
		case 'a':
			ctx->in_args.flags.asyncwr =
				cmd_optargs_curr_as_bool(&opa);
			break;
		case 'M':
			ctx->in_args.flags.stdalloc = true;
			break;
		case 'P':
			ctx->in_args.no_prompt = true;
			break;
		case 'p':
			ctx->in_args.password = cmd_optargs_getpass(&opa);
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			ctx->in_args.explicit_log_level = true;
			break;
		case 'R':
			ctx->in_args.systemd_run = true;
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_mount_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}

	ctx->in_args.repodir_name = cmd_optargs_getarg(&opa, "repodir/name");
	ctx->in_args.mntpoint = cmd_optargs_getarg(&opa, "mountpoint");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_setup_fs_args(struct cmd_mount_ctx *ctx)
{
	const struct cmd_mount_in_args *in_args = &ctx->in_args;
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_fs_args_init2(fs_args, &in_args->flags);
	fs_args->bref.repodir = in_args->repodir_real;
	fs_args->bref.name = in_args->name;
	fs_args->bref.passwd = in_args->password;
	fs_args->mntdir = in_args->mntpoint_real;
}

static void cmd_mount_setup_fs_ids(struct cmd_mount_ctx *ctx)
{
	cmd_fs_ids_load(&ctx->fs_args.ids, ctx->in_args.repodir_real);
}

static void cmd_mount_load_bref(struct cmd_mount_ctx *ctx)
{
	cmd_bootref_load(&ctx->fs_args.bref);
}

static void cmd_mount_setup_fsenv(struct cmd_mount_ctx *ctx)
{
	cmd_new_fsenv(&ctx->fs_args, &ctx->fsenv);
}

static void cmd_mount_destroy_fsenv(struct cmd_mount_ctx *ctx)
{
	cmd_del_fsenv(&ctx->fsenv);
}

static void cmd_mount_halt_by_signal(int signum)
{
	struct cmd_mount_ctx *ctx;

	ctx = cmd_mount_ctx;
	if (ctx && ctx->fsenv) {
		silofs_halt_fs(ctx->fsenv);
		ctx->halt_signal = signum;
	}
}

static void cmd_mount_enable_signals(void)
{
	cmd_register_sigactions(cmd_mount_halt_by_signal);
}

static void cmd_mount_acquire_lockfile(struct cmd_mount_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_mount_release_lockfile(struct cmd_mount_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_mount_finalize(struct cmd_mount_ctx *ctx)
{
	cmd_mount_destroy_fsenv(ctx);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.mntpoint);
	cmd_pstrfree(&ctx->in_args.mntpoint_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_pstrfree(&ctx->in_args.uhelper);
	cmd_delpass(&ctx->in_args.password);
	cmd_fini_fs_args(&ctx->fs_args);
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
	ctx->in_args.flags.may_splice = true;
	ctx->in_args.flags.lazytime = false;
	ctx->in_args.flags.stdalloc = false;
	ctx->in_args.explicit_log_level = false;
	ctx->in_args.systemd_run = false;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_prepare_mntpoint(struct cmd_mount_ctx *ctx)
{
	cmd_realpath_rdir(ctx->in_args.mntpoint, &ctx->in_args.mntpoint_real);
	cmd_check_mntdir(ctx->in_args.mntpoint_real, true);
	cmd_check_mntsrv_conn();
	cmd_check_mntsrv_perm(ctx->in_args.mntpoint_real);
}

static void cmd_mount_prepare_repo(struct cmd_mount_ctx *ctx)
{
	cmd_check_isreg(ctx->in_args.repodir_name);
	cmd_split_path(ctx->in_args.repodir_name, &ctx->in_args.repodir,
	               &ctx->in_args.name);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real, ctx->in_args.name);
}

static void cmd_mount_getpass(struct cmd_mount_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_mount_open_repo(struct cmd_mount_ctx *ctx)
{
	cmd_open_repo(ctx->fsenv);
}

static void cmd_mount_close_repo(struct cmd_mount_ctx *ctx)
{
	cmd_close_repo(ctx->fsenv);
}

static void cmd_mount_poke_fs(struct cmd_mount_ctx *ctx)
{
	cmd_poke_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_mount_open_fs(struct cmd_mount_ctx *ctx)
{
	cmd_open_fs(ctx->fsenv, &ctx->fs_args.bref);
}

static void cmd_mount_execute_fs(struct cmd_mount_ctx *ctx)
{
	ctx->start_time = silofs_time_now();
	cmd_exec_fs(ctx->fsenv);
	ctx->post_exec_status = silofs_post_exec_fs(ctx->fsenv);
}

static void cmd_mount_close_fs(struct cmd_mount_ctx *ctx)
{
	cmd_close_fs(ctx->fsenv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0015: Use inotify to monitor available mount
 *
 * Better user modern inotify interface on mount-directory instead of this
 * naive busy-loop.
 */
silofs_attr_noreturn static void
cmd_mount_finish_parent(struct cmd_mount_ctx *ctx)
{
	struct stat st = { .st_ino = 0 };
	int retry = 20;
	bool ready = false;

	while ((retry-- > 0) && !ready) {
		cmd_stat_dir(ctx->in_args.mntpoint_real, &st);
		ready = (st.st_ino == SILOFS_INO_ROOT);
		sleep(1);
	}
	exit(ready ? EXIT_SUCCESS : EXIT_FAILURE);
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

static void cmd_mount_boostrap_process(struct cmd_mount_ctx *ctx)
{
	if (!cmd_globals.dont_daemonize) {
		cmd_mount_start_daemon(ctx);
	}
	cmd_setup_coredump_mode(cmd_globals.allow_coredump);
}

static void cmd_mount_update_log_params(const struct cmd_mount_ctx *ctx)
{
	int log_flags = (int)cmd_globals.log_params.flags;

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

/*
 * Trace global setting to user. When running as daemon on systemd-based
 * environments, users should use the following command to inspect silofs's
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
	silofs_log_info("nprocs: %ld", silofs_sc_nproc_onln());
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
	silofs_log_iarg("may_splice=%d", cflags->may_splice);
	silofs_log_iarg("lazytime=%d", cflags->lazytime);
	cmd_trace_versions();
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
	cmd_mount_setup_fsenv(ctx);

	/* Acquire lock */
	cmd_mount_acquire_lockfile(ctx);

	/* Open repository first time */
	cmd_mount_open_repo(ctx);

	/* Load-verify boot-record */
	cmd_mount_poke_fs(ctx);

	/* Require boot + lock-able file-system */
	cmd_mount_open_fs(ctx);

	/* Flush-close file-system */
	cmd_mount_close_fs(ctx);

	/* Close repository */
	cmd_mount_close_repo(ctx);

	/* Release lock */
	cmd_mount_release_lockfile(ctx);

	/* Destroy boot environment instance */
	cmd_mount_destroy_fsenv(ctx);
}

static void cmd_mount_exec_phase2(struct cmd_mount_ctx *ctx)
{
	/* Become daemon process */
	cmd_mount_boostrap_process(ctx);

	/* Update logging */
	cmd_mount_update_log_params(ctx);

	/* Setup main environment instance */
	cmd_mount_setup_fsenv(ctx);

	/* Re-acquire lock */
	cmd_mount_acquire_lockfile(ctx);

	/* Re-open repository */
	cmd_mount_open_repo(ctx);

	/* Re-load and verify boot-record  */
	cmd_mount_poke_fs(ctx);

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
	cmd_mount_destroy_fsenv(ctx);
}

void cmd_execute_mount(void)
{
	struct cmd_mount_ctx ctx = {
		.fsenv = NULL,
		.halt_signal = -1,
		.post_exec_status = 0,
	};

	/* Do all cleanups upon exits */
	cmd_mount_start(&ctx);

	/* Setup default boot-args */
	cmd_mount_mkdefaults(&ctx);

	/* Parse command's arguments */
	cmd_mount_parse_optargs(&ctx);

	/* Require valid mount-point */
	cmd_mount_prepare_mntpoint(&ctx);

	/* Require minimal repository validity */
	cmd_mount_prepare_repo(&ctx);

	/* Require password */
	cmd_mount_getpass(&ctx);

	/* Setup input arguments */
	cmd_mount_setup_fs_args(&ctx);

	/* Load fs-ids mapping */
	cmd_mount_setup_fs_ids(&ctx);

	/* Load fs boot-reference */
	cmd_mount_load_bref(&ctx);

	/* Execute pre-mount as command-line process */
	cmd_mount_exec_phase1(&ctx);

	/* Execute mount as daemon process */
	cmd_mount_exec_phase2(&ctx);

	/* Post execution cleanups */
	cmd_mount_post_exec_cleanup(&ctx);

	/* Finalize resource allocations */
	cmd_mount_finalize(&ctx);
}
