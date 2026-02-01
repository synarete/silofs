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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <time.h>

static const char *const cmd_mount_help_desc =
	"mount [options] <repodir/fsname> <mountpoint>                     \n"
	"                                                                  \n"
	"options:                                                          \n"
	"  -o, --opts=subopts           Comma-separated sub-options        \n"
	"  -r, --rdonly                 Mount in read-only mode            \n"
	"  -X, --noexec                 Do not allow programs execution    \n"
	"  -S, --nosuid                 Do not honor special bits          \n"
	"  -i  --allow-hostids          Use local host uid/gid             \n"
	"  -E  --allow-xattr-acl        ACLs via extended attributes       \n"
	"  -Z  --allow-ispecial         Allow fifo and socket inodes       \n"
	"  -A  --no-allow-other         Do not allow other users           \n"
	"  -W  --no-writeback-cache     Disable write-back cache mode      \n"
	"  -B  --buffer-copy-mode       Set FUSE with copy-to-buffer mode  \n"
	"  -D, --nodaemon               Do not run as daemon process       \n"
	"  -C, --coredump               Allow core-dumps upon fatal errors \n"
	"  -M, --stdalloc               Use standard C malloc/free         \n"
	"  -L, --loglevel=level         Logging level (rfc5424)            \n";

struct cmd_mount_in_args {
	char *repodir_fsname;
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *mntpoint;
	char *mntpoint_real;
	char *uhelper;
	char *password;
	int flags;
	bool explicit_log_level;
	bool systemd_run;
	bool no_prompt;
};

struct cmd_mount_ctx {
	struct cmd_mount_in_args in_args;
	struct silofs_spec spec;
	struct silofs_env *env;
	pid_t child_pid;
	time_t start_time;
	int halt_signal;
	int post_exec_status;
	bool has_lockfile;
	bool with_progname; /* XXX: TODO: allow set */
};

static struct cmd_mount_ctx *cmd_mount_ctx_p;

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
	char subopts[256]  = "";
	char tok_ro[]      = "ro";
	char tok_rw[]      = "rw";
	char tok_dev[]     = "dev";
	char tok_nodev[]   = "nodev";
	char tok_suid[]    = "suid";
	char tok_nosuid[]  = "nosuid";
	char tok_exec[]    = "exec";
	char tok_noexec[]  = "noexec";
	char tok_hostids[] = "hostids";
	char tok_passwd[]  = "passwd";
	char *const toks[] = {
		[CMD_MOUNT_OPT_RO]      = tok_ro,      //
		[CMD_MOUNT_OPT_RW]      = tok_rw,      //
		[CMD_MOUNT_OPT_DEV]     = tok_dev,     //
		[CMD_MOUNT_OPT_NODEV]   = tok_nodev,   //
		[CMD_MOUNT_OPT_SUID]    = tok_suid,    //
		[CMD_MOUNT_OPT_NOSUID]  = tok_nosuid,  //
		[CMD_MOUNT_OPT_EXEC]    = tok_exec,    //
		[CMD_MOUNT_OPT_NOEXEC]  = tok_noexec,  //
		[CMD_MOUNT_OPT_HOSTIDS] = tok_hostids, //
		[CMD_MOUNT_OPT_PASSWD]  = tok_passwd,  //
		nullptr                                //
	};
	char *sopt = nullptr;
	char *sval = nullptr;
	int skey   = 0;
	size_t len;

	len = strlen(optarg);
	if (len >= sizeof(subopts)) {
		cmd_diez("too many sub-options: %s", optarg);
	}
	memcpy(subopts, optarg, len);
	sopt = subopts;
	while (*sopt != '\0') {
		sval = nullptr;
		skey = getsubopt(&sopt, toks, &sval);
		if (skey == CMD_MOUNT_OPT_RO) {
			ctx->in_args.flags |= SILOFS_F_RDONLY;
		} else if (skey == CMD_MOUNT_OPT_RW) {
			ctx->in_args.flags &= ~SILOFS_F_RDONLY;
		} else if (skey == CMD_MOUNT_OPT_DEV) {
			ctx->in_args.flags &= ~SILOFS_F_NODEV;
		} else if (skey == CMD_MOUNT_OPT_NODEV) {
			ctx->in_args.flags |= SILOFS_F_NODEV;
		} else if (skey == CMD_MOUNT_OPT_SUID) {
			ctx->in_args.flags &= ~SILOFS_F_NOSUID;
		} else if (skey == CMD_MOUNT_OPT_NOSUID) {
			ctx->in_args.flags |= SILOFS_F_NOSUID;
		} else if (skey == CMD_MOUNT_OPT_EXEC) {
			ctx->in_args.flags &= ~SILOFS_F_NOEXEC;
		} else if (skey == CMD_MOUNT_OPT_NOEXEC) {
			ctx->in_args.flags |= SILOFS_F_NOEXEC;
		} else if (skey == CMD_MOUNT_OPT_HOSTIDS) {
			ctx->in_args.flags |= SILOFS_F_ALLOWHOSTIDS;
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
		{ "allow-ispecial", 'Z', 0 },
		{ "no-allow-other", 'A', 0 },
		{ "no-writeback-cache", 'W', 0 },
		{ "buffer-copy-mode", 'B', 0 },
		{ "nodaemon", 'D', 0 },
		{ "coredump", 'C', 0 },
		{ "developer-mode", 'X', 0 },
		{ "asyncwr", 'a', 1 },
		{ "stdalloc", 'M', 0 },
		{ "no-prompt", 'P', 0 },
		{ "password", 'p', 1 },
		{ "loglevel", 'L', 1 },
		{ "systemd-run", 'R', 0 },
		{ "help", 'h', 0 },
		{ nullptr, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;
	bool barg;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'o':
			cmd_mount_getsubopts(ctx);
			break;
		case 'i':
			ctx->in_args.flags |= SILOFS_F_ALLOWHOSTIDS;
			break;
		case 'A':
			ctx->in_args.flags &= ~SILOFS_F_ALLOWOTHER;
			break;
		case 'E':
			ctx->in_args.flags |= SILOFS_F_ALLOWXACL;
			break;
		case 'W':
			ctx->in_args.flags |= SILOFS_F_NOWRITEBACK;
			ctx->in_args.flags |= SILOFS_F_AUTOINVAL;
			break;
		case 'Z':
			ctx->in_args.flags |= SILOFS_F_ALLOWIFIFO;
			ctx->in_args.flags |= SILOFS_F_ALLOWISOCK;
			break;
		case 'B':
			ctx->in_args.flags &= ~SILOFS_F_MAYSPLICE;
			break;
		case 'D':
			cmd_global_params.dont_daemonize = true;
			break;
		case 'C':
			cmd_global_params.allow_coredump = true;
			break;
		case 'X':
			cmd_global_params.developer_mode = true;
			break;
		case 'a':
			barg = cmd_optargs_curr_as_bool(&opa);
			if (barg) {
				ctx->in_args.flags |= SILOFS_F_ASYNCWR;
			} else {
				ctx->in_args.flags &= ~SILOFS_F_ASYNCWR;
			}
			break;
		case 'M':
			ctx->in_args.flags |= SILOFS_F_STDALLOC;
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

	ctx->in_args.repodir_fsname =
		cmd_optargs_getarg(&opa, "repodir/fsname");
	ctx->in_args.mntpoint = cmd_optargs_getarg(&opa, "mountpoint");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mount_setup_spec(struct cmd_mount_ctx *ctx)
{
	cmd_spec_setup1(&ctx->spec, (enum silofs_flags)ctx->in_args.flags);
	cmd_spec_own_passwd(&ctx->spec, &ctx->in_args.password);
	cmd_spec_set_baseref(&ctx->spec, ctx->in_args.repodir_real,
	                     ctx->in_args.fsname);
}

static void cmd_mount_load_spec(struct cmd_mount_ctx *ctx)
{
	cmd_spec_jload(&ctx->spec);
	cmd_spec_need_self(&ctx->spec);
}

static void cmd_mount_setup_env(struct cmd_mount_ctx *ctx, bool clear_fsids)
{
	cmd_env_setup(&ctx->spec, &ctx->env);
	if (clear_fsids) {
		cmd_spec_clear_fsids(&ctx->spec);
	}
}

static void cmd_mount_destroy_env(struct cmd_mount_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
}

static void cmd_mount_halt_by_signal(int signum)
{
	struct cmd_mount_ctx *ctx = cmd_mount_ctx_p;

	if ((ctx != nullptr) && (ctx->env != nullptr)) {
		silofs_halt_fs(ctx->env);
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
		cmd_lock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = true;
	}
}

static void cmd_mount_release_lockfile(struct cmd_mount_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_unlock_fs(ctx->in_args.repodir_real, ctx->in_args.fsname);
		ctx->has_lockfile = false;
	}
}

static void cmd_mount_finalize(struct cmd_mount_ctx *ctx)
{
	cmd_mount_destroy_env(ctx);
	cmd_pstrfree(&ctx->in_args.repodir_fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.mntpoint);
	cmd_pstrfree(&ctx->in_args.mntpoint_real);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.uhelper);
	cmd_delpass(&ctx->in_args.password);
	cmd_spec_reset(&ctx->spec);
	cmd_close_syslog();
	cmd_mount_ctx_p = nullptr;
}

static void cmd_mount_atexit(void)
{
	struct cmd_mount_ctx *ctx = cmd_mount_ctx_p;

	if (ctx != nullptr) {
		cmd_mount_release_lockfile(ctx);
		cmd_mount_finalize(cmd_mount_ctx_p);
	}
}

static void cmd_mount_start(struct cmd_mount_ctx *ctx)
{
	cmd_mount_ctx_p = ctx;
	cmd_atexit(cmd_mount_atexit);
}

static void cmd_mount_mkdefaults(struct cmd_mount_ctx *ctx)
{
	ctx->in_args.flags = 0;
	ctx->in_args.flags |= SILOFS_F_WITHFUSE;
	ctx->in_args.flags |= SILOFS_F_ASYNCWR;
	ctx->in_args.flags |= SILOFS_F_ALLOWOTHER;
	ctx->in_args.flags |= SILOFS_F_ALLOWADMIN;
	ctx->in_args.flags |= SILOFS_F_MAYSPLICE;
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
	cmd_check_isreg(ctx->in_args.repodir_fsname);
	cmd_path_split(ctx->in_args.repodir_fsname, &ctx->in_args.repodir,
	               &ctx->in_args.fsname);
	cmd_realpath_rdir(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repodir_fsname(ctx->in_args.repodir_real,
	                         ctx->in_args.fsname);
}

static void cmd_mount_restrict_process(struct cmd_mount_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, false);
}

static void cmd_mount_getpass(struct cmd_mount_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass_simple(ctx->in_args.no_prompt,
		                   &ctx->in_args.password);
	}
}

static void cmd_mount_sense_fs(struct cmd_mount_ctx *ctx)
{
	cmd_sense_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_mount_reload_fs(struct cmd_mount_ctx *ctx)
{
	cmd_reload_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_mount_execute_fs(struct cmd_mount_ctx *ctx)
{
	ctx->start_time = time(nullptr);
	cmd_exec_fs(ctx->env, ctx->in_args.mntpoint_real);
	ctx->post_exec_status = silofs_post_exec_fs(ctx->env);
}

static void cmd_mount_unload_fs(struct cmd_mount_ctx *ctx)
{
	cmd_unload_fs(ctx->env);
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
	int retry      = 20;
	bool ready     = false;

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
	exited      = WIFEXITED(wstatus);
	exit_status = WEXITSTATUS(wstatus);
	if (exited && exit_status) {
		exit(exit_status);
	}
}

static void cmd_mount_start_daemon(struct cmd_mount_ctx *ctx)
{
	const pid_t pre_pid = getpid();

	cmd_daemonize_process(&ctx->child_pid);
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
	if (!cmd_global_params.developer_mode) {
		cmd_chdir("/");
	}
	if (!cmd_global_params.dont_daemonize) {
		cmd_mount_start_daemon(ctx);
	}
	cmd_setup_coredump_mode(cmd_global_params.allow_coredump);
}

static void cmd_mount_update_log_params(const struct cmd_mount_ctx *ctx)
{
	int log_flags = (int)cmd_global_params.log_params.flags;

	/* log control flags bits-mask */
	if (!cmd_global_params.dont_daemonize) { /* daemon mode */
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
	cmd_global_params.log_params.flags = (enum silofs_log_flags)log_flags;

	/* log level */
	if (!ctx->in_args.explicit_log_level) {
		if (ctx->in_args.systemd_run) {
			cmd_global_params.log_params.level = SILOFS_LOG_ERROR;
		} else {
			cmd_global_params.log_params.level = SILOFS_LOG_INFO;
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
#define cmd_mount_log_arg(fmt_, ...) \
	silofs_log_info("inarg: " fmt_, __VA_ARGS__)

static int cmd_mount_testf(const struct cmd_mount_ctx *ctx, int mask)
{
	return ((ctx->in_args.flags & mask) == mask);
}

static void cmd_mount_log_start(const struct cmd_mount_ctx *ctx)
{
	silofs_log_meta_banner(cmd_global_params.name, 1);
	silofs_log_info("executable: %s", cmd_global_params.prog);
	silofs_log_info("nprocs: %ld", silofs_sc_nproc_onln());

	cmd_mount_log_arg("mountpoint=%s", ctx->in_args.mntpoint_real);
	cmd_mount_log_arg("repodir=%s", ctx->in_args.repodir_real);
	cmd_mount_log_arg("rdonly=%d", cmd_mount_testf(ctx, SILOFS_F_RDONLY));
	cmd_mount_log_arg("noexec=%d", cmd_mount_testf(ctx, SILOFS_F_NOEXEC));
	cmd_mount_log_arg("nosuid=%d", cmd_mount_testf(ctx, SILOFS_F_NOSUID));
	cmd_mount_log_arg("nodev=%d", cmd_mount_testf(ctx, SILOFS_F_NODEV));
	cmd_mount_log_arg("asyncwr=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_ASYNCWR));
	cmd_mount_log_arg("allow_admin=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_ALLOWADMIN));
	cmd_mount_log_arg("allow_other=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_ALLOWOTHER));
	cmd_mount_log_arg("allow_hostids=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_ALLOWHOSTIDS));
	cmd_mount_log_arg("allow_xattr_acl=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_ALLOWXACL));
	cmd_mount_log_arg("writeback_cache=%d",
	                  !cmd_mount_testf(ctx, SILOFS_F_NOWRITEBACK));
	cmd_mount_log_arg("auto_inval_data=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_AUTOINVAL));
	cmd_mount_log_arg("may_splice=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_MAYSPLICE));
	cmd_mount_log_arg("lazytime=%d",
	                  cmd_mount_testf(ctx, SILOFS_F_LAZYTIME));
	cmd_trace_versions();
}

static void cmd_mount_log_finish(const struct cmd_mount_ctx *ctx)
{
	const time_t exec_time = time(nullptr) - ctx->start_time;

	silofs_log_info("mount done: %s", ctx->in_args.mntpoint_real);
	silofs_log_info("execution time: %ld seconds", exec_time);
	silofs_log_meta_banner(cmd_global_params.name, 0);
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
	cmd_mount_setup_env(ctx, false);

	/* Acquire lock */
	cmd_mount_acquire_lockfile(ctx);

	/* Load-verify boot-record */
	cmd_mount_sense_fs(ctx);

	/* Require boot + lock-able file-system */
	cmd_mount_reload_fs(ctx);

	/* Flush-close file-system */
	cmd_mount_unload_fs(ctx);

	/* Release lock */
	cmd_mount_release_lockfile(ctx);

	/* Destroy boot environment instance */
	cmd_mount_destroy_env(ctx);
}

static void cmd_mount_exec_phase2(struct cmd_mount_ctx *ctx)
{
	/* Become daemon process */
	cmd_mount_boostrap_process(ctx);

	/* Update logging */
	cmd_mount_update_log_params(ctx);

	/* (Re)Setup main environment instance */
	cmd_mount_setup_env(ctx, true);

	/* Re-acquire lock */
	cmd_mount_acquire_lockfile(ctx);

	/* Re-load and verify boot-record  */
	cmd_mount_sense_fs(ctx);

	/* Open-load file-system meta-data */
	cmd_mount_reload_fs(ctx);

	/* Report beginning-of-mount */
	cmd_mount_log_start(ctx);

	/* Allow halt by signal */
	cmd_mount_enable_signals();

	/* Execute as long as needed... */
	cmd_mount_execute_fs(ctx);

	/* Flush-close file-system meta-data */
	cmd_mount_unload_fs(ctx);

	/* Release lock */
	cmd_mount_release_lockfile(ctx);

	/* Report end-of-mount */
	cmd_mount_log_finish(ctx);

	/* Destroy main environment instance */
	cmd_mount_destroy_env(ctx);
}

void cmd_execute_mount(void)
{
	struct cmd_mount_ctx ctx = {
		.env              = nullptr,
		.halt_signal      = -1,
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

	/* Restrict process access */
	cmd_mount_restrict_process(&ctx);

	/* Require password */
	cmd_mount_getpass(&ctx);

	/* Setup input arguments */
	cmd_mount_setup_spec(&ctx);

	/* Load fs spec */
	cmd_mount_load_spec(&ctx);

	/* Execute pre-mount as command-line process */
	cmd_mount_exec_phase1(&ctx);

	/* Execute mount as daemon process */
	cmd_mount_exec_phase2(&ctx);

	/* Post execution cleanups */
	cmd_mount_post_exec_cleanup(&ctx);

	/* Finalize resource allocations */
	cmd_mount_finalize(&ctx);
}
