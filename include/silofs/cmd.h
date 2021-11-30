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
#ifndef SILOFS_CMD_H_
#define SILOFS_CMD_H_

#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>

#define SILOFS_FSNAME_DEFAULT "main"

typedef void (*silofs_exec_fn)(void);

/* sub-command descriptor */
struct silofs_cmd_info {
	const char *name;
	silofs_exec_fn action_hook;
};

/* arguments for 'init' sub-command */
struct silofs_subcmd_init {
	char   *name;
	char   *repodir;
	char   *repodir_real;
};

/* arguments for 'mkfs' sub-command */
struct silofs_subcmd_mkfs {
	char   *name;
	char   *repodir;
	char   *repodir_real;
	char   *size;
	long    fs_size;
	bool    force;
};

/* arguments for 'mount' sub-command */
struct silofs_subcmd_mount {
	char   *name;
	char   *repodir;
	char   *repodir_real;
	char   *mntpoint;
	char   *mntpoint_real;
	char   *options;
	bool    allowother;
	bool    lazytime;
	bool    noexec;
	bool    nosuid;
	bool    nodev;
	bool    rdonly;
	bool    nokcopy;
};

/* arguments for 'umount' sub-command */
struct silofs_subcmd_umount {
	char   *mntpoint;
	char   *mntpoint_real;
	bool    force;
	bool    lazy;
};

/* arguments for 'snap' sub-command */
struct silofs_subcmd_snap {
	char   *name;
	char   *dirpath;
	char   *dirpath_real;
};

/* arguments for 'archive' sub-command */
struct silofs_subcmd_archive {
	char   *passphrase;
	char   *passphrase_file;
	char   *repodir;
	char   *name;
};

/* arguments for 'show' sub-command */
struct silofs_subcmd_show {
	char   *pathname;
	char   *pathname_real;
	char   *subcmd;
};

/* arguments for 'refs' sub-command */
struct silofs_subcmd_refs {
	char   *pathname;
	char   *pathname_real;
	bool    full;
};

/* arguments for 'fsck' sub-command */
struct silofs_subcmd_fsck {
	char   *repodir;
};

/* arguments for 'prune' sub-command */
struct silofs_subcmd_prune {
	char   *repodir;
};

/* arguments for 'lsmnt' sub-command */
struct silofs_subcmd_lsmnt {
	char   *mntpoint;
	char   *mntpoint_real;
	bool    long_listing;
};

/* sub-commands options */
union silofs_subcmd_args {
	struct silofs_subcmd_init       init;
	struct silofs_subcmd_mkfs       mkfs;
	struct silofs_subcmd_mount      mount;
	struct silofs_subcmd_umount     umount;
	struct silofs_subcmd_snap       snap;
	struct silofs_subcmd_show       show;
	struct silofs_subcmd_refs       refs;
	struct silofs_subcmd_lsmnt      lsmnt;
	struct silofs_subcmd_archive    archive;
	struct silofs_subcmd_prune      prune;
	struct silofs_subcmd_fsck       fsck;
};

/* repository configuration */
struct silofs_rconf {
	const char *passphrase_base64;
	const char *aws_access_key_id;
	const char *aws_secret_access_key;
};

/* global settings */
struct silofs_globals {
	/* program's version string */
	const char *version;

	/* program's arguments */
	char   *name;
	char   *prog;
	int     argc;
	char  **argv;
	char   *cmd_name;
	char  **cmd_argv;
	int     cmd_argc;
	int     log_mask;

	/* process ids */
	pid_t   pid;
	uid_t   uid;
	gid_t   gid;
	mode_t  umsk;

	/* common process settings */
	bool    dont_daemonize;
	bool    allow_coredump;
	bool    disable_ptrace; /* XXX: TODO: allow set */

	/* capability */
	bool    cap_sys_admin;

	/* signals info */
	int     sig_halt;
	int     sig_fatal;

	/* execution start-time */
	time_t  start_time;

	/* sub-commands arguments */
	union silofs_subcmd_args cmd;

	/* sub-command execution hook */
	const struct silofs_cmd_info *cmdi;
};

extern struct silofs_globals silofs_globals;


/* execution hooks */
void silofs_execute_mkfs(void);

void silofs_execute_mount(void);

void silofs_execute_umount(void);

void silofs_execute_show(void);

void silofs_execute_refs(void);

void silofs_execute_snap(void);

void silofs_execute_archive(void);

void silofs_execute_fsck(void);

void silofs_execute_prune(void);

void silofs_execute_lsmnt(void);

/* common utilities */

__attribute__((__noreturn__))
void silofs_die_redundant_arg(const char *s);

__attribute__((__noreturn__))
void silofs_die_missing_arg(const char *s);

__attribute__((__noreturn__))
void silofs_die_unsupported_opt(void);

void silofs_die_if_missing_arg(const char *arg_name, const void *arg_val);

void silofs_die_if_redundant_arg(void);

void silofs_die_if_illegal_name(const char *arg_name, const char *arg_val);

void silofs_die_if_not_dir(const char *path, bool w_ok);

void silofs_die_if_not_dir_or_empty(const char *path, bool w_ok);

void silofs_die_if_not_empty_dir(const char *path, bool w_ok);

void silofs_die_if_not_mntdir(const char *path, bool mount);

void silofs_die_if_not_reg(const char *path, bool w_ok);

void silofs_die_if_exists(const char *path);

void silofs_die_if_no_mountd(void);

void silofs_require_valid_fsname(const char *arg_name, char **p_fsname);


char *silofs_cmd_getarg(const char *arg_name, bool last);

int silofs_cmd_getopt(const char *sopts, const struct option *lopts);

long silofs_cmd_parse_size(const char *str);

char *silofs_cmd_lockfile(const char *dirpath);

char *silofs_cmd_realpath(const char *path);

char *silofs_cmd_basename(const char *path);

void silofs_cmd_stat_ok(const char *path, struct stat *st);

void silofs_cmd_stat_reg(const char *path, struct stat *st);

void silofs_cmd_stat_reg_or_dir(const char *path, struct stat *st);


void silofs_fork_daemon(void);

void silofs_open_syslog(void);

void silofs_close_syslog(void);

void silofs_setrlimit_nocore(void);

void silofs_prctl_non_dumpable(void);


void silofs_setup_globals(int argc, char *argv[]);

void silofs_init_process(void);

void silofs_set_verbose_mode(const char *mode);

void silofs_show_help_and_exit(const char **help_strings);

void silofs_show_version_and_exit(const char *prog);

void silofs_pretty_size(size_t n, char *buf, size_t bsz);


void *silofs_zalloc_safe(size_t n);

void silofs_zfree_safe(void *ptr, size_t nbytes);

void silofs_pfree_string(char **pp);

char *silofs_strdup_safe(const char *s);

char *silofs_strndup_safe(const char *s, size_t n);

char *silofs_sprintf_path(const char *fmt, ...);

/* singleton instance */
void silofs_create_fse_inst(const struct silofs_fs_args *args);

void silofs_destroy_fse_inst(void);

struct silofs_fs_env *silofs_fse_inst(void);


/* signals handling */
typedef void (*silofs_signal_hook_fn)(int);

void silofs_register_sigactions(silofs_signal_hook_fn sig_hook);

/* passphrase input */
char *silofs_getpass(const char *path);

char *silofs_getpass2(const char *path);

void silofs_delpass(char **pass);


#endif /* SILOFS_CMD_H_ */
