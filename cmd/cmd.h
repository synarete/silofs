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

#include <silofs/infra.h>
#include <silofs/fs.h>
#include <getopt.h>

typedef void (*silofs_exec_fn)(void);

/* sub-command descriptor */
struct cmd_info {
	const char *name;
	silofs_exec_fn action_hook;
};

/* global settings */
struct cmd_globals {
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
	bool    dumpable; /* XXX: TODO: allow set */

	/* capability */
	bool    cap_sys_admin;

	/* signals info */
	int     sig_halt;
	int     sig_fatal;

	/* sub-command execution hook */
	const struct cmd_info *cmdi;
};

extern struct cmd_globals cmd_globals;

/* execution hooks */
void cmd_execute_init(void);

void cmd_execute_mkfs(void);

void cmd_execute_mount(void);

void cmd_execute_umount(void);

void cmd_execute_show(void);

void cmd_execute_snap(void);

void cmd_execute_unrefs(void);

void cmd_execute_lsmnt(void);

void cmd_execute_archive(void);

void cmd_execute_restore(void);

void cmd_execute_prune(void);

void cmd_execute_fsck(void);

/* fatal-error handling */
__attribute__((__noreturn__))
void cmd_dief(int errnum, const char *restrict fmt, ...);

__attribute__((__noreturn__))
void cmd_fatal_unsupported_opt(void);


/* common utilities */
void cmd_require_arg(const char *arg_name, const void *arg_val);

void cmd_check_fsname(const char *arg_val);

void cmd_check_notdir(const char *path);

void cmd_check_notexists(const char *path);

void cmd_check_notexists2(const char *path, const char *name);

void cmd_check_diff(const char *path1, const char *path2);

void cmd_check_exists(const char *path);

void cmd_check_isdir(const char *path, bool w_ok);

void cmd_check_nonemptydir(const char *path, bool w_ok);

void cmd_check_emptydir(const char *path, bool w_ok);

void cmd_check_mntdir(const char *path, bool mount);

void cmd_check_reg(const char *path, bool w_ok);

void cmd_check_reg_or_dir(const char *path);

void cmd_check_mountd(void);

void cmd_mkdir(const char *path, mode_t mode);

void cmd_getoptarg(const char *opt_name, char **out_opt);

void cmd_getarg(const char *arg_name, char **out_arg);

void cmd_getarg_or_cwd(const char *arg_name, char **out_arg);

int cmd_getopt(const char *sopts, const struct option *lopts);

void cmd_endargs(void);

long cmd_parse_size(const char *str);

void cmd_realpath(const char *path, char **out_real);

void cmd_stat_reg(const char *path, struct stat *st);

void cmd_stat_dir(const char *path, struct stat *st);

void cmd_split_path(const char *path, char **out_head, char **out_tail);

void cmd_split_path2(const char *path, const char *name,
                     char **out_head, char **out_tail);

void cmd_join_path(const char *dirpath, const char *name, char **out_path);

void cmd_fork_daemon(void);

void cmd_open_syslog(void);

void cmd_close_syslog(void);

void cmd_setrlimit_nocore(void);

void cmd_set_verbose_mode(const char *mode);

void cmd_print_help_and_exit(const char **help_strings);

void *cmd_zalloc(size_t n);

void cmd_zfree(void *ptr, size_t nbytes);

void cmd_pstrfree(char **pp);

char *cmd_strdup(const char *s);

char *cmd_strndup(const char *s, size_t n);

char *cmd_mkpathf(const char *fmt, ...);

/* repository operation */
void cmd_setup_bpath(struct silofs_bootpath *bp,
                     const char *repodir, const char *name);

bool cmd_trylock_bpath(const struct silofs_bootpath *bpath, int *out_fd);

void cmd_unlock_bpath(const struct silofs_bootpath *bpath, int *pfd);

void cmd_lock_bpath(const struct silofs_bootpath *bpath, int *out_fd);

void cmd_load_bsec(const struct silofs_bootpath *bpath,
                   struct silofs_bootsec *out_bsec);

void cmd_save_bsec(const struct silofs_bootpath *bpath,
                   const struct silofs_bootsec *bsec);

void cmd_unref_bsec(const struct silofs_bootpath *bpath);

/* complex fs operations */
void cmd_format_repo(struct silofs_fs_env *fse);

void cmd_open_repo(struct silofs_fs_env *fse);

void cmd_close_repo(struct silofs_fs_env *fse);

void cmd_format_fs(struct silofs_fs_env *fse,
                   struct silofs_bootsec *bsec);

void cmd_shutdown_fs(struct silofs_fs_env *fse);

void cmd_snap_fs(struct silofs_fs_env *fse,
                 const struct silofs_bootsec *bsec,
                 struct silofs_bootsecs *out_bsecs);

void cmd_verify_fs(struct silofs_fs_env *fse,
                   const struct silofs_bootsec *bsec);

void cmd_serve_fs(struct silofs_fs_env *fse,
                  const struct silofs_bootsec *bsec);

void cmd_archive_fs(struct silofs_fs_env *fse,
                    const struct silofs_bootlink *src_blnk,
                    struct silofs_bootlink *dst_blnk);

void cmd_restore_fs(struct silofs_fs_env *fse,
                    const struct silofs_bootlink *src_blnk,
                    struct silofs_bootlink *dst_blnk);

/* extra utilities */
struct silofs_proc_mntinfo {
	struct silofs_proc_mntinfo *next;
	const char *mntdir;
	const char *mntargs;
	size_t msz;
};

struct silofs_proc_mntinfo *cmd_parse_mountinfo(void);

void cmd_free_mountinfo(struct silofs_proc_mntinfo *mi_list);

void cmd_trace_debug_info(void);

/* file-system environment */
void cmd_new_env(struct silofs_fs_env **pfse,
                 const struct silofs_fs_args *args);

void cmd_del_env(struct silofs_fs_env **pfse);

/* signals handling */
void cmd_register_sigactions(void (*sig_hook_fn)(int));

/* passphrase input */
void cmd_getpass(const char *path, char **out_pass);

void cmd_getpass2(const char *path, char **out_pass);

void cmd_delpass(char **pass);

#endif /* SILOFS_CMD_H_ */
