/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

void cmd_execute_sync(void);

void cmd_execute_rmfs(void);

void cmd_execute_lsmnt(void);

void cmd_execute_prune(void);

void cmd_execute_fsck(void);

/* fatal-error handling */
__attribute__((__noreturn__))
void cmd_dief(int errnum, const char *restrict fmt, ...);

__attribute__((__noreturn__))
void cmd_fatal_unsupported_opt(void);


/* common utilities */
void cmd_require_arg(const char *arg_name, const void *arg_val);

void cmd_check_repopath(const char *arg_val);

void cmd_check_fsname(const char *arg_val);

void cmd_check_notdir(const char *path);

void cmd_check_notexists(const char *path);

void cmd_check_notexists2(const char *path, const char *name);

void cmd_check_exists(const char *path);

void cmd_check_not_same(const char *path, const char *other);

void cmd_check_isdir(const char *path, bool w_ok);

void cmd_check_nonemptydir(const char *path, bool w_ok);

void cmd_check_emptydir(const char *path, bool w_ok);

void cmd_check_mntdir(const char *path, bool mount);

void cmd_check_fusefs(const char *path);

void cmd_check_isreg(const char *path, bool w_ok);

void cmd_check_reg_or_dir(const char *path);

void cmd_check_mntsrv_conn(void);

void cmd_check_mntsrv_perm(const char *path);

void cmd_mkdir(const char *path, mode_t mode);

void cmd_getoptarg(const char *opt_name, char **out_opt);

void cmd_getarg(const char *arg_name, char **out_arg);

void cmd_getarg_or_cwd(const char *arg_name, char **out_arg);

int cmd_getopt(const char *sopts, const struct option *lopts);

void cmd_endargs(void);

void cmd_realpath(const char *path, char **out_real);

void cmd_stat_reg(const char *path, struct stat *st);

void cmd_stat_dir(const char *path, struct stat *st);

void cmd_split_path(const char *path, char **out_head, char **out_tail);

void cmd_remake_path(const char *path, const char *suffix,
                     char **out_head, char **out_tail);

void cmd_remake_path2(const char *path, const char *suffix,
                      char **out_head, char **out_tail);

void cmd_join_path(const char *dirpath, const char *name, char **out_path);

void cmd_fork_daemon(pid_t *out_pid);

void cmd_open_syslog(void);

void cmd_close_syslog(void);

void cmd_setrlimit_nocore(void);

void cmd_set_verbose_mode(const char *mode);

void *cmd_zalloc(size_t n);

void cmd_zfree(void *ptr, size_t nbytes);

void cmd_pstrfree(char **pp);

char *cmd_strdup(const char *s);

char *cmd_strndup(const char *s, size_t n);

char *cmd_mkpathf(const char *fmt, ...);

__attribute__((__noreturn__))
void cmd_print_help_and_exit(const char **help_strings);

/* parse helpers */
long cmd_parse_str_as_size(const char *str);

uid_t cmd_parse_str_as_uid(const char *str);

gid_t cmd_parse_str_as_gid(const char *str);

bool cmd_parse_str_as_bool(const char *str);

/* locking facilities */
void cmd_lockf(const char *dirpath, const char *name, int *out_fd);

bool cmd_trylockf(const char *dirpath, const char *name, int *out_fd);

void cmd_unlockf(int *pfd);

/* complex fs operations */
void cmd_init_fs_args(struct silofs_fs_args *fs_args);

void cmd_format_repo(struct silofs_fs_env *fse);

void cmd_open_repo(struct silofs_fs_env *fse);

void cmd_close_repo(struct silofs_fs_env *fse);

void cmd_format_fs(struct silofs_fs_env *fse, struct silofs_uuid *out_uuid);

void cmd_close_fs(struct silofs_fs_env *fse);

void cmd_require_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid);

void cmd_boot_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid);

void cmd_open_fs(struct silofs_fs_env *fse);

void cmd_exec_fs(struct silofs_fs_env *fse);

void cmd_fork_fs(struct silofs_fs_env *fse,
                 struct silofs_uuid *out_uuid1, struct silofs_uuid *out_uuid2);

void cmd_unref_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid);

void cmd_inspect_fs(struct silofs_fs_env *fse);


/* extra utilities */
struct cmd_proc_mntinfo {
	struct cmd_proc_mntinfo *next;
	const char *mntdir;
	const char *mntargs;
	size_t msz;
};

struct cmd_proc_mntinfo *cmd_parse_mountinfo(void);

void cmd_free_mountinfo(struct cmd_proc_mntinfo *mi_list);

void cmd_trace_debug_info(void);

/* file-system environment */
void cmd_new_env(struct silofs_fs_env **pfse,
                 const struct silofs_fs_args *args);

void cmd_del_env(struct silofs_fs_env **pfse);

/* signals handling */
void cmd_register_sigactions(void (*sig_hook_fn)(int));

/* password input */
void cmd_getpass(const char *path, char **out_pass);

void cmd_getpass2(const char *path, char **out_pass);

void cmd_delpass(char **pass);

/* init configuration */
void cmd_iconf_init(struct silofs_iconf *iconf);

void cmd_iconf_clone(struct silofs_iconf *iconf,
                     const struct silofs_iconf *other);

void cmd_iconf_reset(struct silofs_iconf *iconf);

void cmd_iconf_setname(struct silofs_iconf *iconf, const char *name);

void cmd_iconf_setuuid(struct silofs_iconf *iconf,
                       const struct silofs_uuid *uuid);

void cmd_iconf_add_user(struct silofs_iconf *iconf,
                        const char *user, bool with_sup_groups);

void cmd_iconf_load(struct silofs_iconf *iconf, const char *repodir);

void cmd_iconf_save(const struct silofs_iconf *iconf, const char *repodir);

void cmd_iconf_unlink(const struct silofs_iconf *iconf, const char *repodir);


char *cmd_getlogin(void);

void cmd_resolve_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid);

#endif /* SILOFS_CMD_H_ */
