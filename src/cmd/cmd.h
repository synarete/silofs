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
#ifndef SILOFS_CMD_H_
#define SILOFS_CMD_H_

#include <silofs/libsilofs.h>
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

	/* logging */
	struct silofs_log_params log_params;

	/* process ids */
	pid_t   pid;
	uid_t   uid;
	gid_t   gid;
	mode_t  umsk;

	/* common process settings */
	bool    dont_daemonize;
	bool    allow_coredump;

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

void cmd_execute_tune(void);

void cmd_execute_rmfs(void);

void cmd_execute_lsmnt(void);

void cmd_execute_prune(void);

void cmd_execute_fsck(void);

void cmd_execute_view(void);

void cmd_execute_pack(void);

void cmd_execute_unpack(void);

/* fatal-error handling */
__attribute__((__noreturn__))
void cmd_dief(int errnum, const char *restrict fmt, ...);

/* common utilities */
void cmd_require_arg(const char *arg_name, const void *arg_val);

void cmd_check_repopath(const char *arg_val);

void cmd_check_fsname(const char *arg_val);

void cmd_check_repodir(const char *path);

void cmd_check_repodir_fsname(const char *basedir, const char *fsname);

void cmd_check_notdir(const char *path);

void cmd_check_notexists(const char *path);

void cmd_check_notexists2(const char *path, const char *name);

void cmd_check_exists(const char *path);

void cmd_check_not_same(const char *path, const char *other);

void cmd_check_nonemptydir(const char *path, bool w_ok);

void cmd_check_emptydir(const char *path, bool w_ok);

void cmd_check_mntdir(const char *path, bool mount);

void cmd_check_fusefs(const char *path);

void cmd_check_isreg(const char *path);

void cmd_check_isreg2(const char *dirpath, const char *name);

void cmd_check_reg_or_dir(const char *path);

void cmd_check_mntsrv_conn(void);

void cmd_check_mntsrv_perm(const char *path);

void cmd_mkdir(const char *path, mode_t mode);

void cmd_getoptarg(const char *opt_name, char **out_opt);

void cmd_getoptarg_pass(char **out_pass);

void cmd_getarg_or_cwd(const char *arg_name, char **out_arg);

void cmd_realpath(const char *path, char **out_real);

void cmd_realpath_dir(const char *path, char **out_real);

void cmd_realpath_rdir(const char *path, char **out_real);

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

void cmd_setup_coredump_mode(bool enable_coredump);

void cmd_set_log_level_by(const char *s);

void *cmd_zalloc(size_t n);

void cmd_zfree(void *ptr, size_t nbytes);

void cmd_pstrfree(char **pp);

char *cmd_strdup(const char *s);

char *cmd_strndup(const char *s, size_t n);

char *cmd_mkpathf(const char *fmt, ...);

__attribute__((__noreturn__))
void cmd_print_help_and_exit(const char **help_strings);

/* getopt wrappers */
int cmd_getopt(const char *sopts, const struct option *lopts);

void cmd_getopt_endargs(void);

void cmd_getopt_getarg(const char *arg_name, char **out_arg);

__attribute__((__noreturn__))
void cmd_getopt_unrecognized(void);

/* parse helpers */
long cmd_parse_str_as_size(const char *str);

uint32_t cmd_parse_str_as_u32(const char *str);

uint32_t cmd_parse_str_as_u32v(const char *str, uint32_t vmin, uint32_t vmax);

uid_t cmd_parse_str_as_uid(const char *str);

gid_t cmd_parse_str_as_gid(const char *str);

bool cmd_parse_str_as_bool(const char *str);

/* locking facilities */

void cmd_lock_fs(const char *repodir, const char *name);

void cmd_unlock_fs(const char *repodir, const char *name);


void cmd_wrlock_repo(const char *repodir, int *pfd);

void cmd_rdlock_repo(const char *repodir, int *pfd);

void cmd_unlock_repo(const char *repodir, int *pfd);


/* complex fs operations */
void cmd_init_fs_args(struct silofs_fs_args *fs_args);

void cmd_format_repo(struct silofs_fsenv *fsenv);

void cmd_open_repo(struct silofs_fsenv *fsenv);

void cmd_close_repo(struct silofs_fsenv *fsenv);

void cmd_format_fs(struct silofs_fsenv *fsenv, struct silofs_fs_bconf *bconf);

void cmd_close_fs(struct silofs_fsenv *fsenv);

void cmd_require_fs(struct silofs_fsenv *fsenv,
                    const struct silofs_fs_bconf *bconf);

void cmd_boot_fs(struct silofs_fsenv *fsenv,
                 const struct silofs_fs_bconf *bconf);

void cmd_open_fs(struct silofs_fsenv *fsenv);

void cmd_exec_fs(struct silofs_fsenv *fsenv);

void cmd_fork_fs(struct silofs_fsenv *fsenv,
                 struct silofs_caddr *out_new, struct silofs_caddr *out_alt);

void cmd_unref_fs(struct silofs_fsenv *fsenv,
                  const struct silofs_fs_bconf *bconf);

void cmd_inspect_fs(struct silofs_fsenv *fsenv,
                    silofs_visit_laddr_fn cb, void *user_ctx);

void cmd_pack_fs(struct silofs_fsenv *fsenv, struct silofs_caddr *out_caddr);

void cmd_unpack_fs(struct silofs_fsenv *fsenv,
                   const struct silofs_caddr *caddr);

/* mount-info */
struct cmd_proc_mntinfo {
	struct cmd_proc_mntinfo *next;
	const char *mntdir;
	const char *mntargs;
	size_t msz;
};

struct cmd_proc_mntinfo *cmd_parse_mountinfo(void);

void cmd_free_mountinfo(struct cmd_proc_mntinfo *mi_list);

/* ioctl helpers */
union silofs_ioc_u *cmd_new_ioc(void);

void cmd_del_iocp(union silofs_ioc_u **pioc);

void cmd_reset_ioc(union silofs_ioc_u *ioc);

/* misc */
void cmd_trace_versions(void);

/* file-system environment */
void cmd_new_fsenv(const struct silofs_fs_args *fs_args,
                   struct silofs_fsenv **p_fsenv);

void cmd_del_fsenv(struct silofs_fsenv **p_fsenv);

/* signals handling */
void cmd_register_sigactions(void (*sig_hook_fn)(int));

/* password input */
void cmd_getpass(const char *path, bool with_prompt, char **out_pass);

void cmd_getpass2(const char *path, bool with_prompt, char **out_pass);

void cmd_getpass_simple(bool no_prompt, char **out_pass);

char *cmd_duppass(const char *pass);

void cmd_delpass(char **pass);

/* init configuration */
void cmd_bconf_init(struct silofs_fs_bconf *bconf);

void cmd_bconf_fini(struct silofs_fs_bconf *bconf);

void cmd_bconf_reset_ids(struct silofs_fs_bconf *bconf);

void cmd_bconf_assign(struct silofs_fs_bconf *bconf,
                      const struct silofs_fs_bconf *other);

void cmd_bconf_set_boot_ref(struct silofs_fs_bconf *bconf,
                            const struct silofs_caddr *caddr);

void cmd_bconf_set_pack_ref(struct silofs_fs_bconf *bconf,
                            const struct silofs_caddr *caddr);

void cmd_bconf_set_name(struct silofs_fs_bconf *bconf, const char *name);

void cmd_bconf_add_user(struct silofs_fs_bconf *bconf,
                        const char *user, bool with_sup_groups);

void cmd_bconf_load(struct silofs_fs_bconf *bconf,
                    const char *basedir);

void cmd_bconf_save(const struct silofs_fs_bconf *bconf,
                    const char *basedir);

void cmd_bconf_save_rdonly(const struct silofs_fs_bconf *bconf,
                           const char *basedir);

void cmd_bconf_unlink(const struct silofs_fs_bconf *bconf,
                      const char *basedir);


char *cmd_getpwuid(uid_t uid);

char *cmd_getusername(void);

void cmd_resolve_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid);

#endif /* SILOFS_CMD_H_ */
