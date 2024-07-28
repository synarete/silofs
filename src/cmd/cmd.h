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

typedef void (*silofs_exec_fn)(void);

/* sub-command descriptor */
struct cmd_info {
	const char *name;
	silofs_exec_fn action_hook;
};

/* sub-command option descriptor */
struct cmd_optdesc {
	const char *lopt;
	char sopt;
	int has_arg;
};

/* internal getopt state */
struct cmd_getopt_info;

/* sub-command options and arguments */
struct cmd_optargs {
	struct cmd_getopt_info *opa_goi;
	char      **opa_cmd_argv;
	int         opa_cmd_argc;
	int         opa_optind;
	int         opa_optidx;
	int         opa_opterr;
	char       *opa_optarg;
	bool        opa_done;
};

/* global settings */
struct cmd_globals {
	/* program's version string */
	const char *version;

	/* program short/full name */
	const char *name;
	const char *prog;

	/* program arguments */
	int     argc;
	char  **argv;

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

void cmd_execute_archive(void);

void cmd_execute_restore(void);

/* options-arguments parsing via getopt */
void cmd_optargs_init(struct cmd_optargs *opa, const struct cmd_optdesc *ods);

void cmd_optargs_fini(struct cmd_optargs *opa);

int cmd_optargs_parse(struct cmd_optargs *opa);

char *cmd_optargs_dupcurr(const struct cmd_optargs *opa);

char *cmd_optarg_dupoptarg(const struct cmd_optargs *opa, const char *id);

char *cmd_optargs_getarg(struct cmd_optargs *opa, const char *arg_name);

char *cmd_optargs_getarg2(struct cmd_optargs *opa,
                          const char *arg_name, const char *default_val);

char *cmd_optargs_getpass(const struct cmd_optargs *opa);

bool cmd_optargs_curr_as_bool(const struct cmd_optargs *opa);

long cmd_optargs_curr_as_size(const struct cmd_optargs *opa);

uint32_t cmd_optargs_curr_as_u32v(const struct cmd_optargs *opa,
                                  uint32_t vmin, uint32_t vmax);

void cmd_optargs_endargs(const struct cmd_optargs *opa);

void cmd_optargs_set_loglevel(const struct cmd_optargs *opa);


void cmd_require_arg(const char *arg_name, const void *arg_val);

void cmd_require_arg_size(const char *arg_name, long val);

/* fatal-error handling */
__attribute__((__noreturn__))
void cmd_die(int errnum, const char *restrict fmt, ...);

/* common utilities */

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

char *cmd_struuid(const uint8_t uu[16]);

char *cmd_mkpathf(const char *fmt, ...);

__attribute__((__noreturn__))
void cmd_print_help_and_exit(const char **help_strings);

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
void cmd_format_repo(struct silofs_fsenv *fsenv);

void cmd_open_repo(struct silofs_fsenv *fsenv);

void cmd_close_repo(struct silofs_fsenv *fsenv);

void cmd_format_fs(struct silofs_fsenv *fsenv, struct silofs_fs_bref *bref);

void cmd_close_fs(struct silofs_fsenv *fsenv);

void cmd_poke_fs(struct silofs_fsenv *fsenv,
                 const struct silofs_fs_bref *bref);

void cmd_poke_archive(struct silofs_fsenv *fsenv,
                      const struct silofs_fs_bref *bref);

void cmd_boot_fs(struct silofs_fsenv *fsenv,
                 const struct silofs_fs_bref *bref);

void cmd_open_fs(struct silofs_fsenv *fsenv);

void cmd_exec_fs(struct silofs_fsenv *fsenv);

void cmd_fork_fs(struct silofs_fsenv *fsenv,
                 struct silofs_caddr *out_new, struct silofs_caddr *out_alt);

void cmd_unref_fs(struct silofs_fsenv *fsenv,
                  const struct silofs_fs_bref *bconf);

void cmd_inspect_fs(struct silofs_fsenv *fsenv,
                    silofs_visit_laddr_fn cb, void *user_ctx);

void cmd_archive_fs(struct silofs_fsenv *fsenv,
                    struct silofs_caddr *out_caddr);

void cmd_restore_fs(struct silofs_fsenv *fsenv,
                    struct silofs_caddr *out_caddr);

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

/* boot-reference */
void cmd_bootref_load(struct silofs_fs_bref *bref);

void cmd_bootref_load_ar(struct silofs_fs_bref *bref);

void cmd_bootref_save(const struct silofs_fs_bref *bref);

void cmd_bootref_resave(const struct silofs_fs_bref *bref,
                        const struct silofs_caddr *caddr,
                        const char *newname);

void cmd_bootref_unlink(const struct silofs_fs_bref *bref);

/* fs input arguments */
void cmd_fs_args_init(struct silofs_fs_args *fs_args);

void cmd_fs_args_init2(struct silofs_fs_args *fs_args,
                       const struct silofs_fs_cflags *fs_cflags);

void cmd_fini_fs_args(struct silofs_fs_args *fs_args);

/* fs-ids config */
void cmd_fs_ids_unlinkat(const char *basedir);

void cmd_fs_ids_init(struct silofs_fs_ids *ids);

void cmd_fs_ids_fini(struct silofs_fs_ids *ids);

void cmd_fs_ids_assign(struct silofs_fs_ids *ids,
                       const struct silofs_fs_ids *other);

void cmd_fs_ids_reset(struct silofs_fs_ids *ids);

void cmd_fs_ids_load(struct silofs_fs_ids *ids, const char *basedir);

void cmd_fs_ids_save(const struct silofs_fs_ids *ids, const char *basedir);

void cmd_fs_ids_add_user(struct silofs_fs_ids *ids,
                         const char *user, bool with_sup_groups);

/* users/groups */
char *cmd_getpwuid(uid_t uid);

char *cmd_getusername(void);

void cmd_resolve_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid);

void cmd_require_uidgid(const struct silofs_fs_ids *ids,
                        const char *name, uid_t *out_uid, gid_t *out_gid);

/* misc */
void cmd_trace_versions(void);

#endif /* SILOFS_CMD_H_ */
