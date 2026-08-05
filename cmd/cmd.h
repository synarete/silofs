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
#ifndef SILOFS_CMD_H_
#define SILOFS_CMD_H_

#include <silofs/configs.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include <silofs/api.h>

typedef void (*silofs_subcmd_fn)(void);

/* sub-command descriptor */
struct cmd_info {
	const char      *name;
	silofs_subcmd_fn subcmd;
};

/* sub-command option descriptor */
struct cmd_optdesc {
	const char *lopt;
	int         sopt;
	int         has_arg;
};

#define CMD_OPTDESC(lopt_, sopt_, has_arg_) \
	{ .lopt = (lopt_), .sopt = (sopt_), .has_arg = (has_arg_) }

#define CMD_OPTDESC_LAST CMD_OPTDESC(nullptr, 0, 0)

/* internal getopt state */
struct cmd_getopt_info;

/* sub-command options and arguments */
struct cmd_optargs {
	struct cmd_getopt_info *opa_goi;
	char                  **opa_cmd_argv;
	int                     opa_cmd_argc;
	int                     opa_optind;
	int                     opa_optidx;
	int                     opa_opterr;
	char                   *opa_optarg;
	bool                    opa_done;
};

/* global settings */
struct cmd_globals {
	/* program's version string */
	const char *version;

	/* program short/full name */
	const char *name;
	const char *prog;

	/* program arguments */
	int    argc;
	char **argv;

	/* logging */
	struct silofs_log_params log_params;

	/* process ids */
	pid_t pid;
	uid_t uid;
	gid_t gid;

	/* process settings */
	bool developer_mode;
	bool allow_coredump;
	bool cap_sys_admin;
	bool dont_daemonize;

	/* signals info */
	int sig_halt;
	int sig_fatal;

	/* sub-command execution hook */
	const struct cmd_info *cmdi;
};

extern struct cmd_globals cmd_global_params;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* execution hooks */
void cmd_execute_mkfs(void);

void cmd_execute_mount(void);

void cmd_execute_umount(void);

void cmd_execute_show(void);

void cmd_execute_clone(void);

void cmd_execute_sync(void);

void cmd_execute_tune(void);

void cmd_execute_rmfs(void);

void cmd_execute_lsmnt(void);

void cmd_execute_prune(void);

void cmd_execute_fsck(void);

void cmd_execute_view(void);

/* options-arguments parsing via getopt */
void cmd_optargs_init(struct cmd_optargs *opa, const struct cmd_optdesc *ods);

void cmd_optargs_fini(struct cmd_optargs *opa);

int cmd_optargs_parse(struct cmd_optargs *opa);

char *cmd_optargs_getcurr(const struct cmd_optargs *opa);

char *cmd_optarg_getcurr2(const struct cmd_optargs *opa, const char *id);

char *cmd_optargs_getarg(struct cmd_optargs *opa, const char *arg_name);

char *cmd_optargs_getarg2(struct cmd_optargs *opa, const char *arg_name,
                          const char *default_val);

char *cmd_optargs_getpass(const struct cmd_optargs *opa);

bool cmd_optargs_curr_as_bool(const struct cmd_optargs *opa);

size_t cmd_optargs_curr_as_size(const struct cmd_optargs *opa);

uint32_t cmd_optargs_curr_as_u32v(const struct cmd_optargs *opa, uint32_t vmin,
                                  uint32_t vmax);

void cmd_optargs_endargs(const struct cmd_optargs *opa);

void cmd_optargs_set_loglevel(const struct cmd_optargs *opa);

void cmd_require_arg(const char *arg_name, const void *arg_val);

void cmd_require_arg_size(const char *arg_name, size_t val);

void cmd_atexit(void (*fn)(void));

/* fatal-error handling */

silofs_attr_dief(2, 0) void cmd_vdie(int     err, const char *restrict,
                                     va_list ap);

silofs_attr_dief(2, 3) void cmd_die(int err, const char *restrict, ...);

silofs_attr_dief(1, 2) void cmd_diez(const char *restrict, ...);

/* common utilities */

/* checkers */
void cmd_check_repopath(const char *arg_val);

void cmd_check_fsname(const char *fsname);

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

bool cmd_test_fusefs(const char *path);

void cmd_check_isreg(const char *path);

void cmd_check_isreg2(const char *dirpath, const char *name);

void cmd_check_reg_or_dir(const char *path);

void cmd_check_mntsrv_conn(void);

void cmd_check_mntsrv_perm(const char *path);

void cmd_mkdir(const char *path, mode_t mode);

void cmd_mkdirp(const char *path, mode_t mode);

void cmd_chdir(const char *path);

void cmd_realpath(const char *path, char **out_real);

void cmd_realpath_dir(const char *path, char **out_real);

void cmd_realpath_rdir(const char *path, char **out_real);

void cmd_stat_dir(const char *path, struct stat *st);

void cmd_daemonize_process(pid_t *out_pid);

void cmd_open_syslog(void);

void cmd_close_syslog(void);

void cmd_setup_coredump_mode(bool enable_coredump);

void cmd_set_log_level_by(const char *s);

void *cmd_zalloc(size_t n);

void cmd_zfree(void *ptr, size_t nbytes);

void cmd_strfree(char *s);

void cmd_pstrfree(char **pp);

char *cmd_strcat(const char *s1, const char *s2);

char *cmd_strcat3(const char *s1, const char *s2, const char *s3);

char *cmd_strdup(const char *s);

char *cmd_strndup(const char *s, size_t n);

char *cmd_strvdup(const void *p, size_t n);

silofs_attr_noreturn void cmd_print_help_and_exit(const char *help_strings);

/* path-name */
void cmd_path_split(const char *path, char **out_head, char **out_tail);

char *cmd_path_join(const char *dirpath, const char *name);

silofs_attr_printf(1, 2) char *cmd_path_fmt(const char *fmt, ...);

/* parse helpers */
size_t cmd_parse_str_as_size(const char *str);

uint32_t cmd_parse_str_as_u32(const char *str);

uint32_t cmd_parse_str_as_u32v(const char *str, uint32_t vmin, uint32_t vmax);

uid_t cmd_parse_str_as_uid(const char *str);

gid_t cmd_parse_str_as_gid(const char *str);

bool cmd_parse_str_as_bool(const char *str);

/* repo-dir & fsname */
void cmd_require_fsname(char **pfsname);

void cmd_resolve_repodir(const char *path, bool w_ok, char **out_real);

void cmd_resolve_mntpoint(const char *path, bool mnt, char **out_real);

/* locking facilities */
void cmd_fslock_acquirex(const char *repodir, const char *fsname, int *out_fd);

void cmd_fslock_acquire(const char *repodir, const char *fsname, int *out_fd);

void cmd_fslock_release(const char *repodir, const char *fsname, int *pfd);

/* API wrappers */
void cmd_format_repo(struct silofs_env *env);

void cmd_format_fs(struct silofs_env *env, struct silofs_fsref *out_fsref);

void cmd_sense_fs(struct silofs_env *env, const struct silofs_fsref *fsref);

void cmd_reload_fs(struct silofs_env *env, const struct silofs_fsref *fsref);

void cmd_unload_fs(struct silofs_env *env);

void cmd_exec_fs(struct silofs_env *env, const char *mntdir);

void cmd_fork_fs(struct silofs_env *env, struct silofs_fsrefs *out_fsrefs);

void cmd_remove_fs(struct silofs_env *env, const struct silofs_fsref *fsref);

void cmd_inspect_fs(struct silofs_env *env, bool view);

/* mount-info */
struct silofs_mntinfos *cmd_parse_mountinfo(void);

void cmd_free_mountinfo(struct silofs_mntinfos *mntinfos);

/* ioctl helpers */
union silofs_ioc_u *cmd_new_ioc(void);

void cmd_del_iocp(union silofs_ioc_u **pioc);

void cmd_reset_ioc(union silofs_ioc_u *ioc);

/* environment context */
void cmd_env_setup(const struct silofs_spec *spec, struct silofs_env **penv);

void cmd_env_destroy(struct silofs_env **p_env);

/* signals handling */
void cmd_register_sigactions(void (*sig_hook_fn)(int));

/* password input */
void cmd_getpass(const char *path, bool with_prompt, char **out_pass);

void cmd_getpass2(const char *path, bool with_prompt, char **out_pass);

void cmd_getpass_simple(bool no_prompt, char **out_pass);

char *cmd_duppass(const char *pass);

void cmd_delpass(char **pass);

void cmd_checkpass(const char *pass);

void cmd_mkpasswd(struct silofs_password *pw, const char *pass);

/* spec */
void cmd_spec_setup(struct silofs_spec *spec);

void cmd_spec_setup1(struct silofs_spec *spec, int flags);

void cmd_spec_setup2(struct silofs_spec *spec, size_t fs_capacity, int flags);

void cmd_spec_update_fsref(struct silofs_spec        *spec,
                           const struct silofs_fsref *fsref);

void cmd_spec_own_passwd(struct silofs_spec *spec, char **passwd);

void cmd_spec_set_baseref(struct silofs_spec *spec, const char *repodir,
                          const char *refname);

void cmd_spec_set_baseref2(struct silofs_spec *spec, const char *repodir,
                           const char *refname);

void cmd_spec_update_owner(struct silofs_spec *spec, const char *username,
                           bool with_sup_groups);

void cmd_spec_append_user(struct silofs_spec *spec, const char *username);

void cmd_spec_clear_fsids(struct silofs_spec *spec);

void cmd_spec_need_self(const struct silofs_spec *spec);

void cmd_spec_reset(struct silofs_spec *spec);

void cmd_spec_jsave(const struct silofs_spec *spec);

void cmd_spec_jsave2(const struct silofs_spec *spec);

void cmd_spec_jload(struct silofs_spec *spec);

void cmd_spec_jload2(struct silofs_spec *spec);

void cmd_spec_junlink(const struct silofs_spec *spec);

/* security restrictions (landlock) */
void cmd_restrict_process(const char *path, bool allow_mkdir);

/* misc */
void cmd_trace_versions(void);

char *cmd_getusername(void);

#endif /* SILOFS_CMD_H_ */
