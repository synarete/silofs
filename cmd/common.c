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
#include <silofs/cmd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <dirent.h>
#include <locale.h>
#include <getopt.h>


#define SILOFS_LOG_DEFAULT  \
	(SILOFS_LOG_WARN  | \
	 SILOFS_LOG_ERROR | \
	 SILOFS_LOG_CRIT  | \
	 SILOFS_LOG_STDOUT)

/* Global process' variables */
struct silofs_globals silofs_globals;

__attribute__((__noreturn__))
void silofs_die_missing_arg(const char *s)
{
	silofs_die(0, "missing argument: %s", s);
}

__attribute__((__noreturn__))
void silofs_die_redundant_arg(const char *s)
{
	silofs_die(0, "redundant argument: %s", s);
}

__attribute__((__noreturn__))
void silofs_die_unsupported_opt(void)
{
	exit(EXIT_FAILURE);
}

void silofs_die_if_missing_arg(const char *arg_name, const void *arg_val)
{
	if (arg_val == NULL) {
		silofs_die_missing_arg(arg_name);
	}
}

static void silofs_die_if_redundant_arg(void)
{
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	if (optind < argc) {
		silofs_die_redundant_arg(argv[optind]);
	}
}

void silofs_die_if_illegal_fsname(const char *arg_name, const char *arg_val)
{
	struct silofs_namestr nstr;
	int err;

	silofs_namestr_init(&nstr, arg_val);
	err = silofs_check_fs_name(&nstr);
	if (err) {
		silofs_die(err, "illegal %s: %s",
		           arg_name ? arg_name : "name", arg_val);
	}
}

void silofs_die_if_not_dir(const char *path, bool w_ok)
{
	int err;
	struct stat st;
	int access_mode = R_OK | X_OK | (w_ok ? W_OK : 0);

	silofs_cmd_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		silofs_die(-ENOTDIR, "illegal dir-path: %s", path);
	}
	err = silofs_sys_access(path, access_mode);
	if (err) {
		silofs_die(err, "no-access: %s", path);
	}
}

void silofs_die_if_not_reg(const char *path, bool w_ok)
{
	int err;
	struct stat st;
	int access_mode = R_OK | (w_ok ? W_OK : 0);

	silofs_cmd_stat_ok(path, &st);
	if (S_ISDIR(st.st_mode)) {
		silofs_die(-EISDIR, "illegal: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		silofs_die(0, "not reg: %s", path);
	}
	err = silofs_sys_access(path, access_mode);
	if (err) {
		silofs_die(err, "no-access: %s", path);
	}
}

void silofs_die_if_not_dir_or_reg(const char *path)
{
	struct stat st;

	silofs_cmd_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
		silofs_die(-ENOTDIR, "not dir-or-reg: %s", path);
	}
}

void silofs_die_if_exists(const char *path)
{
	int err;
	struct stat st;

	err = silofs_sys_stat(path, &st);
	if (!err) {
		if (S_ISDIR(st.st_mode)) {
			silofs_die(0, "directory exists: %s", path);
		} else {
			silofs_die(0, "path exists: %s", path);
		}
	}
	if (err != -ENOENT) {
		silofs_die(err, "stat failure: %s", path);
	}
}

void silofs_die_if_no_mountd(void)
{
	int err;
	const char *sock = SILOFS_MNTSOCK_NAME;

	err = silofs_rpc_handshake(getuid(), getgid());
	if (err) {
		silofs_die(err, "failed to handshake with mountd: "
		           "sock=@%s", sock);
	}
}

void silofs_die_if_not_dir_or_empty(const char *path, bool w_ok)
{
	int err;
	int dfd = -1;
	size_t ndes = 0;
	struct dirent64 de[8];
	const size_t nde = SILOFS_ARRAY_SIZE(de);
	char buf[1024] = "";

	silofs_die_if_not_dir(path, w_ok);
	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "open-dir error: %s", path);
	}
	err = silofs_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		silofs_die(err, "read dir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		silofs_die(err, "close-dir error: %s", path);
	}
	if (ndes <= 2) {
		silofs_die(0, "an empty directory: %s", path);
	}
}

void silofs_die_if_not_empty_dir(const char *path, bool w_ok)
{
	int err;
	int dfd = -1;
	size_t ndes = 0;
	struct dirent64 de[8];
	const size_t nde = SILOFS_ARRAY_SIZE(de);
	char buf[1024] = "";

	silofs_die_if_not_dir(path, w_ok);
	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "open-dir error: %s", path);
	}
	err = silofs_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		silofs_die(err, "read dir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		silofs_die(err, "close-dir error: %s", path);
	}
	if (ndes > 2) {
		silofs_die(0, "not an empty directory: %s", path);
	}
}

void silofs_die_if_not_mkdir(const char *path, mode_t mode)
{
	int err;

	err = silofs_sys_mkdir(path, mode);
	if (err) {
		silofs_die(err, "mkdir failed: %s", path);
	}
}

static void silofs_access_ok(const char *path)
{
	int err;

	err = silofs_sys_access(path, R_OK);
	if (err == -ENOENT) {
		silofs_die(err, "no such path: %s", path);
	}
	if (err) {
		silofs_die(err, "no access: %s uid=%d gid=%d",
		           path, getuid(), getgid());
	}
}

static void silofs_statfs_ok(const char *path, struct statfs *stfs)
{
	int err;

	silofs_access_ok(path);
	err = silofs_sys_statfs(path, stfs);
	if (err) {
		silofs_die(err, "statfs failure: %s", path);
	}
}

void silofs_die_if_not_mntdir(const char *path, bool mount)
{
	long fstype;
	struct stat st;
	struct statfs stfs;
	const struct silofs_fsinfo *fsi = NULL;


	if (strlen(path) >= SILOFS_MNTPATH_MAX) {
		silofs_die(0, "illegal mount-path length: %s", path);
	}
	silofs_die_if_not_dir(path, mount);

	if (mount) {
		silofs_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi = silofs_fsinfo_by_vfstype(fstype);
		if (fsi == NULL) {
			silofs_die(0, "unknown fstype at: "
			           "%s fstype=0x%lx", path, fstype);
		}
		if (fsi->isfuse) {
			silofs_die(0, "can not mount over FUSE file-system: "
			           "%s fstype=0x%lx", path, fstype);
		}
		if (!fsi->allowed) {
			silofs_die(0, "not allowed to mount over: "
			           "%s fstype=0x%lx", path, fstype);
		}
		silofs_die_if_not_empty_dir(path, true);
	} else {
		silofs_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi = silofs_fsinfo_by_vfstype(fstype);
		if (fsi == NULL) {
			silofs_die(0, "unknown fstype at: "
			           "%s fstype=0x%lx", path, fstype);
		}
		if (!fsi->isfuse) {
			silofs_die(0, "not a FUSE file-system: %s", path);
		}
		silofs_cmd_stat_ok(path, &st);
		if (st.st_ino != SILOFS_INO_ROOT) {
			silofs_die(0, "not a silofs mount-point: %s", path);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_require_valid_fsname(const char *arg_name, char **p_fsname)
{
	if (*p_fsname == NULL) {
		*p_fsname = silofs_cmd_strdup(SILOFS_FSNAME_DEFAULT);
	} else {
		silofs_die_if_illegal_fsname(arg_name, *p_fsname);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cmd_endargs(void)
{
	silofs_die_if_redundant_arg();
}

void silofs_cmd_getarg(const char *arg_name, char **out_arg)
{
	char *arg = NULL;
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	arg = argv[optind];
	if ((optind >= argc) || (arg == NULL)) {
		silofs_die_missing_arg(arg_name);
	}
	optind++;
	*out_arg = silofs_cmd_strdup(arg);
}

void silofs_cmd_getarg_or_cwd(const char *arg_name, char **out_arg)
{
	char *arg = NULL;
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	arg = argv[optind];
	if ((optind >= argc) || (arg == NULL)) {
		arg = get_current_dir_name();
		if (arg == NULL) {
			silofs_die(errno, "no arg '%s' and failed to get "
			           "current working directory", arg_name);
		}
	}
	optind++;
	*out_arg = silofs_cmd_strdup(arg);
}

int silofs_cmd_getopt(const char *sopts, const struct option *lopts)
{
	int opt_index = 0;
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	return getopt_long(argc, argv, sopts, lopts, &opt_index);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long silofs_cmd_parse_size(const char *str)
{
	long mul = 0;
	char *endptr = NULL;
	long double val;
	long double iz;

	errno = 0;
	val = strtold(str, &endptr);
	if ((endptr == str) || (errno == ERANGE) || isnan(val)) {
		goto illegal_value;
	}
	if (strlen(endptr) > 1) {
		goto illegal_value;
	}
	switch (toupper(*endptr)) {
	case 'K':
		mul = SILOFS_KILO;
		break;
	case 'M':
		mul = SILOFS_MEGA;
		break;
	case 'G':
		mul = SILOFS_GIGA;
		break;
	case 'T':
		mul = SILOFS_TERA;
		break;
	case 'P':
		mul = SILOFS_PETA;
		break;
	case '\0':
		mul = 1;
		break;
	default:
		goto illegal_value;
	}
	modfl(val, &iz);
	if ((iz < 0.0F) || isnan(iz)) {
		goto illegal_value;
	}
	return (long)(val * (long double)mul);

illegal_value:
	silofs_die(0, "illegal value: %s", str);
	return -EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0014: Dance with systemd upon logout
 *
 * May need to call 'loginctl enable-linger username' if we want daemon to
 * stay alive after login. Need more investigating.
 */
static void silofs_daemonize(void)
{
	int err;

	err = daemon(0, 1);
	if (err) {
		silofs_die(0, "failed to daemonize");
	}
	silofs_globals.log_mask |= SILOFS_LOG_SYSLOG;
	silofs_globals.log_mask &= ~SILOFS_LOG_STDOUT;

	/*
	 * TODO-0024: No fd=0
	 *
	 * Ensure that next allocated fd is positive (non-zero) or bad things
	 * may happen in various places where code assumes (fd > 0).
	 */
}

void silofs_fork_daemon(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		silofs_die(errno, "fork error");
	}
	if (pid == 0) {
		silofs_daemonize();
	}
}

void silofs_open_syslog(void)
{
	silofs_globals.log_mask |= SILOFS_LOG_SYSLOG;
	openlog(silofs_globals.name, LOG_CONS | LOG_NDELAY, 0);
}

void silofs_close_syslog(void)
{
	if (silofs_globals.log_mask & SILOFS_LOG_SYSLOG) {
		closelog();
		silofs_globals.log_mask &= ~SILOFS_LOG_SYSLOG;
	}
}

void silofs_setrlimit_nocore(void)
{
	int err;
	struct rlimit rlim = { .rlim_cur = 0, .rlim_max = 0 };

	err = silofs_sys_setrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		silofs_die(err, "failed to disable core-dupms");
	}
}

void silofs_prctl_non_dumpable(void)
{
	int err;

	err = silofs_sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (err) {
		silofs_die(err, "failed to prctl non-dumpable");
	}
}

char *silofs_cmd_realpath(const char *path)
{
	char *real_path;

	real_path = realpath(path, NULL);
	if (real_path == NULL) {
		silofs_die(-errno, "realpath failure: '%s'", path);
	}
	return real_path;
}

void silofs_cmd_stat_ok(const char *path, struct stat *st)
{
	int err;
	mode_t mode;

	silofs_access_ok(path);

	err = silofs_sys_stat(path, st);
	if (err) {
		silofs_die(err, "stat failure: %s", path);
	}
	mode = st->st_mode;
	if (!S_ISREG(mode) && !S_ISDIR(mode) && !S_ISBLK(mode)) {
		silofs_die(0, "unsupported mode: 0%o %s", mode, path);
	}
}

void silofs_cmd_stat_reg(const char *path, struct stat *st)
{
	silofs_cmd_stat_ok(path, st);
	if (!S_ISREG(st->st_mode)) {
		silofs_die(0, "not a regular file: %s", path);
	}
}

void silofs_cmd_stat_reg_or_dir(const char *path, struct stat *st)
{
	silofs_cmd_stat_ok(path, st);
	if (!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode)) {
		silofs_die(0, "not dir-or-reg: %s", path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *silofs_cmd_zalloc(size_t nbytes)
{
	int err;
	void *mem = NULL;

	err = silofs_zmalloc(nbytes, &mem);
	if (err) {
		silofs_die(-err, "alloc failed: nbytes=%lu", nbytes);
	}
	return mem;
}

void silofs_cmd_zfree(void *ptr, size_t nbytes)
{
	if (ptr != NULL) {
		silofs_zfree(ptr, nbytes);
	}
}

void silofs_cmd_pfrees(char **pp)
{
	if (*pp != NULL) {
		free(*pp);
		*pp = NULL;
	}
}

char *silofs_cmd_strdup(const char *s)
{
	char *d = strdup(s);

	if (d == NULL) {
		silofs_die(errno, "strdup failed");
	}
	return d;
}

char *silofs_cmd_strndup(const char *s, size_t n)
{
	char *d = strndup(s, n);

	if (d == NULL) {
		silofs_die(errno, "strndup failed: n=%lu", n);
	}
	return d;
}

char *silofs_cmd_mkpathf(const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t path_size = PATH_MAX;
	char *path = silofs_cmd_zalloc(path_size);
	char *path_dup;

	va_start(ap, fmt);
	n = vsnprintf(path, path_size - 1, fmt, ap);
	va_end(ap);

	if (n >= (int)path_size) {
		silofs_die(0, "illegal path-len %d", n);
	}
	path_dup = silofs_cmd_strdup(path);
	silofs_cmd_pfrees(&path);
	return path_dup;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Singleton instance */
static struct silofs_fs_env *g_fs_env_inst;

static void silofs_require_no_inst(const void *inst)
{
	if (inst != NULL) {
		silofs_die(0, "internal error: singleton already at %p", inst);
	}
}

void silofs_create_fse_inst(const struct silofs_fs_args *args)
{
	int err;

	silofs_require_no_inst(g_fs_env_inst);
	err = silofs_fse_new(args, &g_fs_env_inst);
	if (err) {
		silofs_die(err, "failed to create instance");
	}
}

void silofs_destroy_fse_inst(void)
{
	if (g_fs_env_inst) {
		silofs_fse_del(g_fs_env_inst);
		g_fs_env_inst = NULL;
		silofs_burnstack();
	}
}

struct silofs_fs_env *silofs_fse_inst(void)
{
	return g_fs_env_inst;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void show_help_strings(FILE *fp, const char *name,
                              const char **help_strings)
{
	size_t idx = 0;
	const char *help_string = NULL;
	bool with_name = (name != NULL) && strlen(name);

	help_string = help_strings[idx++];
	while (help_string != NULL) {
		if (with_name && !strlen(help_string)) {
			with_name = false;
		}
		if (with_name) {
			fprintf(fp, "%s %s\n", name, help_string);
		} else {
			fprintf(fp, "%s\n", help_string);
		}
		help_string = help_strings[idx++];
	}
	fputs("\n", fp);
	fflush(fp);
}

void silofs_print_help_and_exit(const char **help_strings)
{
	const char *prefix = silofs_globals.name;

	show_help_strings(stdout, prefix, help_strings);
	exit(EXIT_SUCCESS);
}

void silofs_print_version_and_exit(const char *prog)
{
	fprintf(stdout, "%s %s\n",
	        (prog != NULL) ? prog : "silofs", silofs_globals.version);
	exit(0);
}

static void silofs_atexit_flush(void)
{
	fflush(stdout);
	fflush(stderr);
}

static void silofs_error_print_progname(void)
{
	FILE *fp = stderr;
	const char *name = silofs_globals.name;
	const char *subcmd = silofs_globals.cmd_name;

	if (subcmd && (subcmd[0] != '-')) {
		fprintf(fp, "%s %s: ", name, subcmd);
	} else {
		fprintf(fp, "%s: ", name);
	}
	fflush(fp);
}

void silofs_setup_globals(int argc, char *argv[])
{
	SILOFS_STATICASSERT_LT(sizeof(silofs_globals), 1024);

	silofs_globals.version = silofs_version.string;
	silofs_globals.name = program_invocation_short_name;
	silofs_globals.prog = program_invocation_name;
	silofs_globals.argc = argc;
	silofs_globals.argv = argv;
	silofs_globals.cmd_argc = argc;
	silofs_globals.cmd_argv = argv;
	silofs_globals.cmd_name = NULL;
	silofs_globals.pid = getpid();
	silofs_globals.uid = getuid();
	silofs_globals.gid = getgid();
	silofs_globals.umsk = 0022;
	silofs_globals.start_time = time(NULL);
	silofs_globals.dont_daemonize = false;
	silofs_globals.allow_coredump = false;
	silofs_globals.disable_ptrace = true; /* XXX */
	silofs_globals.log_mask = SILOFS_LOG_DEFAULT;

	umask(silofs_globals.umsk);
	setlocale(LC_ALL, "");
	atexit(silofs_atexit_flush);
	error_print_progname = silofs_error_print_progname;
}

static void silofs_resolve_caps(void)
{
	int err = 1;
	pid_t pid;
	cap_t cap;
	cap_flag_value_t flag = CAP_CLEAR;

	pid = getpid();
	cap = cap_get_pid(pid);
	if (cap != NULL) {
		err = cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &flag);
		cap_free(cap);
	}
	silofs_globals.cap_sys_admin = (!err && (flag == CAP_SET));
}

void silofs_init_process(void)
{
	int err;

	err = silofs_boot_lib();
	if (err) {
		silofs_die(err, "unable to init lib");
	}
	silofs_set_logmaskp(&silofs_globals.log_mask);
	silofs_resolve_caps();
}

void silofs_set_verbose_mode(const char *mode)
{
	silofs_log_mask_by_str(&silofs_globals.log_mask, mode);
}


