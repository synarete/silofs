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

#define _GNU_SOURCE 1
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
#include "cmd.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

__attribute__((__noreturn__))
void cmd_dief(int errnum, const char *restrict fmt, ...)
{
	char msg[2048] = "";
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);
	error(EXIT_FAILURE, abs(errnum), "%s", msg);
	_exit(EXIT_FAILURE); /* never gets here, but makes clang-scan happy */
}

__attribute__((__noreturn__))
static void cmd_fatal_missing_arg(const char *s)
{
	cmd_dief(0, "missing argument: %s", s);
}

__attribute__((__noreturn__))
static void cmd_fatal_redundant_arg(const char *s)
{
	cmd_dief(0, "redundant argument: %s", s);
}

__attribute__((__noreturn__))
void cmd_fatal_unsupported_opt(void)
{
	exit(EXIT_FAILURE);
}

void cmd_require_arg(const char *arg_name, const void *arg_val)
{
	if (arg_val == NULL) {
		cmd_fatal_missing_arg(arg_name);
	}
}

void cmd_check_fsname(const char *arg_val)
{
	struct silofs_namestr nstr;
	int err;

	err = silofs_make_fsnamestr(&nstr, arg_val);
	if (err) {
		cmd_dief(err, "illegal file-system name: %s", arg_val);
	}
}

static void cmd_stat_ok(const char *path, struct stat *st)
{
	int err;

	err = silofs_sys_stat(path, st);
	if (err == -ENOENT) {
		cmd_dief(0, "no such path: %s", path);
	} else if (err) {
		cmd_dief(err, "stat failed: %s", path);
	}
}

void cmd_check_isdir(const char *path, bool w_ok)
{
	int err;
	struct stat st;
	int access_mode = R_OK | X_OK | (w_ok ? W_OK : 0);

	cmd_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		cmd_dief(-ENOTDIR, "illegal dir-path: %s", path);
	}
	err = silofs_sys_access(path, access_mode);
	if (err) {
		cmd_dief(err, "no-access: %s", path);
	}
}

void cmd_check_reg(const char *path, bool w_ok)
{
	int err;
	struct stat st;
	int access_mode = R_OK | (w_ok ? W_OK : 0);

	cmd_stat_ok(path, &st);
	if (S_ISDIR(st.st_mode)) {
		cmd_dief(-EISDIR, "illegal: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_dief(0, "not reg: %s", path);
	}
	err = silofs_sys_access(path, access_mode);
	if (err) {
		cmd_dief(err, "no-access: %s", path);
	}
}

void cmd_check_reg_or_dir(const char *path)
{
	struct stat st;

	cmd_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
		cmd_dief(0, "not dir-or-reg: %s", path);
	}
}

static int cmd_stat_or_noent(const char *path, struct stat *st)
{
	int err;

	err = silofs_sys_stat(path, st);
	if (err && (err != -ENOENT)) {
		cmd_dief(err, "stat failed: %s", path);
	}
	return err;
}

void cmd_check_notdir(const char *path)
{
	struct stat st;
	int err;

	err = silofs_sys_stat(path, &st);
	if (!err && S_ISDIR(st.st_mode)) {
		cmd_dief(EISDIR, "illegal: %s", path);
	}
}

void cmd_check_notexists(const char *path)
{
	struct stat st;
	int err;

	err = silofs_sys_stat(path, &st);
	if (!err) {
		if (S_ISDIR(st.st_mode)) {
			cmd_dief(0, "directory exists: %s", path);
		} else {
			cmd_dief(0, "path exists: %s", path);
		}
	}
	if (err != -ENOENT) {
		cmd_dief(err, "stat failure: %s", path);
	}
}

static char *cmd_joinpath_safe(const char *path, const char *name)
{
	char *xpath;
	const size_t plen = strlen(path);
	const size_t nlen = strlen(name);

	xpath = cmd_zalloc(plen + nlen + 2);
	memcpy(xpath, path, plen);
	memcpy(xpath + 1 + plen, name, nlen);
	xpath[plen] = '/';
	xpath[plen + nlen + 1] = '\0';
	return xpath;
}

void cmd_check_notexists2(const char *path, const char *name)
{
	char *xpath;

	xpath = cmd_joinpath_safe(path, name);
	cmd_check_notexists(xpath);
	cmd_pstrfree(&xpath);
}

void cmd_check_diff(const char *path0, const char *path1)
{
	struct stat st[2];
	int err[2];

	err[0] = cmd_stat_or_noent(path0, &st[0]);
	err[1] = cmd_stat_or_noent(path1, &st[1]);
	if ((err[0] == 0) && (err[1] == 0) &&
	    (st[0].st_ino == st[1].st_ino) &&
	    (st[0].st_dev == st[1].st_dev)) {
		cmd_dief(0, "same path: %s %s",
		         path0, strcmp(path0, path1) ? path1 : "");
	}
}

void cmd_check_exists(const char *path)
{
	struct stat st;

	cmd_stat_ok(path, &st);
}

void cmd_check_mountd(void)
{
	int err;
	const char *sock = SILOFS_MNTSOCK_NAME;

	err = silofs_rpc_handshake(getuid(), getgid());
	if (err) {
		cmd_dief(err, "failed to handshake with mountd: "
		         "sock=@%s", sock);
	}
}

void cmd_check_nonemptydir(const char *path, bool w_ok)
{
	int err;
	int dfd = -1;
	size_t ndes = 0;
	struct dirent64 de[8];
	const size_t nde = SILOFS_ARRAY_SIZE(de);
	char buf[1024] = "";

	cmd_check_isdir(path, w_ok);
	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_dief(err, "open-dir error: %s", path);
	}
	err = silofs_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		cmd_dief(err, "read dir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		cmd_dief(err, "close-dir error: %s", path);
	}
	if (ndes <= 2) {
		cmd_dief(0, "an empty directory: %s", path);
	}
}

void cmd_check_emptydir(const char *path, bool w_ok)
{
	int err;
	int dfd = -1;
	size_t ndes = 0;
	struct dirent64 de[8];
	const size_t nde = SILOFS_ARRAY_SIZE(de);
	char buf[1024] = "";

	cmd_check_isdir(path, w_ok);
	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_dief(err, "open-dir error: %s", path);
	}
	err = silofs_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		cmd_dief(err, "read dir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		cmd_dief(err, "close-dir error: %s", path);
	}
	if (ndes > 2) {
		cmd_dief(0, "not an empty directory: %s", path);
	}
}

void cmd_mkdir(const char *path, mode_t mode)
{
	int err;

	err = silofs_sys_mkdir(path, mode);
	if (err) {
		cmd_dief(err, "mkdir failed: %s", path);
	}
}

static void cmd_access_ok(const char *path)
{
	int err;

	err = silofs_sys_access(path, R_OK);
	if (err == -ENOENT) {
		cmd_dief(err, "no such path: %s", path);
	}
	if (err) {
		cmd_dief(err, "no access: %s uid=%d gid=%d",
		         path, getuid(), getgid());
	}
}

static void cmd_statfs_ok(const char *path, struct statfs *stfs)
{
	int err;

	cmd_access_ok(path);
	err = silofs_sys_statfs(path, stfs);
	if (err) {
		cmd_dief(err, "statfs failure: %s", path);
	}
}

void cmd_check_mntdir(const char *path, bool mount)
{
	long fstype;
	struct stat st;
	struct statfs stfs;
	const struct silofs_fsinfo *fsi = NULL;

	if (strlen(path) >= SILOFS_MNTPATH_MAX) {
		cmd_dief(0, "illegal mount-path length: %s", path);
	}
	cmd_check_isdir(path, mount);

	if (mount) {
		cmd_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi = silofs_fsinfo_by_vfstype(fstype);
		if (fsi == NULL) {
			cmd_dief(0, "unknown fstype at: "
			         "%s fstype=0x%lx", path, fstype);
		}
		if (fsi->isfuse) {
			cmd_dief(0, "can not mount over FUSE file-system: "
			         "%s fstype=0x%lx", path, fstype);
		}
		if (!fsi->allowed) {
			cmd_dief(0, "not allowed to mount over: "
			         "%s fstype=0x%lx", path, fstype);
		}
		cmd_check_emptydir(path, true);
	} else {
		cmd_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi = silofs_fsinfo_by_vfstype(fstype);
		if (fsi == NULL) {
			cmd_dief(0, "unknown fstype at: "
			         "%s fstype=0x%lx", path, fstype);
		}
		if (!fsi->isfuse) {
			cmd_dief(0, "not a FUSE file-system: %s", path);
		}
		cmd_stat_ok(path, &st);
		if (st.st_ino != SILOFS_INO_ROOT) {
			cmd_dief(0, "not a silofs mount-point: %s", path);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_endargs(void)
{
	int argc = cmd_globals.cmd_argc;
	char **argv = cmd_globals.cmd_argv;

	if (optind < argc) {
		cmd_fatal_redundant_arg(argv[optind]);
	}
}

void cmd_getoptarg(const char *opt_name, char **out_opt)
{
	if (!optarg || !strlen(optarg)) {
		cmd_dief(0, "missing option argument: %s", opt_name);
	}
	*out_opt = cmd_strdup(optarg);
}

void cmd_getarg(const char *arg_name, char **out_arg)
{
	char *arg = NULL;
	char **argv = cmd_globals.cmd_argv;
	int argc = cmd_globals.cmd_argc;

	arg = argv[optind];
	if ((optind >= argc) || (arg == NULL)) {
		cmd_fatal_missing_arg(arg_name);
	}
	optind++;
	*out_arg = cmd_strdup(arg);
}

static void cmd_getcwd(char **out_wd)
{
	*out_wd = get_current_dir_name();
	if (*out_wd == NULL) {
		cmd_dief(errno, "failed to get current working directory");
	}
}

void cmd_getarg_or_cwd(const char *arg_name, char **out_arg)
{
	char *arg = NULL;
	char **argv = cmd_globals.cmd_argv;
	int argc = cmd_globals.cmd_argc;

	arg = argv[optind];
	if ((optind >= argc) || (arg == NULL)) {
		cmd_getcwd(out_arg);
	} else {
		optind++;
		*out_arg = cmd_strdup(arg);
	}
	silofs_unused(arg_name);
}

int cmd_getopt(const char *sopts, const struct option *lopts)
{
	int opt_index = 0;
	int argc = cmd_globals.cmd_argc;
	char **argv = cmd_globals.cmd_argv;

	return getopt_long(argc, argv, sopts, lopts, &opt_index);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long cmd_parse_size(const char *str)
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
	cmd_dief(0, "illegal value: %s", str);
	return -EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0014: Dance with systemd upon logout
 *
 * May need to call 'loginctl enable-linger username' if we want daemon to
 * stay alive after login. Need more investigating.
 */
static void cmd_daemonize(void)
{
	int err;

	err = daemon(0, 1);
	if (err) {
		cmd_dief(0, "failed to daemonize");
	}
	cmd_globals.log_mask |= SILOFS_LOG_SYSLOG;
	cmd_globals.log_mask &= ~SILOFS_LOG_STDOUT;

	/*
	 * TODO-0024: No fd=0
	 *
	 * Ensure that next allocated fd is positive (non-zero) or bad things
	 * may happen in various places where code assumes (fd > 0).
	 */
}

void cmd_fork_daemon(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		cmd_dief(errno, "fork error");
	}
	if (pid == 0) {
		cmd_daemonize();
	}
}

void cmd_open_syslog(void)
{
	cmd_globals.log_mask |= SILOFS_LOG_SYSLOG;
	openlog(cmd_globals.name, LOG_CONS | LOG_NDELAY, 0);
}

void cmd_close_syslog(void)
{
	if (cmd_globals.log_mask & SILOFS_LOG_SYSLOG) {
		closelog();
		cmd_globals.log_mask &= ~SILOFS_LOG_SYSLOG;
	}
}

void cmd_setrlimit_nocore(void)
{
	struct rlimit rlim = { .rlim_cur = 0, .rlim_max = 0 };
	int err;

	err = silofs_sys_setrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		cmd_dief(err, "failed to disable core-dupms");
	}
}

void cmd_realpath(const char *path, char **out_real)
{
	*out_real = realpath(path, NULL);
	if (*out_real == NULL) {
		cmd_dief(-errno, "realpath failure: '%s'", path);
	}
}

void cmd_stat_reg(const char *path, struct stat *st)
{
	cmd_stat_ok(path, st);
	if (!S_ISREG(st->st_mode)) {
		cmd_dief(0, "not a regular file: %s", path);
	}
}

void cmd_stat_dir(const char *path, struct stat *st)
{
	cmd_stat_ok(path, st);
	if (!S_ISDIR(st->st_mode)) {
		cmd_dief(0, "not a directory: %s", path);
	}
}

void cmd_split_path(const char *path, char **out_head, char **out_tail)
{
	const char *sep;
	size_t head_len;
	size_t tail_len;

	sep = strrchr(path, '/');
	if (sep == NULL) {
		cmd_getcwd(out_head);
		*out_tail = cmd_strdup(path);
	} else {
		tail_len = strlen(sep + 1);
		if (!tail_len) {
			cmd_dief(0, "missing filename: %s", path);
		}
		if (sep == path) {
			cmd_dief(0, "missing basename: %s", path);
		}
		head_len = (size_t)(sep - path);
		*out_head = cmd_strndup(path, head_len);
		*out_tail = cmd_strndup(sep + 1, tail_len);
	}
}

void cmd_split_path2(const char *path, const char *name,
                     char **out_head, char **out_tail)
{
	struct stat st;
	char *xpath;
	int err;

	err = silofs_sys_stat(path, &st);
	if (!err && S_ISDIR(st.st_mode)) {
		xpath = cmd_joinpath_safe(path, name);
	} else {
		xpath = cmd_strdup(path);
	}
	cmd_split_path(xpath, out_head, out_tail);
	cmd_pstrfree(&xpath);
}

void cmd_join_path(const char *dirpath, const char *name, char **out_path)
{
	*out_path = cmd_mkpathf("%s/%s", dirpath, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *cmd_zalloc(size_t nbytes)
{
	void *mem = NULL;
	int err;

	err = silofs_zmalloc(nbytes, &mem);
	if (err) {
		cmd_dief(-err, "alloc failed: nbytes=%lu", nbytes);
	}
	return mem;
}

void cmd_zfree(void *ptr, size_t nbytes)
{
	if (ptr != NULL) {
		silofs_zfree(ptr, nbytes);
	}
}

void cmd_pstrfree(char **pp)
{
	if (*pp != NULL) {
		cmd_zfree(*pp, strlen(*pp));
		*pp = NULL;
	}
}

char *cmd_strdup(const char *s)
{
	char *d = strdup(s);

	if (d == NULL) {
		cmd_dief(errno, "strdup failed");
	}
	return d;
}

char *cmd_strndup(const char *s, size_t n)
{
	char *d = strndup(s, n);

	if (d == NULL) {
		cmd_dief(errno, "strndup failed: n=%lu", n);
	}
	return d;
}

char *cmd_mkpathf(const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t path_size = PATH_MAX;
	char *path = cmd_zalloc(path_size);
	char *path_dup;

	va_start(ap, fmt);
	n = vsnprintf(path, path_size - 1, fmt, ap);
	va_end(ap);

	if (n >= (int)path_size) {
		cmd_dief(0, "illegal path-len %d", n);
	}
	path_dup = cmd_strdup(path);
	cmd_pstrfree(&path);
	return path_dup;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_show_help_strings(FILE *fp, const char *name,
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

void cmd_print_help_and_exit(const char **help_strings)
{
	const char *prefix = cmd_globals.name;

	cmd_show_help_strings(stdout, prefix, help_strings);
	exit(EXIT_SUCCESS);
}

void cmd_set_verbose_mode(const char *mode)
{
	silofs_log_mask_by_str(&cmd_globals.log_mask, mode);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_openat(int dfd, const char *name, int flags, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dfd, name, flags, 0, out_fd);
	if (err) {
		cmd_dief(err, "failed to open: %s flags=%o", name, flags);
	}
}

static void cmd_opendir(const char *pathname, int *out_dfd)
{
	int err;

	err = silofs_sys_opendir(pathname, out_dfd);
	if (err) {
		cmd_dief(err, "failed to open directory: %s", pathname);
	}
}

static void cmd_read(int fd, void *buf, size_t cnt, size_t *nrd)
{
	int err;

	err = silofs_sys_read(fd, buf, cnt, nrd);
	if (err) {
		cmd_dief(err, "read error");
	}
}

static void cmd_readfile(int fd, char *buf, size_t bsz, size_t *out_nrd)
{
	size_t cnt;
	size_t nrd = 0;
	size_t len = 0;
	const size_t pgsz = (size_t)silofs_sc_page_size();

	while (len < bsz) {
		cnt = silofs_min(pgsz, bsz - len);
		cmd_read(fd, buf + len, cnt, &nrd);
		if (!nrd) {
			break;
		}
		len += nrd;
		nrd = 0;
	}
	*out_nrd = len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sys_flock(int fd, int operation)
{
	return silofs_sys_flock(fd, operation);
}

static void cmd_lockf_at(int fd, const char *repodir, const char *name)
{
	int err;

	err = sys_flock(fd, LOCK_EX | LOCK_NB);
	if (err == -EWOULDBLOCK) {
		cmd_dief(0, "already locked by another process: %s/%s",
		         repodir, name);
	} else if (err) {
		cmd_dief(err, "can not lock: %s/%s", repodir, name);
	}
}

static int cmd_trylockf_at(int fd, const char *repodir, const char *name)
{
	int err;

	err = sys_flock(fd, LOCK_EX | LOCK_NB);
	if (err && (err != -EWOULDBLOCK)) {
		cmd_dief(err, "can not lock: %s/%s", repodir, name);
	}
	return err;
}

static void cmd_unlockf_at(int fd)
{
	int err;

	err = sys_flock(fd, LOCK_UN);
	if (err) {
		cmd_dief(err, "failed to unlock");
	}
}

static void cmd_fchmodat(int dfd, const char *name, mode_t mode)
{
	int err;

	err = silofs_sys_fchmodat(dfd, name, mode, 0);
	if (err) {
		cmd_dief(err, "failed to chmod: %s mode=%o", name, mode);
	}
}

static void cmd_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		cmd_dief(err, "close error: fd=%d", *pfd);
	}
}

static void cmd_openlockf(int dfd, const char *name, int *out_fd)
{
	cmd_fchmodat(dfd, name, 0600);
	cmd_openat(dfd, name, O_RDWR, out_fd);
	cmd_fchmodat(dfd, name, 0400);
}

static void cmd_lockf(const char *dirpath, const char *name, int *out_fd)
{
	int dfd = -1;
	int fd = -1;

	cmd_opendir(dirpath, &dfd);
	cmd_openlockf(dfd, name, &fd);
	cmd_closefd(&dfd);
	cmd_lockf_at(fd, dirpath, name);
	*out_fd = fd;
}

void cmd_lock_bpath(const struct silofs_bootpath *bpath, int *out_fd)
{
	cmd_lockf(bpath->repodir.str, bpath->name.s.str, out_fd);
}

static bool cmd_trylockf(const char *repodir, const char *name, int *out_fd)
{
	int dfd = -1;
	int fd = -1;
	int err;

	cmd_opendir(repodir, &dfd);
	cmd_openlockf(dfd, name, &fd);
	cmd_closefd(&dfd);
	err = cmd_trylockf_at(fd, repodir, name);
	if (err) {
		cmd_closefd(&fd);
		*out_fd = -1;
		return false;
	}
	*out_fd = fd;
	return true;
}

bool cmd_trylock_bpath(const struct silofs_bootpath *bpath, int *out_fd)
{
	return cmd_trylockf(bpath->repodir.str, bpath->name.s.str, out_fd);
}

static void cmd_unlockf(int *pfd)
{
	if (pfd && (*pfd > 0)) {
		cmd_unlockf_at(*pfd);
		cmd_closefd(pfd);
	}
}

void cmd_unlock_bpath(const struct silofs_bootpath *bpath, int *pfd)
{
	cmd_unlockf(pfd);
	(void)bpath;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *cmd_read_proc_mountinfo(void)
{
	const size_t bsz = 1UL << 20;
	char *buf = cmd_zalloc(bsz);
	size_t size = 0;
	int dfd = -1;
	int fd = -1;

	cmd_opendir("/proc/self", &dfd);
	cmd_openat(dfd, "mountinfo", O_RDONLY, &fd);
	cmd_closefd(&dfd);
	cmd_readfile(fd, buf, bsz, &size);
	cmd_closefd(&fd);
	return buf;
}

static bool substr_isempty(const struct silofs_substr *ss)
{
	return silofs_substr_isempty(ss);
}

static void cmd_parse_field(const struct silofs_substr *line, size_t idx,
                            struct silofs_substr *out_field)
{
	struct silofs_substr_pair pair;
	struct silofs_substr *word = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_init(out_field, "");
	silofs_substr_split(line, " \t\v", &pair);
	while (!substr_isempty(word) || !substr_isempty(tail)) {
		if (idx == 0) {
			silofs_substr_strip_ws(word, out_field);
			break;
		}
		silofs_substr_split(tail, " \t\v", &pair);
		idx--;
	}
}

static void cmd_parse_mountinfo_line(const struct silofs_substr *line,
                                     struct silofs_substr *out_mntdir,
                                     struct silofs_substr *out_mntargs)
{
	struct silofs_substr_pair pair;
	struct silofs_substr *head = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_split_str(line, " - ", &pair);
	cmd_parse_field(head, 4, out_mntdir);
	cmd_parse_field(tail, 2, out_mntargs);
}

static bool cmd_isfusesilofs_mountinfo_line(const struct silofs_substr *line)
{
	return (silofs_substr_find(line, "fuse.silofs") < line->len);
}

static size_t round_up(size_t sz)
{
	const size_t align = sizeof(void *);

	return ((sz + align - 1) / align) * align;
}

static void *memory_at(void *mem, size_t pos)
{
	return (uint8_t *)mem + pos;
}

static struct silofs_proc_mntinfo *
cmd_new_mntinfo(const struct silofs_substr *mntdir,
                const struct silofs_substr *mntargs)
{
	struct silofs_proc_mntinfo *mi;
	void *mem;
	char *str;
	size_t sz1;
	size_t sz2;
	size_t hsz;
	size_t msz;

	hsz = round_up(sizeof(*mi));
	sz1 = round_up(mntdir->len + 1);
	sz2 = round_up(mntargs->len + 1);
	msz = hsz + sz1 + sz2;
	mem = cmd_zalloc(msz);

	mi = mem;
	mi->msz = msz;
	mi->next = NULL;

	str = memory_at(mem, hsz);
	silofs_substr_copyto(mntdir, str, sz1);
	mi->mntdir = str;

	str = memory_at(mem, hsz + sz1);
	silofs_substr_copyto(mntargs, str, sz2);
	mi->mntargs = str;

	return mi;
};

static struct silofs_proc_mntinfo *
cmd_new_mntinfo_of(const struct silofs_substr *line)
{
	struct silofs_substr mntdir;
	struct silofs_substr mntargs;

	cmd_parse_mountinfo_line(line, &mntdir, &mntargs);
	return cmd_new_mntinfo(&mntdir, &mntargs);
}

static void cmd_parse_mountinfo_into(struct silofs_proc_mntinfo **pmi_list,
                                     const char *mount_info_text)
{
	struct silofs_substr info;
	struct silofs_substr_pair pair;
	struct silofs_substr *line = &pair.first;
	struct silofs_substr *tail = &pair.second;
	struct silofs_proc_mntinfo *mi = NULL;

	silofs_substr_init(&info, mount_info_text);
	silofs_substr_split_chr(&info, '\n', &pair);
	while (!silofs_substr_isempty(line) ||
	       !silofs_substr_isempty(tail)) {
		if (cmd_isfusesilofs_mountinfo_line(line)) {
			mi = cmd_new_mntinfo_of(line);
			mi->next = *pmi_list;
			*pmi_list = mi;
		}
		silofs_substr_split_chr(tail, '\n', &pair);
	}
}

struct silofs_proc_mntinfo *cmd_parse_mountinfo(void)
{
	struct silofs_proc_mntinfo *mi_list = NULL;
	char *mount_info;

	mount_info = cmd_read_proc_mountinfo();
	cmd_parse_mountinfo_into(&mi_list, mount_info);
	cmd_pstrfree(&mount_info);

	return mi_list;
}

void cmd_free_mountinfo(struct silofs_proc_mntinfo *mi_list)
{
	struct silofs_proc_mntinfo *mi_next;

	while (mi_list != NULL) {
		mi_next = mi_list->next;
		cmd_zfree(mi_list, mi_list->msz);
		mi_list = mi_next;
	}
}

