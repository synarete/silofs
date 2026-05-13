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
#include <linux/magic.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <ctype.h>
#include <math.h>
#include <dirent.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cmd_errnum_of(int err)
{
	const int abs_err = abs(err);

	return (abs_err < SILOFS_ERRBASE) ? abs_err : 0;
}

void cmd_vdie(int err, const char *fmt, va_list ap)
{
	char msg[1024] = "";
	va_list ap2;
	int ret;

	va_copy(ap2, ap);
	ret = vsnprintf(msg, sizeof(msg), fmt, ap2);
	va_end(ap2);

	if (ret < 0) {                           /* formatting error */
		msg[0] = '\0';
	} else if ((size_t)ret >= sizeof(msg)) { /* truncated */
		msg[sizeof(msg) - 1] = '\0';
	}

	error(EXIT_FAILURE, cmd_errnum_of(err), "%s", msg);
	exit(EXIT_FAILURE); /* never gets here, but makes clang-scan happy */
}

void cmd_die(int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cmd_vdie(err, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE); /* never gets here, but makes clang-scan happy */
}

void cmd_diez(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cmd_vdie(0, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE); /* never gets here, but makes clang-scan happy */
}

void cmd_atexit(void (*fn)(void))
{
	int err;

	err = atexit(fn);
	if (err) {
		error(EXIT_FAILURE, cmd_errnum_of(err), "atexit failure");
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t cmd_safe_strlen(const char *s)
{
	const size_t lmax = SILOFS_MEGA;
	const size_t slen = strnlen(s, lmax);

	if (slen >= lmax) {
		cmd_die(0, "bad string length: '%.8s...' len=%zu", s, slen);
	}
	return slen;
}

static void cmd_check_ascii_fsname(const char *s, size_t n)
{
	const char *allowed = "abcdefghijklmnopqrstuvwxyz"
			      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			      "0123456789_-.+=@";
	int ch;

	for (size_t i = 0; i < n; ++i) {
		ch = (int)(s[i]);
		if (isspace(ch)) {
			cmd_diez("illegal space char in fsname: 0%o", ch);
		}
		if (iscntrl(ch)) {
			cmd_diez("illegal control char in fsname: 0%o", ch);
		}
		if (!isprint(ch)) {
			cmd_diez("non-printable char in fsname: 0%o", ch);
		}
		if (!isascii(ch)) {
			cmd_diez("non-ASCII char in fsname: 0%o", ch);
		}
		if (strchr(allowed, ch) == nullptr) {
			cmd_diez("char not allowed in fsname: '%c'", ch);
		}
	}
}

void cmd_check_fsname(const char *s)
{
	size_t n;

	n = cmd_safe_strlen(s);
	if (!n) {
		cmd_die(-SILOFS_EILLSTR, "fs-name must not be empty");
	}
	if (n > SILOFS_FSNAME_MAX) {
		cmd_die(-ENAMETOOLONG, "fs-name too long: '%s'", s);
	}
	if (s[0] == '.') {
		cmd_diez("fs-name must not start with dot");
	}
	cmd_check_ascii_fsname(s, n);
}

void cmd_check_repopath(const char *arg_val)
{
	const size_t len = cmd_safe_strlen(arg_val);

	if ((len < 2) || (len >= SILOFS_REPOPATH_MAX)) {
		cmd_die(-EINVAL, "illegal repo pathname: %s", arg_val);
	}
}

void cmd_check_repodir(const char *path)
{
	cmd_check_repopath(path);
	cmd_check_nonemptydir(path, false);
}

void cmd_check_repodir_fsname(const char *basedir, const char *fsname)
{
	cmd_check_repodir(basedir);
	cmd_check_fsname(fsname);
}

static void cmd_stat_ok(const char *path, struct stat *st)
{
	int err;

	err = silofs_sys_stat(path, st);
	if (err == -ENOENT) {
		cmd_diez("no such path: %s", path);
	} else if (err) {
		cmd_die(err, "stat failed: %s", path);
	}
}

static void cmd_check_isdir(const char *path, bool w_ok)
{
	struct stat st;
	int access_mode = R_OK | X_OK | (w_ok ? W_OK : 0);
	int err;

	cmd_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		cmd_die(-ENOTDIR, "illegal dir-path: %s", path);
	}
	err = silofs_sys_access(path, access_mode);
	if (err) {
		cmd_die(err, "no-access: %s", path);
	}
}

void cmd_check_isreg(const char *path)
{
	struct stat st        = { .st_mode = 0 };
	const int access_mode = R_OK;
	int err;

	cmd_stat_ok(path, &st);
	if (S_ISDIR(st.st_mode)) {
		cmd_die(-EISDIR, "illegal: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_diez("not reg: %s", path);
	}
	err = silofs_sys_access(path, access_mode);
	if (err) {
		cmd_die(err, "no-access: %s", path);
	}
}

void cmd_check_isreg2(const char *dirpath, const char *name)
{
	char *path = nullptr;

	path = cmd_path_join(dirpath, name);
	cmd_check_isreg(path);
	cmd_pstrfree(&path);
}

void cmd_check_reg_or_dir(const char *path)
{
	struct stat st;

	cmd_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
		cmd_diez("not dir-or-reg: %s", path);
	}
}

void cmd_check_notdir(const char *path)
{
	struct stat st;
	int err;

	err = silofs_sys_stat(path, &st);
	if (!err && S_ISDIR(st.st_mode)) {
		cmd_die(EISDIR, "illegal: %s", path);
	}
}

void cmd_check_notexists(const char *path)
{
	struct stat st;
	int err;

	err = silofs_sys_stat(path, &st);
	if (!err) {
		if (S_ISDIR(st.st_mode)) {
			cmd_diez("directory exists: %s", path);
		} else {
			cmd_diez("path exists: %s", path);
		}
	}
	if (err != -ENOENT) {
		cmd_die(err, "stat failure: %s", path);
	}
}

void cmd_check_notexists2(const char *dirpath, const char *name)
{
	char *path = nullptr;

	path = cmd_path_join(dirpath, name);
	cmd_check_notexists(path);
	cmd_pstrfree(&path);
}

void cmd_check_exists(const char *path)
{
	struct stat st;

	cmd_stat_ok(path, &st);
}

void cmd_check_not_same(const char *path, const char *other)
{
	struct stat st;
	struct stat st_other;

	cmd_stat_ok(path, &st);
	cmd_stat_ok(other, &st_other);
	if ((st.st_ino == st_other.st_ino) && (st.st_dev == st_other.st_dev)) {
		if (S_ISDIR(st.st_mode)) {
			cmd_diez("not different directory: %s", path);
		} else if (S_ISREG(st.st_mode)) {
			cmd_diez("not different file: %s", path);
		} else {
			cmd_diez("not different: %s", path);
		}
	}
}

static const char *cmd_mntsock_name(void)
{
	return SILOFS_MNTSOCK_NAME;
}

void cmd_check_mntsrv_conn(void)
{
	const uid_t uid = getuid();
	const gid_t gid = getgid();
	int err;

	err = silofs_mntrpc_handshake(uid, gid);
	if (err) {
		cmd_die(err,
		        "failed to handshake with mountd: "
		        "sock=@%s",
		        cmd_mntsock_name());
	}
}

void cmd_check_mntsrv_perm(const char *path)
{
	const uid_t uid   = getuid();
	const gid_t gid   = getgid();
	const size_t rdsz = SILOFS_MEGA;
	int fd            = -1;
	int err;

	err = silofs_mntrpc_mount(path, uid, gid, rdsz, 0, false, true, &fd);
	if (err == -SILOFS_EMOUNT) {
		cmd_diez("mount not permitted: %s", path);
	} else if (err) {
		cmd_die(err, "can not mount: %s", path);
	}
}

void cmd_check_nonemptydir(const char *path, bool w_ok)
{
	char buf[1024] = "";
	struct dirent64 de[8];
	const size_t nde = SILOFS_ARRAY_SIZE(de);
	size_t ndes      = 0;
	int dfd          = -1;
	int err;

	cmd_check_isdir(path, w_ok);
	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_die(err, "open-dir error: %s", path);
	}
	err = silofs_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		cmd_die(err, "read dir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		cmd_die(err, "close-dir error: %s", path);
	}
	if (ndes <= 2) {
		cmd_diez("an empty directory: %s", path);
	}
}

void cmd_check_emptydir(const char *path, bool w_ok)
{
	struct dirent64 de[4];
	char buf[1024]   = "";
	const size_t nde = SILOFS_ARRAY_SIZE(de);
	size_t ndes      = 0;
	int dfd;
	int err;

	cmd_check_isdir(path, w_ok);
	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_die(err, "open-dir error: %s", path);
	}
	err = silofs_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		cmd_die(err, "read dir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		cmd_die(err, "close-dir error: %s", path);
	}
	if (ndes > 2) {
		cmd_diez("not an empty directory: %s", path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_mkdir(const char *path, mode_t mode)
{
	int err;

	err = silofs_sys_mkdir(path, mode);
	if (err) {
		cmd_die(err, "mkdir failed: %s", path);
	}
}

void cmd_chdir(const char *path)
{
	int err;

	err = silofs_sys_chdir(path);
	if (err) {
		cmd_die(err, "chdir failed: %s", path);
	}
}

static void cmd_access_ok(const char *path)
{
	int err;

	err = silofs_sys_access(path, R_OK);
	if (err == -ENOENT) {
		cmd_die(err, "no such path: %s", path);
	}
	if (err) {
		cmd_die(err, "no access: %s uid=%d gid=%d", path, getuid(),
		        getgid());
	}
}

static void cmd_statfs_ok(const char *path, struct statfs *stfs)
{
	int err;

	cmd_access_ok(path);
	err = silofs_sys_statfs(path, stfs);
	if (err) {
		cmd_die(err, "statfs failure: %s", path);
	}
}

void cmd_check_mntdir(const char *path, bool mount)
{
	long fstype;
	struct stat st;
	struct statfs stfs;
	const struct silofs_fsinfo *fsi = nullptr;

	if (strlen(path) >= SILOFS_MNTPATH_MAX) {
		cmd_diez("illegal mount-path length: %s", path);
	}
	cmd_check_isdir(path, mount);

	if (mount) {
		cmd_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi    = silofs_fsinfo_by_vfstype(fstype);
		if (fsi == nullptr) {
			cmd_diez("unknown fstype at: %s fstype=0x%lx", path,
			         fstype);
		}
		if (fsi->isfuse) {
			cmd_diez("can not mount over FUSE file-system: "
			         "%s fstype=0x%lx",
			         path, fstype);
		}
		if (!fsi->allowed) {
			cmd_diez("not allowed to mount over: %s fstype=0x%lx",
			         path, fstype);
		}
		cmd_check_emptydir(path, true);
	} else {
		cmd_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi    = silofs_fsinfo_by_vfstype(fstype);
		if (fsi == nullptr) {
			cmd_diez("unknown fstype at: %s fstype=0x%lx", path,
			         fstype);
		}
		if (!fsi->isfuse) {
			cmd_diez("not a FUSE file-system: %s", path);
		}
		cmd_stat_ok(path, &st);
		if (st.st_ino != SILOFS_INO_ROOT) {
			cmd_diez("not a silofs mount-point: %s", path);
		}
	}
}

static bool cmd_is_fusefs(long fstype)
{
	return (fstype == FUSE_SUPER_MAGIC);
}

void cmd_check_fusefs(const char *path)
{
	struct statfs stfs;

	cmd_statfs_ok(path, &stfs);
	if (!cmd_is_fusefs(stfs.f_type)) {
		cmd_diez("not on FUSE file-system: %s", path);
	}
}

bool cmd_test_fusefs(const char *path)
{
	struct statfs stfs = {};
	int err;

	err = silofs_sys_statfs(path, &stfs);
	return !err && cmd_is_fusefs(stfs.f_type);
}

static char *cmd_getcwd(void)
{
	char *cwd = get_current_dir_name();

	if (cwd == nullptr) {
		cmd_die(errno, "failed to get current working directory");
	}
	return cwd;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool equal_ci(char c1, char c2)
{
	const int uc1 = (int)toupper((unsigned char)c1);
	const int uc2 = (int)toupper((unsigned char)c2);

	return uc1 == uc2;
}

size_t cmd_parse_str_as_size(const char *str)
{
	const struct {
		char suffix;
		size_t mul;
	} units[] = {
		{ 'K', SILOFS_KILO }, //
		{ 'M', SILOFS_MEGA }, //
		{ 'G', SILOFS_GIGA }, //
		{ 'T', SILOFS_TERA }, //
		{ 'P', SILOFS_PETA }, //
		{ '\0', 1 },          //
	};
	char *endptr = nullptr;
	unsigned long long val;
	size_t mul = 0;

	errno = 0;
	val   = strtoull(str, &endptr, 10);
	if ((endptr == str) || errno == ERANGE || !endptr) {
		goto illegal_value;
	}
	if (strlen(endptr) > 1) {
		goto illegal_value;
	}

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(units); ++i) {
		if (equal_ci(*endptr, units[i].suffix)) {
			mul = units[i].mul;
			break;
		}
	}

	if (!mul) {
		goto illegal_value;
	}
	if (val > (SIZE_MAX / mul)) {
		goto illegal_value;
	}

	return (size_t)(val * mul);

illegal_value:
	cmd_die(0, "illegal value: %s", str);
	return 0; /* never gets here */
}

static long cmd_parse_str_as_long(const char *str)
{
	char *endptr = nullptr;
	long val;

	errno = 0;
	val   = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		cmd_die(errno, "bad integer value: %s", str);
	}
	if (strlen(endptr) > 1) {
		cmd_diez("illegal integer value: %s", str);
	}
	return val;
}

uint32_t cmd_parse_str_as_u32(const char *str)
{
	long val;

	val = cmd_parse_str_as_long(str);
	if ((val < 0) || (val > UINT32_MAX)) {
		cmd_diez("bad uint32 value: %s", str);
	}
	return (uint32_t)val;
}

uint32_t cmd_parse_str_as_u32v(const char *str, uint32_t vmin, uint32_t vmax)
{
	uint32_t val;

	val = cmd_parse_str_as_u32(str);
	if ((val < vmin) || (val > vmax)) {
		cmd_diez("%s is not within range [%u..%u]", str, vmin, vmax);
	}
	return val;
}

uid_t cmd_parse_str_as_uid(const char *str)
{
	long val;

	val = cmd_parse_str_as_long(str);
	if ((val < 0) || (val > (INT_MAX / 2))) {
		cmd_diez("illegal uid: %s", str);
	}
	return (uid_t)val;
}

gid_t cmd_parse_str_as_gid(const char *str)
{
	long val;

	val = cmd_parse_str_as_long(str);
	if ((val < 0) || (val > (INT_MAX / 2))) {
		cmd_diez("illegal gid: %s", str);
	}
	return (gid_t)val;
}

bool cmd_parse_str_as_bool(const char *str)
{
	bool val = false;

	if (!strcmp(str, "0") || !strcmp(str, "false")) {
		val = false;
	} else if (!strcmp(str, "1") || !strcmp(str, "true")) {
		val = true;
	} else {
		cmd_diez("illegal bool: %s", str);
	}
	return val;
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
		cmd_die(0, "failed to daemonize");
	}

	/*
	 * TODO-0024: No fd=0
	 *
	 * Ensure that next allocated fd is positive (non-zero) or bad things
	 * may happen in various places where code assumes (fd > 0).
	 */
}

void cmd_daemonize_process(pid_t *out_pid)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		cmd_die(errno, "fork error");
	}
	if (pid == 0) {
		cmd_daemonize();
	}
	*out_pid = pid;
}

void cmd_open_syslog(void)
{
	cmd_global_params.log_params.flags |= SILOFS_LOGF_SYSLOG;
	openlog(cmd_global_params.name, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
}

void cmd_close_syslog(void)
{
	int log_flags = (int)cmd_global_params.log_params.flags;

	if (log_flags & SILOFS_LOGF_SYSLOG) {
		closelog();
		log_flags &= ~SILOFS_LOGF_SYSLOG;
		cmd_global_params.log_params.flags =
			(enum silofs_log_flags)log_flags;
	}
}

static void cmd_setup_dumpable(void)
{
	const unsigned int state = 1;
	int err;

	err = silofs_sys_prctl(PR_SET_DUMPABLE, state, 0, 0, 0);
	if (err) {
		cmd_die(err, "prctl PR_SET_DUMPABLE failed: state=%d", state);
	}
}

void cmd_setup_coredump_mode(bool enable_coredump)
{
	struct rlimit rlim = {
		.rlim_cur = 0,
		.rlim_max = 0,
	};
	int err;

	err = silofs_sys_getrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		cmd_die(err, "failed to getrlimit RLIMIT_CORE");
	}
	if (enable_coredump) {
		rlim.rlim_cur = rlim.rlim_max;
	} else {
		rlim.rlim_cur = rlim.rlim_max = 0;
	}
	err = silofs_sys_setrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		cmd_die(err,
		        "failed to setrlimit RLIMIT_CORE: "
		        "rlim_cur=%zu rlim_max=%zu",
		        rlim.rlim_cur, rlim.rlim_max);
	}
	if (enable_coredump) {
		cmd_setup_dumpable();
	}
}

void cmd_realpath(const char *path, char **out_real)
{
	*out_real = realpath(path, nullptr);
	if (*out_real == nullptr) {
		cmd_die(-errno, "realpath failure: '%s'", path);
	}
}

void cmd_realpath_dir(const char *path, char **out_real)
{
	cmd_realpath(path, out_real);
	cmd_check_isdir(*out_real, true);
}

void cmd_realpath_rdir(const char *path, char **out_real)
{
	cmd_realpath(path, out_real);
	cmd_check_isdir(*out_real, false);
}

void cmd_stat_dir(const char *path, struct stat *st)
{
	cmd_stat_ok(path, st);
	if (!S_ISDIR(st->st_mode)) {
		cmd_diez("not a directory: %s", path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *cmd_zalloc(size_t nbytes)
{
	void *mem = nullptr;
	int err;

	err = silofs_zmalloc(nbytes, &mem);
	if (err) {
		cmd_die(-err, "alloc failed: nbytes=%lu", nbytes);
	}
	return mem;
}

void cmd_zfree(void *ptr, size_t nbytes)
{
	if (ptr != nullptr) {
		silofs_zfree(ptr, nbytes);
	}
}

void cmd_strfree(char *s)
{
	cmd_zfree(s, cmd_safe_strlen(s));
}

void cmd_pstrfree(char **pp)
{
	if (*pp != nullptr) {
		cmd_strfree(*pp);
		*pp = nullptr;
	}
}

char *cmd_strcat(const char *s1, const char *s2)
{
	const size_t n1 = cmd_safe_strlen(s1);
	const size_t n2 = cmd_safe_strlen(s2);
	char *s;

	s = cmd_zalloc(n1 + n2 + 1);
	memcpy(s, s1, n1);
	memcpy(s + n1, s2, n2);
	return s;
}

char *cmd_strcat3(const char *s1, const char *s2, const char *s3)
{
	char *s, *t;

	t = cmd_strcat(s1, s2);
	s = cmd_strcat(t, s3);
	cmd_strfree(t);
	return s;
}

char *cmd_strdup(const char *s)
{
	return cmd_strndup(s, cmd_safe_strlen(s));
}

char *cmd_strndup(const char *s, size_t n)
{
	char *d = strndup(s, n);

	if (d == nullptr) {
		cmd_die(errno, "strndup failed: n=%zu", n);
	}
	return d;
}

char *cmd_strvdup(const void *p, size_t n)
{
	const char *s  = p;
	const size_t k = strnlen(s, n);

	if (k >= n) {
		cmd_diez("illegal string value: n=%zu", n);
	}
	return cmd_strndup(s, k);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_path_split(const char *path, char **out_head, char **out_tail)
{
	const char *sep;
	char *head = nullptr;
	char *tail = nullptr;
	size_t head_len;
	size_t tail_len;

	sep = strrchr(path, '/');
	if (sep == nullptr) {
		head = cmd_getcwd();
		tail = cmd_strdup(path);
		goto out;
	}
	tail_len = strlen(sep + 1);
	if (!tail_len) {
		cmd_diez("missing filename: %s", path);
	}
	if (sep == path) {
		cmd_diez("missing basename: %s", path);
	}
	head_len = (size_t)(sep - path);
	head     = cmd_strndup(path, head_len);
	tail     = cmd_strndup(sep + 1, tail_len);
out:
	*out_head = head;
	*out_tail = tail;
}

char *cmd_path_join(const char *dirpath, const char *name)
{
	char *xpath = nullptr;
	size_t plen, nlen;

	plen  = cmd_safe_strlen(dirpath);
	nlen  = cmd_safe_strlen(name);
	xpath = cmd_zalloc(plen + nlen + 2);
	strlcpy(xpath, dirpath, plen + 1);
	xpath[plen] = '/';
	strlcpy(xpath + 1 + plen, name, nlen + 1);
	return xpath;
}

char *cmd_path_fmt(const char *fmt, ...)
{
	va_list ap;
	constexpr size_t path_size = PATH_MAX;
	char *path_dup, *path;
	int n;

	path = cmd_zalloc(path_size);
	va_start(ap, fmt);
	n = vsnprintf(path, path_size, fmt, ap);
	va_end(ap);

	if (n >= (int)path_size) {
		cmd_diez("illegal path-len %d", n);
	}
	if ((n * 2) > (int)path_size) {
		goto out;
	}
	path_dup = cmd_strdup(path);
	cmd_pstrfree(&path);
	path = path_dup;
out:
	return path;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_print_help_and_exit(const char *help_string)
{
	FILE *fp         = stdout;
	const char *name = cmd_global_params.name;

	if (strlen(name) > 0) {
		fprintf(fp, "%s %s\n", name, help_string);
	} else {
		fprintf(fp, "%s\n", help_string);
	}
	fflush(fp);
	exit(EXIT_SUCCESS);
}

void cmd_set_log_level_by(const char *s)
{
	cmd_global_params.log_params.level = silofs_log_level_by_rfc5424(s);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_openat(int dfd, const char *name, int flags, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dfd, name, flags, 0, out_fd);
	if (err) {
		cmd_die(err, "failed to open: %s flags=%o", name, flags);
	}
}

static void cmd_opendir(const char *pathname, int *out_dfd)
{
	int err;

	err = silofs_sys_opendir(pathname, out_dfd);
	if (err) {
		cmd_die(err, "failed to open directory: %s", pathname);
	}
}

static void cmd_read(int fd, void *buf, size_t cnt, size_t *nrd)
{
	int err;

	err = silofs_sys_read(fd, buf, cnt, nrd);
	if (err) {
		cmd_die(err, "read error");
	}
}

static size_t cmd_readfile_stepsize(void)
{
	const long pgsz = silofs_sc_page_size();

	return (size_t)(pgsz < 4096 ? 4096 : 65536);
}

static void cmd_readfile(int fd, char *buf, size_t bsz, size_t *out_nrd)
{
	const size_t step = cmd_readfile_stepsize();
	size_t len        = 0;

	while (len < bsz) {
		const size_t rem = bsz - len;
		const size_t cnt = rem < step ? rem : step;
		size_t nrd       = 0;

		cmd_read(fd, buf + len, cnt, &nrd);
		if (!nrd) {
			break;
		}
		len += nrd;
	}
	*out_nrd = len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		cmd_die(err, "close error: fd=%d", *pfd);
	}
}

static char *cmd_read_proc_mountinfo(void)
{
	const size_t bsz = 1UL << 20;
	char *buf        = cmd_zalloc(bsz);
	size_t size      = 0;
	int dfd          = -1;
	int fd           = -1;

	cmd_opendir("/proc/self", &dfd);
	cmd_openat(dfd, "mountinfo", O_RDONLY, &fd);
	cmd_closefd(&dfd);
	cmd_readfile(fd, buf, bsz, &size);
	cmd_closefd(&fd);
	return buf;
}

struct silofs_mntinfos *cmd_parse_mountinfo(void)
{
	struct silofs_mntinfos *minfos = nullptr;
	char *midata                   = nullptr;
	int err;

	midata = cmd_read_proc_mountinfo();
	minfos = cmd_zalloc(sizeof(*minfos));
	err    = silofs_parse_mntinfos(minfos, nullptr, midata);
	if (err) {
		cmd_die(err, "failed to parse mountinfo");
	}
	cmd_pstrfree(&midata);

	return minfos;
}

void cmd_free_mountinfo(struct silofs_mntinfos *mntinfos)
{
	if (mntinfos != nullptr) {
		silofs_release_mntinfos(mntinfos, nullptr);
		cmd_zfree(mntinfos, sizeof(*mntinfos));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

union silofs_ioc_u *cmd_new_ioc(void)
{
	union silofs_ioc_u *ioc = nullptr;

	ioc = cmd_zalloc(sizeof(*ioc));
	return ioc;
}

void cmd_del_iocp(union silofs_ioc_u **pioc)
{
	if ((pioc != nullptr) && (*pioc != nullptr)) {
		cmd_zfree(*pioc, sizeof(**pioc));
		*pioc = nullptr;
	}
}

void cmd_reset_ioc(union silofs_ioc_u *ioc)
{
	memset(ioc, 0, sizeof(*ioc));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_trace_versions(void)
{
	struct silofs_versions vers;

	silofs_getversions(&vers);
	silofs_log_info("silofs version: %s", vers.silofs_version);
	silofs_log_info("gcrypt version: %s", vers.gcrypt_version);
	silofs_log_info("zstd version: %s", vers.zstd_version);
}
