/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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

void silofs_die_if_redundant_arg(void)
{
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	if (optind < argc) {
		silofs_die_redundant_arg(argv[optind]);
	}
}

void silofs_die_if_illegal_name(const char *arg_name, const char *arg_val)
{
	int err;

	err = silofs_check_name(arg_val);
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

	silofs_stat_ok(path, &st);
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

	silofs_stat_ok(path, &st);
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

void silofs_die_if_not_reg3(const char *dirpath, const char *subdir,
                            const char *name, bool w_ok)
{
	char *path;

	path = silofs_sprintf_path("%s/%s/%s", dirpath, subdir, name);
	silofs_die_if_not_reg(path, w_ok);
	silofs_pfree_string(&path);
}

void silofs_die_if_exists(const char *path)
{
	int err;
	struct stat st;

	err = silofs_sys_stat(path, &st);
	if (!err) {
		silofs_die(0, "file exists: %s", path);
	}
	if (err != -ENOENT) {
		silofs_die(err, "stat failure: %s", path);
	}
}

static struct silofs_super_block *new_super_block(void)
{
	struct silofs_super_block *sb = NULL;

	sb = silofs_zalloc_safe(sizeof(*sb));
	return sb;
}

static void del_super_block(struct silofs_super_block *sb)
{
	memset(sb, 0xFE, sizeof(*sb));
	free(sb);
}

static struct silofs_super_block *read_super_block(const char *path)
{
	int fd = -1;
	int err;
	loff_t size = 0;
	struct stat st = { .st_size = 0 };
	struct silofs_super_block *sb = NULL;

	silofs_stat_reg_or_blk(path, &st, &size);
	if (size == 0) {
		silofs_die(0, "empty volume: %s", path);
	}
	if (size < (int)sizeof(*sb)) {
		silofs_die(0, "no super-block in: %s", path);
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "open failed: %s", path);
	}
	sb = new_super_block();
	err = silofs_sys_preadn(fd, sb, sizeof(*sb), 0);
	if (err) {
		silofs_die(err, "pread error: %s", path);
	}
	silofs_sys_close(fd);
	return sb;
}

static int decrypt_super_block(struct silofs_super_block *sb,
                               const struct silofs_cipher_args *cip_args,
                               const struct silofs_crypto *crypto,
                               const struct silofs_passphrase *passph)
{
	int err;
	struct silofs_kivam kivam;

	silofs_kivam_init(&kivam);
	err = silofs_derive_kivam(cip_args, passph, &crypto->md, &kivam);
	if (!err) {
		err = silofs_sb_decrypt(sb, &crypto->ci, &kivam, sb);
	}
	silofs_kivam_fini(&kivam);
	return err;
}

static void check_super_block(struct silofs_super_block *sb, bool encrypted,
                              const struct silofs_cipher_args *cip_args,
                              const char *password, const char *sb_path)
{
	int err;
	struct silofs_crypto crypto;
	struct silofs_hash512 hash;
	struct silofs_passphrase passph;

	err = silofs_crypto_init(&crypto);
	if (err) {
		silofs_die(err, "failed to create crypto: %s", sb_path);
	}
	err = silofs_sb_check_root(sb);
	if (err) {
		silofs_die(err, "not a valid super-block: %s", sb_path);
	}
	if (encrypted && password) {
		err = silofs_passphrase_setup(&passph, password);
		if (err) {
			silofs_die(err, "bad password (password-length: %d)",
			           strlen(password));
		}
		err = decrypt_super_block(sb, cip_args, &crypto, &passph);
		if (err) {
			silofs_die(err, "bad super-block: %s", sb_path);
		}
		silofs_sha3_512_of(&crypto.md, passph.pass,
		                   passph.passlen, &hash);
		err = silofs_sb_check_pass_hash(sb, &hash);
		if (err) {
			silofs_die(err, "illegal passphrase: %s", sb_path);
		}
	}
	err = silofs_sb_check_rand(sb, &crypto.md);
	if (err) {
		silofs_die(err, "corrupted super block: %s", sb_path);
	}
	silofs_crypto_fini(&crypto);
	silofs_passphrase_reset(&passph);
}

void silofs_die_if_bad_sb(const char *sb_path, const char *pass,
                          const struct silofs_cipher_args *cip_args)
{
	struct silofs_super_block *sb;

	sb = read_super_block(sb_path);
	check_super_block(sb, false, cip_args, pass, sb_path);
	del_super_block(sb);
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
		silofs_stat_ok(path, &st);
		if (st.st_ino != SILOFS_INO_ROOT) {
			silofs_die(0, "not a silofs mount-point: %s", path);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_require_valid_fsname(const char *arg_name, char **p_fsname)
{
	if (*p_fsname == NULL) {
		*p_fsname = silofs_strdup_safe(SILOFS_FSNAME_DEFAULT);
	} else {
		silofs_die_if_illegal_name(arg_name, *p_fsname);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *discover_unused_tmppath(const char *path)
{
	int err;
	char *tmppath = NULL;
	struct stat st = { .st_ino = 0 };

	for (int i = 1; i < 100; ++i) {
		tmppath = silofs_sprintf_path("%s.%02d~", path, i);
		err = silofs_sys_stat(tmppath, &st);
		if (err == -ENOENT) {
			break;
		}
		silofs_pfree_string(&tmppath);
	}
	return tmppath;
}

char *silofs_clone_as_tmppath(const char *path)
{
	int err = 0;
	int dst_fd = -1;
	int src_fd = -1;
	loff_t off_out = 0;
	struct stat st;
	const mode_t mode = S_IRUSR | S_IWUSR;
	char *tpath = NULL;

	err = silofs_sys_stat(path, &st);
	if (err) {
		goto out;
	}
	tpath = discover_unused_tmppath(path);
	if (tpath == NULL) {
		goto out;
	}
	err = silofs_sys_open(tpath, O_CREAT | O_RDWR | O_EXCL, mode, &dst_fd);
	if (err) {
		goto out;
	}
	err = silofs_sys_ftruncate(dst_fd, st.st_size);
	if (err) {
		goto out;
	}
	err = silofs_sys_llseek(dst_fd, 0, SEEK_SET, &off_out);
	if (err) {
		goto out;
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &src_fd);
	if (err) {
		goto out;
	}
	err = silofs_sys_ioctl_ficlone(dst_fd, src_fd);
	if (err) {
		goto out;
	}
out:
	silofs_sys_closefd(&src_fd);
	silofs_sys_closefd(&dst_fd);
	if (err && tpath) {
		silofs_sys_unlink(tpath);
		silofs_pfree_string(&tpath);
	}
	return tpath;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

char *silofs_consume_cmdarg(const char *arg_name, bool last)
{
	char *arg = NULL;
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	if (optind >= argc) {
		silofs_die_missing_arg(arg_name);
	}
	arg = argv[optind++];
	if (last) {
		silofs_die_if_redundant_arg();
	}
	return arg;
}

int silofs_getopt_subcmd(const char *sopts, const struct option *lopts)
{
	int opt_index = 0;
	int argc = silofs_globals.cmd_argc;
	char **argv = silofs_globals.cmd_argv;

	return getopt_long(argc, argv, sopts, lopts, &opt_index);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long silofs_parse_size(const char *str)
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
void silofs_daemonize(void)
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

char *silofs_joinpath_safe(const char *path, const char *base)
{
	char *rpath;
	const size_t plen = strlen(path);
	const size_t blen = strlen(base);

	rpath = silofs_zalloc_safe(plen + blen + 2);
	memcpy(rpath, path, plen);
	memcpy(rpath + 1 + plen, base, blen);
	rpath[plen] = '/';
	rpath[plen + blen + 1] = '\0';
	return rpath;
}

char *silofs_realpath_safe(const char *path)
{
	char *real_path;

	real_path = realpath(path, NULL);
	if (real_path == NULL) {
		silofs_die(-errno, "realpath failure: '%s'", path);
	}
	return real_path;
}

char *silofs_basename_safe(const char *path)
{
	const char *base;
	const char *last = strrchr(path, '/');

	base = (last == NULL) ? path : (last + 1);
	silofs_die_if_illegal_name("basename", base);

	return silofs_strdup_safe(base);
}

char *silofs_lockfile_path(const char *dirpath)
{
	return silofs_joinpath_safe(dirpath, "silofs.lock");
}

static void silofs_access_ok(const char *path)
{
	int err;
	const uid_t uid = getuid();
	const gid_t gid = getgid();

	err = silofs_sys_access(path, R_OK);
	if (err == -ENOENT) {
		silofs_die(err, "no such path: %s", path);
	}
	if (err) {
		silofs_die(err, "no access: %s uid=%d gid=%d", path, uid, gid);
	}
}

void silofs_statfs_ok(const char *path, struct statfs *stfs)
{
	int err;

	silofs_access_ok(path);

	err = silofs_sys_statfs(path, stfs);
	if (err) {
		silofs_die(err, "statfs failure: %s", path);
	}
}

void silofs_stat_ok(const char *path, struct stat *st)
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

void silofs_stat_reg(const char *path, struct stat *st)
{
	silofs_stat_ok(path, st);
	if (!S_ISREG(st->st_mode)) {
		silofs_die(0, "not a regular file: %s", path);
	}
}

void silofs_stat_reg_or_dir(const char *path, struct stat *st)
{
	silofs_stat_ok(path, st);
	if (!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode)) {
		silofs_die(0, "not dir-or-reg: %s", path);
	}
}

void silofs_stat_reg_or_blk(const char *path, struct stat *st, loff_t *out_sz)
{
	silofs_stat_ok(path, st);
	if (!S_ISREG(st->st_mode) && !S_ISBLK(st->st_mode)) {
		silofs_die(0, "not a regular-file or block-device: %s", path);
	}
	if (S_ISREG(st->st_mode)) {
		*out_sz = st->st_size;
	} else {
		*out_sz = silofs_blkgetsize_ok(path);
	}
}


loff_t silofs_blkgetsize_ok(const char *path)
{
	int fd = -1;
	int err;
	size_t sz;

	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "open failure: %s", path);
	}
	err = silofs_sys_ioctl_blkgetsize64(fd, &sz);
	silofs_sys_close(fd);
	if (err) {
		silofs_die(err, "ioctl BLKGETSIZE64 failed: %s", path);
	}
	if (sz >= (size_t)(LONG_MAX)) {
		silofs_die(0, "illegal block-device size: %lu", sz);
	}
	return (loff_t)sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *silofs_zalloc_safe(size_t nbytes)
{
	int err;
	void *mem = NULL;

	err = silofs_zmalloc(nbytes, &mem);
	if (err) {
		silofs_die(-err, "alloc failed: nbytes=%lu", nbytes);
	}
	return mem;
}

void silofs_zfree_safe(void *ptr, size_t nbytes)
{
	if (ptr != NULL) {
		silofs_zfree(ptr, nbytes);
	}
}

void silofs_pfree_string(char **pp)
{
	if (*pp != NULL) {
		free(*pp);
		*pp = NULL;
	}
}

char *silofs_strdup_safe(const char *s)
{
	char *d = strdup(s);

	if (d == NULL) {
		silofs_die(errno, "strdup failed");
	}
	return d;
}

char *silofs_strndup_safe(const char *s, size_t n)
{
	char *d = strndup(s, n);

	if (d == NULL) {
		silofs_die(errno, "strndup failed: n=%lu", n);
	}
	return d;
}

char *silofs_sprintf_path(const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t path_size = PATH_MAX;
	char *path = silofs_zalloc_safe(path_size);
	char *path_dup;

	va_start(ap, fmt);
	n = vsnprintf(path, path_size - 1, fmt, ap);
	va_end(ap);

	if (n >= (int)path_size) {
		silofs_die(0, "illegal path-len %d", n);
	}
	path_dup = silofs_strdup_safe(path);
	silofs_pfree_string(&path);
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

void silofs_show_help_and_exit(const char **help_strings)
{
	const char *prefix = silofs_globals.name;

	show_help_strings(stdout, prefix, help_strings);
	exit(EXIT_SUCCESS);
}

void silofs_show_version_and_exit(const char *prog)
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
	silofs_globals.umsk = umask(0022);
	silofs_globals.umsk = umask(0022);
	silofs_globals.start_time = time(NULL);
	silofs_globals.dont_daemonize = false;
	silofs_globals.allow_coredump = false;
	silofs_globals.disable_ptrace = true; /* XXX */
	silofs_globals.log_mask = SILOFS_LOG_DEFAULT;

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pretty_size(size_t n, char *buf, size_t bsz)
{
	const size_t k = SILOFS_UKILO;
	const size_t m = SILOFS_UMEGA;
	const size_t g = SILOFS_UGIGA;

	if (n >= g) {
		snprintf(buf, bsz, "%0.1fG", (float)n / (float)g);
	} else if (n >= m) {
		snprintf(buf, bsz, "%0.1fM", (float)n / (float)m);
	} else if (n >= k) {
		snprintf(buf, bsz, "%0.1fK", (float)n / (float)k);
	} else {
		snprintf(buf, bsz, "%0.1f", (float)n);
	}
}


