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
#include "funtests.h"
#include <utime.h>
#include <error.h>
#include <time.h>

#define expect_ok(err_, fl_, ln_) \
	do_expect_ok(err_, __func__, fl_, ln_)
#define expect_err(err_, exp_, fl_, ln_) \
	do_expect_err(err_, exp_, __func__, fl_, ln_)

static const char *path_basename(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

static const char *syscall_name(const char *fn)
{
	const char *prefix = "ft_do_";
	const size_t preflen = strlen(prefix);

	if (!strncmp(prefix, fn, preflen)) {
		fn += preflen;
	}
	return fn;
}

static void do_expect_ok(int err, const char *fn, const char *fl, int ln)
{
	if (err != 0) {
		silofs_die_at(0, path_basename(fl), ln,
		              "%s ==> %d", syscall_name(fn), err);
	}
}

static void do_expect_err(int err, int exp, const char *fn,
                          const char *fl, int ln)
{
	if (err != exp) {
		silofs_die_at(0, path_basename(fl), ln,
		              "%s ==> %d (!%d)", syscall_name(fn), err, exp);
	}
}

void ft_do_syncfs(int fd, const char *fl, int ln)
{
	int res;

	res = silofs_sys_syncfs(fd);
	expect_ok(res, fl, ln);
}

void ft_do_fsync(int fd, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fsync(fd);
	expect_ok(res, fl, ln);
}

void ft_do_fsync_err(int fd, int err, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fsync(fd);
	expect_err(res, err, fl, ln);
}

void ft_do_stat(const char *path, struct stat *st, const char *fl, int ln)
{
	int res;

	res = silofs_sys_stat(path, st);
	expect_ok(res, fl, ln);
}

void ft_do_stat_err(const char *path, int err, const char *fl, int ln)
{
	struct stat st = { .st_size = -1 };
	int res;

	res = silofs_sys_stat(path, &st);
	expect_err(res, err, fl, ln);
}

void ft_do_stat_noent(const char *path, const char *fl, int ln)
{
	ft_do_stat_err(path, -ENOENT, fl, ln);
}

void ft_do_fstat(int fd, struct stat *st, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fstat(fd, st);
	expect_ok(res, fl, ln);
}

void ft_do_lstat(const char *path, struct stat *st, const char *fl, int ln)
{
	int res;

	res = silofs_sys_lstat(path, st);
	expect_ok(res, fl, ln);
}

void ft_do_lstat_err(const char *path, int err, const char *fl, int ln)
{
	struct stat st = { .st_size = -1 };
	int res;

	res = silofs_sys_lstat(path, &st);
	expect_err(res, err, fl, ln);
}

void ft_do_fstatat(int dirfd, const char *name, struct stat *st, int flags,
                   const char *fl, int ln)
{
	int res;

	res = silofs_sys_fstatat(dirfd, name, st, flags);
	expect_ok(res, fl, ln);
}

void ft_do_fstatat_err(int dirfd, const char *name, int flags,
                       int err, const char *fl, int ln)
{
	struct stat st = { .st_size = -1 };
	int res;

	res = silofs_sys_fstatat(dirfd, name, &st, flags);
	expect_err(res, err, fl, ln);
}

void ft_do_statx(int dirfd, const char *name, int flags, unsigned int mask,
                 struct statx *stx, const char *fl, int ln)
{
	int res;

	res = silofs_sys_statx(dirfd, name, flags, mask, stx);
	expect_ok(res, fl, ln);
}

void ft_do_statvfs(const char *path, struct statvfs *stv,
                   const char *fl, int ln)
{
	int res;

	res = silofs_sys_statvfs(path, stv);
	expect_ok(res, fl, ln);
}

void ft_do_statvfs_err(const char *path, int err, const char *fl, int ln)
{
	struct statvfs stv = { .f_bsize = 0 };
	int res;

	res = silofs_sys_statvfs(path, &stv);
	expect_err(res, err, fl, ln);
}

void ft_do_fstatvfs(int fd, struct statvfs *stvfs, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fstatvfs(fd, stvfs);
	expect_ok(res, fl, ln);
}

void ft_do_utime(const char *path, const struct utimbuf *tm,
                 const char *fl, int ln)
{
	int res;

	res = silofs_sys_utime(path, tm);
	expect_ok(res, fl, ln);
}

void ft_do_utimes(const char *path, const struct timeval tm[2],
                  const char *fl, int ln)
{
	int res;

	res = silofs_sys_utimes(path, tm);
	expect_ok(res, fl, ln);
}

void ft_do_utimensat(int dirfd, const char *name,
                     const struct timespec tm[2], int flags,
                     const char *fl, int ln)
{
	int res;

	res = silofs_sys_utimensat(dirfd, name, tm, flags);
	expect_ok(res, fl, ln);
}

void ft_do_futimens(int fd, const struct timespec tm[2],
                    const char *fl, int ln)
{
	int res;

	res = silofs_sys_futimens(fd, tm);
	expect_ok(res, fl, ln);
}

void ft_do_mkdir(const char *path, mode_t mode, const char *fl, int ln)
{
	int res;

	res = silofs_sys_mkdir(path, mode);
	expect_ok(res, fl, ln);
}

void ft_do_mkdir_err(const char *path, mode_t mode, int err,
                     const char *fl, int ln)
{
	int res;

	res = silofs_sys_mkdir(path, mode);
	expect_err(res, err, fl, ln);
}

void ft_do_mkdirat(int dirfd, const char *name, mode_t mode,
                   const char *fl, int ln)
{
	int res;

	res = silofs_sys_mkdirat(dirfd, name, mode);
	expect_ok(res, fl, ln);
}

void ft_do_rmdir(const char *path, const char *fl, int ln)
{
	int res;

	res = silofs_sys_rmdir(path);
	expect_ok(res, fl, ln);
}

void ft_do_rmdir_err(const char *path, int err, const char *fl, int ln)
{
	int res;

	res = silofs_sys_rmdir(path);
	expect_err(res, err, fl, ln);
}

void ft_do_unlink(const char *path, const char *fl, int ln)
{
	int res;

	res = silofs_sys_unlink(path);
	expect_ok(res, fl, ln);
}

void ft_do_unlink_err(const char *path, int err, const char *fl, int ln)
{
	int res;

	res = silofs_sys_unlink(path);
	expect_err(res, err, fl, ln);
}

void ft_do_unlink_noent(const char *path, const char *fl, int ln)
{
	ft_do_unlink_err(path, -ENOENT, fl, ln);
}

void ft_do_unlinkat(int dirfd, const char *name, int flags,
                    const char *fl, int ln)
{
	int res;

	res = silofs_sys_unlinkat(dirfd, name, flags);
	expect_ok(res, fl, ln);
}

static void ft_do_unlinkat_err(int dirfd, const char *name, int flags,
                               int err, const char *fl, int ln)
{
	int res;

	res = silofs_sys_unlinkat(dirfd, name, flags);
	expect_err(res, err, fl, ln);
}

void ft_do_unlinkat_noent(int dirfd, const char *name, const char *fl, int ln)
{
	ft_do_unlinkat_err(dirfd, name, 0, -ENOENT, fl, ln);
}

void ft_do_open(const char *path, int flags, mode_t mode,
                int *out_fd, const char *fl, int ln)
{
	int res;

	res = silofs_sys_open(path, flags, mode, out_fd);
	expect_ok(res, fl, ln);
}

void ft_do_open_err(const char *path, int flags, mode_t mode, int err,
                    const char *fl, int ln)
{
	int fd = -1;
	int res;

	res = silofs_sys_open(path, flags, mode, &fd);
	expect_err(res, err, fl, ln);
}

void ft_do_openat(int dirfd, const char *name, int flags, mode_t mode,
                  int *out_fd, const char *fl, int ln)
{
	int res;

	res = silofs_sys_openat(dirfd, name, flags, mode, out_fd);
	expect_ok(res, fl, ln);
}

void ft_do_openat_err(int dirfd, const char *name, int flags, mode_t mode,
                      int err, const char *fl, int ln)
{
	int fd = -1;
	int res;

	res = silofs_sys_openat(dirfd, name, flags, mode, &fd);
	expect_err(res, err, fl, ln);
}

void ft_do_creat(const char *path, mode_t mode, int *out_fd,
                 const char *fl, int ln)
{
	int res;

	res = silofs_sys_creat(path, mode, out_fd);
	expect_ok(res, fl, ln);
}

void ft_do_close(int fd, const char *fl, int ln)
{
	int res;

	res = silofs_sys_close(fd);
	expect_ok(res, fl, ln);
}

void ft_do_truncate(const char *path, loff_t len, const char *fl, int ln)
{
	int res;

	res = silofs_sys_truncate(path, len);
	expect_ok(res, fl, ln);
}

void ft_do_ftruncate(int fd, loff_t len, const char *fl, int ln)
{
	int res;

	res = silofs_sys_ftruncate(fd, len);
	expect_ok(res, fl, ln);
}

void ft_do_llseek(int fd, loff_t off, int whence, loff_t *out_pos,
                  const char *fl, int ln)
{
	int res;

	res = silofs_sys_llseek(fd, off, whence, out_pos);
	expect_ok(res, fl, ln);
}

void ft_do_llseek_err(int fd, loff_t off, int whence, int err,
                      const char *fl, int ln)
{
	loff_t pos = -1;
	int res;

	res = silofs_sys_llseek(fd, off, whence, &pos);
	expect_err(res, err, fl, ln);
}

void ft_do_write(int fd, const void *buf, size_t cnt, size_t *out_nwr,
                 const char *fl, int ln)
{
	int res;

	res = silofs_sys_write(fd, buf, cnt, out_nwr);
	expect_ok(res, fl, ln);
}

void ft_do_write_err(int fd, const void *buf, size_t cnt, int err,
                     const char *fl, int ln)
{
	size_t nwr = 0;
	int res;

	res = silofs_sys_write(fd, buf, cnt, &nwr);
	expect_err(res, err, fl, ln);
}

void ft_do_pwrite(int fd, const void *buf, size_t cnt, loff_t off,
                  size_t *out_nwr, const char *fl, int ln)
{
	int res;

	res = silofs_sys_pwrite(fd, buf, cnt, off, out_nwr);
	expect_ok(res, fl, ln);
}

void ft_do_pwrite_err(int fd, const void *buf,
                      size_t cnt, loff_t off, int err, const char *fl, int ln)
{
	size_t nwr = 0;
	int res;

	res = silofs_sys_pwrite(fd, buf, cnt, off, &nwr);
	expect_err(res, err, fl, ln);
}

void ft_do_read(int fd, void *buf, size_t cnt, size_t *out_nrd,
                const char *fl, int ln)
{
	int res;

	res = silofs_sys_read(fd, buf, cnt, out_nrd);
	expect_ok(res, fl, ln);
}

void ft_do_read_err(int fd, void *buf, size_t cnt, int err,
                    const char *fl, int ln)
{
	size_t nrd = 0;
	int res;

	res = silofs_sys_read(fd, buf, cnt, &nrd);
	expect_err(res, err, fl, ln);
}

void ft_do_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *out_nrd,
                 const char *fl, int ln)
{
	int res;

	res = silofs_sys_pread(fd, buf, cnt, off, out_nrd);
	expect_ok(res, fl, ln);
}

void ft_do_fallocate(int fd, int mode, loff_t off, loff_t len,
                     const char *fl, int ln)
{
	int res;

	res = silofs_sys_fallocate(fd, mode, off, len);
	expect_ok(res, fl, ln);
}

void ft_do_fallocate_err(int fd, int mode, loff_t off, loff_t len, int err,
                         const char *fl, int ln)
{
	int res;

	res = silofs_sys_fallocate(fd, mode, off, len);
	expect_err(res, err, fl, ln);
}

void ft_do_fdatasync(int fd, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fdatasync(fd);
	expect_ok(res, fl, ln);
}

void ft_do_mkfifo(const char *path, mode_t mode, const char *fl, int ln)
{
	int res;

	res = silofs_sys_mkfifo(path, mode);
	expect_ok(res, fl, ln);
}

void ft_do_mkfifoat(int dirfd, const char *name, mode_t mode,
                    const char *fl, int ln)
{
	int res;

	res = silofs_sys_mkfifoat(dirfd, name, mode);
	expect_ok(res, fl, ln);
}

void ft_do_mknod(const char *path, mode_t mode, dev_t dev,
                 const char *fl, int ln)
{
	int res;

	res = silofs_sys_mknod(path, mode, dev);
	expect_ok(res, fl, ln);
}

void ft_do_mknodat(int dirfd, const char *name, mode_t mode, dev_t dev,
                   const char *fl, int ln)
{
	int res;

	res = silofs_sys_mknodat(dirfd, name, mode, dev);
	expect_ok(res, fl, ln);
}

void ft_do_symlink(const char *oldpath, const char *newpath,
                   const char *fl, int ln)
{
	int res;

	res = silofs_sys_symlink(oldpath, newpath);
	expect_ok(res, fl, ln);
}

void ft_do_symlinkat(const char *target, int dirfd, const char *linkpath,
                     const char *fl, int ln)
{
	int res;

	res = silofs_sys_symlinkat(target, dirfd, linkpath);
	expect_ok(res, fl, ln);
}

void ft_do_readlink(const char *path, char *buf, size_t bsz, size_t *out_cnt,
                    const char *fl, int ln)
{
	int res;

	res = silofs_sys_readlink(path, buf, bsz, out_cnt);
	expect_ok(res, fl, ln);
}

void ft_do_readlink_err(const char *path, char *buf, size_t bsz, int err,
                        const char *fl, int ln)
{
	size_t cnt = 0;
	int res;

	res = silofs_sys_readlink(path, buf, bsz, &cnt);
	expect_err(res, err, fl, ln);
}

void ft_do_readlinkat(int dirfd, const char *name, char *buf, size_t bsz,
                      size_t *out_cnt, const char *fl, int ln)
{
	int res;

	res = silofs_sys_readlinkat(dirfd, name, buf, bsz, out_cnt);
	expect_ok(res, fl, ln);
}

void ft_do_rename(const char *oldpath, const char *newpath,
                  const char *fl, int ln)
{
	int res;

	res = silofs_sys_rename(oldpath, newpath);
	expect_ok(res, fl, ln);
}

void ft_do_rename_err(const char *oldpath, const char *newpath, int err,
                      const char *fl, int ln)
{
	int res;

	res = silofs_sys_rename(oldpath, newpath);
	expect_err(res, err, fl, ln);
}

void ft_do_renameat(int olddirfd, const char *oldpath,
                    int newdirfd, const char *newpath, const char *fl, int ln)
{
	int res;

	res = silofs_sys_renameat(olddirfd, oldpath, newdirfd, newpath);
	expect_ok(res, fl, ln);
}

void ft_do_renameat2(int olddirfd, const char *oldpath,
                     int newdirfd, const char *newpath, unsigned int flags,
                     const char *fl, int ln)
{
	int res;

	res = silofs_sys_renameat2(olddirfd, oldpath,
	                           newdirfd, newpath, flags);
	expect_ok(res, fl, ln);
}

void ft_do_link(const char *oldpath, const char *newpath,
                const char *fl, int ln)
{
	int res;

	res = silofs_sys_link(oldpath, newpath);
	expect_ok(res, fl, ln);
}

void ft_do_link_err(const char *oldpath, const char *newpath, int err,
                    const char *fl, int ln)
{
	int res;

	res = silofs_sys_link(oldpath, newpath);
	expect_err(res, err, fl, ln);
}

void ft_do_linkat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, int flags,
                  const char *fl, int ln)
{
	int res;

	res = silofs_sys_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
	expect_ok(res, fl, ln);
}

void ft_do_linkat_err(int olddirfd, const char *oldpath,
                      int newdirfd, const char *newpath,
                      int flags, int err, const char *fl, int ln)
{
	int res;

	res = silofs_sys_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
	expect_err(res, err, fl, ln);
}

void ft_do_chmod(const char *path, mode_t mode, const char *fl, int ln)
{
	int res;

	res = silofs_sys_chmod(path, mode);
	expect_ok(res, fl, ln);
}

void ft_do_fchmod(int fd, mode_t mode, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fchmod(fd, mode);
	expect_ok(res, fl, ln);
}

void ft_do_fchmod_err(int fd, mode_t mode, int err, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fchmod(fd, mode);
	expect_err(res, err, fl, ln);
}

void ft_do_chown(const char *path, uid_t uid, gid_t gid,
                 const char *fl, int ln)
{
	int res;

	res = silofs_sys_chown(path, uid, gid);
	expect_ok(res, fl, ln);
}

void ft_do_fchown(int fd, uid_t uid, gid_t gid, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fchown(fd, uid, gid);
	expect_ok(res, fl, ln);
}

void ft_do_access(const char *path, int mode, const char *fl, int ln)
{
	int res;

	res = silofs_sys_access(path, mode);
	expect_ok(res, fl, ln);
}

void ft_do_access_err(const char *path, int mode, int err,
                      const char *fl, int ln)
{
	int res;

	res = silofs_sys_access(path, mode);
	expect_err(res, err, fl, ln);
}

void ft_do_mmap(void *addr, size_t len, int prot, int flags,
                int fd, off_t offset, void **out, const char *fl, int ln)
{
	int res;

	res = silofs_sys_mmap(addr, len, prot, flags, fd, offset, out);
	expect_ok(res, fl, ln);
}

void ft_do_munmap(void *addr, size_t len, const char *fl, int ln)
{
	int res;

	res = silofs_sys_munmap(addr, len);
	expect_ok(res, fl, ln);
}

void ft_do_msync(void *addr, size_t len, int flags, const char *fl, int ln)
{
	int res;

	res = silofs_sys_msync(addr, len, flags);
	expect_ok(res, fl, ln);
}

void ft_do_madvise(void *addr, size_t len, int advice, const char *fl, int ln)
{
	int res;

	res = silofs_sys_madvise(addr, len, advice);
	expect_ok(res, fl, ln);
}

void ft_do_setxattr(const char *path, const char *name, const void *value,
                    size_t size, int flags, const char *fl, int ln)
{
	int res;

	res = silofs_sys_setxattr(path, name, value, size, flags);
	expect_ok(res, fl, ln);
}

void ft_do_lsetxattr(const char *path, const char *name, const void *value,
                     size_t size, int flags, const char *fl, int ln)
{
	int res;

	res = silofs_sys_lsetxattr(path, name, value, size, flags);
	expect_ok(res, fl, ln);
}

void ft_do_fsetxattr(int fd, const char *name, const void *value,
                     size_t size, int flags, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fsetxattr(fd, name, value, size, flags);
	expect_ok(res, fl, ln);
}

void ft_do_getxattr(const char *path, const char *name, void *value,
                    size_t size, size_t *out_cnt, const char *fl, int ln)
{
	int res;

	res = silofs_sys_getxattr(path, name, value, size, out_cnt);
	expect_ok(res, fl, ln);
}

void ft_do_getxattr_err(const char *path, const char *name, int err,
                        const char *fl, int ln)
{
	size_t cnt = 0;
	int res;

	res = silofs_sys_getxattr(path, name, NULL, 0, &cnt);
	expect_err(res, err, fl, ln);
}

void ft_do_lgetxattr(const char *path, const char *name, void *value,
                     size_t size, size_t *out_cnt, const char *fl, int ln)
{
	int res;

	res = silofs_sys_lgetxattr(path, name, value, size, out_cnt);
	expect_ok(res, fl, ln);
}

void ft_do_fgetxattr(int fd, const char *name, void *value, size_t size,
                     size_t *out_cnt, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fgetxattr(fd, name, value, size, out_cnt);
	expect_ok(res, fl, ln);
}

void ft_do_fgetxattr_err(int fd, const char *name, int err,
                         const char *fl, int ln)
{
	size_t cnt = 0;
	int res;

	res = silofs_sys_fgetxattr(fd, name, NULL, 0, &cnt);
	expect_err(res, err, fl, ln);
}

void ft_do_removexattr(const char *path, const char *name,
                       const char *fl, int ln)
{
	int res;

	res = silofs_sys_removexattr(path, name);
	expect_ok(res, fl, ln);
}

void ft_do_lremovexattr(const char *path, const char *name,
                        const char *fl, int ln)
{
	int res;

	res = silofs_sys_lremovexattr(path, name);
	expect_ok(res, fl, ln);
}

void ft_do_fremovexattr(int fd, const char *name, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fremovexattr(fd, name);
	expect_ok(res, fl, ln);
}

void ft_do_fremovexattr_err(int fd, const char *name, int err,
                            const char *fl, int ln)
{
	int res;

	res = silofs_sys_fremovexattr(fd, name);
	expect_err(res, err, fl, ln);
}

void ft_do_listxattr(const char *path, char *list, size_t size, size_t *out,
                     const char *fl, int ln)
{
	int res;

	res = silofs_sys_listxattr(path, list, size, out);
	expect_ok(res, fl, ln);
}

void ft_do_llistxattr(const char *path, char *list, size_t size, size_t *out,
                      const char *fl, int ln)
{
	int res;

	res = silofs_sys_llistxattr(path, list, size, out);
	expect_ok(res, fl, ln);
}

void ft_do_flistxattr(int fd, char *list, size_t size, size_t *out,
                      const char *fl, int ln)
{
	int res;

	res = silofs_sys_flistxattr(fd, list, size, out);
	expect_ok(res, fl, ln);
}

void ft_do_flistxattr_err(int fd, char *list, size_t size, int err,
                          const char *fl, int ln)
{
	size_t len = 0;
	int res;

	res = silofs_sys_flistxattr(fd, list, size, &len);
	expect_err(res, err, fl, ln);
}

void ft_do_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                           loff_t *off_out, size_t len, size_t *out_ncp,
                           const char *fl, int ln)
{
	int res;

	res = silofs_sys_copy_file_range(fd_in, off_in, fd_out,
	                                 off_out, len, 0, out_ncp);
	expect_ok(res, fl, ln);
}

void ft_do_fiemap(int fd, struct fiemap *fm, const char *fl, int ln)
{
	int res;

	res = silofs_sys_fiemap(fd, fm);
	expect_ok(res, fl, ln);
}

void ft_do_getdents(int fd, void *buf, size_t bsz,
                    struct dirent64 *des, size_t ndes, size_t *out_ndes,
                    const char *fl, int ln)
{
	int res;

	res = silofs_sys_getdents(fd, buf, bsz, des, ndes, out_ndes);
	expect_ok(res, fl, ln);
}

void ft_do_getdent(int fd, struct dirent64 *dent, const char *fl, int ln)
{
	char buf[1024];
	size_t nde = 0;

	ft_do_getdents(fd, buf, sizeof(buf), dent, 1, &nde, fl, ln);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_readn(int fd, void *buf, size_t cnt, const char *fl, int ln)
{
	uint8_t *ptr = NULL;
	size_t nrd = 0;
	size_t nrd_cur = 0;

	while (nrd < cnt) {
		ptr = (uint8_t *)buf + nrd;
		nrd_cur = 0;
		ft_do_read(fd, ptr, cnt - nrd, &nrd_cur, fl, ln);
		if (!nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	ft_expect_eq(nrd, cnt);
}

void ft_do_preadn(int fd, void *buf, size_t cnt, loff_t off,
                  const char *fl, int ln)
{
	uint8_t *ptr = NULL;
	loff_t pos = 0;
	size_t nrd = 0;
	size_t nrd_cur = 0;

	while (nrd < cnt) {
		ptr = (uint8_t *)buf + nrd;
		pos = off + (loff_t)nrd;
		nrd_cur = 0;
		ft_do_pread(fd, ptr, cnt - nrd, pos, &nrd_cur, fl, ln);
		if (!nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	ft_expect_eq(nrd, cnt);
}

void ft_do_writen(int fd, const void *buf, size_t cnt, const char *fl, int ln)
{
	const uint8_t *ptr = NULL;
	size_t nwr = 0;
	size_t nwr_cur = 0;

	while (nwr < cnt) {
		ptr = (const uint8_t *)buf + nwr;
		ft_do_write(fd, ptr, cnt - nwr, &nwr_cur, fl, ln);
		if (!nwr_cur) {
			break;
		}
		nwr += nwr_cur;
		nwr_cur = 0;
	}
	ft_expect_eq(nwr, cnt);
}

void ft_do_pwriten(int fd, const void *buf, size_t cnt, loff_t off,
                   const char *fl, int ln)
{
	const uint8_t *ptr = NULL;
	loff_t pos = 0;
	size_t nwr = 0;
	size_t nwr_cur = 0;

	while (nwr < cnt) {
		ptr = (const uint8_t *)buf + nwr;
		pos = off + (loff_t)nwr;
		nwr_cur = 0;
		ft_do_pwrite(fd, ptr, cnt - nwr, pos, &nwr_cur, fl, ln);
		if (!nwr_cur) {
			break;
		}
		nwr += nwr_cur;
	}
	ft_expect_eq(nwr, cnt);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ft_do_ioctl_syncfs(int fd, const char *fl, int ln)
{
	struct silofs_ioc_syncfs syncfs = { .flags = 0 };
	int res;

	res = silofs_sys_ioctlp(fd, SILOFS_IOC_SYNCFS, &syncfs);
	expect_ok(res, fl, ln);
}
