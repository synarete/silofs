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
#include "vfstests.h"
#include <utime.h>
#include <error.h>
#include <time.h>


#define expect_ok(err)          do_expect_ok(err, __func__)
#define expect_err(err, x)      do_expect_err(err, x, __func__)


static const char *syscall_name(const char *fn)
{
	const char *prefix = "vt_";
	const size_t preflen = strlen(prefix);

	if (!strncmp(prefix, fn, preflen)) {
		fn += preflen;
	}
	return fn;
}

static void do_expect_ok(int err, const char *fn)
{
	if (err != 0) {
		silofs_panic("%s ==> %d", syscall_name(fn), err);
	}
}

static void do_expect_err(int err, int exp, const char *fn)
{
	if (err != exp) {
		silofs_panic("%s ==> %d (!%d)", syscall_name(fn), err, exp);
	}
}

void vt_syncfs(int fd)
{
	expect_ok(silofs_sys_syncfs(fd));
}

void vt_fsync(int fd)
{
	expect_ok(silofs_sys_fsync(fd));
}

void vt_stat(const char *path, struct stat *st)
{
	expect_ok(silofs_sys_stat(path, st));
}

void vt_stat_exists(const char *path)
{
	struct stat st;

	vt_stat(path, &st);
}

void vt_stat_err(const char *path, int err)
{
	struct stat st;

	expect_err(silofs_sys_stat(path, &st), err);
}

void vt_stat_noent(const char *path)
{
	struct stat st;

	expect_err(silofs_sys_stat(path, &st), -ENOENT);
}

void vt_fstat(int fd, struct stat *st)
{
	expect_ok(silofs_sys_fstat(fd, st));
}

void vt_lstat(const char *path, struct stat *st)
{
	expect_ok(silofs_sys_lstat(path, st));
}

void vt_fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
	expect_ok(silofs_sys_fstatat(dirfd, path, st, flags));
}

void vt_fstatat_err(int dirfd, const char *path, int flags, int err)
{
	struct stat st;

	expect_err(silofs_sys_fstatat(dirfd, path, &st, flags), err);
}

void vt_lstat_err(const char *path, int err)
{
	struct stat st;

	expect_err(silofs_sys_lstat(path, &st), err);
}

void vt_statx(int dfd, const char *pathname, int flags,
              unsigned int mask, struct statx *stx)
{
	expect_ok(silofs_sys_statx(dfd, pathname, flags, mask, stx));
}

void vt_statvfs(const char *path, struct statvfs *stv)
{
	expect_ok(silofs_sys_statvfs(path, stv));
}

void vt_statvfs_err(const char *path, int err)
{
	struct statvfs stv;

	expect_err(silofs_sys_statvfs(path, &stv), err);
}

void vt_fstatvfs(int fd, struct statvfs *stvfs)
{
	expect_ok(silofs_sys_fstatvfs(fd, stvfs));
}

void vt_utime(const char *filename, const struct utimbuf *times)
{
	expect_ok(silofs_sys_utime(filename, times));
}

void vt_utimes(const char *filename, const struct timeval tm[2])
{
	expect_ok(silofs_sys_utimes(filename, tm));
}

void vt_utimensat(int dirfd, const char *pathname,
                  const struct timespec tm[2], int flags)
{
	expect_ok(silofs_sys_utimensat(dirfd, pathname, tm, flags));
}

void vt_futimens(int fd, const struct timespec times[2])
{
	expect_ok(silofs_sys_futimens(fd, times));
}

void vt_mkdir(const char *path, mode_t mode)
{
	expect_ok(silofs_sys_mkdir(path, mode));
}

void vt_mkdir_err(const char *path, mode_t mode, int err)
{
	expect_err(silofs_sys_mkdir(path, mode), err);
}

void vt_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	expect_ok(silofs_sys_mkdirat(dirfd, pathname, mode));
}

void vt_rmdir(const char *path)
{
	expect_ok(silofs_sys_rmdir(path));
}

void vt_rmdir_err(const char *path, int err)
{
	expect_err(silofs_sys_rmdir(path), err);
}

void vt_unlink(const char *path)
{
	expect_ok(silofs_sys_unlink(path));
}

void vt_unlink_err(const char *path, int err)
{
	expect_err(silofs_sys_unlink(path), err);
}

void vt_unlink_noent(const char *path)
{
	vt_unlink_err(path, -ENOENT);
}

void vt_unlinkat(int dirfd, const char *pathname, int flags)
{
	expect_ok(silofs_sys_unlinkat(dirfd, pathname, flags));
}

void vt_open(const char *path, int flags, mode_t mode, int *fd)
{
	expect_ok(silofs_sys_open(path, flags, mode, fd));
}

void vt_open_err(const char *path, int flags, mode_t mode, int err)
{
	int fd;

	expect_err(silofs_sys_open(path, flags, mode, &fd), err);
}

void vt_openat(int dirfd, const char *path,
               int flags, mode_t mode, int *fd)
{
	expect_ok(silofs_sys_openat(dirfd, path, flags, mode, fd));
}

void vt_openat_err(int dirfd, const char *path,
                   int flags, mode_t mode, int err)
{
	int fd;

	expect_err(silofs_sys_openat(dirfd, path, flags, mode, &fd), err);
}


void vt_creat(const char *path, mode_t mode, int *fd)
{
	expect_ok(silofs_sys_creat(path, mode, fd));
}

void vt_close(int fd)
{
	expect_ok(silofs_sys_close(fd));
}

void vt_truncate(const char *path, loff_t len)
{
	expect_ok(silofs_sys_truncate(path, len));
}

void vt_ftruncate(int fd, loff_t len)
{
	expect_ok(silofs_sys_ftruncate(fd, len));
}

void vt_llseek(int fd, loff_t off, int whence, loff_t *pos)
{
	expect_ok(silofs_sys_llseek(fd, off, whence, pos));
}

void vt_llseek_err(int fd, loff_t off, int whence, int err)
{
	loff_t pos;

	expect_err(silofs_sys_llseek(fd, off, whence, &pos), err);
}

void vt_write(int fd, const void *buf, size_t cnt, size_t *nwr)
{
	expect_ok(silofs_sys_write(fd, buf, cnt, nwr));
}

void vt_pwrite(int fd, const void *buf, size_t cnt, loff_t off, size_t *nwr)
{
	expect_ok(silofs_sys_pwrite(fd, buf, cnt, off, nwr));
}

void vt_pwrite_err(int fd, const void *buf,
                   size_t cnt, loff_t off, int err)
{
	size_t nwr;

	expect_err(silofs_sys_pwrite(fd, buf, cnt, off, &nwr), err);
}

void vt_read(int fd, void *buf, size_t cnt, size_t *nrd)
{
	expect_ok(silofs_sys_read(fd, buf, cnt, nrd));
}

void vt_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *nrd)
{
	expect_ok(silofs_sys_pread(fd, buf, cnt, off, nrd));
}

void vt_fallocate(int fd, int mode, loff_t off, loff_t len)
{
	expect_ok(silofs_sys_fallocate(fd, mode, off, len));
}

void vt_fallocate_err(int fd, int mode, loff_t off, loff_t len, int err)
{
	expect_err(silofs_sys_fallocate(fd, mode, off, len), err);
}

void vt_fdatasync(int fd)
{
	expect_ok(silofs_sys_fdatasync(fd));
}

void vt_mkfifo(const char *path, mode_t mode)
{
	expect_ok(silofs_sys_mkfifo(path, mode));
}

void vt_mkfifoat(int dirfd, const char *pathname, mode_t mode)
{
	expect_ok(silofs_sys_mkfifoat(dirfd, pathname, mode));
}

void vt_mknod(const char *pathname, mode_t mode, dev_t dev)
{
	expect_ok(silofs_sys_mknod(pathname, mode, dev));
}

void vt_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
	expect_ok(silofs_sys_mknodat(dirfd, pathname, mode, dev));
}

void vt_symlink(const char *oldpath, const char *newpath)
{
	expect_ok(silofs_sys_symlink(oldpath, newpath));
}

void vt_symlinkat(const char *target, int dirfd, const char *linkpath)
{
	expect_ok(silofs_sys_symlinkat(target, dirfd, linkpath));
}

void vt_readlink(const char *path, char *buf, size_t bsz, size_t *cnt)
{
	expect_ok(silofs_sys_readlink(path, buf, bsz, cnt));
}

void vt_readlink_err(const char *path, char *buf, size_t bsz, int err)
{
	size_t cnt;

	expect_err(silofs_sys_readlink(path, buf, bsz, &cnt), err);
}

void vt_readlinkat(int dirfd, const char *pathname,
                   char *buf, size_t bsz, size_t *cnt)
{
	expect_ok(silofs_sys_readlinkat(dirfd, pathname, buf, bsz, cnt));
}

void vt_rename(const char *oldpath, const char *newpath)
{
	expect_ok(silofs_sys_rename(oldpath, newpath));
}

void vt_rename_err(const char *oldpath, const char *newpath, int err)
{
	expect_err(silofs_sys_rename(oldpath, newpath), err);
}

void vt_renameat(int olddirfd, const char *oldpath,
                 int newdirfd, const char *newpath)
{
	expect_ok(silofs_sys_renameat(olddirfd, oldpath, newdirfd, newpath));
}

void vt_renameat2(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, unsigned int flags)
{
	expect_ok(silofs_sys_renameat2(olddirfd, oldpath,
	                               newdirfd, newpath, flags));
}

void vt_link(const char *path1, const char *path2)
{
	expect_ok(silofs_sys_link(path1, path2));
}

void vt_link_err(const char *path1, const char *path2, int err)
{
	expect_err(silofs_sys_link(path1, path2), err);
}

void vt_linkat(int olddirfd, const char *oldpath,
               int newdirfd, const char *newpath, int flags)
{
	expect_ok(silofs_sys_linkat(olddirfd, oldpath,
	                            newdirfd, newpath, flags));
}

void vt_linkat_err(int olddirfd, const char *oldpath,
                   int newdirfd, const char *newpath, int flags, int err)
{
	expect_err(silofs_sys_linkat(olddirfd, oldpath,
	                             newdirfd, newpath, flags), err);
}

void vt_chmod(const char *path, mode_t mode)
{
	expect_ok(silofs_sys_chmod(path, mode));
}

void vt_fchmod(int fd, mode_t mode)
{
	expect_ok(silofs_sys_fchmod(fd, mode));
}

void vt_chown(const char *path, uid_t uid, gid_t gid)
{
	expect_ok(silofs_sys_chown(path, uid, gid));
}

void vt_fchown(int fd, uid_t uid, gid_t gid)
{
	expect_ok(silofs_sys_fchown(fd, uid, gid));
}

void vt_access(const char *path, int mode)
{
	expect_ok(silofs_sys_access(path, mode));
}

void vt_access_err(const char *path, int mode, int err)
{
	expect_err(silofs_sys_access(path, mode), err);
}

void vt_mmap(void *addr, size_t length, int prot, int flags,
             int fd, off_t offset, void **out)
{
	expect_ok(silofs_sys_mmap(addr, length, prot, flags, fd, offset, out));
}

void vt_munmap(void *addr, size_t length)
{
	expect_ok(silofs_sys_munmap(addr, length));
}

void vt_msync(void *addr, size_t len, int flags)
{
	expect_ok(silofs_sys_msync(addr, len, flags));
}

void vt_madvise(void *addr, size_t len, int advice)
{
	expect_ok(silofs_sys_madvise(addr, len, advice));
}

void vt_setxattr(const char *path, const char *name,
                 const void *value, size_t size, int flags)
{
	expect_ok(silofs_sys_setxattr(path, name, value, size, flags));
}

void vt_lsetxattr(const char *path, const char *name,
                  const void *value, size_t size, int flags)
{
	expect_ok(silofs_sys_lsetxattr(path, name, value, size, flags));
}

void vt_fsetxattr(int fd, const char *name,
                  const void *value, size_t size, int flags)
{
	expect_ok(silofs_sys_fsetxattr(fd, name, value, size, flags));
}

void vt_getxattr(const char *path, const char *name,
                 void *value, size_t size, size_t *cnt)
{
	expect_ok(silofs_sys_getxattr(path, name, value, size, cnt));
}

void vt_getxattr_err(const char *path, const char *name, int err)
{
	size_t cnt;

	expect_err(silofs_sys_getxattr(path, name, NULL, 0, &cnt), err);
}

void vt_lgetxattr(const char *path, const char *name,
                  void *value, size_t size, size_t *cnt)
{
	expect_ok(silofs_sys_lgetxattr(path, name, value, size, cnt));
}

void vt_fgetxattr(int fd, const char *name,
                  void *value, size_t size, size_t *cnt)
{
	expect_ok(silofs_sys_fgetxattr(fd, name, value, size, cnt));
}

void vt_removexattr(const char *path, const char *name)
{
	expect_ok(silofs_sys_removexattr(path, name));
}

void vt_lremovexattr(const char *path, const char *name)
{
	expect_ok(silofs_sys_lremovexattr(path, name));
}

void vt_fremovexattr(int fd, const char *name)
{
	expect_ok(silofs_sys_fremovexattr(fd, name));
}

void vt_fremovexattr_err(int fd, const char *name, int err)
{
	expect_err(silofs_sys_fremovexattr(fd, name), err);
}

void vt_listxattr(const char *path, char *list, size_t size, size_t *out)
{
	expect_ok(silofs_sys_listxattr(path, list, size, out));
}

void vt_llistxattr(const char *path, char *list, size_t size, size_t *out)
{
	expect_ok(silofs_sys_llistxattr(path, list, size, out));
}

void vt_flistxattr(int fd, char *list, size_t size, size_t *out)
{
	expect_ok(silofs_sys_flistxattr(fd, list, size, out));
}

void vt_flistxattr_err(int fd, char *list, size_t size, int err)
{
	size_t len;

	expect_err(silofs_sys_flistxattr(fd, list, size, &len), err);
}

void vt_getdents(int fd, void *buf, size_t bsz,
                 struct dirent64 *des, size_t ndes, size_t *out_ndes)
{
	expect_ok(silofs_sys_getdents(fd, buf, bsz, des, ndes, out_ndes));
}

void vt_getdent(int fd, struct dirent64 *dent)
{
	size_t nde;
	char buf[1024];

	vt_getdents(fd, buf, sizeof(buf), dent, 1, &nde);
}

void vt_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                        loff_t *off_out, size_t len, size_t *out_ncp)
{
	expect_ok(silofs_sys_copy_file_range(fd_in, off_in, fd_out,
	                                     off_out, len, 0, out_ncp));
}

void vt_ioctl_ficlone(int dest_fd, int src_fd)
{
	expect_ok(silofs_sys_ioctl_ficlone(dest_fd, src_fd));
}


void vt_fiemap(int fd, struct fiemap *fm)
{
	expect_ok(silofs_sys_fiemap(fd, fm));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void vt_readn(int fd, void *buf, size_t cnt)
{
	char *ptr;
	size_t nrd = 0;
	size_t nrd_cur = 0;

	while (nrd < cnt) {
		ptr = (char *)buf + nrd;
		nrd_cur = 0;
		vt_read(fd, ptr, cnt - nrd, &nrd_cur);
		if (!nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	vt_expect_eq(nrd, cnt);
}

void vt_preadn(int fd, void *buf, size_t cnt, loff_t offset)
{
	char *ptr;
	loff_t off;
	size_t nrd = 0;
	size_t nrd_cur = 0;

	while (nrd < cnt) {
		ptr = (char *)buf + nrd;
		off = offset + (loff_t)nrd;
		nrd_cur = 0;
		vt_pread(fd, ptr, cnt - nrd, off, &nrd_cur);
		if (!nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	vt_expect_eq(nrd, cnt);
}

void vt_writen(int fd, const void *buf, size_t cnt)
{
	size_t nwr = 0;
	size_t nwr_cur = 0;
	const char *ptr = NULL;

	while (nwr < cnt) {
		ptr = (const char *)buf + nwr;
		vt_write(fd, ptr, cnt - nwr, &nwr_cur);
		if (!nwr_cur) {
			break;
		}
		nwr += nwr_cur;
		nwr_cur = 0;
	}
	vt_expect_eq(nwr, cnt);
}

void vt_pwriten(int fd, const void *buf, size_t cnt, loff_t offset)
{
	loff_t off;
	size_t nwr_cur;
	size_t nwr = 0;
	const char *ptr;

	while (nwr < cnt) {
		ptr = (const char *)buf + nwr;
		off = offset + (loff_t)nwr;
		nwr_cur = 0;
		vt_pwrite(fd, ptr, cnt - nwr, off, &nwr_cur);
		if (!nwr_cur) {
			break;
		}
		nwr += nwr_cur;
	}
	vt_expect_eq(nwr, cnt);
}
