/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include <silofs/configs.h>
#include <silofs/syscall.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <features.h>
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <utime.h>
#include <poll.h>
#include <time.h>
#include <sched.h>

#if _POSIX_C_SOURCE < 200809L
#error "_POSIX_C_SOURCE < 200809L"
#endif

#if _ATFILE_SOURCE != 1
#error "_ATFILE_SOURCE != 1"
#endif

static int errno_value(void)
{
	return (errno > 0) ? -errno : errno;
}

static int ok_or_errno(int err)
{
	return err ? errno_value() : 0;
}

static int val_or_errno(int val)
{
	return (val < 0) ? errno_value() : val;
}

static int val_or_errno2(int val, int *out_val)
{
	int err;

	if (val >= 0) {
		*out_val = val;
		err = 0;
	} else {
		err = errno_value();
		*out_val = -1;
	}
	return err;
}

static int fd_or_errno(int err, int *fd)
{
	if (err >= 0) {
		*fd = err;
		err = 0;
	} else {
		err = errno_value();
		*fd = -1;
	}
	return err;
}

static int nfds_or_errno(int err, int *nfds)
{
	if (err >= 0) {
		*nfds = err;
		err = 0;
	} else {
		err = errno_value();
		*nfds = -1;
	}
	return err;
}

static int size_or_errno(ssize_t res, size_t *cnt)
{
	int err;

	if (res >= 0) {
		err = 0;
		*cnt = (size_t)res;
	} else {
		err = errno_value();
		*cnt = 0;
	}
	return err;
}

static int off_or_errno(loff_t off, loff_t *out)
{
	int err;

	if (off >= 0) {
		err = 0;
		*out = off;
	} else {
		err = errno_value();
		*out = off;
	}
	return err;
}

static int differ_or_errno(void *ptr, void *errptr, void **out)
{
	int err;

	if (ptr == errptr) {
		err = errno_value();
		*out = NULL;
	} else {
		err = 0;
		*out = ptr;
	}
	return err;
}

static int errno_or_generic_error(void)
{
	const int errnum = errno_value();

	return errnum ? errnum : -EPERM;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sys_mount(const char *source, const char *target, const char *fstyp,
                     unsigned long mntflags, const void *data)
{
	return ok_or_errno(mount(source, target, fstyp, mntflags, data));
}

int silofs_sys_umount(const char *target)
{
	return ok_or_errno(umount(target));
}

int silofs_sys_umount2(const char *target, int flags)
{
	return ok_or_errno(umount2(target, flags));
}

int silofs_sys_chmod(const char *path, mode_t mode)
{
	return ok_or_errno(chmod(path, mode));
}

int silofs_sys_fchmod(int fd, mode_t mode)
{
	return ok_or_errno(fchmod(fd, mode));
}

int silofs_sys_fchmodat(int dirfd, const char *pathname, mode_t mode,
                        int flags)
{
	return ok_or_errno(fchmodat(dirfd, pathname, mode, flags));
}

int silofs_sys_chown(const char *path, uid_t uid, gid_t gid)
{
	return ok_or_errno(chown(path, uid, gid));
}

int silofs_sys_fchown(int fd, uid_t uid, gid_t gid)
{
	return ok_or_errno(fchown(fd, uid, gid));
}

int silofs_sys_fchownat(int dirfd, const char *pathname, uid_t uid, gid_t gid,
                        int flags)
{
	return ok_or_errno(fchownat(dirfd, pathname, uid, gid, flags));
}

int silofs_sys_utime(const char *filename, const struct utimbuf *times)
{
	return ok_or_errno(utime(filename, times));
}

int silofs_sys_utimes(const char *filename, const struct timeval times[2])
{
	return ok_or_errno(utimes(filename, times));
}

int silofs_sys_utimensat(int dirfd, const char *pathname,
                         const struct timespec times[2], int flags)
{
	return ok_or_errno(utimensat(dirfd, pathname, times, flags));
}

int silofs_sys_futimens(int fd, const struct timespec times[2])
{
	return ok_or_errno(futimens(fd, times));
}

int silofs_sys_mkdir(const char *path, mode_t mode)
{
	return ok_or_errno(mkdir(path, mode));
}

int silofs_sys_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	return ok_or_errno(mkdirat(dirfd, pathname, mode));
}

int silofs_sys_rmdir(const char *path)
{
	return ok_or_errno(rmdir(path));
}

int silofs_sys_creat(const char *path, mode_t mode, int *fd)
{
	return fd_or_errno(creat(path, mode), fd);
}

int silofs_sys_open(const char *path, int flags, mode_t mode, int *fd)
{
	return fd_or_errno(open(path, flags, mode), fd);
}

int silofs_sys_openat(int dirfd, const char *pathname, int flags, mode_t mode,
                      int *fd)
{
	return fd_or_errno(openat(dirfd, pathname, flags, mode), fd);
}

int silofs_sys_close(int fd)
{
	return ok_or_errno(close(fd));
}

int silofs_sys_access(const char *path, int mode)
{
	return ok_or_errno(access(path, mode));
}

int silofs_sys_faccessat(int dirfd, const char *pathname, int mode, int flags)
{
	return ok_or_errno(faccessat(dirfd, pathname, mode, flags));
}

int silofs_sys_link(const char *path1, const char *path2)
{
	return ok_or_errno(link(path1, path2));
}

int silofs_sys_linkat(int olddirfd, const char *oldpath, int newdirfd,
                      const char *newpath, int flags)
{
	return ok_or_errno(linkat(olddirfd, oldpath, newdirfd, newpath,
	                          flags));
}

int silofs_sys_unlink(const char *path)
{
	return ok_or_errno(unlink(path));
}

int silofs_sys_unlinkat(int dirfd, const char *pathname, int flags)
{
	return ok_or_errno(unlinkat(dirfd, pathname, flags));
}

int silofs_sys_rename(const char *oldpath, const char *newpath)
{
	return ok_or_errno(rename(oldpath, newpath));
}

int silofs_sys_renameat(int olddirfd, const char *oldpath, int newdirfd,
                        const char *newpath)
{
	return ok_or_errno(renameat(olddirfd, oldpath, newdirfd, newpath));
}

int silofs_sys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                         const char *newpath, unsigned int flags)
{
	return ok_or_errno(renameat2(olddirfd, oldpath, newdirfd, newpath,
	                             flags));
}

int silofs_sys_llseek(int fd, loff_t off, int whence, loff_t *pos)
{
	return off_or_errno(lseek64(fd, off, whence), pos);
}

int silofs_sys_syncfs(int fd)
{
	return ok_or_errno(syncfs(fd));
}

int silofs_sys_fsync(int fd)
{
	return ok_or_errno(fsync(fd));
}

int silofs_sys_fdatasync(int fd)
{
	return ok_or_errno(fdatasync(fd));
}

int silofs_sys_sync_file_range(int fd, loff_t off, loff_t nb, unsigned int fl)
{
	return ok_or_errno(sync_file_range(fd, off, nb, fl));
}

int silofs_sys_fallocate(int fd, int mode, loff_t off, loff_t len)
{
	return ok_or_errno(fallocate(fd, mode, off, len));
}

int silofs_sys_truncate(const char *path, loff_t len)
{
	return ok_or_errno(truncate(path, len));
}

int silofs_sys_ftruncate(int fd, loff_t len)
{
	return ok_or_errno(ftruncate(fd, len));
}

int silofs_sys_mkfifo(const char *path, mode_t mode)
{
	return ok_or_errno(mkfifo(path, mode));
}

int silofs_sys_mkfifoat(int dirfd, const char *pathname, mode_t mode)
{
	return ok_or_errno(mkfifoat(dirfd, pathname, mode));
}

int silofs_sys_mknod(const char *pathname, mode_t mode, dev_t dev)
{
	return ok_or_errno(mknod(pathname, mode, dev));
}

int silofs_sys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
	return ok_or_errno(mknodat(dirfd, pathname, mode, dev));
}

int silofs_sys_symlink(const char *oldpath, const char *newpath)
{
	return ok_or_errno(symlink(oldpath, newpath));
}

int silofs_sys_symlinkat(const char *target, int dirfd, const char *linkpath)
{
	return ok_or_errno(symlinkat(target, dirfd, linkpath));
}

int silofs_sys_readlink(const char *path, char *buf, size_t bsz, size_t *cnt)
{
	return size_or_errno(readlink(path, buf, bsz), cnt);
}

int silofs_sys_readlinkat(int dirfd, const char *pathname, char *buf,
                          size_t bsz, size_t *cnt)
{
	return size_or_errno(readlinkat(dirfd, pathname, buf, bsz), cnt);
}

int silofs_sys_fstat(int fd, struct stat *st)
{
	return ok_or_errno(fstat(fd, st));
}

int silofs_sys_fstatat(int dirfd, const char *pathname, struct stat *st,
                       int flags)
{
	return ok_or_errno(fstatat(dirfd, pathname, st, flags));
}

int silofs_sys_stat(const char *path, struct stat *st)
{
	return ok_or_errno(stat(path, st));
}

int silofs_sys_lstat(const char *path, struct stat *st)
{
	return ok_or_errno(lstat(path, st));
}

int silofs_sys_statx(int dfd, const char *pathname, int flags,
                     unsigned int mask, struct statx *stx)
{
	return ok_or_errno(statx(dfd, pathname, flags, mask, stx));
}

int silofs_sys_statvfs(const char *path, struct statvfs *stv)
{
	return ok_or_errno(statvfs(path, stv));
}

int silofs_sys_fstatvfs(int fd, struct statvfs *stv)
{
	return ok_or_errno(fstatvfs(fd, stv));
}

int silofs_sys_statfs(const char *path, struct statfs *stfs)
{
	return ok_or_errno(statfs(path, stfs));
}

int silofs_sys_fstatfs(int fd, struct statfs *stfs)
{
	return ok_or_errno(fstatfs(fd, stfs));
}

int silofs_sys_flock(int fd, int operation)
{
	return ok_or_errno(flock(fd, operation));
}

int silofs_sys_read(int fd, void *buf, size_t cnt, size_t *nrd)
{
	return size_or_errno(read(fd, buf, cnt), nrd);
}

int silofs_sys_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *nrd)
{
	return size_or_errno(pread(fd, buf, cnt, off), nrd);
}

int silofs_sys_write(int fd, const void *buf, size_t cnt, size_t *nwr)
{
	return size_or_errno(write(fd, buf, cnt), nwr);
}

int silofs_sys_pwrite(int fd, const void *buf, size_t cnt, loff_t off,
                      size_t *nwr)
{
	return size_or_errno(pwrite(fd, buf, cnt, off), nwr);
}

int silofs_sys_readv(int fd, const struct iovec *iov, int iovcnt, size_t *nrd)
{
	return size_or_errno(readv(fd, iov, iovcnt), nrd);
}

int silofs_sys_writev(int fd, const struct iovec *iov, int iovcnt, size_t *nwr)
{
	return size_or_errno(writev(fd, iov, iovcnt), nwr);
}

int silofs_sys_preadv(int fd, const struct iovec *iov, int iovcnt, off_t off,
                      size_t *nrd)
{
	return size_or_errno(preadv(fd, iov, iovcnt, off), nrd);
}

int silofs_sys_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t off,
                       size_t *nwr)
{
	return size_or_errno(pwritev(fd, iov, iovcnt, off), nwr);
}

int silofs_sys_preadv2(int fd, const struct iovec *iov, int iovcnt, off_t off,
                       int flags, size_t *nrd)
{
	return size_or_errno(preadv2(fd, iov, iovcnt, off, flags), nrd);
}

int silofs_sys_pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t off,
                        int flags, size_t *nwr)
{
	return size_or_errno(pwritev2(fd, iov, iovcnt, off, flags), nwr);
}

int silofs_sys_splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags, size_t *nsp)
{
	return size_or_errno(
		splice(fd_in, off_in, fd_out, off_out, len, flags), nsp);
}

int silofs_sys_vmsplice(int fd, const struct iovec *iov, size_t nr_segs,
                        unsigned int flags, size_t *nsp)
{
	return size_or_errno(vmsplice(fd, iov, nr_segs, flags), nsp);
}

int silofs_sys_ioctlp(int fd, unsigned long int cmd, void *ptr)
{
	return ok_or_errno(ioctl(fd, cmd, ptr));
}

int silofs_sys_fiemap(int fd, struct fiemap *fm)
{
	return silofs_sys_ioctlp(fd, FS_IOC_FIEMAP, fm);
}

int silofs_sys_setxattr(const char *path, const char *name, const void *value,
                        size_t size, int flags)
{
	return ok_or_errno(setxattr(path, name, value, size, flags));
}

int silofs_sys_lsetxattr(const char *path, const char *name, const void *value,
                         size_t size, int flags)
{
	return ok_or_errno(lsetxattr(path, name, value, size, flags));
}

int silofs_sys_fsetxattr(int fd, const char *name, const void *value,
                         size_t size, int flags)
{
	return ok_or_errno(fsetxattr(fd, name, value, size, flags));
}

int silofs_sys_getxattr(const char *path, const char *name, void *value,
                        size_t size, size_t *cnt)
{
	return size_or_errno(getxattr(path, name, value, size), cnt);
}

int silofs_sys_lgetxattr(const char *path, const char *name, void *value,
                         size_t size, size_t *cnt)
{
	return size_or_errno(lgetxattr(path, name, value, size), cnt);
}

int silofs_sys_fgetxattr(int fd, const char *name, void *value, size_t size,
                         size_t *cnt)
{
	return size_or_errno(fgetxattr(fd, name, value, size), cnt);
}

int silofs_sys_removexattr(const char *path, const char *name)
{
	return ok_or_errno(removexattr(path, name));
}

int silofs_sys_lremovexattr(const char *path, const char *name)
{
	return ok_or_errno(lremovexattr(path, name));
}

int silofs_sys_fremovexattr(int fd, const char *name)
{
	return ok_or_errno(fremovexattr(fd, name));
}

int silofs_sys_listxattr(const char *path, char *list, size_t size,
                         size_t *out_size)
{
	return size_or_errno(listxattr(path, list, size), out_size);
}

int silofs_sys_llistxattr(const char *path, char *list, size_t size,
                          size_t *out_size)
{
	return size_or_errno(llistxattr(path, list, size), out_size);
}

int silofs_sys_flistxattr(int fd, char *list, size_t size, size_t *out_size)
{
	return size_or_errno(flistxattr(fd, list, size), out_size);
}

int silofs_sys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                    loff_t offset, void **out_addr)
{
	return differ_or_errno(mmap(addr, length, prot, flags, fd, offset),
	                       MAP_FAILED, out_addr);
}

int silofs_sys_mmap_anon(size_t length, int xflags, void **out_addr)
{
	const int prot = PROT_WRITE | PROT_READ;
	const int flags = MAP_PRIVATE | MAP_ANONYMOUS;

	return silofs_sys_mmap(NULL, length, prot, flags | xflags, -1, 0,
	                       out_addr);
}

int silofs_sys_munmap(void *addr, size_t length)
{
	return ok_or_errno(munmap(addr, length));
}

int silofs_sys_msync(void *addr, size_t len, int flags)
{
	return ok_or_errno(msync(addr, len, flags));
}

int silofs_sys_madvise(void *addr, size_t len, int advice)
{
	return ok_or_errno(madvise(addr, len, advice));
}

int silofs_sys_mlock(const void *addr, size_t len)
{
	return ok_or_errno(mlock(addr, len));
}

int silofs_sys_mlock2(const void *addr, size_t len, unsigned int flags)
{
	return ok_or_errno(mlock2(addr, len, flags));
}

int silofs_sys_munlock(const void *addr, size_t len)
{
	return ok_or_errno(munlock(addr, len));
}

int silofs_sys_mlockall(int flags)
{
	return ok_or_errno(mlockall(flags));
}

int silofs_sys_munlockall(void)
{
	return ok_or_errno(munlockall());
}

int silofs_sys_brk(void *addr)
{
	return ok_or_errno(brk(addr));
}

int silofs_sys_sbrk(intptr_t increment, void **out_addr)
{
	return differ_or_errno(sbrk(increment), (void *)(-1), out_addr);
}

int silofs_sys_getrlimit(int resource, struct rlimit *rlim)
{
	return ok_or_errno(getrlimit((__rlimit_resource_t)resource, rlim));
}

int silofs_sys_setrlimit(int resource, const struct rlimit *rlim)
{
	return ok_or_errno(setrlimit((__rlimit_resource_t)resource, rlim));
}

int silofs_sys_prctl(int option, unsigned long arg2, unsigned long arg3,
                     unsigned long arg4, unsigned long arg5)
{
	return val_or_errno(prctl(option, arg2, arg3, arg4, arg5));
}

int silofs_sys_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                               loff_t *off_out, size_t len, unsigned int flags,
                               size_t *out_ncp)
{
	return size_or_errno(copy_file_range(fd_in, off_in, fd_out, off_out,
	                                     len, flags),
	                     out_ncp);
}

int silofs_sys_memfd_create(const char *name, unsigned int flags, int *fd)
{
	return fd_or_errno(memfd_create(name, flags), fd);
}

int silofs_sys_ioctl_blkgetsize64(int fd, size_t *sz)
{
	return ok_or_errno(ioctl(fd, BLKGETSIZE64, sz));
}

struct linux_dirent64_view {
	ino64_t d_ino;
	off64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[5];
};

int silofs_sys_getdents(int fd, void *buf, size_t bsz, struct dirent64 *dents,
                        size_t ndents, size_t *out_ndents)
{
	long nread;
	long pos = 0;
	size_t len;
	size_t ndents_decoded = 0;
	const struct linux_dirent64_view *d = NULL;
	void *ptr = buf;
	struct dirent64 *dent = dents;
	struct dirent64 *end = dents + ndents;

	errno = 0;
	if (!ndents || (bsz < sizeof(*dents))) {
		return -EINVAL;
	}
	nread = syscall(SYS_getdents64, fd, ptr, bsz);
	if (nread == -1) {
		return errno_or_generic_error();
	}
	if (nread == 0) {
		memset(dent, 0, sizeof(*dent));
		dent->d_off = -1;
		goto out; /* End-of-stream */
	}
	d = (const struct linux_dirent64_view *)ptr;
	if (d->d_reclen >= bsz) {
		return -EINVAL;
	}
	*out_ndents = 0;
	while ((pos < nread) && (dent < end)) {
		len = strlen(d->d_name);
		if (len >= sizeof(dent->d_name)) {
			return -ENAMETOOLONG;
		}
		memset(dent, 0, sizeof(*dent));
		dent->d_ino = d->d_ino;
		dent->d_off = (loff_t)d->d_off;
		dent->d_type = d->d_type;
		memcpy(dent->d_name, d->d_name, len);

		pos += d->d_reclen;
		ptr = (char *)buf + pos;
		d = (const struct linux_dirent64_view *)ptr;

		++ndents_decoded;
		++dent;
	}
out:
	*out_ndents = ndents_decoded;
	return 0;
}

int silofs_sys_sigaction(int signum, const struct sigaction *act,
                         struct sigaction *oldact)
{
	return ok_or_errno(sigaction(signum, act, oldact));
}

int silofs_sys_clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	return ok_or_errno(clock_gettime(clock_id, tp));
}

int silofs_sys_fcntl_flock(int fd, int cmd, struct flock *fl)
{
	return ok_or_errno(fcntl(fd, cmd, fl));
}

int silofs_sys_fcntl_getfl(int fd, int *out_fl)
{
	return val_or_errno2(fcntl(fd, F_GETFL), out_fl);
}

int silofs_sys_fcntl_setfl(int fd, int fl)
{
	return ok_or_errno(fcntl(fd, F_SETFL, fl));
}

int silofs_sys_fcntl_setpipesz(int fd, int pipesize)
{
	return ok_or_errno(fcntl(fd, F_SETPIPE_SZ, pipesize));
}

int silofs_sys_fcntl_getpipesz(int fd, int *out_pipesize)
{
	return val_or_errno2(fcntl(fd, F_GETPIPE_SZ), out_pipesize);
}

int silofs_sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, const struct timespec *timeout,
                       const sigset_t *sigmask, int *out_nfds)
{
	return nfds_or_errno(pselect(nfds, readfds, writefds, exceptfds,
	                             timeout, sigmask),
	                     out_nfds);
}

int silofs_sys_poll(struct pollfd *fds, nfds_t nfds, int timeout,
                    int *out_nfds)
{
	return nfds_or_errno(poll(fds, nfds, timeout), out_nfds);
}

int silofs_sys_socket(int domain, int type, int protocol, int *out_sd)
{
	return fd_or_errno(socket(domain, type, protocol), out_sd);
}

int silofs_sys_bind(int sd, const struct sockaddr *addr, socklen_t addrlen)
{
	return ok_or_errno(bind(sd, addr, addrlen));
}

int silofs_sys_send(int sd, const void *buf, size_t len, int flags,
                    size_t *out_sent)
{
	return size_or_errno(send(sd, buf, len, flags), out_sent);
}

int silofs_sys_sendto(int sd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen,
                      size_t *out_sent)
{
	return size_or_errno(sendto(sd, buf, len, flags, dest_addr, addrlen),
	                     out_sent);
}

int silofs_sys_sendmsg(int sd, const struct msghdr *msg, int flags,
                       size_t *out_sent)
{
	return size_or_errno(sendmsg(sd, msg, flags), out_sent);
}

int silofs_sys_recv(int sd, void *buf, size_t len, int flags, size_t *out_recv)
{
	return size_or_errno(recv(sd, buf, len, flags), out_recv);
}

int silofs_sys_recvfrom(int sd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen,
                        size_t *out_recv)
{
	return size_or_errno(recvfrom(sd, buf, len, flags, src_addr, addrlen),
	                     out_recv);
}

int silofs_sys_recvmsg(int sd, struct msghdr *msg, int flags, size_t *out_recv)
{
	return size_or_errno(recvmsg(sd, msg, flags), out_recv);
}

int silofs_sys_listen(int sd, int backlog)
{
	return ok_or_errno(listen(sd, backlog));
}

int silofs_sys_accept(int sd, struct sockaddr *addr, socklen_t *addrlen,
                      int *out_sd)
{
	return fd_or_errno(accept(sd, addr, addrlen), out_sd);
}

int silofs_sys_connect(int sd, const struct sockaddr *addr, socklen_t addrlen)
{
	return ok_or_errno(connect(sd, addr, addrlen));
}

int silofs_sys_shutdown(int sd, int how)
{
	return ok_or_errno(shutdown(sd, how));
}

int silofs_sys_setsockopt(int sd, int level, int optname, const void *optval,
                          socklen_t optlen)
{
	return ok_or_errno(setsockopt(sd, level, optname, optval, optlen));
}

int silofs_sys_getsockopt(int sd, int level, int optname, void *optval,
                          socklen_t *optlen)
{
	return ok_or_errno(getsockopt(sd, level, optname, optval, optlen));
}

int silofs_sys_pipe2(int pipefd[2], int flags)
{
	return ok_or_errno(pipe2(pipefd, flags));
}

int silofs_sys_seteuid(uid_t euid)
{
	return ok_or_errno(seteuid(euid));
}

int silofs_sys_setegid(gid_t egid)
{
	return ok_or_errno(setegid(egid));
}

int silofs_sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	return ok_or_errno(getresuid(ruid, euid, suid));
}

int silofs_sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	return ok_or_errno(getresgid(rgid, egid, sgid));
}

int silofs_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return ok_or_errno(setresuid(ruid, euid, suid));
}

int silofs_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	return ok_or_errno(setresgid(rgid, egid, sgid));
}

int silofs_sys_sched_yield(void)
{
	return ok_or_errno(sched_yield());
}
