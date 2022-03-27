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
#ifndef SILOFS_SYSCALL_H_
#define SILOFS_SYSCALL_H_

#include <unistd.h>
#include <stdlib.h>

struct stat;
struct statx;
struct statvfs;
struct statfs;
struct dirent64;
struct iovec;
struct utimbuf;
struct timeval;
struct timespec;
struct sigaction;
struct rlimit;
struct flock;
struct fiemap;
struct sockaddr;
struct msghdr;
struct pollfd;


/* syscall */
int silofs_sys_mount(const char *source, const char *target, const char *fstyp,
                     unsigned long mntflags, const void *data);

int silofs_sys_umount(const char *target);

int silofs_sys_umount2(const char *target, int flags);

int silofs_sys_access(const char *path, int mode);

int silofs_sys_faccessat(int dirfd, const char *pathname, int mode, int flags);

int silofs_sys_link(const char *path1, const char *path2);

int silofs_sys_linkat(int olddirfd, const char *oldpath,
                      int newdirfd, const char *newpath, int flags);

int silofs_sys_unlink(const char *path);

int silofs_sys_unlinkat(int dirfd, const char *pathname, int flags);

int silofs_sys_rename(const char *oldpath, const char *newpath);

int silofs_sys_renameat(int olddirfd, const char *oldpath,
                        int newdirfd, const char *newpath);

int silofs_sys_renameat2(int olddirfd, const char *oldpath,
                         int newdirfd, const char *newpath,
                         unsigned int flags);

int silofs_sys_fstatvfs(int fd, struct statvfs *stv);

int silofs_sys_statfs(const char *path, struct statfs *stfs);

int silofs_sys_fstatfs(int fd, struct statfs *stfs);

int silofs_sys_flock(int fd, int operation);

int silofs_sys_statvfs(const char *path, struct statvfs *stv);

int silofs_sys_fstat(int fd, struct stat *st);

int silofs_sys_fstatat(int dirfd, const char *pathname,
                       struct stat *st, int flags);

int silofs_sys_stat(const char *path, struct stat *st);

int silofs_sys_lstat(const char *path, struct stat *st);

int silofs_sys_statx(int dfd, const char *pathname, int flags,
                     unsigned int mask, struct statx *stx);

int silofs_sys_chmod(const char *path, mode_t mode);

int silofs_sys_fchmod(int fd, mode_t mode);

int silofs_sys_fchmodat(int dirfd, const char *pathname,
                        mode_t mode, int flags);

int silofs_sys_chown(const char *path, uid_t uid, gid_t gid);

int silofs_sys_fchown(int fd, uid_t uid, gid_t gid);

int silofs_sys_fchownat(int dirfd, const char *pathname,
                        uid_t uid, gid_t gid, int flags);

int silofs_sys_utime(const char *filename, const struct utimbuf *times);

int silofs_sys_utimes(const char *filename, const struct timeval times[2]);

int silofs_sys_utimensat(int dirfd, const char *pathname,
                         const struct timespec times[2], int flags);

int silofs_sys_futimens(int fd, const struct timespec times[2]);

int silofs_sys_mkdir(const char *path, mode_t mode);

int silofs_sys_mkdirat(int dirfd, const char *pathname, mode_t mode);

int silofs_sys_rmdir(const char *path);

int silofs_sys_getdents(int fd, void *buf, size_t bsz, struct dirent64 *dents,
                        size_t ndents, size_t *out_ndents);

int silofs_sys_creat(const char *path, mode_t mode, int *fd);

int silofs_sys_memfd_create(const char *name, unsigned int flags, int *fd);

int silofs_sys_open(const char *path, int flags, mode_t mode, int *fd);

int silofs_sys_openat(int dirfd, const char *pathname,
                      int flags, mode_t mode, int *fd);

int silofs_sys_close(int fd);

int silofs_sys_llseek(int fd, loff_t off, int whence, loff_t *pos);

int silofs_sys_syncfs(int fd);

int silofs_sys_fsync(int fd);

int silofs_sys_fdatasync(int fd);

int silofs_sys_fallocate(int fd, int mode, loff_t off, loff_t len);

int silofs_sys_truncate(const char *path, loff_t len);

int silofs_sys_ftruncate(int fd, loff_t len);

int silofs_sys_readlink(const char *path, char *buf, size_t bsz, size_t *cnt);

int silofs_sys_readlinkat(int dirfd, const char *pathname,
                          char *buf, size_t bsz, size_t *cnt);

int silofs_sys_symlink(const char *oldpath, const char *newpath);

int silofs_sys_symlinkat(const char *target, int dirfd, const char *linkpath);

int silofs_sys_mkfifo(const char *path, mode_t mode);

int silofs_sys_mkfifoat(int dirfd, const char *pathname, mode_t mode);

int silofs_sys_mknod(const char *pathname, mode_t mode, dev_t dev);

int silofs_sys_mknodat(int dirfd, const char *pathname,
                       mode_t mode, dev_t dev);

int silofs_sys_mmap(void *addr, size_t length, int prot, int flags,
                    int fd, off_t offset, void **out_addr);

int silofs_sys_mmap_anon(size_t length, int flags, void **out_addr);

int silofs_sys_munmap(void *addr, size_t length);

int silofs_sys_msync(void *addr, size_t len, int flags);

int silofs_sys_madvise(void *addr, size_t len, int advice);

int silofs_sys_mlock(const void *addr, size_t len);

int silofs_sys_mlock2(const void *addr, size_t len, unsigned int flags);

int silofs_sys_munlock(const void *addr, size_t len);

int silofs_sys_mlockall(int flags);

int silofs_sys_munlockall(void);

int silofs_sys_brk(void *addr);

int silofs_sys_sbrk(intptr_t increment, void **out_addr);

int silofs_sys_ioctl_blkgetsize64(int fd, size_t *sz);

int silofs_sys_ioctl_ficlone(int dest_fd, int src_fd);

int silofs_sys_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                               loff_t *off_out, size_t len, unsigned int flags,
                               size_t *out_ncp);

int silofs_sys_read(int fd, void *buf, size_t cnt, size_t *nrd);

int silofs_sys_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *);

int silofs_sys_write(int fd, const void *buf, size_t cnt, size_t *nwr);

int silofs_sys_pwrite(int fd, const void *buf, size_t cnt,
                      loff_t off, size_t *nwr);

int silofs_sys_readv(int fd, const struct iovec *iov,
                     int iovcnt, size_t *nrd);

int silofs_sys_writev(int fd, const struct iovec *iov,
                      int iovcnt, size_t *nwr);

int silofs_sys_preadv(int fd, const struct iovec *iov,
                      int iovcnt, off_t off, size_t *nrd);

int silofs_sys_pwritev(int fd, const struct iovec *iov, int iovcnt,
                       off_t off, size_t *nwr);

int silofs_sys_preadv2(int fd, const struct iovec *iov, int iovcnt,
                       off_t off, int flags, size_t *nrd);

int silofs_sys_pwritev2(int fd, const struct iovec *iov, int iovcnt,
                        off_t off, int flags, size_t *nwr);

int silofs_sys_splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags, size_t *nsp);

int silofs_sys_vmsplice(int fd, const struct iovec *iov, size_t nr_segs,
                        unsigned int flags, size_t *nsp);

int silofs_sys_ioctlp(int fd, unsigned long int cmd, void *ptr);

int silofs_sys_fiemap(int fd, struct fiemap *fm);

int silofs_sys_setxattr(const char *path, const char *name,
                        const void *value, size_t size, int flags);

int silofs_sys_lsetxattr(const char *path, const char *name,
                         const void *value, size_t size, int flags);

int silofs_sys_fsetxattr(int fd, const char *name,
                         const void *value, size_t size, int flags);

int silofs_sys_getxattr(const char *path, const char *name,
                        void *value, size_t size, size_t *cnt);

int silofs_sys_lgetxattr(const char *path, const char *name,
                         void *value, size_t size, size_t *cnt);

int silofs_sys_fgetxattr(int fd, const char *name,
                         void *value, size_t size, size_t *cnt);

int silofs_sys_removexattr(const char *path, const char *name);

int silofs_sys_lremovexattr(const char *path, const char *name);

int silofs_sys_fremovexattr(int fd, const char *name);

int silofs_sys_listxattr(const char *path, char *list,
                         size_t size, size_t *out_size);

int silofs_sys_llistxattr(const char *path, char *list,
                          size_t size, size_t *out_size);

int silofs_sys_flistxattr(int fd, char *list, size_t size, size_t *out_size);

int silofs_sys_sigaction(int, const struct sigaction *, struct sigaction *);

int silofs_sys_getrlimit(int resource, struct rlimit *rlim);

int silofs_sys_setrlimit(int resource, const struct rlimit *rlim);

int silofs_sys_prctl(int option, unsigned long arg2, unsigned long arg3,
                     unsigned long arg4, unsigned long arg5);

int silofs_sys_clock_gettime(clockid_t clock_id, struct timespec *tp);

int silofs_sys_fcntl_flock(int fd, int cmd, struct flock *fl);

int silofs_sys_fcntl_getfl(int fd, int *out_fl);

int silofs_sys_fcntl_setfl(int fd, int fl);

int silofs_sys_fcntl_setpipesz(int fd, int pipesize);

int silofs_sys_fcntl_getpipesz(int fd, int *out_pipesize);

int silofs_sys_socket(int domain, int type, int protocol, int *out_sd);

int silofs_sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, const struct timespec *timeout,
                       const sigset_t *sigmask, int *out_nfds);

int silofs_sys_poll(struct pollfd *fds, size_t nfds,
                    int timeout, int *out_nfds);

int silofs_sys_bind(int sd, const struct sockaddr *addr, socklen_t addrlen);

int silofs_sys_send(int sd, const void *buf, size_t len,
                    int flags, size_t *out_sent);

int silofs_sys_sendto(int sd, const void *buf, size_t len, int flags,
                      const struct sockaddr *addr, socklen_t addrlen,
                      size_t *out_sent);

int silofs_sys_sendmsg(int sd, const struct msghdr *msg,
                       int flags, size_t *out_sent);

int silofs_sys_recv(int sd, void *buf, size_t len,
                    int flags, size_t *out_recv);

int silofs_sys_recvfrom(int sd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen,
                        size_t *out_recv);

int silofs_sys_recvmsg(int sd, struct msghdr *msg,
                       int flags, size_t *out_recv);

int silofs_sys_listen(int sd, int backlog);

int silofs_sys_accept(int sd, struct sockaddr *addr,
                      socklen_t *addrlen, int *out_sd);

int silofs_sys_connect(int sd, const struct sockaddr *addr, socklen_t addrlen);

int silofs_sys_shutdown(int sd, int how);

int silofs_sys_setsockopt(int sd, int level, int optname,
                          const void *optval, socklen_t optlen);

int silofs_sys_getsockopt(int sd, int level, int optname,
                          void *optval, socklen_t *optlen);

int silofs_sys_pipe2(int pipefd[2], int flags);

int silofs_sys_seteuid(uid_t euid);

int silofs_sys_setegid(gid_t egid);

int silofs_sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);

int silofs_sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);

int silofs_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);

int silofs_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);


/* syscallx */
int silofs_sys_readn(int fd, void *buf, size_t cnt);

int silofs_sys_preadn(int fd, void *buf, size_t cnt, loff_t offset);

int silofs_sys_writen(int fd, const void *buf, size_t cnt);

int silofs_sys_pwriten(int fd, const void *buf, size_t cnt, loff_t offset);

int silofs_sys_pwritevn(int fd, const struct iovec *iov, int cnt, loff_t off);

int silofs_sys_opendir(const char *path, int *out_fd);

int silofs_sys_opendirat(int dfd, const char *pathname, int *out_fd);

int silofs_sys_closefd(int *pfd);

int silofs_sys_munmapp(void **paddr, size_t length);

int silofs_sys_llseek_data(int fd, loff_t off, loff_t *out_data_off);

int silofs_proc_pipe_max_size(long *out_value);

int silofs_sys_pselect_rfd(int fd, const struct timespec *ts);

int silofs_sys_pollin_rfd(int fd, int timeout);

/* sysconf */
long silofs_sc_page_size(void);

long silofs_sc_phys_pages(void);

long silofs_sc_avphys_pages(void);

long silofs_sc_l1_dcache_linesize(void);

long silofs_sc_nproc_conf(void);

long silofs_sc_nproc_onln(void);


#endif /* SILOFS_SYSCALL_H_ */

