/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_FFTESTS_H_
#define SILOFS_FFTESTS_H_

#include <silofs/configs.h>
#include <silofs/defs.h>
#include <silofs/ioctls.h>
#include <silofs/infra.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>


/* re-mapped macros */
#define FT_1K                   SILOFS_KILO
#define FT_2K                   (2 * SILOFS_KILO)
#define FT_4K                   (4 * SILOFS_KILO)
#define FT_8K                   (8 * SILOFS_KILO)
#define FT_64K                  (64 * SILOFS_KILO)
#define FT_1M                   SILOFS_MEGA
#define FT_2M                   (2 * SILOFS_MEGA)
#define FT_4M                   (4 * SILOFS_MEGA)
#define FT_1G                   SILOFS_GIGA
#define FT_1T                   SILOFS_TERA

#define FT_FRGSIZE              (512) /* Fragment size (see stat(2)) */
#define FT_BK_SIZE              SILOFS_LBK_SIZE
#define FT_FILEMAP_NCHILD       SILOFS_FILE_NODE_NCHILDS
#define FT_FILESIZE_MAX         SILOFS_FILE_SIZE_MAX
#define FT_IOSIZE_MAX           SILOFS_IO_SIZE_MAX

#define FT_STR(x_)              SILOFS_STR(x_)
#define FT_ARRAY_SIZE(x_)       SILOFS_ARRAY_SIZE(x_)

#define ft_expect_true(p)       silofs_expect(p)
#define ft_expect_false(p)      silofs_expect(!(p))
#define ft_expect_ok(err)       silofs_expect_ok(err)
#define ft_expect_err(err, x)   silofs_expect_err(err, x)
#define ft_expect_eq(a, b)      silofs_expect_eq(a, b)
#define ft_expect_ne(a, b)      silofs_expect_ne(a, b)
#define ft_expect_lt(a, b)      silofs_expect_lt(a, b)
#define ft_expect_le(a, b)      silofs_expect_le(a, b)
#define ft_expect_gt(a, b)      silofs_expect_gt(a, b)
#define ft_expect_ge(a, b)      silofs_expect_ge(a, b)
#define ft_expect_eqm(a, b, n)  silofs_expect_eqm(a, b, n)

#define ft_expect_ts_eq(t1, t2) \
	ft_expect_eq(ft_timespec_diff(t1, t2), 0)
#define ft_expect_ts_gt(t1, t2) \
	ft_expect_gt(ft_timespec_diff(t1, t2), 0)
#define ft_expect_ts_ge(t1, t2) \
	ft_expect_ge(ft_timespec_diff(t1, t2), 0)
#define ft_expect_mtime_eq(st1, st2) \
	ft_expect_ts_eq(&((st1)->st_mtim), &((st2)->st_mtim))
#define ft_expect_mtime_gt(st1, st2) \
	ft_expect_ts_gt(&((st1)->st_mtim), &((st2)->st_mtim))
#define ft_expect_ctime_eq(st1, st2) \
	ft_expect_ts_eq(&((st1)->st_ctim), &((st2)->st_ctim))
#define ft_expect_ctime_gt(st1, st2) \
	ft_expect_ts_gt(&((st1)->st_ctim), &((st2)->st_ctim))
#define ft_expect_ctime_ge(st1, st2) \
	ft_expect_ts_ge(&((st1)->st_ctim), &((st2)->st_ctim))

#define ft_expect_xts_eq(xt1, xt2) \
	ft_expect_eq(ft_xtimestamp_diff(xt1, xt2), 0)
#define ft_expect_xts_gt(xt1, xt2) \
	ft_expect_gt(ft_xtimestamp_diff(xt1, xt2), 0)


#define ft_expect_dir(m)        ft_expect_true(S_ISDIR(m))
#define ft_expect_reg(m)        ft_expect_true(S_ISREG(m))
#define ft_expect_lnk(m)        ft_expect_true(S_ISLNK(m))


/* tests' control flags */
enum ft_flags {
	FT_F_NORMAL     = (1 << 1),
	FT_F_IGNORE     = (1 << 2),
	FT_F_STAVFS     = (1 << 3),
	FT_F_NOSTAVFS   = (1 << 4),
	FT_F_TMPFILE    = (1 << 5),
	FT_F_RANDOM     = (1 << 6),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct ft_env;
struct ft_mchunk;


/* test definition */
struct ft_tdef {
	void (*hook)(struct ft_env *);
	const char *name;
	int flags;
	int pad;
};


/* tests-array define */
struct ft_tests {
	const struct ft_tdef *arr;
	size_t len;
};


/* tests execution parameters */
struct ft_params {
	const char *progname;
	const char *testdir;
	const char *testname;
	long repeatn;
	int testsmask;
	int listtests;
	int pad;
};


/* tests execution environment context */
struct ft_env {
	struct silofs_mutex     mutex;
	struct silofs_prandgen  prng;
	struct ft_params        params;
	const struct ft_tdef   *currtest;
	struct statvfs          stvfs;
	struct timespec         ts_start;
	uint64_t seqn;
	time_t  start;
	pid_t   pid;
	uid_t   uid;
	gid_t   gid;
	mode_t  umsk;
	size_t  nbytes_alloc;
	struct ft_mchunk *malloc_list;
	struct ft_tests   tests;
};

/* I/O range to test */
struct ft_range {
	loff_t off;
	size_t len;
};


/* sanity-testing utility */
void fte_init(struct ft_env *fte, const struct ft_params *params);

void fte_exec(struct ft_env *fte);

void fte_fini(struct ft_env *fte);

void ft_relax_mem(struct ft_env *fte);

void ft_suspend(const struct ft_env *fte, int sec, int part);

void ft_suspends(const struct ft_env *fte, int sec);

void ft_freeall(struct ft_env *fte);

char *ft_strdup(struct ft_env *fte, const char *str);

char *ft_strcat(struct ft_env *fte, const char *str1, const char *str2);

char *ft_strfmt(struct ft_env *fte, const char *fmt, ...);

char *ft_make_ulong_name(struct ft_env *fte, unsigned long key);

char *ft_make_rand_name(struct ft_env *fte, size_t name_len);

char *ft_make_xname_unique(struct ft_env *fte, size_t nlen, char *p, size_t n);

char *ft_new_name_unique(struct ft_env *fte);

char *ft_new_path_unique(struct ft_env *fte);

char *ft_new_path_under(struct ft_env *fte, const char *base);

char *ft_new_path_name(struct ft_env *fte, const char *name);

char *ft_new_path_nested(struct ft_env *fte,
                         const char *base, const char *name);

char *ft_new_namef(struct ft_env *fte, const char *fmt, ...);

char *ft_new_pathf(struct ft_env *fte, const char *p, const char *fmt, ...);

void *ft_new_buf_zeros(struct ft_env *fte, size_t bsz);

void *ft_new_buf_rands(struct ft_env *fte, size_t bsz);

void *ft_new_buf_nums(struct ft_env *fte, long base, size_t bsz);

long *ft_new_buf_randseq(struct ft_env *fte, size_t cnt, long base);

long ft_lrand(struct ft_env *fte);

long ft_timespec_diff(const struct timespec *ts1, const struct timespec *ts2);

long ft_xtimestamp_diff(const struct statx_timestamp *ts1,
                        const struct statx_timestamp *ts2);

size_t ft_page_size(void);

const char *ft_curr_test_name(const struct ft_env *fte);

/* Directory-entry helpers */
int ft_dirent_isdot(const struct dirent64 *dent);

int ft_dirent_isdotdot(const struct dirent64 *dent);

int ft_dirent_isxdot(const struct dirent64 *dent);

int ft_dirent_isdir(const struct dirent64 *dent);

int ft_dirent_isreg(const struct dirent64 *dent);

mode_t ft_dirent_gettype(const struct dirent64 *dent);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* wrappers over system calls */
void ft_syncfs(int fd);

void ft_fsync(int fd);

void ft_fsync_err(int fd, int err);

void ft_statvfs(const char *path, struct statvfs *stv);

void ft_statvfs_err(const char *path, int err);

void ft_fstatvfs(int fd, struct statvfs *stvfs);

void ft_utime(const char *filename, const struct utimbuf *times);

void ft_utimes(const char *filename, const struct timeval tm[2]);

void ft_utimensat(int dirfd, const char *pathname,
                  const struct timespec tm[2], int flags);

void ft_futimens(int fd, const struct timespec times[2]);

void ft_stat(const char *path, struct stat *st);

void ft_fstat(int fd, struct stat *st);

void ft_fstatat(int dirfd, const char *path, struct stat *st, int flags);

void ft_fstatat_err(int dirfd, const char *path, int flags, int err);

void ft_lstat(const char *path, struct stat *st);

void ft_lstat_err(const char *path, int err);

void ft_statx(int dfd, const char *pathname, int flags,
              unsigned int mask, struct statx *stx);

void ft_stat_exists(const char *path);

void ft_stat_err(const char *path, int err);

void ft_stat_noent(const char *path);

void ft_mkdir(const char *path, mode_t mode);

void ft_mkdir_err(const char *path, mode_t mode, int err);

void ft_mkdirat(int dirfd, const char *pathname, mode_t mode);

void ft_rmdir(const char *path);

void ft_rmdir_err(const char *path, int err);

void ft_unlink(const char *path);

void ft_unlink2(const char *path1, const char *path2);

void ft_unlink_err(const char *path, int err);

void ft_unlink_noent(const char *path);

void ft_unlinkat(int dirfd, const char *pathname, int flags);

void ft_unlinkat_noent(int dirfd, const char *pathname);

void ft_open(const char *path, int flags, mode_t mode, int *fd);

void ft_open_err(const char *path, int flags, mode_t mode, int err);

void ft_openat(int dirfd, const char *path,
               int flags, mode_t mode, int *fd);

void ft_openat_err(int dirfd, const char *path,
                   int flags, mode_t mode, int err);

void ft_creat(const char *path, mode_t mode, int *fd);

void ft_truncate(const char *path, loff_t len);

void ft_ftruncate(int fd, loff_t len);

void ft_llseek(int fd, loff_t off, int whence, loff_t *pos);

void ft_llseek_err(int fd, loff_t off, int whence, int err);

void ft_write(int fd, const void *buf, size_t cnt, size_t *nwr);

void ft_write_err(int fd, const void *buf, size_t cnt, int err);

void ft_pwrite(int fd, const void *buf, size_t cnt, loff_t off, size_t *nwr);

void ft_pwrite_err(int fd, const void *buf,
                   size_t cnt, loff_t off, int err);

void ft_read(int fd, void *buf, size_t cnt, size_t *nrd);

void ft_read_err(int fd, void *buf, size_t cnt, int err);

void ft_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *nrd);

void ft_fallocate(int fd, int mode, loff_t off, loff_t len);

void ft_fallocate_err(int fd, int mode, loff_t off, loff_t len, int err);

void ft_fdatasync(int fd);

void ft_mkfifo(const char *path, mode_t mode);

void ft_mkfifoat(int dirfd, const char *pathname, mode_t mode);

void ft_mknod(const char *pathname, mode_t mode, dev_t dev);

void ft_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);

void ft_symlink(const char *oldpath, const char *newpath);

void ft_symlinkat(const char *target, int dirfd, const char *linkpath);

void ft_readlink(const char *path, char *buf, size_t bsz, size_t *cnt);

void ft_readlink_err(const char *path, char *buf, size_t bsz, int err);

void ft_readlinkat(int dirfd, const char *pathname,
                   char *buf, size_t bsz, size_t *cnt);

void ft_rename(const char *oldpath, const char *newpath);

void ft_rename_err(const char *oldpath, const char *newpath, int err);

void ft_renameat(int olddirfd, const char *oldpath,
                 int newdirfd, const char *newpath);

void ft_renameat2(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, unsigned int flags);

void ft_link(const char *path1, const char *path2);

void ft_link_err(const char *path1, const char *path2, int err);

void ft_linkat(int olddirfd, const char *oldpath,
               int newdirfd, const char *newpath, int flags);

void ft_linkat_err(int olddirfd, const char *oldpath,
                   int newdirfd, const char *newpath, int flags, int err);

void ft_chmod(const char *path, mode_t mode);

void ft_fchmod(int fd, mode_t mode);

void ft_fchmod_err(int fd, mode_t mode, int err);

void ft_chown(const char *path, uid_t uid, gid_t gid);

void ft_fchown(int fd, uid_t uid, gid_t gid);

void ft_access(const char *path, int mode);

void ft_access_err(const char *path, int mode, int err);

void ft_close(int fd);

void ft_close2(int fd1, int fd2);

void ft_mmap(void *addr, size_t length, int prot, int flags,
             int fd, off_t offset, void **out);

void ft_munmap(void *addr, size_t length);

void ft_msync(void *addr, size_t len, int flags);

void ft_madvise(void *addr, size_t len, int advice);

void ft_setxattr(const char *path, const char *name,
                 const void *value, size_t size, int flags);

void ft_lsetxattr(const char *path, const char *name,
                  const void *value, size_t size, int flags);

void ft_fsetxattr(int fd, const char *name,
                  const void *value, size_t size, int flags);

void ft_getxattr(const char *path, const char *name,
                 void *value, size_t size, size_t *cnt);

void ft_getxattr_err(const char *path, const char *name, int err);

void ft_lgetxattr(const char *path, const char *name,
                  void *value, size_t size, size_t *cnt);

void ft_fgetxattr(int fd, const char *name,
                  void *value, size_t size, size_t *cnt);

void ft_fgetxattr_err(int fd, const char *name, int err);

void ft_removexattr(const char *path, const char *name);

void ft_lremovexattr(const char *path, const char *name);

void ft_fremovexattr(int fd, const char *name);

void ft_fremovexattr_err(int fd, const char *name, int err);

void ft_listxattr(const char *path, char *list, size_t size, size_t *out);

void ft_llistxattr(const char *path, char *list, size_t size, size_t *out);

void ft_flistxattr(int fd, char *list, size_t size, size_t *out);

void ft_flistxattr_err(int fd, char *list, size_t size, int err);

void ft_getdent(int fd, struct dirent64 *dent);

void ft_getdents(int fd, void *buf, size_t bsz,
                 struct dirent64 *des, size_t ndes, size_t *out_ndes);

void ft_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                        loff_t *off_out, size_t len, size_t *out_ncp);

void ft_fiemap(int fd, struct fiemap *fm);

/* complex wrappers */
void ft_readn(int fd, void *buf, size_t cnt);

void ft_preadn(int fd, void *buf, size_t cnt, loff_t offset);

void ft_writen(int fd, const void *buf, size_t cnt);

void ft_pwriten(int fd, const void *buf, size_t cnt, loff_t offset);

/* ioctl wrappers */
void ft_ioctl_syncfs(int fd);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* test-and-relax ranges */
#define ft_exec_with_ranges(fte_, fn_, args_) \
	ft_exec_with_ranges_(fte_, fn_, args_, FT_ARRAY_SIZE(args_))

void ft_exec_with_ranges_(struct ft_env *fte,
                          void (*fn)(struct ft_env *, loff_t, size_t),
                          const struct ft_range *range, size_t na);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* sub-tests grouped by topic */
extern const struct ft_tests ft_test_access;
extern const struct ft_tests ft_test_stat;
extern const struct ft_tests ft_test_statvfs;
extern const struct ft_tests ft_test_utimes;
extern const struct ft_tests ft_test_mkdir;
extern const struct ft_tests ft_test_readdir;
extern const struct ft_tests ft_test_create;
extern const struct ft_tests ft_test_open;
extern const struct ft_tests ft_test_opath;
extern const struct ft_tests ft_test_link;
extern const struct ft_tests ft_test_unlink;
extern const struct ft_tests ft_test_chmod;
extern const struct ft_tests ft_test_symlink;
extern const struct ft_tests ft_test_mkfifo;
extern const struct ft_tests ft_test_fsync;
extern const struct ft_tests ft_test_rename;
extern const struct ft_tests ft_test_xattr;
extern const struct ft_tests ft_test_write;
extern const struct ft_tests ft_test_truncate;
extern const struct ft_tests ft_test_lseek;
extern const struct ft_tests ft_test_fiemap;
extern const struct ft_tests ft_test_boundaries;
extern const struct ft_tests ft_test_tmpfile;
extern const struct ft_tests ft_test_stat_io;
extern const struct ft_tests ft_test_rw_basic;
extern const struct ft_tests ft_test_rw_sequencial;
extern const struct ft_tests ft_test_rw_sparse;
extern const struct ft_tests ft_test_rw_random;
extern const struct ft_tests ft_test_rw_large;
extern const struct ft_tests ft_test_rw_osync;
extern const struct ft_tests ft_test_unlinked_file;
extern const struct ft_tests ft_test_truncate_io;
extern const struct ft_tests ft_test_fallocate;
extern const struct ft_tests ft_test_copy_file_range;
extern const struct ft_tests ft_test_mmap;
extern const struct ft_tests ft_test_mmap_mt;
extern const struct ft_tests ft_test_namespace;
extern const struct ft_tests ft_test_xstress_mt;

/* test-define helper macros */
#define FT_DEFTESTF(fn_, fl_) \
	{ .hook = (fn_), .name = FT_STR(fn_), .flags = (fl_) }

#define FT_DEFTEST(fn_) \
	FT_DEFTESTF(fn_, FT_F_NORMAL)

#define FT_DEFTESTS(a_) \
	{ .arr = (a_), .len = FT_ARRAY_SIZE(a_) }


#define FT_MKRANGE0(off_) \
	{ .off = off_, .len = 0 }

#define FT_MKRANGE(off_, len_) \
	{ .off = off_, .len = len_ }

/* common inline utility functions */
#include "fftests-inline.h"

#endif /* SILOFS_FFTESTS_H_ */

