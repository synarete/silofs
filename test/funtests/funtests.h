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
#ifndef SILOFS_FUNTESTS_H_
#define SILOFS_FUNTESTS_H_

#include <silofs/configs.h>
#include <silofs/defs.h>
#include <silofs/ioctls.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
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
#define FT_IOSIZE_MAX           SILOFS_IO_SIZE_MAX
#define FT_FILEMAP_NCHILD       SILOFS_FILE_NODE_NCHILDS
#define FT_FILESIZE_MAX         SILOFS_FILE_SIZE_MAX
#define FT_FILESIZE_ALIGNED_MAX ((FT_FILESIZE_MAX / FT_BK_SIZE) * FT_BK_SIZE)

#define FT_STR(x_)              SILOFS_STR(x_)
#define FT_ARRAY_SIZE(x_)       SILOFS_ARRAY_SIZE(x_)

#define FT_FL_LN_               SILOFS_FL_LN_


/* tests' control flags */
enum ft_flags {
	FT_F_NORMAL     = (1 << 1),
	FT_F_IGNORE     = (1 << 2),
	FT_F_STATVFS    = (1 << 3),
	FT_F_TMPFILE    = (1 << 4),
	FT_F_RANDOM     = (1 << 5),
	FT_F_FLAKY      = (1 << 6),
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
	int tests_mask;
	int tests_xmask;
	int listtests;
};

/* tests execution environment context */
struct ft_env {
	struct silofs_mutex     mutex;
	struct silofs_prandgen  prng;
	struct ft_params        params;
	const struct ft_tdef   *currtest;
	struct statvfs          stvfs;
	struct timespec         ts_start;
	struct timespec         ts_finish;
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

/* testing utility functions */
void fte_init(struct ft_env *fte, const struct ft_params *params);

void fte_run(struct ft_env *fte);

void fte_fini(struct ft_env *fte);

void ft_relax_mem(struct ft_env *fte);

void ft_suspend(const struct ft_env *fte, int sec, int part);

void ft_suspends(const struct ft_env *fte, int sec);

void ft_suspend1(const struct ft_env *fte);

void ft_freeall(struct ft_env *fte);

char *ft_strdup(struct ft_env *fte, const char *str);

char *ft_strcat(struct ft_env *fte, const char *str1, const char *str2);

silofs_attr_printf(2, 3)
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

silofs_attr_printf(2, 3)
char *ft_new_namef(struct ft_env *fte, const char *fmt, ...);

silofs_attr_printf(3, 4)
char *ft_new_pathf(struct ft_env *fte, const char *p, const char *fmt, ...);

void *ft_new_buf_zeros(struct ft_env *fte, size_t bsz);

void *ft_new_buf_rands(struct ft_env *fte, size_t bsz);

void *ft_new_buf_nums(struct ft_env *fte, long base, size_t bsz);

long *ft_new_buf_randseq(struct ft_env *fte, size_t cnt, long base);

long ft_lrand(struct ft_env *fte);

long ft_timespec_diff(const struct timespec *ts1, const struct timespec *ts2);

long ft_xtimestamp_diff(const struct statx_timestamp *ts1,
                        const struct statx_timestamp *ts2);

const char *ft_curr_test_name(const struct ft_env *fte);

/* Directory-entry helpers */
int ft_dirent_isdot(const struct dirent64 *dent);

int ft_dirent_isdotdot(const struct dirent64 *dent);

int ft_dirent_isxdot(const struct dirent64 *dent);

int ft_dirent_isdir(const struct dirent64 *dent);

int ft_dirent_isreg(const struct dirent64 *dent);

/* misc */
void ft_memcpy(void *dst, const void *src, size_t n);

int ft_memcmp(const void *p, const void *q, size_t n);

size_t ft_strlen(const char *s);

size_t ft_page_size(void);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* test-and-relax over array of ranges */
#define ft_exec_with_ranges(fte_, fn_, args_) \
        ft_exec_with_ranges_(fte_, fn_, args_, FT_ARRAY_SIZE(args_))

void ft_exec_with_ranges_(struct ft_env *fte,
                          void (*fn)(struct ft_env *, loff_t, size_t),
                          const struct ft_range *range, size_t na);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* sub-tests grouped by topic */
extern const struct ft_tests ft_test_access;
extern const struct ft_tests ft_test_stat;
extern const struct ft_tests ft_test_statx;
extern const struct ft_tests ft_test_stat_io;
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
extern const struct ft_tests ft_stress_rw;

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
#include "funtests_inline.h"

/* system-calls wrappers */
#include "funtests_syscall.h"

/* expect utilities */
#include "funtests_expect.h"

#endif /* SILOFS_FUNTESTS_H_ */
