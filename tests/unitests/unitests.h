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
#ifndef SILOFS_UNITESTS_H_
#define SILOFS_UNITESTS_H_

#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#ifndef SILOFS_UNITEST
#error "this header must not be included out-side of unitests"
#endif


#define UT_MKRANGE0(pos_) \
	{ .off = (pos_), .len = 0 }

#define UT_MKRANGE1(pos_, cnt_) \
	{ .off = (pos_), .len = (cnt_) }

#define UT_MKRANGE2(pos1_, pos2_, cnt_) \
	{ .off1 = (pos1_), .off2 = (pos2_), .len = (cnt_) }

#define UT_MKRANGE1S(a_) \
	{ .arr = (a_), .cnt = UT_ARRAY_SIZE(a_) }

/* tests control-flags */
#define UT_F_NORMAL     (0)
#define UT_F_QUICK      (1)
#define UT_F_FTYPE2     (2)

struct ut_range {
	loff_t off;
	size_t len;
};

struct ut_range2 {
	loff_t off1;
	loff_t off2;
	size_t len;
};

struct ut_ranges {
	const struct ut_range *arr;
	size_t cnt;
};

struct ut_keyval {
	const char *name;
	const void *value;
	size_t size;
};

struct ut_kvl {
	struct ut_env *ute;
	struct ut_keyval **list;
	size_t limit;
	size_t count;
};

struct ut_dirent_info {
	struct dirent64 de;
	struct stat attr;
};

struct ut_readdir_ctx {
	struct silofs_readdir_ctx rd_ctx;
	struct ut_dirent_info dei[64];
	unsigned int nde;
	int plus;
};

struct ut_listxattr_ctx {
	struct ut_env *ute;
	struct silofs_listxattr_ctx lxa_ctx;
	size_t count;
	char *names[64];
};

struct ut_malloc_chunk {
	struct ut_malloc_chunk *next;
	size_t  size;
	void   *data;
};

struct ut_args {
	struct silofs_fs_args    fs_args;
	const char *program;
};

struct ut_env {
	struct silofs_prandgen   prng;
	struct silofs_password   passwd;
	struct silofs_treeid      treeid[2];
	struct ut_args          *args;
	struct silofs_fs_env    *fs_env;
	struct timespec          ts_start;
	struct statvfs           stvfs[2];
	struct silofs_spacestats spst[2];
	struct silofs_mutex      mutex;
	struct ut_malloc_chunk  *malloc_list;
	size_t                   ualloc_start;
	size_t                   nbytes_alloc;
	long                     unique_opid;
	int                      run_level;
	enum silofs_file_type    ftype;
};

struct ut_dvec {
	loff_t  off;
	size_t  len;
	uint8_t dat[8];
};

typedef void (*ut_test_hook_fn)(struct ut_env *);

struct ut_testdef {
	ut_test_hook_fn hook;
	const char     *name;
	int             flags;
};

struct ut_testdefs {
	const struct ut_testdef *arr;
	size_t len;
};

struct ut_tgroup {
	const struct ut_testdefs *tests;
	const char *name;
};

/* global params */
struct ut_globals {
	struct silofs_log_params log_params;
	char          **argv;
	int             argc;
	int             run_level;
	const char     *program;
	const char     *version;
	const char     *test_dir;
	char           *test_dir_real;
	char           *test_dir_repo;
	struct timespec start_ts;
	bool            asyncwr;
	bool            stdalloc;
	bool            pedantic;
};

extern struct ut_globals ut_globals;

/* modules unit-tests entry-points */
extern const struct ut_testdefs ut_tdefs_avl;
extern const struct ut_testdefs ut_tdefs_base64;
extern const struct ut_testdefs ut_tdefs_strings;
extern const struct ut_testdefs ut_tdefs_qalloc;
extern const struct ut_testdefs ut_tdefs_super;
extern const struct ut_testdefs ut_tdefs_statfs;
extern const struct ut_testdefs ut_tdefs_dir;
extern const struct ut_testdefs ut_tdefs_dir_iter;
extern const struct ut_testdefs ut_tdefs_dir_list;
extern const struct ut_testdefs ut_tdefs_namei;
extern const struct ut_testdefs ut_tdefs_rename;
extern const struct ut_testdefs ut_tdefs_symlink;
extern const struct ut_testdefs ut_tdefs_xattr;
extern const struct ut_testdefs ut_tdefs_ioctl;
extern const struct ut_testdefs ut_tdefs_file_basic;
extern const struct ut_testdefs ut_tdefs_file_stat;
extern const struct ut_testdefs ut_tdefs_file_rwiter;
extern const struct ut_testdefs ut_tdefs_file_ranges;
extern const struct ut_testdefs ut_tdefs_file_truncate;
extern const struct ut_testdefs ut_tdefs_file_records;
extern const struct ut_testdefs ut_tdefs_file_random;
extern const struct ut_testdefs ut_tdefs_file_edges;
extern const struct ut_testdefs ut_tdefs_file_fallocate;
extern const struct ut_testdefs ut_tdefs_file_fiemap;
extern const struct ut_testdefs ut_tdefs_file_lseek;
extern const struct ut_testdefs ut_tdefs_file_copy_range;
extern const struct ut_testdefs ut_tdefs_file_mthreads;
extern const struct ut_testdefs ut_tdefs_inspect;
extern const struct ut_testdefs ut_tdefs_reload;
extern const struct ut_testdefs ut_tdefs_fillfs;
extern const struct ut_testdefs ut_tdefs_snap_basic;
extern const struct ut_testdefs ut_tdefs_snap_io;
extern const struct ut_testdefs ut_tdefs_pack;

/* exec */
void ut_execute_tests(void);

void ut_relax_mem(struct ut_env *ute);

void ut_freeall(struct ut_env *ute);

void *ut_malloc(struct ut_env *ute, size_t nbytes);

void *ut_zalloc(struct ut_env *ute, size_t nbytes);

char *ut_strdup(struct ut_env *ute, const char *str);

char *ut_strndup(struct ut_env *ute, const char *str, size_t);

const char *ut_make_name(struct ut_env *ute, const char *pre, size_t idx);

void *ut_zerobuf(struct ut_env *ute, size_t bsz);

void ut_randfill(struct ut_env *ute, void *buf, size_t bsz);

void *ut_randbuf(struct ut_env *ute, size_t bsz);

long *ut_randseq(struct ut_env *, size_t len, long base);

char *ut_randstr(struct ut_env *, size_t len);

char *ut_strfmt(struct ut_env *ute, const char *fmt, ...);

struct ut_readdir_ctx *ut_new_readdir_ctx(struct ut_env *ute);

struct ut_dvec *ut_new_dvec(struct ut_env *, loff_t, size_t);


void ut_setup_task(struct ut_env *ute, struct silofs_task *task);

void ut_release_task(struct ut_env *ute, struct silofs_task *task);

/* no-fail operations wrappers */
void ut_access_ok(struct ut_env *ute, ino_t ino, int mode);

void ut_statfs_ok(struct ut_env *ute, ino_t ino, struct statvfs *st);

void ut_statfs_rootd_ok(struct ut_env *ute, struct statvfs *st);

void ut_statsp_ok(struct ut_env *ute, ino_t ino,
                  struct silofs_spacestats *spst);

void ut_statsp_rootd_ok(struct ut_env *ute, struct silofs_spacestats *spst);

void ut_statx_ok(struct ut_env *ute, ino_t ino, struct statx *stx);

void ut_getattr_ok(struct ut_env *ute, ino_t ino, struct stat *st);

void ut_getattr_noent(struct ut_env *ute, ino_t ino);

void ut_getattr_reg(struct ut_env *ute, ino_t ino, struct stat *st);

void ut_getattr_lnk(struct ut_env *ute, ino_t ino, struct stat *st);

void ut_getattr_dir(struct ut_env *ute, ino_t ino, struct stat *st);

void ut_getattr_dirsize(struct ut_env *ute, ino_t ino, loff_t size);

void ut_utimens_atime(struct ut_env *ute,
                      ino_t ino, const struct timespec *atime);

void ut_utimens_mtime(struct ut_env *ute,
                      ino_t ino, const struct timespec *mtime);

void ut_lookup_ok(struct ut_env *ute, ino_t parent,
                  const char *name, struct stat *out_st);

void ut_lookup_ino(struct ut_env *ute, ino_t parent,
                   const char *name, ino_t *out_ino);

void ut_lookup_exists(struct ut_env *ute, ino_t parent,
                      const char *name, ino_t ino, mode_t mode);

void ut_lookup_dir(struct ut_env *ute, ino_t parent,
                   const char *name, ino_t dino);

void ut_lookup_file(struct ut_env *ute, ino_t parent,
                    const char *name, ino_t ino);

void ut_lookup_lnk(struct ut_env *ute, ino_t parent,
                   const char *name, ino_t ino);

void ut_lookup_noent(struct ut_env *ute, ino_t ino, const char *name);

void ut_mkdir_ok(struct ut_env *ute, ino_t parent,
                 const char *name, struct stat *out_st);

void ut_mkdir_oki(struct ut_env *ute, ino_t parent,
                  const char *name, ino_t *out_ino);

void ut_mkdir_at_root(struct ut_env *ute, const char *name, ino_t *out_ino);

void ut_mkdir_err(struct ut_env *ute,
                  ino_t parent, const char *name, int err);

void ut_rmdir_ok(struct ut_env *ute, ino_t parent, const char *name);

void ut_rmdir_err(struct ut_env *ute, ino_t parent,
                  const char *name, int err);

void ut_rmdir_at_root(struct ut_env *ute, const char *name);

void ut_opendir_ok(struct ut_env *ute, ino_t ino);

void ut_opendir_err(struct ut_env *ute, ino_t ino, int err);

void ut_releasedir_ok(struct ut_env *ute, ino_t ino);

void ut_releasedir_err(struct ut_env *ute, ino_t ino, int err);

void ut_fsyncdir_ok(struct ut_env *ute, ino_t ino);

void ut_readdir_ok(struct ut_env *ute, ino_t ino, loff_t doff,
                   struct ut_readdir_ctx *ut_rd_ctx);

void ut_readdirplus_ok(struct ut_env *ute, ino_t ino, loff_t doff,
                       struct ut_readdir_ctx *ut_rd_ctx);

void ut_link_ok(struct ut_env *ute, ino_t ino,
                ino_t parent, const char *name, struct stat *out_st);

void ut_link_err(struct ut_env *ute, ino_t ino,
                 ino_t parent, const char *name, int err);

void ut_unlink_ok(struct ut_env *ute, ino_t parent, const char *name);

void ut_unlink_err(struct ut_env *ute, ino_t parent,
                   const char *name, int err);

void ut_unlink_file(struct ut_env *ute, ino_t parent, const char *name);

void ut_rename_move(struct ut_env *ute, ino_t parent, const char *name,
                    ino_t newparent, const char *newname);

void ut_rename_replace(struct ut_env *ute, ino_t parent, const char *name,
                       ino_t newparent, const char *newname);

void ut_rename_exchange(struct ut_env *ute, ino_t parent, const char *name,
                        ino_t newparent, const char *newname);

void ut_symlink_ok(struct ut_env *ute, ino_t parent,
                   const char *name, const char *value, ino_t *out_ino);

void ut_readlink_expect(struct ut_env *ute, ino_t ino, const char *value);

void ut_create_ok(struct ut_env *ute, ino_t parent,
                  const char *name, mode_t mode, struct stat *out_st);

void ut_create_file(struct ut_env *ute, ino_t parent,
                    const char *name, ino_t *out_ino);

void ut_create_noent(struct ut_env *ute,
                     ino_t parent, const char *name);

void ut_create_special(struct ut_env *ute, ino_t parent,
                       const char *name, mode_t mode, ino_t *out_ino);

void ut_release_ok(struct ut_env *ute, ino_t ino);

void ut_release_flush_ok(struct ut_env *ute, ino_t ino);

void ut_release_file(struct ut_env *ute, ino_t ino);

void ut_fsync_ok(struct ut_env *ute, ino_t ino, bool datasync);

void ut_remove_file(struct ut_env *ute, ino_t parent,
                    const char *, ino_t ino);

void ut_create_only(struct ut_env *ute, ino_t parent,
                    const char *name, ino_t *out_ino);

void ut_open_rdonly(struct ut_env *ute, ino_t ino);

void ut_open_rdwr(struct ut_env *ute, ino_t ino);

void ut_remove_link(struct ut_env *ute,
                    ino_t parent, const char *name);

void ut_flush_ok(struct ut_env *ute, ino_t ino, bool now);

void ut_write_ok(struct ut_env *ute, ino_t ino,
                 const void *buf, size_t bsz, loff_t off);

void ut_write_iter_ok(struct ut_env *ute, ino_t ino,
                      const void *buf, size_t bsz, off_t off);

void ut_write_nospc(struct ut_env *ute, ino_t ino,
                    const void *buf, size_t bsz,
                    loff_t off, size_t *out_nwr);

void ut_write_read(struct ut_env *ute, ino_t ino,
                   const void *buf, size_t bsz, loff_t off);

void ut_write_read1(struct ut_env *ute, ino_t ino, loff_t off);

void ut_write_read_str(struct ut_env *ute, ino_t ino,
                       const char *str, loff_t off);

void ut_read_verify(struct ut_env *ute, ino_t ino,
                    const void *buf, size_t bsz, loff_t off);

void ut_read_verify_str(struct ut_env *ute,
                        ino_t ino, const char *str, loff_t off);

void ut_read_zero(struct ut_env *ute, ino_t ino, loff_t off);

void ut_read_zeros(struct ut_env *ute, ino_t ino, loff_t off, size_t len);

void ut_read_ok(struct ut_env *ute, ino_t ino,
                void *buf, size_t bsz, loff_t off);

void ut_trunacate_file(struct ut_env *ute, ino_t ino, loff_t off);

void ut_trunacate_zero(struct ut_env *ute, ino_t ino);

void ut_fallocate_reserve(struct ut_env *ute, ino_t ino,
                          loff_t off, loff_t len);

void ut_fallocate_keep_size(struct ut_env *ute, ino_t ino,
                            loff_t off, loff_t len);

void ut_fallocate_punch_hole(struct ut_env *ute, ino_t ino,
                             loff_t off, loff_t len);

void ut_fallocate_zero_range(struct ut_env *ute, ino_t ino,
                             loff_t off, loff_t len, bool keep_size);

void ut_setxattr_create(struct ut_env *ute, ino_t ino,
                        const struct ut_keyval *kv);

void ut_setxattr_replace(struct ut_env *ute, ino_t ino,
                         const struct ut_keyval *kv);

void ut_setxattr_rereplace(struct ut_env *ute, ino_t ino,
                           const struct ut_keyval *kv);

void ut_getxattr_value(struct ut_env *ute, ino_t ino,
                       const struct ut_keyval *kv);

void ut_getxattr_nodata(struct ut_env *ute, ino_t ino,
                        const struct ut_keyval *);

void ut_removexattr_ok(struct ut_env *ute, ino_t ino,
                       const struct ut_keyval *);

void ut_listxattr_ok(struct ut_env *ute, ino_t ino,
                     const struct ut_kvl *kvl);

void ut_setxattr_all(struct ut_env *ute, ino_t ino,
                     const struct ut_kvl *kvl);

void ut_removexattr_all(struct ut_env *ute, ino_t ino,
                        const struct ut_kvl *kvl);

void ut_query_ok(struct ut_env *ute, ino_t ino,
                 enum silofs_query_type qtype,
                 struct silofs_ioc_query *out_qry);

void ut_query_spst_ok(struct ut_env *ute, ino_t ino,
                      struct silofs_spacestats *out_spst);

void ut_snap_ok(struct ut_env *ute, ino_t ino);


void ut_fiemap_ok(struct ut_env *ute, ino_t ino, struct fiemap *fm);

void ut_lseek_data(struct ut_env *ute,
                   ino_t ino, loff_t off, loff_t *out_off);

void ut_lseek_hole(struct ut_env *ute,
                   ino_t ino, loff_t off, loff_t *out_off);

void ut_lseek_nodata(struct ut_env *ute, ino_t ino, loff_t off);

void ut_copy_file_range_ok(struct ut_env *ute, ino_t ino_in, loff_t off_in,
                           ino_t ino_out, loff_t off_out, size_t len);

void ut_write_dvec(struct ut_env *ute, ino_t ino,
                   const struct ut_dvec *dvec);

void ut_read_dvec(struct ut_env *ute, ino_t ino,
                  const struct ut_dvec *dvec);

void ut_sync_drop(struct ut_env *ute);

void ut_drop_caches_fully(struct ut_env *ute);

void ut_tune_ftype2_ok(struct ut_env *ute, ino_t ino);

void ut_timedout_ok(struct ut_env *ute);

void ut_reload_fs_ok(struct ut_env *ute);

void ut_reload_fs_ok_at(struct ut_env *ute, ino_t ino);


/* top-level exec ops */
void ut_format_repo_ok(struct ut_env *ute);

void ut_format_fs_ok(struct ut_env *ute);

void ut_close_fs_ok(struct ut_env *ute);

void ut_open_repo_ok(struct ut_env *ute);

void ut_close_repo_ok(struct ut_env *ute);

void ut_open_fs_ok(struct ut_env *ute);

void ut_open_fs2_ok(struct ut_env *ute);

void ut_inspect_fs_ok(struct ut_env *ute);

void ut_unref_fs2_ok(struct ut_env *ute);

void ut_fork_fs_ok(struct ut_env *ute);


/* utilities */
void ut_prandom_shuffle(struct ut_env *ute, long *arr, size_t len);

void ut_prandom_seq(struct ut_env *ute, long *arr, size_t len, long base);

void ut_reverse_inplace(long *arr, size_t len);

bool ut_dot_or_dotdot(const char *s);

bool ut_not_dot_or_dotdot(const char *s);

/* execution */
#define ut_exec_with_ranges(ute_, fn_, args_) \
	ut_exec_with_ranges_(ute_, fn_, args_, UT_ARRAY_SIZE(args_))

void ut_exec_with_ranges_(struct ut_env *ute,
                          void (*fn)(struct ut_env *, loff_t, size_t),
                          const struct ut_range *range, size_t na);

/* except */
void ut_expect_eq_ts(const struct timespec *ts1, const struct timespec *ts2);

void ut_expect_eq_stat(const struct stat *st1, const struct stat *st2);

void ut_expect_statvfs(const struct statvfs *stv1, const struct statvfs *stv2);

/* except-alias */
#define ut_expect(cond) \
	silofs_expect_true_((bool)(cond), SILOFS_FL)
#define ut_expect_lt(a, b) \
	silofs_expect_lt_((long)(a), (long)(b), SILOFS_FL)
#define ut_expect_le(a, b) \
	silofs_expect_le_((long)(a), (long)(b), SILOFS_FL)
#define ut_expect_gt(a, b) \
	silofs_expect_gt_((long)(a), (long)(b), SILOFS_FL)
#define ut_expect_ge(a, b) \
	silofs_expect_ge_((long)(a), (long)(b), SILOFS_FL)
#define ut_expect_eq(a, b) \
	silofs_expect_eq_((long)(a), (long)(b), SILOFS_FL)
#define ut_expect_ne(a, b) \
	silofs_expect_ne_((long)(a), (long)(b), SILOFS_FL)
#define ut_expect_ok(err) \
	silofs_expect_ok_((int)(err), SILOFS_FL)
#define ut_expect_err(err, exp) \
	silofs_expect_err_((int)(err), (int)(exp), SILOFS_FL)
#define ut_expect_null(ptr) \
	silofs_expect_null_(ptr, SILOFS_FL)
#define ut_expect_not_null(ptr) \
	silofs_expect_not_null_(ptr, SILOFS_FL)
#define ut_expect_eqs(a, b) \
	silofs_expect_eqs_(a, b, SILOFS_FL)
#define ut_expect_eqm(a, b, n) \
	silofs_expect_eqm_(a, b, n, SILOFS_FL)

/* aliases */
#define UT_1K                   SILOFS_KILO
#define UT_4K                   (4 * SILOFS_KILO)
#define UT_8K                   (8 * SILOFS_KILO)
#define UT_64K                  (64 * SILOFS_KILO)
#define UT_1M                   SILOFS_MEGA
#define UT_1G                   SILOFS_GIGA
#define UT_1T                   SILOFS_TERA

#define UT_BK_SIZE              SILOFS_LBK_SIZE
#define UT_FILESIZE_MAX         SILOFS_FILE_SIZE_MAX
#define UT_IOSIZE_MAX           SILOFS_IO_SIZE_MAX
#define UT_FILEMAP_NCHILDS      SILOFS_FILE_NODE_NCHILDS
#define UT_ROOT_INO             SILOFS_INO_ROOT
#define UT_NAME_MAX             SILOFS_NAME_MAX
#define UT_NAME                 __func__
#define UT_NAME_AT              SILOFS_STR(__LINE__)
#define UT_ARRAY_SIZE(x)        SILOFS_ARRAY_SIZE(x)

#define ut_min(x, y)            silofs_min(x, y)
#define ut_min3(x, y, z)        silofs_min3(x, y, z)
#define ut_max(x, y)            silofs_max(x, y)

#define ut_unused(x) \
	silofs_unused(x)

#define ut_container_of(ptr_, type_, member_) \
	silofs_container_of(ptr_, type_, member_)

#define ut_container_of2(ptr_, type_, member_) \
	silofs_container_of2(ptr_, type_, member_)

#define UT_DEFTESTF(fn_, flags_) \
	{ .hook = fn_, .name = SILOFS_STR(fn_), .flags = flags_ }

#define UT_DEFTEST(fn_)         UT_DEFTESTF(fn_, 0)
#define UT_DEFTEST1(fn_)        UT_DEFTESTF(fn_, UT_F_QUICK)
#define UT_DEFTEST2(fn_)        UT_DEFTESTF(fn_, UT_F_FTYPE2)
#define UT_DEFTEST3(fn_)        UT_DEFTESTF(fn_, UT_F_QUICK | UT_F_FTYPE2)

#define UT_MKTESTS(arr_) \
	{ arr_, SILOFS_ARRAY_SIZE(arr_) }

/* inlines */
static inline loff_t ut_off_aligned(loff_t off, loff_t align)
{
	return (off / align) * align;
}

static inline loff_t ut_off_baligned(loff_t off)
{
	return ut_off_aligned(off, SILOFS_LBK_SIZE);
}

static inline size_t ut_off_len(loff_t beg, loff_t end)
{
	return (size_t)(end - beg);
}

#endif /* SILOFS_UNITESTS_H_ */
