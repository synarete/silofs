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
#ifndef SILOFS_OPERS_H_
#define SILOFS_OPERS_H_

#include <silofs/ioctls.h>

struct silofs_readdir_ctx;
struct silofs_rwiter_ctx;
struct silofs_listxattr_ctx;
struct silofs_laddr_visitor;
struct silofs_stat;

int silofs_exec_forget(struct silofs_task_ctx *task, ino_t ino,
                       size_t nlookup);

int silofs_exec_statfs(struct silofs_task_ctx *task, ino_t ino,
                       struct statvfs *stvfs);

int silofs_exec_lookup(struct silofs_task_ctx *task, ino_t parent,
                       const char *name, struct silofs_stat *out_stat);

int silofs_exec_getattr(struct silofs_task_ctx *task, ino_t ino,
                        struct silofs_stat *out_st);

int silofs_exec_mkdir(struct silofs_task_ctx *task, ino_t parent,
                      const char *name, mode_t mode,
                      struct silofs_stat *out_stat);

int silofs_exec_rmdir(struct silofs_task_ctx *task, ino_t parent,
                      const char *name);

int silofs_exec_access(struct silofs_task_ctx *task, ino_t ino, int mode);

int silofs_exec_chmod(struct silofs_task_ctx *task, ino_t ino, mode_t mode,
                      const struct silofs_itimes *itimes,
                      struct silofs_stat         *out_stat);

int silofs_exec_chown(struct silofs_task_ctx *task, ino_t ino, uid_t uid,
                      gid_t gid, bool kill_suidgid,
                      const struct silofs_itimes *itimes,
                      struct silofs_stat         *out_stat);

int silofs_exec_truncate(struct silofs_task_ctx *task, ino_t ino, off_t len,
                         bool kill_suidgid, struct silofs_stat *out_stat);

int silofs_exec_utimens(struct silofs_task_ctx *task, ino_t ino,
                        const struct silofs_itimes *itimes,
                        struct silofs_stat         *out_stat);

int silofs_exec_symlink(struct silofs_task_ctx *task, ino_t parent,
                        const char *name, const char *symval,
                        struct silofs_stat *out_stat);

int silofs_exec_readlink(struct silofs_task_ctx *task, ino_t ino, char *ptr,
                         size_t lim, size_t *out_len);

int silofs_exec_unlink(struct silofs_task_ctx *task, ino_t parent,
                       const char *name);

int silofs_exec_link(struct silofs_task_ctx *task, ino_t ino, ino_t parent,
                     const char *name, struct silofs_stat *out_stat);

int silofs_exec_rename(struct silofs_task_ctx *task, ino_t parent,
                       const char *name, ino_t newparent, const char *newname,
                       int flags);

int silofs_exec_opendir(struct silofs_task_ctx *task, ino_t ino, int o_flags);

int silofs_exec_releasedir(struct silofs_task_ctx *task, ino_t ino,
                           int o_flags);

int silofs_exec_readdir(struct silofs_task_ctx *task, ino_t ino,
                        struct silofs_readdir_ctx *rd_ctx);

int silofs_exec_readdirplus(struct silofs_task_ctx *task, ino_t ino,
                            struct silofs_readdir_ctx *rd_ctx);

int silofs_exec_fsyncdir(struct silofs_task_ctx *task, ino_t ino,
                         bool datasync);

int silofs_exec_create(struct silofs_task_ctx *task, ino_t parent,
                       const char *name, int o_flags, mode_t mode,
                       bool kill_suidgid, struct silofs_stat *out_stat);

int silofs_exec_open(struct silofs_task_ctx *task, ino_t ino, int o_flags,
                     bool kill_suidgid);

int silofs_exec_mknod(struct silofs_task_ctx *task, ino_t parent,
                      const char *name, mode_t mode, dev_t rdev,
                      struct silofs_stat *out_stat);

int silofs_exec_release(struct silofs_task_ctx *task, ino_t ino, int o_flags,
                        bool flush);

int silofs_exec_flush(struct silofs_task_ctx *task, ino_t ino, bool now);

int silofs_exec_fsync(struct silofs_task_ctx *task, ino_t ino, bool datasync);

int silofs_exec_getxattr(struct silofs_task_ctx *task, ino_t ino,
                         const char *name, void *buf, size_t size,
                         size_t *out_size);

int silofs_exec_setxattr(struct silofs_task_ctx *task, ino_t ino,
                         const char *name, const void *value, size_t size,
                         int flags, bool kill_sgid);

int silofs_exec_listxattr(struct silofs_task_ctx *task, ino_t ino,
                          struct silofs_listxattr_ctx *lxa_ctx);

int silofs_exec_removexattr(struct silofs_task_ctx *task, ino_t ino,
                            const char *name);

int silofs_exec_fallocate(struct silofs_task_ctx *task, ino_t ino, int mode,
                          off_t offset, off_t length);

int silofs_exec_lseek(struct silofs_task_ctx *task, ino_t ino, off_t off,
                      int whence, off_t *out_off);

int silofs_exec_copy_file_range(struct silofs_task_ctx *task, ino_t ino_in,
                                off_t off_in, ino_t ino_out, off_t off_out,
                                size_t len, int flags, size_t *out_ncp);

int silofs_exec_read(struct silofs_task_ctx *task, ino_t ino, void *buf,
                     size_t len, off_t off, int o_flags, size_t *out_len);

int silofs_exec_read_iter(struct silofs_task_ctx *task, ino_t ino, int o_flags,
                          struct silofs_rwiter_ctx *rwi_ctx);

int silofs_exec_write(struct silofs_task_ctx *task, ino_t ino, const void *buf,
                      size_t len, off_t off, int o_flags, bool kill_suidgid,
                      size_t *out_len);

int silofs_exec_write_iter(struct silofs_task_ctx *task, ino_t ino,
                           int o_flags, bool kill_suidgid,
                           struct silofs_rwiter_ctx *rwi_ctx);

int silofs_exec_statx(struct silofs_task_ctx *task, ino_t ino,
                      uint32_t sx_want_mask, struct silofs_stat *out_st);

int silofs_exec_fiemap(struct silofs_task_ctx *task, ino_t ino,
                       struct fiemap *fm);

int silofs_exec_syncfs(struct silofs_task_ctx *task, ino_t ino, int flags);

int silofs_exec_query(struct silofs_task_ctx *task, ino_t ino,
                      enum silofs_query_type   qtype,
                      struct silofs_ioc_query *out_qry);

int silofs_exec_forkfs(struct silofs_task_ctx *task, ino_t ino, int flags,
                       struct silofs_mbrefs *out_mbrefs);

int silofs_exec_tune(struct silofs_task_ctx *task, ino_t ino, int iflags_want,
                     int iflags_dont);

int silofs_exec_rdwr_post(const struct silofs_task_ctx *task, int wr_mode,
                          const struct silofs_iovec *iov, size_t cnt);

int silofs_exec_idle(struct silofs_task_ctx *task, int flags);

int silofs_exec_walkfs(struct silofs_task_ctx *task);

int silofs_exec_unrefs(struct silofs_task_ctx *task);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_exec_format_repo(struct silofs_task_ctx *task);

int silofs_exec_format_fs(struct silofs_task_ctx *task, size_t fs_capacity);

int silofs_exec_commit_mbr(struct silofs_task_ctx *task,
                           struct silofs_mbref    *out_mbref);

int silofs_exec_reload_repo(struct silofs_task_ctx *task);

int silofs_exec_reload_fs(struct silofs_task_ctx    *task,
                          const struct silofs_mbref *mbref);

#endif /* SILOFS_OPERS_H_ */
