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
#ifndef SILOFS_OPERS_H_
#define SILOFS_OPERS_H_

#include <unistd.h>
#include <stdlib.h>

struct silofs_fs_apex;
struct silofs_fs_ctx;
struct silofs_ioc_query;
struct silofs_ioc_iterfs;

int silofs_fs_forget(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, size_t nlookup);

int silofs_fs_statfs(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, struct statvfs *stvfs);

int silofs_fs_lookup(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                     const char *name, struct stat *out_stat);

int silofs_fs_getattr(const struct silofs_fs_ctx *fs_ctx,
                      ino_t ino, struct stat *out_stat);

int silofs_fs_mkdir(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat);

int silofs_fs_rmdir(const struct silofs_fs_ctx *fs_ctx,
                    ino_t parent, const char *name);

int silofs_fs_access(const struct silofs_fs_ctx *fs_ctx, ino_t ino, int mode);

int silofs_fs_chmod(const struct silofs_fs_ctx *fs_ctx, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat);

int silofs_fs_chown(const struct silofs_fs_ctx *fs_ctx, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat);

int silofs_fs_truncate(const struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, loff_t len, struct stat *out_stat);

int silofs_fs_utimens(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                      const struct stat *times, struct stat *out_stat);

int silofs_fs_symlink(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat);

int silofs_fs_readlink(const struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len);

int silofs_fs_unlink(const struct silofs_fs_ctx *fs_ctx,
                     ino_t parent, const char *name);

int silofs_fs_link(const struct silofs_fs_ctx *fs_ctx, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat);

int silofs_fs_rename(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags);

int silofs_fs_opendir(const struct silofs_fs_ctx *fs_ctx, ino_t ino);

int silofs_fs_releasedir(const struct silofs_fs_ctx *fs_ctx,
                         ino_t ino, int o_flags);

int silofs_fs_readdir(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx);

int silofs_fs_readdirplus(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_fs_fsyncdir(const struct silofs_fs_ctx *fs_ctx,
                       ino_t ino, bool datasync);

int silofs_fs_create(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat);

int silofs_fs_open(const struct silofs_fs_ctx *fs_ctx, ino_t ino, int o_flags);

int silofs_fs_mknod(const struct silofs_fs_ctx *fs_ctx, ino_t parent,
                    const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat);

int silofs_fs_release(const struct silofs_fs_ctx *fs_ctx,
                      ino_t ino, int o_flags, bool flush);

int silofs_fs_flush(const struct silofs_fs_ctx *fs_ctx, ino_t ino);

int silofs_fs_fsync(const struct silofs_fs_ctx *fs_ctx,
                    ino_t ino, bool datasync);

int silofs_fs_getxattr(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size);

int silofs_fs_setxattr(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags, bool kill_sgid);

int silofs_fs_listxattr(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx);

int silofs_fs_removexattr(const struct silofs_fs_ctx *fs_ctx,
                          ino_t ino, const char *name);

int silofs_fs_fallocate(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        int mode, loff_t offset, loff_t length);

int silofs_fs_lseek(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    loff_t off, int whence, loff_t *out_off);

int silofs_fs_copy_file_range(const struct silofs_fs_ctx *fs_ctx, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp);

int silofs_fs_read(const struct silofs_fs_ctx *fs_ctx, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len);

int silofs_fs_read_iter(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx);

int silofs_fs_write(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len);

int silofs_fs_write_iter(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx);

int silofs_fs_rdwr_post(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                        const struct silofs_xiovec *xiov, size_t cnt);

int silofs_fs_statx(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx);

int silofs_fs_fiemap(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, struct fiemap *fm);

int silofs_fs_syncfs(const struct silofs_fs_ctx *fs_ctx, ino_t ino);

int silofs_fs_query(const struct silofs_fs_ctx *fs_ctx, ino_t ino,
                    struct silofs_ioc_query *out_qry);

int silofs_fs_clone(const struct silofs_fs_ctx *fs_ctx,
                    ino_t ino, const char *name, int flags);

int silofs_fs_unrefs(const struct silofs_fs_ctx *fs_ctx,
                     ino_t ino, const char *name);

int silofs_fs_inspect(const struct silofs_fs_ctx *fs_ctx, ino_t ino);

int silofs_fs_pack(const struct silofs_fs_ctx *fs_ctx,
                   const char *src_name, const char *dst_name);

int silofs_fs_unpack(const struct silofs_fs_ctx *fs_ctx,
                     const char *src_name, const char *dst_name);

int silofs_fs_timedout(struct silofs_fs_apex *apex, int flags);

#endif /* SILOFS_OPERS_H_ */
