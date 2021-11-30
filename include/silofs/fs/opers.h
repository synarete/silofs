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
struct silofs_oper;
struct silofs_ioc_query;

int silofs_fs_forget(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t ino, size_t nlookup);

int silofs_fs_statfs(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t ino,
                     struct statvfs *stvfs);

int silofs_fs_lookup(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t parent,
                     const char *name, struct stat *out_stat);

int silofs_fs_getattr(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op,
                      ino_t ino, struct stat *out_stat);

int silofs_fs_mkdir(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat);

int silofs_fs_rmdir(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t parent, const char *name);

int silofs_fs_access(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t ino, int mode);

int silofs_fs_chmod(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat);

int silofs_fs_chown(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat);

int silofs_fs_truncate(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino, loff_t len,
                       struct stat *out_stat);

int silofs_fs_utimens(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t ino,
                      const struct stat *times, struct stat *out_stat);

int silofs_fs_symlink(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat);

int silofs_fs_readlink(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len);

int silofs_fs_unlink(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t parent, const char *name);

int silofs_fs_link(struct silofs_fs_apex *apex,
                   const struct silofs_oper *op, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat);

int silofs_fs_rename(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags);

int silofs_fs_opendir(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t ino);

int silofs_fs_releasedir(struct silofs_fs_apex *apex,
                         const struct silofs_oper *op, ino_t ino, int o_flags);

int silofs_fs_readdir(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op, ino_t ino,
                      struct silofs_readdir_ctx *rd_ctx);

int silofs_fs_readdirplus(struct silofs_fs_apex *apex,
                          const struct silofs_oper *op, ino_t ino,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_fs_fsyncdir(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino, bool datasync);

int silofs_fs_create(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat);

int silofs_fs_open(struct silofs_fs_apex *apex,
                   const struct silofs_oper *op, ino_t ino, int o_flags);

int silofs_fs_mknod(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t parent, const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat);

int silofs_fs_release(struct silofs_fs_apex *apex,
                      const struct silofs_oper *op,
                      ino_t ino, int o_flags, bool flush);

int silofs_fs_flush(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino);

int silofs_fs_fsync(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t ino, bool datasync);

int silofs_fs_getxattr(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size);

int silofs_fs_setxattr(struct silofs_fs_apex *apex,
                       const struct silofs_oper *op, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags, bool kill_sgid);

int silofs_fs_listxattr(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        struct silofs_listxattr_ctx *lxa_ctx);

int silofs_fs_removexattr(struct silofs_fs_apex *apex,
                          const struct silofs_oper *op,
                          ino_t ino, const char *name);

int silofs_fs_fallocate(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        int mode, loff_t offset, loff_t length);

int silofs_fs_lseek(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    loff_t off, int whence, loff_t *out_off);

int silofs_fs_copy_file_range(struct silofs_fs_apex *apex,
                              const struct silofs_oper *op, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp);

int silofs_fs_read(struct silofs_fs_apex *apex,
                   const struct silofs_oper *op, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len);

int silofs_fs_read_iter(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        struct silofs_rwiter_ctx *rwi_ctx);

int silofs_fs_write(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len);

int silofs_fs_write_iter(struct silofs_fs_apex *apex,
                         const struct silofs_oper *op, ino_t ino,
                         struct silofs_rwiter_ctx *rwi_ctx);

int silofs_fs_rdwr_post(struct silofs_fs_apex *apex,
                        const struct silofs_oper *op, ino_t ino,
                        const struct silofs_fiovec *fiov, size_t cnt);

int silofs_fs_statx(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx);

int silofs_fs_fiemap(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t ino,
                     struct fiemap *fm);

int silofs_fs_syncfs(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op, ino_t ino);

int silofs_fs_query(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op, ino_t ino,
                    struct silofs_ioc_query *out_qry);

int silofs_fs_clone(struct silofs_fs_apex *apex,
                    const struct silofs_oper *op,
                    ino_t ino, const char *name, int flags);

int silofs_fs_iterfs(struct silofs_fs_apex *apex,
                     const struct silofs_oper *op,
                     ino_t ino, loff_t idx, char *out_buf, size_t bsz,
                     time_t *out_btime, loff_t *out_index);

int silofs_fs_timedout(struct silofs_fs_apex *apex, int flags);

#endif /* SILOFS_OPERS_H_ */
