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
#ifndef SILOFS_NAMEI_H_
#define SILOFS_NAMEI_H_

#include <unistd.h>

struct silofs_sb_info;
struct silofs_oper;
struct silofs_ioc_query;


int silofs_make_namestr(const struct silofs_inode_info *ii,
                        const char *name, struct silofs_namestr *str);

int silofs_do_forget(const struct silofs_oper *op,
                     struct silofs_inode_info *ii, size_t nlookup);

int silofs_do_statvfs(const struct silofs_oper *op,
                      struct silofs_inode_info *ii,
                      struct statvfs *out_stvfs);

int silofs_do_access(const struct silofs_oper *op,
                     struct silofs_inode_info *ii, int mode);

int silofs_do_open(const struct silofs_oper *op,
                   struct silofs_inode_info *ii, int flags);

int silofs_do_release(const struct silofs_oper *op,
                      struct silofs_inode_info *ii);

int silofs_do_mkdir(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii);

int silofs_do_rmdir(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name);

int silofs_do_rename(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags);

int silofs_do_symlink(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii);

int silofs_do_link(const struct silofs_oper *op,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info *ii);

int silofs_do_unlink(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name);

int silofs_do_create(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii);

int silofs_do_mknod(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii);

int silofs_do_lookup(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii);

int silofs_do_opendir(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii);

int silofs_do_releasedir(const struct silofs_oper *op,
                         struct silofs_inode_info *dir_ii);

int silofs_do_fsyncdir(const struct silofs_oper *op,
                       struct silofs_inode_info *dir_ii, bool dsync);

int silofs_do_fsync(const struct silofs_oper *op,
                    struct silofs_inode_info *ii, bool datasync);

int silofs_do_flush(const struct silofs_oper *op,
                    struct silofs_inode_info *ii);

int silofs_do_query(const struct silofs_oper *op,
                    struct silofs_inode_info *ii,
                    struct silofs_ioc_query *out_qry);

int silofs_do_clone(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, int flags);

int silofs_do_iterfs(const struct silofs_oper *op,
                     struct silofs_inode_info *ii, loff_t idx,
                     struct silofs_namebuf *out_nb,
                     time_t *out_btime, loff_t *out_idx);

int silofs_check_name(const char *name);

int silof_check_writable_fs(const struct silofs_sb_info *sbi);

#endif /* SILOFS_NAMEI_H_ */
