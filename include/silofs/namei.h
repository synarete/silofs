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
#ifndef SILOFS_NAMEI_H_
#define SILOFS_NAMEI_H_


struct silofs_bootsec;
struct silofs_sb_info;
struct silofs_task;
struct silofs_ioc_query;
struct silofs_ioc_iterfs;
struct silofs_inew_params;


void silofs_inew_params_of(const struct silofs_task *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, dev_t rdev,
                           struct silofs_inew_params *out_args);

int silofs_make_namestr_by(struct silofs_namestr *nstr,
                           const struct silofs_inode_info *ii, const char *s);

int silofs_do_forget(struct silofs_task *task,
                     struct silofs_inode_info *ii, size_t nlookup);

int silofs_do_statvfs(const struct silofs_task *task,
                      struct silofs_inode_info *ii,
                      struct statvfs *out_stvfs);

int silofs_do_access(const struct silofs_task *task,
                     struct silofs_inode_info *ii, int mode);

int silofs_do_open(struct silofs_task *task,
                   struct silofs_inode_info *ii, int flags);

int silofs_do_release(struct silofs_task *task,
                      struct silofs_inode_info *ii, bool flush);

int silofs_do_mkdir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii);

int silofs_do_rmdir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name);

int silofs_do_rename(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags);

int silofs_do_symlink(struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii);

int silofs_do_link(struct silofs_task *task,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info *ii);

int silofs_do_unlink(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name);

int silofs_do_create(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii);

int silofs_do_mknod(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii);

int silofs_do_lookup(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii);

int silofs_do_opendir(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii, int o_flags);

int silofs_do_releasedir(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         int o_flags, bool flush);

int silofs_do_fsyncdir(struct silofs_task *task,
                       struct silofs_inode_info *dir_ii, bool dsync);

int silofs_do_fsync(struct silofs_task *task,
                    struct silofs_inode_info *ii, bool datasync);

int silofs_do_flush(struct silofs_task *task,
                    struct silofs_inode_info *ii, bool now);

int silofs_do_query(struct silofs_task *task,
                    struct silofs_inode_info *ii,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *out_qry);

int silofs_do_clone(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii, int flags,
                    struct silofs_bootsecs *out_bsecs);

int silofs_do_syncfs(struct silofs_task *task,
                     struct silofs_inode_info *ii, int flags);

int silofs_do_timedout(struct silofs_task *task, int flags);

int silofs_do_inspect(struct silofs_task *task);

int silofs_do_unrefs(struct silofs_task *task);

#endif /* SILOFS_NAMEI_H_ */
