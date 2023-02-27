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
#ifndef SILOFS_INODE_H_
#define SILOFS_INODE_H_

#include <unistd.h>
#include <silofs/types.h>

bool silofs_user_cap_fowner(const struct silofs_ucred *ucred);

bool silofs_user_cap_sys_admin(const struct silofs_ucred *ucred);


ino_t silofs_ii_parent(const struct silofs_inode_info *ii);

ino_t silofs_ii_xino_of(const struct silofs_inode_info *ii);

ino_t silofs_ii_ino_of(const struct silofs_inode_info *ii);

uid_t silofs_ii_uid(const struct silofs_inode_info *ii);

gid_t silofs_ii_gid(const struct silofs_inode_info *ii);

mode_t silofs_ii_mode(const struct silofs_inode_info *ii);

nlink_t silofs_ii_nlink(const struct silofs_inode_info *ii);

loff_t silofs_ii_size(const struct silofs_inode_info *ii);

loff_t silofs_ii_span(const struct silofs_inode_info *ii);

blkcnt_t silofs_ii_blocks(const struct silofs_inode_info *ii);

uint64_t silofs_ii_generation(const struct silofs_inode_info *ii);

bool silofs_ii_isdir(const struct silofs_inode_info *ii);

bool silofs_ii_isreg(const struct silofs_inode_info *ii);

bool silofs_ii_isfifo(const struct silofs_inode_info *ii);

bool silofs_ii_issock(const struct silofs_inode_info *ii);

bool silofs_ii_islnk(const struct silofs_inode_info *ii);

bool silofs_ii_isrootd(const struct silofs_inode_info *ii);

bool silofs_is_rootdir(const struct silofs_inode_info *ii);

bool silofs_ii_isevictable(const struct silofs_inode_info *ii);

bool silof_ii_isimmutable(const struct silofs_inode_info *ii);

void silofs_ii_iaddr(const struct silofs_inode_info *ii,
                     struct silofs_iaddr *out_iaddr);

void silofs_ii_fixup_as_rootdir(struct silofs_inode_info *ii);

enum silofs_inodef silofs_ii_flags(const struct silofs_inode_info *ii);

int silofs_do_getattr(struct silofs_task *task,
                      struct silofs_inode_info *ii,
                      struct silofs_stat *out_st);

int silofs_do_statx(struct silofs_task *task, struct silofs_inode_info *ii,
                    unsigned int request_mask, struct statx *out_stx);

int silofs_do_chmod(struct silofs_task *task,
                    struct silofs_inode_info *ii, mode_t mode,
                    const struct silofs_itimes *itimes);

int silofs_do_chown(const struct silofs_task *task,
                    struct silofs_inode_info *ii, uid_t uid, gid_t gid,
                    const struct silofs_itimes *itimes);

int silofs_do_utimens(const struct silofs_task *task,
                      struct silofs_inode_info *ii,
                      const struct silofs_itimes *itimes);

int silofs_verify_inode(const struct silofs_inode *inode);

void silofs_ii_update_itimes(struct silofs_inode_info *ii,
                             const struct silofs_creds *creds,
                             enum silofs_iattr_flags attr_flags);

void silofs_ii_update_iblocks(struct silofs_inode_info *ii,
                              const struct silofs_creds *creds,
                              enum silofs_stype stype, long dif);

void silofs_ii_update_isize(struct silofs_inode_info *ii,
                            const struct silofs_creds *creds, loff_t size);

void silofs_ii_update_iattrs(struct silofs_inode_info *ii,
                             const struct silofs_creds *creds,
                             const struct silofs_iattr *iattr);

void silofs_iattr_setup(struct silofs_iattr *iattr, ino_t ino);

void silofs_ii_refresh_atime(struct silofs_inode_info *ii, bool to_volatile);

void silofs_ii_stamp_mark_visible(struct silofs_inode_info *ii);

void silofs_ii_setup_by(struct silofs_inode_info *ii,
                        const struct silofs_creds *creds,
                        ino_t parent, mode_t parent_mode,
                        mode_t mode, dev_t rdev, uint64_t gen);

void silofs_ii_statof(const struct silofs_inode_info *ii,
                      struct silofs_stat *st);

#endif /* SILOFS_INODE_H_ */
