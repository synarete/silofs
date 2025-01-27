/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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

struct silofs_task;

/* inode's attributes masks */
enum silofs_iattr_flags {
	SILOFS_IATTR_PARENT    = SILOFS_BIT(0),
	SILOFS_IATTR_LAZY      = SILOFS_BIT(1),
	SILOFS_IATTR_SIZE      = SILOFS_BIT(2),
	SILOFS_IATTR_SPAN      = SILOFS_BIT(3),
	SILOFS_IATTR_NLINK     = SILOFS_BIT(4),
	SILOFS_IATTR_BLOCKS    = SILOFS_BIT(5),
	SILOFS_IATTR_MODE      = SILOFS_BIT(6),
	SILOFS_IATTR_UID       = SILOFS_BIT(7),
	SILOFS_IATTR_GID       = SILOFS_BIT(8),
	SILOFS_IATTR_KILL_SUID = SILOFS_BIT(9),
	SILOFS_IATTR_KILL_SGID = SILOFS_BIT(10),
	SILOFS_IATTR_BTIME     = SILOFS_BIT(11),
	SILOFS_IATTR_ATIME     = SILOFS_BIT(12),
	SILOFS_IATTR_MTIME     = SILOFS_BIT(13),
	SILOFS_IATTR_CTIME     = SILOFS_BIT(14),
	SILOFS_IATTR_NOW       = SILOFS_BIT(15),
	SILOFS_IATTR_MCTIME    = SILOFS_IATTR_MTIME | SILOFS_IATTR_CTIME,
	SILOFS_IATTR_TIMES     = SILOFS_IATTR_BTIME | SILOFS_IATTR_ATIME |
	                     SILOFS_IATTR_MTIME | SILOFS_IATTR_CTIME
};

/* extended inode stat */
struct silofs_stat {
	struct stat  st;
	struct statx stx;
	uint64_t     gen;
};

/* inode's time-stamps (birth, access, modify, change) */
struct silofs_itimes {
	struct timespec btime;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

/* inode's attributes */
struct silofs_iattr {
	enum silofs_iattr_flags ia_flags;
	mode_t                  ia_mode;
	ino_t                   ia_ino;
	ino_t                   ia_parent;
	nlink_t                 ia_nlink;
	uid_t                   ia_uid;
	gid_t                   ia_gid;
	dev_t                   ia_rdev;
	ssize_t                 ia_size;
	ssize_t                 ia_span;
	blkcnt_t                ia_blocks;
	struct silofs_itimes    ia_t;
};

/* new-inode's create parameters */
struct silofs_inew_params {
	struct silofs_creds creds;
	struct timespec     ts;
	mode_t              mode;
	dev_t               rdev;
	ino_t               parent_ino;
	mode_t              parent_mode;
	enum silofs_inodef  flags;
};

bool silofs_ino_isnull(ino_t ino);

bool silofs_user_cap_fowner(const struct silofs_cred *cred);

bool silofs_user_cap_sys_admin(const struct silofs_cred *cred);

struct silofs_env *silofs_ii_env(const struct silofs_inode_info *ii);

void silofs_ii_set_ino(struct silofs_inode_info *ii, ino_t ino);

void silofs_ii_set_loose(struct silofs_inode_info *ii);

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

void silofs_ii_fixup_as_rootdir(struct silofs_inode_info *ii);

void silofs_ii_update_iflags(struct silofs_inode_info *ii, int iflags_want,
                             int iflags_dont);

void silofs_ii_update_diattrs(struct silofs_inode_info  *ii,
                              const struct silofs_iattr *iattr);

void silofs_ii_refresh_atime(struct silofs_inode_info *ii, bool to_volatile);

void silofs_ii_set_generation(struct silofs_inode_info *ii, uint64_t gen);

void silofs_ii_setup_by(struct silofs_inode_info        *ii,
                        const struct silofs_inew_params *args);

void silofs_ii_stat_of(const struct silofs_inode_info *ii,
                       uint32_t sx_want_mask, struct silofs_stat *st);

void silofs_ii_mkiattr(const struct silofs_inode_info *ii,
                       struct silofs_iattr            *out_iattr);

void silofs_ii_undirtify_vnis(struct silofs_inode_info *ii);

bool silofs_ii_isloose(const struct silofs_inode_info *ii);

ino_t silofs_ii_parent(const struct silofs_inode_info *ii);

enum silofs_inodef silofs_ii_flags(const struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ii_incref(struct silofs_inode_info *ii);

void silofs_ii_decref(struct silofs_inode_info *ii);

void silofs_ii_dirtify(struct silofs_inode_info *ii);

void silofs_ii_undirtify(struct silofs_inode_info *ii);

bool silofs_ii_isdirty(const struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_do_getattr(struct silofs_task *task, struct silofs_inode_info *ii,
                      struct silofs_stat *out_st);

int silofs_do_statx(struct silofs_task *task, struct silofs_inode_info *ii,
                    uint32_t sx_want_mask, struct silofs_stat *out_st);

int silofs_do_chmod(struct silofs_task *task, struct silofs_inode_info *ii,
                    mode_t mode, const struct silofs_itimes *itimes);

int silofs_do_chown(const struct silofs_task *task,
                    struct silofs_inode_info *ii, uid_t uid, gid_t gid,
                    const struct silofs_itimes *itimes);

int silofs_do_utimens(const struct silofs_task   *task,
                      struct silofs_inode_info   *ii,
                      const struct silofs_itimes *itimes);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_update_itimes_of(const struct silofs_task *task,
                             struct silofs_inode_info *ii,
                             enum silofs_iattr_flags   attr_flags);

void silofs_update_iblocks_of(const struct silofs_task *task,
                              struct silofs_inode_info *ii,
                              enum silofs_ltype ltype, long dif);

void silofs_update_iattrs_of(const struct silofs_task  *task,
                             struct silofs_inode_info  *ii,
                             const struct silofs_iattr *iattr);

void silofs_update_isize_of(const struct silofs_task *task,
                            struct silofs_inode_info *ii, ssize_t size);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_inode(const struct silofs_inode *inode);

int silofs_verify_ino(ino_t ino);

ino_t silofs_inode_ino(const struct silofs_inode *inode);

#endif /* SILOFS_INODE_H_ */
