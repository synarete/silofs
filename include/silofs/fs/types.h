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
#ifndef SILOFS_TYPES_H_
#define SILOFS_TYPES_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <gcrypt.h>
#include <iconv.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/str.h>

/* types forward declarations */
struct silofs_dset;
struct silofs_lnode_info;
struct silofs_unode_info;
struct silofs_vnode_info;
struct silofs_inode_info;
struct silofs_rwiter_ctx;
struct silofs_readdir_ctx;
struct silofs_readdir_info;
struct silofs_listxattr_ctx;

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

/* name-string: a pair of string-view and (optional) 64-bits hash */
struct silofs_namestr {
	struct silofs_strview sv;
	uint64_t              hash;
};

/* pair of ino and dir-type */
struct silofs_ino_dt {
	ino_t  ino;
	mode_t dt;
	int    pad;
};

/* user-credentials */
struct silofs_cred {
	uid_t  uid;
	gid_t  gid;
	mode_t umask;
};

/* external-internal credentials + time */
struct silofs_creds {
	struct silofs_cred host_cred;
	struct silofs_cred fs_cred;
	struct timespec    ts;
};

/* extended inode stat */
struct silofs_stat {
	struct stat st;
	uint64_t    gen;
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

/* in-memory mapping from ino to voff */
struct silofs_inoent {
	struct silofs_list_head htb_lh;
	struct silofs_list_head lru_lh;
	ino_t                   ino;
	loff_t                  voff;
};

#endif /* SILOFS_TYPES_H_ */
