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
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/ps.h>

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

/* stage operation control flags */
enum silofs_stg_mode {
	SILOFS_STG_CUR          = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW          = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW          = SILOFS_BIT(2), /* not-set-yet */
};

/* common control flags */
enum silofs_flags {
	SILOFS_F_NOW            = SILOFS_BIT(0),
	SILOFS_F_FSYNC          = SILOFS_BIT(1),
	SILOFS_F_RELEASE        = SILOFS_BIT(2),
	SILOFS_F_BRINGUP        = SILOFS_BIT(4),
	SILOFS_F_OPSTART        = SILOFS_BIT(5),
	SILOFS_F_OPFINISH       = SILOFS_BIT(6),
	SILOFS_F_TIMEOUT        = SILOFS_BIT(7),
	SILOFS_F_IDLE           = SILOFS_BIT(8),
	SILOFS_F_WALKFS         = SILOFS_BIT(9),
	SILOFS_F_TIMEOUT_IDLE   = SILOFS_F_TIMEOUT | SILOFS_F_IDLE,
};

/* fsenv-block control flags */
enum silofs_ubctl_flags {
	SILOFS_UBF_NLOOKUP      = SILOFS_BIT(0),
	SILOFS_UBF_ALLOWOTHER   = SILOFS_BIT(1),
	SILOFS_UBF_ALLOWADMIN   = SILOFS_BIT(2),
	SILOFS_UBF_ASYNCWR      = SILOFS_BIT(3),
};

/* inode's attributes masks */
enum silofs_iattr_flags {
	SILOFS_IATTR_PARENT     = SILOFS_BIT(0),
	SILOFS_IATTR_LAZY       = SILOFS_BIT(1),
	SILOFS_IATTR_SIZE       = SILOFS_BIT(2),
	SILOFS_IATTR_SPAN       = SILOFS_BIT(3),
	SILOFS_IATTR_NLINK      = SILOFS_BIT(4),
	SILOFS_IATTR_BLOCKS     = SILOFS_BIT(5),
	SILOFS_IATTR_MODE       = SILOFS_BIT(6),
	SILOFS_IATTR_UID        = SILOFS_BIT(7),
	SILOFS_IATTR_GID        = SILOFS_BIT(8),
	SILOFS_IATTR_KILL_SUID  = SILOFS_BIT(9),
	SILOFS_IATTR_KILL_SGID  = SILOFS_BIT(10),
	SILOFS_IATTR_BTIME      = SILOFS_BIT(11),
	SILOFS_IATTR_ATIME      = SILOFS_BIT(12),
	SILOFS_IATTR_MTIME      = SILOFS_BIT(13),
	SILOFS_IATTR_CTIME      = SILOFS_BIT(14),
	SILOFS_IATTR_NOW        = SILOFS_BIT(15),
	SILOFS_IATTR_MCTIME     = SILOFS_IATTR_MTIME | SILOFS_IATTR_CTIME,
	SILOFS_IATTR_TIMES      = SILOFS_IATTR_BTIME | SILOFS_IATTR_ATIME |
	                          SILOFS_IATTR_MTIME | SILOFS_IATTR_CTIME
};

/* regual-file sub-types */
enum silofs_file_type {
	SILOFS_FILE_TYPE_NONE   = 0,
	SILOFS_FILE_TYPE1       = 1,
	SILOFS_FILE_TYPE2       = 2,
};


/* strings */
struct silofs_qstr {
	struct silofs_substr s;
	uint64_t hash;
};

struct silofs_namestr {
	struct silofs_substr s;
};

/* pair of ino and dir-type */
struct silofs_ino_dt {
	ino_t  ino;
	mode_t dt;
	int    pad;
};

/* user-credentials */
struct silofs_cred {
	uid_t           uid;
	gid_t           gid;
	mode_t          umask;
};

/* external-internal credentials + time */
struct silofs_creds {
	struct silofs_cred      host_cred;
	struct silofs_cred      fs_cred;
	struct timespec         ts;
};


/* extended inode stat */
struct silofs_stat {
	struct stat             st;
	uint64_t                gen;
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
	mode_t          ia_mode;
	ino_t           ia_ino;
	ino_t           ia_parent;
	nlink_t         ia_nlink;
	uid_t           ia_uid;
	gid_t           ia_gid;
	dev_t           ia_rdev;
	loff_t          ia_size;
	loff_t          ia_span;
	blkcnt_t        ia_blocks;
	struct silofs_itimes ia_t;
};

/* logical addressing of space-mapping nodes */
struct silofs_uaddr {
	struct silofs_laddr     laddr;
	loff_t                  voff;
	enum silofs_stype       stype;
};

/* block address as extension of logical address */
struct silofs_bkaddr {
	struct silofs_laddr     laddr;
	silofs_lba_t            lba;
};

/* a pair of object tree-address and its associate (random) IV */
struct silofs_llink {
	struct silofs_laddr     laddr;
	struct silofs_iv        riv;
};

/* a pair of unode-address and its associate (random) IV */
struct silofs_ulink {
	struct silofs_uaddr     uaddr;
	struct silofs_iv        riv;
};

/* a pair of block-address and its associate (random) IV */
struct silofs_blink {
	struct silofs_bkaddr    bka;
	struct silofs_iv        riv;
};

/* logical addressing of virtual nodes */
struct silofs_vaddr {
	loff_t                  off;
	enum silofs_stype       stype;
	unsigned int            len;
};

/* set of addresses within single vblock */
struct silofs_vaddrs {
	struct silofs_vaddr     vaddr[SILOFS_NKB_IN_LBK];
	size_t                  count;
};

/* vspace address range [beg, end) */
struct silofs_vrange {
	loff_t                  beg;
	loff_t                  end;
	size_t                  len;
	enum silofs_height      height;
};

/* caching-element's key type */
enum silofs_ckey_type {
	SILOFS_CKEY_NONE,
	SILOFS_CKEY_BKADDR,
	SILOFS_CKEY_UADDR,
	SILOFS_CKEY_VADDR,
	SILOFS_CKEY_VBKADDR
};

/* caching-element's control flags */
enum silofs_ce_flags {
	SILOFS_CEF_NONE         = 0x00,
	SILOFS_CEF_DIRTY        = 0x01,
	SILOFS_CEF_MAPPED       = 0x02,
	SILOFS_CEF_FORGOT       = 0x04,
};

/* caching-element's key, up to 256-bits */
union silofs_ckey_u {
	const struct silofs_bkaddr *bkaddr;
	const struct silofs_uaddr  *uaddr;
	const struct silofs_vaddr  *vaddr;
	const struct silofs_lextid *lextid;
	const struct silofs_vbk_addr *vbk_addr;
	const void                 *key;
};

struct silofs_ckey {
	enum silofs_ckey_type   type;
	unsigned long           hash;
	union silofs_ckey_u     keyu;
};

/* caching-elements */
struct silofs_cache_elem {
	struct silofs_list_head ce_htb_lh;
	struct silofs_list_head ce_lru_lh;
	struct silofs_ckey      ce_ckey;
	struct silofs_cache    *ce_cache;
	unsigned long           ce_magic;
	long                    ce_htb_hitcnt;
	long                    ce_lru_hitcnt;
	enum silofs_ce_flags    ce_flags;
	int                     ce_refcnt;
};

/* logical-block base info */
struct silofs_lbk_info {
	struct silofs_cache_elem        lbk_ce;
	struct silofs_lblock           *lbk;
	struct silofs_bk_state          lbk_view;
};

/* u-addressing block info */
struct silofs_ubk_info {
	struct silofs_lbk_info          ubk;
	struct silofs_bkaddr            ubk_addr;
};

/* virtual-block addressing */
struct silofs_vbk_addr {
	loff_t                          vbk_voff;
	enum silofs_stype               vbk_vspace;
};

/* v-addressing block info */
struct silofs_vbk_info {
	struct silofs_lbk_info           vbk;
	struct silofs_vbk_addr           vbk_addr;
};

/* in-memory mapping from ino to voff */
struct silofs_inoent {
	struct silofs_list_head htb_lh;
	struct silofs_list_head lru_lh;
	ino_t   ino;
	loff_t  voff;
};

/* operations counters */
struct silofs_oper_stat {
	size_t op_iopen_max;
	size_t op_iopen;
	time_t op_time;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* dirty-queue of cached-elements */
struct silofs_dirtyq {
	struct silofs_listq             dq;
	size_t                          dq_accum;
};

#endif /* SILOFS_TYPES_H_ */
