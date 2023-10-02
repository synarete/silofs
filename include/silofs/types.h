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
#include <uuid/uuid.h>
#include <gcrypt.h>
#include <iconv.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <silofs/infra.h>
#include <silofs/fsdef.h>

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

/* uber-block control flags */
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
struct silofs_str {
	const char *str;
	size_t len;
};

struct silofs_qstr {
	struct silofs_str s;
	uint64_t hash;
};

struct silofs_namestr {
	struct silofs_str s;
};

/* pair of ino and dir-type */
struct silofs_ino_dt {
	ino_t  ino;
	mode_t dt;
	int    pad;
};

/* name-buffer */
struct silofs_namebuf {
	char name[SILOFS_NAME_MAX + 1];
};

/* pass-phrase buffers */
struct silofs_password {
	uint8_t pass[SILOFS_PASSWORD_MAX + 1];
	size_t passlen;
};

/* cryptographic interfaces with libgcrypt */
struct silofs_mdigest {
	gcry_md_hd_t md_hd;
};

struct silofs_cipher {
	gcry_cipher_hd_t cipher_hd;
};

struct silofs_crypto {
	struct silofs_mdigest   md;
	struct silofs_cipher    ci;
	unsigned int            set;
};

/* cryptographic-cipher arguments */
struct silofs_cipher_args {
	struct silofs_kdf_pair  kdf;
	unsigned int cipher_algo;
	unsigned int cipher_mode;
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


/* space-addressing */
typedef loff_t          silofs_lba_t;


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

/* encryption tuple (IV, key, cipher-algo, mode) */
struct silofs_ivkey {
	struct silofs_key       key;
	struct silofs_iv        iv;
	unsigned int            algo;
	unsigned int            mode;
};

/* blob identifier */
struct silofs_blobid {
	struct silofs_treeid    treeid;
	loff_t                  voff;
	size_t                  size;
	enum silofs_stype       vspace;
	enum silofs_height      height;
};

/* persistent address of sub-range within blob */
struct silofs_paddr {
	struct silofs_blobid    blobid;
	loff_t                  pos;
	size_t                  len;
};

/* block address within blob */
struct silofs_bkaddr {
	struct silofs_paddr     paddr;
	silofs_lba_t            lba;
};

/* logical addressing of space-mapping elements */
struct silofs_uaddr {
	struct silofs_paddr     paddr;
	loff_t                  voff;
	enum silofs_stype       stype;
};

/* a pair of object-address and its associate (random) IV */
struct silofs_plink {
	struct silofs_paddr     paddr;
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

/* logical addressing of virtual elements */
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
	SILOFS_CKEY_BLOBID,
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
	const struct silofs_blobid *blobid;
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
	struct silofs_blobf            *ubk_blobf;
};

/* virtual-block addressing */
struct silofs_vbk_addr {
	loff_t                          vbk_voff;
	enum silofs_stype               vbk_vspace;
};

/* v-addressing block info */
struct silofs_vbk_info {
	struct silofs_lbk_info           vbk;
	struct silofs_vbk_addr          vbk_addr;
};


/* space accounting per sub-type */
struct silofs_spacegauges {
	ssize_t nsuper;
	ssize_t nspnode;
	ssize_t nspleaf;
	ssize_t ninode;
	ssize_t nxanode;
	ssize_t ndtnode;
	ssize_t nsymval;
	ssize_t nftnode;
	ssize_t ndata1k;
	ssize_t ndata4k;
	ssize_t ndatabk;
};

/* space accounting per sub-kind + sub-type */
struct silofs_spacestats {
	time_t          btime;
	time_t          ctime;
	size_t          capacity;
	size_t          vspacesize;
	uint64_t        generation;
	struct silofs_spacegauges blobs;
	struct silofs_spacegauges bks;
	struct silofs_spacegauges objs;
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

/* dirty-nodes set */
typedef void (*silofs_dset_add_fn)(struct silofs_dset *dset,
                                   struct silofs_lnode_info *lni);

struct silofs_dset {
	struct silofs_lnode_info       *ds_preq;
	struct silofs_lnode_info       *ds_postq;
	struct silofs_avl               ds_avl;
};

struct silofs_dsets {
	struct silofs_dset dset[SILOFS_STYPE_LAST];
};

/* current operation */
struct silofs_oper {
	struct silofs_creds             op_creds;
	pid_t                           op_pid;
	uint64_t                        op_unique;
	uint32_t                        op_code;
};

/* base members of uber-block (provided) */
struct silofs_uber_base {
	const struct silofs_fs_args    *fs_args;
	const struct silofs_ivkey      *boot_ivkey;
	const struct silofs_ivkey      *main_ivkey;
	struct silofs_alloc            *alloc;
	struct silofs_cache            *cache;
	struct silofs_repo             *repo;
	struct silofs_submitq          *submitq;
	struct silofs_idsmap           *idsmap;
};

/* top-level pseudo meta node */
struct silofs_uber {
	struct silofs_uber_base         ub;
	struct silofs_mutex             ub_fs_lock;
	struct silofs_crypto            ub_crypto;
	struct silofs_oper_stat         ub_ops;
	struct silofs_blobf            *ub_sb_blobf;
	struct silofs_sb_info          *ub_sbi;
	struct silofs_ulink             ub_sb_ulink;
	struct silofs_cred              ub_owner;
	unsigned long                   ub_ctl_flags;
	unsigned long                   ub_ms_flags;
	iconv_t                         ub_iconv;
	time_t                          ub_initime;
	uint64_t                        ub_commit_id;
};

/* file-system's input ids */
struct silofs_ids {
	struct silofs_uids     *uids;
	struct silofs_gids     *gids;
	size_t                  nuids;
	size_t                  ngids;
};

/* initialization configurations */
struct silofs_iconf {
	struct silofs_namebuf   name;
	struct silofs_uuid      uuid;
	struct silofs_ids       ids;
};

/* file-system input arguments */
struct silofs_fs_args {
	struct silofs_iconf     iconf;
	const char             *repodir;
	const char             *name;
	const char             *mntdir;
	const char             *passwd;
	uid_t                   uid;
	gid_t                   gid;
	pid_t                   pid;
	mode_t                  umask;
	size_t                  capacity;
	size_t                  memwant;
	bool                    withfuse;
	bool                    pedantic;
	bool                    allowother;
	bool                    allowhostids;
	bool                    allowadmin;
	bool                    writeback_cache;
	bool                    lazytime;
	bool                    noexec;
	bool                    nosuid;
	bool                    nodev;
	bool                    rdonly;
	bool                    asyncwr;
	bool                    stdalloc;
	bool                    restore_forced;
};

/* file-system environment context */
struct silofs_fs_env {
	struct silofs_fs_args   fs_args;
	struct silofs_ivkey     fs_boot_ivkey;
	struct silofs_ivkey     fs_main_ivkey;
	struct silofs_qalloc   *fs_qalloc;
	struct silofs_calloc   *fs_calloc;
	struct silofs_alloc    *fs_alloc;
	struct silofs_cache    *fs_cache;
	struct silofs_repo     *fs_repo;
	struct silofs_submitq  *fs_submitq;
	struct silofs_idsmap   *fs_idsmap;
	struct silofs_uber     *fs_uber;
	struct silofs_fuseq    *fs_fuseq;
	struct silofs_password *fs_passwd;
	struct silofs_uaddr     fs_sb_addr;
	int                     fs_signum;
};

/* file-system' internal cache stats */
struct silofs_fs_stats {
	size_t nalloc_bytes;
	size_t ncache_ublocks;
	size_t ncache_vblocks;
	size_t ncache_unodes;
	size_t ncache_vnodes;
};

/* call-back types for file-system operations */
typedef int (*silofs_filldir_fn)(struct silofs_readdir_ctx *rd_ctx,
                                 const struct silofs_readdir_info *rdi);

struct silofs_readdir_info {
	struct silofs_stat attr;
	const char     *name;
	size_t          namelen;
	ino_t           ino;
	loff_t          off;
	mode_t          dt;
};

struct silofs_readdir_ctx {
	silofs_filldir_fn actor;
	loff_t pos;
};


typedef int (*silofs_fillxattr_fn)(struct silofs_listxattr_ctx *lxa_ctx,
                                   const char *name, size_t name_len);

struct silofs_listxattr_ctx {
	silofs_fillxattr_fn actor;
};

typedef int (*silofs_rwiter_fn)(struct silofs_rwiter_ctx *rwi_ctx,
                                const struct silofs_iovec *iov);

struct silofs_rwiter_ctx {
	silofs_rwiter_fn actor;
	loff_t off;
	size_t len;
};


#endif /* SILOFS_TYPES_H_ */
