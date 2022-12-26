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
struct silofs_snode_info;
struct silofs_unode_info;
struct silofs_vnode_info;
struct silofs_inode_info;
struct silofs_rwiter_ctx;
struct silofs_readdir_ctx;
struct silofs_readdir_info;
struct silofs_listxattr_ctx;

/* stage-elements mode */
enum silofs_stage_mode {
	SILOFS_STAGE_RO         = SILOFS_BIT(1),
	SILOFS_STAGE_RW         = SILOFS_BIT(2),
};

/* common control flags */
enum silofs_flags {
	SILOFS_F_FSYNC          = SILOFS_BIT(1),
	SILOFS_F_RELEASE        = SILOFS_BIT(2),
	SILOFS_F_NOW            = SILOFS_BIT(3),
	SILOFS_F_BLKDEV         = SILOFS_BIT(4),
	SILOFS_F_MEMFD          = SILOFS_BIT(5),
	SILOFS_F_BRINGUP        = SILOFS_BIT(6),
	SILOFS_F_OPSTART        = SILOFS_BIT(7),
	SILOFS_F_TIMEOUT        = SILOFS_BIT(8),
	SILOFS_F_IDLE           = SILOFS_BIT(9),
	SILOFS_F_WALKFS         = SILOFS_BIT(10),
};

/* super-block control flags */
enum silofs_sbctl_flags {
	SILOFS_SBCF_KCOPY       = SILOFS_BIT(1),
	SILOFS_SBCF_NLOOKUP     = SILOFS_BIT(2),
	SILOFS_SBCF_ALLOWOTHER  = SILOFS_BIT(3),
	SILOFS_SBCF_ALLOWADMIN  = SILOFS_BIT(4),
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
};

/* cryptographic-cipher arguments */
struct silofs_cipher_args {
	struct silofs_kdf_pair  kdf;
	unsigned int cipher_algo;
	unsigned int cipher_mode;
};

/* user-credentials */
struct silofs_ucred {
	uid_t  uid;
	gid_t  gid;
	pid_t  pid;
	mode_t umask;
};

/* external-internal credentials + time */
struct silofs_creds {
	struct silofs_ucred     xcred;
	struct silofs_ucred     icred;
	struct timespec         ts;
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

/* space-tree id */
struct silofs_treeid {
	struct silofs_uuid      uuid;
};

/* tree-addressing blob-id */
struct silofs_blobid_ta {
	struct silofs_treeid    treeid;
	loff_t                  voff;
};

/* content-addressing blob-id */
struct silofs_blobid_ca {
	uint8_t hash[SILOFS_HASH256_LEN];
};

/* union of possible blob addressing */
union silofs_blobid_u {
	struct silofs_blobid_ta ta;
	struct silofs_blobid_ca ca;
};

/* blob identifier */
struct silofs_blobid {
	union silofs_blobid_u   u;
	size_t                  size;
	enum silofs_stype       vspace;
	enum silofs_height      height;
	enum silofs_blobtype    btype;
	enum silofs_pack        pmode;
};

/* block address within blob */
struct silofs_bkaddr {
	struct silofs_blobid    blobid;
	silofs_lba_t            lba;
};

/* object address within blob */
struct silofs_oaddr {
	struct silofs_bkaddr    bka;
	loff_t                  pos;
	size_t                  len;
};

/* logical addressing of space-mapping elements */
struct silofs_uaddr {
	struct silofs_oaddr     oaddr;
	loff_t                  voff;
	enum silofs_stype       stype;
	enum silofs_height      height;
};

/* logical addressing of virtual elements */
struct silofs_vaddr {
	loff_t                  voff;
	enum silofs_stype       stype;
	unsigned int            len;
};

/* inodes addressing: ino to logical address mapping */
struct silofs_iaddr {
	ino_t                   ino;
	struct silofs_vaddr     vaddr;
};

/* vnode's object placement address */
struct silofs_voaddr {
	struct silofs_vaddr     vaddr;
	struct silofs_oaddr     oaddr;
};

/* inode's placement address */
struct silofs_ivoaddr {
	ino_t                   ino;
	struct silofs_voaddr    voa;
};

/* vspace address range [beg, end) */
struct silofs_vrange {
	loff_t                  beg;
	loff_t                  end;
	size_t                  len;
	enum silofs_height      height;
};

/* dirty-queue id-number of snode (zero=no-owner) */
typedef unsigned long silofs_dqid_t;

/* dirty-queues special ids */
#define SILOFS_DQID_DFL         (0)
#define SILOFS_DQID_ALL         ((1UL << 56) - 1)

/* caching-element's key type */
enum silofs_ckey_type {
	SILOFS_CKEY_NONE,
	SILOFS_CKEY_BLOBID,
	SILOFS_CKEY_BKADDR,
	SILOFS_CKEY_UADDR,
	SILOFS_CKEY_VADDR,
	SILOFS_CKEY_VBKADDR
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
	int     ce_refcnt;
	int     ce_hitcnt;
	bool    ce_dirty;
	bool    ce_mapped;
	bool    ce_forgot;
};

/* uber-block info */
struct silofs_ubk_info {
	struct silofs_cache_elem        ubk_ce;
	struct silofs_bkaddr            ubk_addr;
	struct silofs_block            *ubk;
	struct silofs_blobref_info     *ubk_bri;
};

/* virtual-block addressing */
struct silofs_vbk_addr {
	loff_t                          vbk_voff;
	enum silofs_stype               vbk_vspace;
};

/* virtual-block info */
struct silofs_vbk_info {
	struct silofs_cache_elem        vbk_ce;
	struct silofs_block            *vbk;
	struct silofs_vbk_addr          vbk_addr;
};


/* space accounting per sub-type */
struct silofs_spacegauges {
	ssize_t nsuper;
	ssize_t nspnode;
	ssize_t nspleaf;
	ssize_t nitnode;
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
	time_t btime;
	time_t ctime;
	size_t capacity;
	size_t vspacesize;
	struct silofs_spacegauges blobs;
	struct silofs_spacegauges bks;
	struct silofs_spacegauges objs;
};

/* v-space allocation hints */
struct silofs_vspalloc_hints {
	loff_t data1k;
	loff_t data4k;
	loff_t databk;
	loff_t itnode;
	loff_t inode;
	loff_t xanode;
	loff_t dirnode;
	loff_t filenode;
	loff_t symval;
};

/* in-memory mapping from ino to voff */
struct silofs_inoent {
	struct silofs_list_head htb_lh;
	struct silofs_list_head lru_lh;
	ino_t   ino;
	loff_t  voff;
};

/* in-memory hash-map of ino-to-voff mapping */
struct silofs_inomap {
	struct silofs_listq      im_lru;
	struct silofs_alloc     *im_alloc;
	struct silofs_list_head *im_htbl;
	size_t im_htbl_nelems;
};

/* inodes-table reference */
struct silofs_itable_info {
	struct silofs_inomap    it_inomap;
	struct silofs_vaddr     it_root_itb;
	struct silofs_iaddr     it_root_dir;
	ino_t  it_apex_ino;
	size_t it_ninodes;
	size_t it_ninodes_max;
};

/* operations counters */
struct silofs_oper_stat {
	size_t op_iopen_max;
	size_t op_iopen;
	time_t op_time;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* dirty-vnodes set */
typedef void (*silofs_dset_add_fn)(struct silofs_dset *dset,
                                   struct silofs_snode_info *si);

struct silofs_dset {
	silofs_dset_add_fn              ds_add_fn;
	struct silofs_snode_info       *ds_siq;
	struct silofs_avl               ds_avl;
};

/* current operation */
struct silofs_oper {
	struct silofs_creds             op_creds;
	uint64_t                        op_unique;
	int                             op_code;
};

/* file-system oper-execution context */
struct silofs_fs_ctx {
	struct silofs_fs_uber          *fsc_uber;
	struct silofs_oper              fsc_oper;
	volatile int                    fsc_interrupt;
};

/* top-level pseudo meta node */
struct silofs_fs_uber {
	const struct silofs_fs_args    *ub_args;
	struct silofs_alloc            *ub_alloc;
	struct silofs_crypto           *ub_crypto;
	struct silofs_repos            *ub_repos;
	struct silofs_idsmap           *ub_idsm;
	struct silofs_mutex             ub_fs_lock;
	struct silofs_piper             ub_piper;
	struct silofs_oper_stat         ub_ops;
	struct silofs_blobref_info     *ub_sb_bri;
	struct silofs_sb_info          *ub_sbi;
	struct silofs_uaddr             ub_sb_addr;
	iconv_t                         ub_iconv;
	time_t                          ub_initime;
};

/* file-system's input id vectors */
struct silofs_ids {
	struct silofs_id       *uids;
	struct silofs_id       *gids;
	size_t                  nuids;
	size_t                  ngids;
};

/* file-system's input config-file arguments */
struct silofs_fs_cargs {
	struct silofs_uuid      uuid;
	struct silofs_ids       ids;
	bool pack;
};

/* file-system input arguments */
struct silofs_fs_args {
	struct silofs_fs_cargs  ca;
	const char             *repodir;
	const char             *name;
	const char             *atticdir;
	const char             *arname;
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
	bool                    wbackcache;
	bool                    lazytime;
	bool                    noexec;
	bool                    nosuid;
	bool                    nodev;
	bool                    rdonly;
	bool                    kcopy;
	bool                    concp;
	bool                    restore_forced;
};

/* file-system environment context */
struct silofs_fs_env {
	struct silofs_fs_args   fs_args;
	struct silofs_ivkey     fs_ivkey;
	struct silofs_qalloc   *fs_qalloc;
	struct silofs_alloc    *fs_alloc;
	struct silofs_crypto   *fs_crypto;
	struct silofs_repos    *fs_repos;
	struct silofs_idsmap   *fs_idsmap;
	struct silofs_fs_uber  *fs_uber;
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
	struct stat     attr;
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
