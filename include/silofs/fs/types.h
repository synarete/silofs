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
#include <silofs/fs/defs.h>


/* standard types forward declarations */
struct stat;
struct statx;
struct ucred;
struct timespec;

/* types forward declarations */
struct silofs_list_head;
struct silofs_listq;
struct silofs_avl;
struct silofs_avl_node;
struct silofs_thread;
struct silofs_mutex;
struct silofs_qalloc;
struct silofs_cache;
struct silofs_repo;
struct silofs_tnode_info;
struct silofs_unode_info;
struct silofs_vnode_info;
struct silofs_inode_info;
struct silofs_fuseq;
struct silofs_fuseq_worker;
struct silofs_fuseq_in;
struct silofs_fuseq_inb;
struct silofs_fuseq_outb;
struct silofs_bootmap;
struct silofs_sb_info;
struct silofs_oper;
struct silofs_dset;
struct silofs_rwiter_ctx;
struct silofs_readdir_ctx;
struct silofs_readdir_info;
struct silofs_listxattr_ctx;


/* file-system control flags */
enum silofs_flags {
	SILOFS_F_KCOPY          = SILOFS_BIT(0),
	SILOFS_F_SYNC           = SILOFS_BIT(1),
	SILOFS_F_NOW            = SILOFS_BIT(2),
	SILOFS_F_BLKDEV         = SILOFS_BIT(3),
	SILOFS_F_MEMFD          = SILOFS_BIT(4),
	SILOFS_F_ALLOWOTHER     = SILOFS_BIT(5),
	SILOFS_F_NLOOKUP        = SILOFS_BIT(6),
	SILOFS_F_BRINGUP        = SILOFS_BIT(7),
	SILOFS_F_OPSTART        = SILOFS_BIT(8),
	SILOFS_F_TIMEOUT        = SILOFS_BIT(9),
	SILOFS_F_SLUGGISH       = SILOFS_BIT(10),
	SILOFS_F_IDLE           = SILOFS_BIT(11),
	SILOFS_F_SEAL           = SILOFS_BIT(12),
	SILOFS_F_MMAPBLOBS      = SILOFS_BIT(13),
};

/* stage-element control flags */
enum silofs_stage_flags {
	SILOFS_STAGE_RDONLY     = SILOFS_BIT(1),
	SILOFS_STAGE_MUTABLE    = SILOFS_BIT(2),
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


/* strings & buffer */
struct silofs_str {
	const char *str;
	size_t len;
};

struct silofs_qstr {
	struct silofs_str str;
	uint64_t hash;
};

struct silofs_namestr {
	struct silofs_str str;
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

/* pass-phrase + salt buffers */
struct silofs_passphrase {
	uint8_t pass[SILOFS_PASSPHRASE_MAX + 1];
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

/* encryption tuple (key, iv, algo, mode) */
struct silofs_kivam {
	struct silofs_key       key;
	struct silofs_iv        iv;
	unsigned int            cipher_algo;
	unsigned int            cipher_mode;
};

/* opaque meta-element identifier */
struct silofs_metaid {
	uint64_t id[2];
};

/* opaque blob identifier */
struct silofs_blobid {
	struct silofs_metaid    tree_id;
	struct silofs_metaid    uniq_id;
	size_t                  size;
	int                     height;
};

/* object address within blob */
struct silofs_oaddr {
	struct silofs_blobid    bid;
	loff_t                  pos;
	size_t                  len;
};

/* logical addressing of space-mapping elements */
struct silofs_uaddr {
	struct silofs_oaddr     oaddr;
	loff_t                  voff;
	enum silofs_stype       stype;
};

/* meta-link via pair of space-addressing */
struct silofs_ulink {
	struct silofs_uaddr     owner;
	struct silofs_uaddr     child;
};

/* tree addressing of space-mapping elements */
struct silofs_taddr {
	struct silofs_metaid    tree_id;
	loff_t                  voff;
	int                     height;
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

/* vnode's placement address */
struct silofs_uvaddr {
	struct silofs_uaddr     uaddr;
	struct silofs_vaddr     vaddr;
};

/* inode's placement address */
struct silofs_iuvaddr {
	ino_t                   ino;
	struct silofs_uvaddr    uva;
};

/* vspace address range [beg, end) */
struct silofs_vrange {
	loff_t beg;
	loff_t end;
};

/* boot-sector in-memory repr  */
struct silofs_bootsec {
	struct silofs_namebuf           name;
	struct silofs_uuid              uuid;
	struct silofs_uaddr             sb_uaddr;
	struct silofs_cipher_args       cip_args;
	enum silofs_bootf               bootf;
	time_t btime;
};

/* caching-element's key, up to 256-bits */
enum silofs_ckey_type {
	SILOFS_CKEY_NONE,
	SILOFS_CKEY_BLOBID,
	SILOFS_CKEY_OADDR,
	SILOFS_CKEY_UADDR,
	SILOFS_CKEY_VADDR,
	SILOFS_CKEY_VOFF,
};

union silofs_ckey_u {
	const struct silofs_oaddr  *oaddr;
	const struct silofs_uaddr  *uaddr;
	const struct silofs_vaddr  *vaddr;
	const struct silofs_blobid *bid;
	const loff_t               *voff;
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
	int  ce_refcnt;
	bool ce_dirty;
	bool ce_mapped;
	bool ce_forgot;
	char ce_pad;
};

/* object-addressing block info */
struct silofs_ubk_info {
	struct silofs_cache_elem        ubk_ce;
	struct silofs_oaddr             ubk_oaddr;
	struct silofs_block            *ubk;
};

/* voffset-addressing block info */
struct silofs_vbk_info {
	struct silofs_cache_elem        vbk_ce;
	struct silofs_block            *vbk;
	loff_t                          vbk_voff;
};

/* space accounting */
struct silofs_space_stat {
	ssize_t uspace_nmeta;
	ssize_t vspace_ndata;
	ssize_t vspace_nmeta;
	ssize_t vspace_nfiles;
};

/* inodes-table's in-memory map entry */
struct silofs_itment {
	ino_t   ino;
	loff_t  off;
};

/* inodes-table's in-memory (hash) map */
struct silofs_itmap {
	struct silofs_alloc_if *itm_alif;
	struct silofs_itment   *itm_htbl;
	size_t ithm_nelems;
};

/* inodes-table reference */
struct silofs_itable_info {
	struct silofs_itmap     it_map;
	struct silofs_vaddr     it_treeroot;
	struct silofs_iaddr     it_rootdir;
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
                                   struct silofs_tnode_info *ti);

struct silofs_dset {
	silofs_dset_add_fn              ds_add_fn;
	struct silofs_tnode_info       *ds_tiq;
	struct silofs_avl               ds_avl;
};

/* map of all boot records */
struct silofs_bootmap {
	struct silofs_alloc_if         *bm_alif;
	struct silofs_mdigest          *bm_md;
	struct silofs_listq             bm_lsq;
	loff_t bm_next_index;
};

/* current operation state */
struct silofs_oper {
	struct silofs_fs_apex          *op_apex;
	struct silofs_ucred             op_ucred;
	struct timespec                 op_xtime;
	uint64_t                        op_unique;
	int                             op_code;
	volatile int                    op_interrupt;
};

/* top-level pseudo meta node */
struct silofs_fs_apex {
	const struct silofs_fs_args    *ap_args;
	struct silofs_alloc_if         *ap_alif;
	struct silofs_qalloc           *ap_qalloc;
	struct silofs_cache            *ap_cache;
	struct silofs_repo             *ap_repo;
	struct silofs_crypto           *ap_crypto;
	struct silofs_sb_info          *ap_sbi;
	struct silofs_piper             ap_piper;
	struct silofs_oper_stat         ap_ops;
	iconv_t                         ap_iconv;
	time_t                          ap_initime;
	int                             ap_slock_fd;
};

/* file-system input arguments */
struct silofs_fs_args {
	const char *repodir;
	const char *mntdir;
	const char *fsname;
	const char *passwd;
	size_t capacity;
	size_t memwant;
	uid_t  uid;
	gid_t  gid;
	pid_t  pid;
	mode_t umask;
	bool   lock_repo;
	bool   with_fuseq;
	bool   pedantic;
	bool   allowother;
	bool   lazytime;
	bool   noexec;
	bool   nosuid;
	bool   nodev;
	bool   rdonly;
	bool   kcopy;
	bool   concp;
};

/* file-system environment context */
struct silofs_fs_env {
	struct silofs_fs_args           fs_args;
	struct silofs_passphrase        fs_passph;
	struct silofs_kivam             fs_kivam;
	struct silofs_qalloc           *fs_qalloc;
	struct silofs_alloc_if         *fs_alif;
	struct silofs_mpool            *fs_mpool;
	struct silofs_cache            *fs_cache;
	struct silofs_crypto           *fs_crypto;
	struct silofs_repo             *fs_repo;
	struct silofs_fs_apex          *fs_apex;
	struct silofs_fuseq            *fs_fuseq;
	int                             fs_signum;
};

/* call-back types for file-system operations */
typedef int (*silofs_filldir_fn)(struct silofs_readdir_ctx *rd_ctx,
                                 const struct silofs_readdir_info *rdi);

struct silofs_readdir_info {
	struct stat attr;
	const char *name;
	size_t  namelen;
	ino_t   ino;
	loff_t  off;
	mode_t  dt;
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
                                const struct silofs_fiovec *fiov);

struct silofs_rwiter_ctx {
	silofs_rwiter_fn actor;
	loff_t off;
	size_t len;
};


#endif /* SILOFS_TYPES_H_ */
