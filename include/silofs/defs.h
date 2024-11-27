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
#ifndef SILOFS_DEFS_H_
#define SILOFS_DEFS_H_

#include <silofs/ccattr.h>
#include <stdint.h>

/* current on-disk format version number */
#define SILOFS_FMT_VERSION (1)

/* current repo format version number */
#define SILOFS_REPO_VERSION (1)

/* current pack format version number */
#define SILOFS_PACK_VERSION (1)

/* repo meta-file magic-signature (ASCII: "#SILOFS#") */
#define SILOFS_REPO_META_MAGIC (0x2353464F4C495323L)

/* boot-record magic-signature (ASCII: "@SILOFS@") */
#define SILOFS_BOOT_RECORD_MAGIC (0x4053464F4C495340L)

/* pack-index header magic-signature (ASCII: "%silofs%") */
#define SILOFS_PAR_INDEX_MAGIC (0x2573666F6C697325L)

/* super-block special magic-signature (ASCII: "@silofs@") */
#define SILOFS_SUPER_MAGIC (0x4073666F6C697340L)

/* file-system fsid magic number (ASCII: "SILO") */
#define SILOFS_FSID_MAGIC (0x4F4C4953U)

/* magic numbers at meta-objects start (ASCII: "silo") */
#define SILOFS_META_MAGIC (0x6F6C6973U)

/* max length of encryption password */
#define SILOFS_PASSWORD_MAX (255)

/* max size for names (not including null terminator) */
#define SILOFS_NAME_MAX (255)

/* max size for file-system names (not including null terminator) */
#define SILOFS_FSNAME_MAX (127)

/* max size of path (symbolic link value, including null) */
#define SILOFS_PATH_MAX (4096)

/* max size of mount-path (including null) */
#define SILOFS_MNTPATH_MAX (1920)

/* max path-length of repository-path (including null) */
#define SILOFS_REPOPATH_MAX (1536)

/* size of repository meta-files  */
#define SILOFS_REPO_METAFILE_SIZE (1024)

/* repository meta sub-dir name */
#define SILOFS_REPO_DOTS_DIRNAME ".silofs"

/* repository meta descriptor-file name */
#define SILOFS_REPO_META_FILENAME "meta"

/* repository global lock file name */
#define SILOFS_REPO_LOCK_FILENAME "lock"

/* repository boot-refs sub-directory */
#define SILOFS_REPO_REFS_DIRNAME "refs"

/* repository blobs sub-directory */
#define SILOFS_REPO_BLOBS_DIRNAME "blobs"

/* repository pack-archive sub-directory */
#define SILOFS_REPO_PACK_DIRNAME "pack"

/* repository objects sub-directory */
#define SILOFS_REPO_OBJS_DIRNAME "objs"

/* number of sub-dirs within objects directories */
#define SILOFS_REPO_OBJS_NSUBS (256)

/* max number of hard-links to file or sub-directories */
#define SILOFS_LINK_MAX ((1L << 15) - 1)

/* max number of supplementary groups per each uid (same as NFS) */
#define SILOFS_NSGRP_MAX (16)

/* size of boot-record */
#define SILOFS_BOOTREC_SIZE (1024)

/* number of octets in UUID */
#define SILOFS_UUID_SIZE (16)

/* size of common meta-data header */
#define SILOFS_HEADER_SIZE (16)

/* on-disk size of persistent segment chkpt node */
#define SILOFS_PSEG_CHKPT_SIZE (4096)

/* number of pointers btree mapping-node */
#define SILOFS_BTREE_NODE_NCHILDS (42)

/* number of keys in btree mapping-node */
#define SILOFS_BTREE_NODE_NKEYS (SILOFS_BTREE_NODE_NCHILDS - 1)

/* number of entries in btree mapping-leaf */
#define SILOFS_BTREE_LEAF_NENTS (84)

/* on-disk size of btree node */
#define SILOFS_BTREE_NODE_SIZE (4096)

/* on-disk size of btree leaf */
#define SILOFS_BTREE_LEAF_SIZE (8192)

/* minimal file-system capacity, in bytes (2G) */
#define SILOFS_CAPACITY_SIZE_MIN (2L * SILOFS_GIGA)

/* maximal file-system capacity, in bytes (64T) */
#define SILOFS_CAPACITY_SIZE_MAX (64L * SILOFS_TERA)

/* maximal size of virtual address space (256P) */
#define SILOFS_VSPACE_SIZE_MAX (1L << 58)

/* small ("sector") meta-block size (1K) */
#define SILOFS_KB_SIZE (1024)

/* bits-shift of logical block */
#define SILOFS_LBK_SHIFT (16)

/* logical block size (64K) */
#define SILOFS_LBK_SIZE (1L << SILOFS_LBK_SHIFT)

/* number of 1K blocks in logical block */
#define SILOFS_NKB_IN_LBK (SILOFS_LBK_SIZE / SILOFS_KB_SIZE)

/* maximal number of logical blocks within single tree-segment */
#define SILOFS_NLBK_IN_LSEG_MAX (256L)

/* maximal size in bytes of single tree-segment (16M) */
#define SILOFS_LSEG_SIZE_MAX (SILOFS_NLBK_IN_LSEG_MAX * SILOFS_LBK_SIZE)

/* non-valid ("NIL") logical byte address */
#define SILOFS_OFF_NULL (-1)

/* max bit-shift of LBA value */
#define SILOFS_LBA_SHIFT_MAX (56)

/* non-valid ("NIL") logical block address */
#define SILOFS_LBA_NULL ((1L << SILOFS_LBA_SHIFT_MAX) - 1)

/* "nil" inode number */
#define SILOFS_INO_NULL (0)

/* export ino towards vfs of root inode */
#define SILOFS_INO_ROOT (1)

/* max valid ino number */
#define SILOFS_INO_MAX ((1L << 56) - 1)

/* on-disk size of super-block */
#define SILOFS_SB_SIZE (8192)

/* bits-shift for space-mapping children fan-out */
#define SILOFS_SPMAP_SHIFT (8)

/* number of children per space-mapping node/leaf */
#define SILOFS_SPMAP_NCHILDS (1L << SILOFS_SPMAP_SHIFT)

/* on-disk size of space-node/leaf mapping */
#define SILOFS_SPMAP_SIZE (32768)

/* number of space-maps per logical-block */
#define SILOFS_NSPMAP_IN_LBK (SILOFS_LBK_SIZE / SILOFS_SPMAP_SIZE)

/* on-disk size-shift of inode */
#define SILOFS_INODE_SHIFT (10)

/* on-disk size of inode */
#define SILOFS_INODE_SIZE (1 << SILOFS_INODE_SHIFT)

/* number of inodes per logical-block */
#define SILOFS_NINODE_IN_LBK (SILOFS_LBK_SIZE / SILOFS_INODE_SIZE)

/* base size of empty directory */
#define SILOFS_DIR_EMPTY_SIZE SILOFS_INODE_SIZE

/* on-disk size of directory tree-node */
#define SILOFS_DIR_NODE_SIZE (8192)

/* number of directory tree-nodes per logical-block */
#define SILOFS_NDTNODE_IN_LBK (SILOFS_LBK_SIZE / SILOFS_DIR_NODE_SIZE)

/* number of directory-entries in dir's hash-tree node */
#define SILOFS_DIR_NODE_NENTS (480)

/* max size of names-buffer in dir's tree-mapping node */
#define SILOFS_DIR_NODE_NBUF_SIZE (7680)

/* bits-shift of children per dir tree-mapping node */
#define SILOFS_DIR_NODE_SHIFT (6)

/* number of children per dir tree-mapping node */
#define SILOFS_DIR_NODE_NCHILDS (1 << SILOFS_DIR_NODE_SHIFT)

/* maximum depth of directory tree-mapping */
#define SILOFS_DIR_TREE_DEPTH_MAX (4L)

/* max dir-node index of tree-mapping nodes (1-based) */
#define SILOFS_DIR_TREE_INDEX_MAX \
	((1L << (SILOFS_DIR_NODE_SHIFT * SILOFS_DIR_TREE_DEPTH_MAX)))

/* non-valid dir's tree-mapping node-index */
#define SILOFS_DIR_TREE_INDEX_NULL (0)

/* node-index of dir's tree-mapping root */
#define SILOFS_DIR_TREE_INDEX_ROOT (1)

/* max entries in directory */
#define SILOFS_DIR_ENTRIES_MAX \
	(SILOFS_DIR_NODE_NENTS * SILOFS_DIR_TREE_INDEX_MAX)

/* max value of directory offset */
#define SILOFS_DIR_OFFSET_MAX (SILOFS_DIR_ENTRIES_MAX + 1)

/* height-limit of file-mapping radix-tree */
#define SILOFS_FILE_HEIGHT_MAX (5)

/* bits-shift of single file-mapping address-space */
#define SILOFS_FILE_MAP_SHIFT (10)

/* file's level1 head-mapping block-sizes (1K) */
#define SILOFS_FILE_HEAD1_LEAF_SIZE (SILOFS_KB_SIZE)

/* number of 1K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD1_NLEAF (4)

/* file's level2 head-mapping block-sizes (4K) */
#define SILOFS_FILE_HEAD2_LEAF_SIZE (4 * SILOFS_KB_SIZE)

/* number of 4K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD2_NLEAF (15)

/* file's tree-mapping block-sizes */
#define SILOFS_FILE_TREE_LEAF_SIZE SILOFS_LBK_SIZE

/* number of mapping-slots per single file tree node */
#define SILOFS_FILE_NODE_NCHILDS (1LL << SILOFS_FILE_MAP_SHIFT)

/* maximum number of data-leafs in regular file */
#define SILOFS_FILE_LEAVES_MAX \
	(1LL << (SILOFS_FILE_MAP_SHIFT * (SILOFS_FILE_HEIGHT_MAX - 1)))

/* maximum size in bytes of regular file */
#define SILOFS_FILE_SIZE_MAX ((SILOFS_LBK_SIZE * SILOFS_FILE_LEAVES_MAX) - 1)

/* on-disk size of file's radix-tree-node */
#define SILOFS_FILE_RTNODE_SIZE (8192)

/* number of file's radix-tree-nodes per logical-block */
#define SILOFS_NFRTNODE_IN_LBK (SILOFS_LBK_SIZE / SILOFS_FILE_RTNODE_SIZE)

/* max number of callbacks for read-write iter operations */
#define SILOFS_FILE_NITER_MAX                                \
	(SILOFS_FILE_HEAD1_NLEAF + SILOFS_FILE_HEAD2_NLEAF + \
	 (SILOFS_IO_SIZE_MAX / SILOFS_LBK_SIZE))

/* max size of symbolic-link value (including null terminator) */
#define SILOFS_SYMLNK_MAX SILOFS_PATH_MAX

/* max size of within-inode symbolic-link value  */
#define SILOFS_SYMLNK_HEAD_MAX (480)

/* max size of symbolic-link part  */
#define SILOFS_SYMLNK_PART_MAX (4032)

/* number of possible symbolic-link parts  */
#define SILOFS_SYMLNK_NPARTS (2)

/* on-disk size of symbolic-link tail-value */
#define SILOFS_SYMLNK_VAL_SIZE (4096)

/* number of symval-nodes per logical-block */
#define SILOFS_NSYMVAL_IN_LBK (SILOFS_LBK_SIZE / SILOFS_SYMLNK_VAL_SIZE)

/* number of extended-attributes entries in indirect node */
#define SILOFS_XATTR_NENTS (504)

/* max length of extended attributes value */
#define SILOFS_XATTR_VALUE_MAX (2048)

/* on-disk size of xattr node */
#define SILOFS_XATTR_NODE_SIZE (4096)

/* number of xattr-nodes per logical-block */
#define SILOFS_NXANODE_IN_LBK (SILOFS_LBK_SIZE / SILOFS_XATTR_NODE_SIZE)

/* max size of single I/O operation (2M - 64K) */
#define SILOFS_IO_SIZE_MAX ((1UL << 21) - SILOFS_LBK_SIZE)

/* cryptographic key size */
#define SILOFS_KEY_SIZE (32)

/* initialization vector size (for AES256) */
#define SILOFS_IV_SIZE (16)

/* cryptographic hash-128-bits bytes-size */
#define SILOFS_HASH128_LEN (16)

/* cryptographic hash-256-bits bytes-size */
#define SILOFS_HASH256_LEN (32)

/* cryptographic hash-512-bits bytes-size */
#define SILOFS_HASH512_LEN (64)

/* boot-record flags */
enum silofs_bootf {
	SILOFS_BOOTF_NONE = 0x00,
};

/* common-header flags */
enum silofs_hdrf {
	SILOFS_HDRF_CSUM  = 0x01,
	SILOFS_HDRF_PTYPE = 0x02,
	SILOFS_HDRF_LTYPE = 0x04,
};

/* format endianness */
enum silofs_endianness {
	SILOFS_ENDIANNESS_LE = 1,
	SILOFS_ENDIANNESS_BE = 2,
};

/* content-addressable sub-types */
enum silofs_ctype {
	SILOFS_CTYPE_NONE    = 0,
	SILOFS_CTYPE_BOOTREC = 1,
	SILOFS_CTYPE_PACKIDX = 2,
	SILOFS_CTYPE_ENCSEG  = 3,
};

/* persistent-elements types */
enum silofs_ptype {
	SILOFS_PTYPE_NONE   = 0,
	SILOFS_PTYPE_CHKPT  = 1,
	SILOFS_PTYPE_BTNODE = 2,
	SILOFS_PTYPE_BTLEAF = 3,
	SILOFS_PTYPE_DATA   = 4,
	SILOFS_PTYPE_LAST, /* keep last */
};

/* persistent nodes' flags */
enum silofs_pnodef {
	SILOFS_PNODEF_NONE   = 0x00,
	SILOFS_PNODEF_META   = 0x01,
	SILOFS_PNODEF_DATA   = 0x02,
	SILOFS_PNODEF_BTROOT = 0x04,
};

/* logical-elements types */
enum silofs_ltype {
	SILOFS_LTYPE_NONE    = 0,
	SILOFS_LTYPE_BOOTREC = 1,
	SILOFS_LTYPE_SUPER   = 2,
	SILOFS_LTYPE_SPNODE  = 3,
	SILOFS_LTYPE_SPLEAF  = 4,
	SILOFS_LTYPE_INODE   = 5,
	SILOFS_LTYPE_XANODE  = 6,
	SILOFS_LTYPE_SYMVAL  = 7,
	SILOFS_LTYPE_DTNODE  = 8,
	SILOFS_LTYPE_FTNODE  = 9,
	SILOFS_LTYPE_DATA1K  = 10,
	SILOFS_LTYPE_DATA4K  = 11,
	SILOFS_LTYPE_DATABK  = 12,
	SILOFS_LTYPE_LAST, /* keep last */
};

/* logical heights of unode mappings */
enum silofs_height {
	SILOFS_HEIGHT_NONE    = 0,
	SILOFS_HEIGHT_VDATA   = 1,
	SILOFS_HEIGHT_SPLEAF  = 2,
	SILOFS_HEIGHT_SPNODE1 = 3,
	SILOFS_HEIGHT_SPNODE2 = 4,
	SILOFS_HEIGHT_SPNODE3 = 5,
	SILOFS_HEIGHT_SPNODE4 = 6,
	SILOFS_HEIGHT_SUPER   = 7,
	SILOFS_HEIGHT_BOOT    = 8,
	SILOFS_HEIGHT_LAST, /* keep last */
};

/* super-block flags */
enum silofs_superf {
	SILOFS_SUPERF_NONE   = 0x00,
	SILOFS_SUPERF_FOSSIL = 0x01,
};

/* inode control flags */
enum silofs_inodef {
	SILOFS_INODEF_ROOTD  = 0x01,
	SILOFS_INODEF_FTYPE2 = 0x02,
};

/* dir-inode control flags */
enum silofs_dirf {
	SILOFS_DIRF_NONE      = 0x00,
	SILOFS_DIRF_NAME_UTF8 = 0x01,
};

/* dir-inode hash-functions for names */
enum silofs_dirhfn {
	SILOFS_DIRHASH_SHA256 = 1,
	SILOFS_DIRHASH_XXH64  = 2,
};

/* extended attributes known classes */
enum silofs_xattr_ns {
	SILOFS_XATTR_NONE     = 0,
	SILOFS_XATTR_SECURITY = 1,
	SILOFS_XATTR_SYSTEM   = 2,
	SILOFS_XATTR_TRUSTED  = 3,
	SILOFS_XATTR_USER     = 4,
	SILOFS_XATTR_GNU      = 5,
};

/* encryption cipher settings (libgcrypt values) */
enum silofs_cipher_algo {
	SILOFS_CIPHER_AES256 = 9,
};

enum silofs_cipher_mode {
	SILOFS_CIPHER_MODE_CBC = 3,
	SILOFS_CIPHER_MODE_GCM = 9,
	SILOFS_CIPHER_MODE_XTS = 13,
};

/* hash-function type (libgcrypt values) */
enum silofs_md_type {
	SILOFS_MD_NONE     = 0,
	SILOFS_MD_SHA256   = 8,
	SILOFS_MD_SHA3_256 = 313,
	SILOFS_MD_SHA3_512 = 315
};

/* key-derivation functions (libgcrypt values) */
enum silofs_kdf_algos {
	SILOFS_KDF_NONE   = 0,
	SILOFS_KDF_PBKDF2 = 34,
	SILOFS_KDF_SCRYPT = 48,
};

/* unix-domain socket for mount daemon */
#define SILOFS_MNTSOCK_NAME "silofs-mount"

/* max number of mount-rules */
#define SILOFS_MNTRULE_MAX 1024

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_tm64b {
	uint16_t tm_sec;
	uint16_t tm_min;
	uint8_t  tm_hour;
	uint8_t  tm_mday;
	uint8_t  tm_mon;
	uint8_t  tm_wday;
	uint32_t tm_year;
	uint32_t tm_yday;
	uint64_t tm_gmtoff;
	uint64_t tm_reserved;
} silofs_attr_aligned64;

struct silofs_timespec {
	uint64_t t_sec;
	uint64_t t_nsec;
} silofs_attr_aligned16;

struct silofs_hash128 {
	uint8_t hash[SILOFS_HASH128_LEN];
} silofs_attr_aligned16;

struct silofs_hash256 {
	uint8_t hash[SILOFS_HASH256_LEN];
} silofs_attr_aligned32;

struct silofs_hash512 {
	uint8_t hash[SILOFS_HASH512_LEN];
} silofs_attr_aligned64;

struct silofs_name {
	uint8_t name[SILOFS_NAME_MAX + 1];
} silofs_attr_aligned64;

struct silofs_key {
	uint8_t key[SILOFS_KEY_SIZE];
} silofs_attr_aligned16;

struct silofs_iv {
	uint8_t iv[SILOFS_IV_SIZE];
} silofs_attr_aligned8;

struct silofs_uuid {
	uint8_t uu[SILOFS_UUID_SIZE];
} silofs_attr_aligned16;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pvid {
	struct silofs_uuid uuid;
} silofs_attr_aligned16;

struct silofs_lvid {
	struct silofs_uuid uuid;
} silofs_attr_aligned16;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* persistent volume's segment identifier */
struct silofs_psid32b {
	struct silofs_pvid pvid;
	uint32_t           index;
	uint8_t            pad[12];
} silofs_attr_aligned16;

/* persistent volume sub-range */
struct silofs_prange64b {
	struct silofs_psid32b psid;
	int64_t               cur;
	uint32_t              nsegs;
	uint8_t               pad[20];
} silofs_attr_aligned64;

/* persistent volume sub-ranges pair*/
struct silofs_pstate128b {
	struct silofs_prange64b meta;
	struct silofs_prange64b data;
} silofs_attr_aligned64;

/* persistent object address */
struct silofs_paddr48b {
	struct silofs_psid32b psid;
	int64_t               off;
	uint32_t              len;
	uint8_t               ptype;
	uint8_t               pad[3];
} silofs_attr_aligned16;

/* logical volume's segment identifier */
struct silofs_lsid32b {
	struct silofs_lvid lvid;
	uint32_t           lsize;
	uint32_t           vindex;
	uint8_t            vspace;
	uint8_t            height;
	uint8_t            ltype;
	uint8_t            pad[5];
} silofs_attr_aligned16;

/* logical address */
struct silofs_laddr48b {
	struct silofs_lsid32b lsid;
	uint32_t              pos;
	uint32_t              len;
	uint8_t               pad[8];
} silofs_attr_aligned16;

/* content address (by hash) */
struct silofs_caddr64b {
	struct silofs_hash256 hash;
	uint32_t              size;
	uint8_t               ctype;
	uint8_t               reserved[27];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uaddr64b {
	struct silofs_laddr48b laddr;
	int64_t                voff;
	uint8_t                pad[8];
} silofs_attr_aligned32;

struct silofs_vrange128 {
	int64_t  beg;
	uint64_t len_height;
} silofs_attr_aligned8;

struct silofs_vaddr56 {
	uint8_t b[7];
};

struct silofs_vaddr64 {
	uint64_t voff_ltype;
} silofs_attr_aligned8;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_bootrec1k {
	uint64_t                 br_magic;
	uint64_t                 br_version;
	struct silofs_uuid       br_uuid;
	uint64_t                 br_flags;
	uint32_t                 br_chiper_algo;
	uint32_t                 br_chiper_mode;
	uint8_t                  br_reserved1[16];
	struct silofs_key        br_main_key;
	struct silofs_iv         br_main_iv;
	struct silofs_iv         br_sb_riv;
	struct silofs_uaddr64b   br_sb_uaddr;
	uint8_t                  br_reserved2[64];
	struct silofs_pstate128b br_pstate;
	uint8_t                  br_reserved3[608];
	struct silofs_hash256    br_hash;
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_header {
	uint32_t h_magic;
	uint8_t  h_type;
	uint8_t  h_reserved;
	uint16_t h_flags;
	uint32_t h_size;
	uint32_t h_csum;
} silofs_attr_aligned16;

struct silofs_sb_sproots {
	struct silofs_uaddr64b sb_sproot_reserved;
	struct silofs_uaddr64b sb_sproot_inode;
	struct silofs_uaddr64b sb_sproot_xanode;
	struct silofs_uaddr64b sb_sproot_dtnode;
	struct silofs_uaddr64b sb_sproot_ftnode;
	struct silofs_uaddr64b sb_sproot_symval;
	struct silofs_uaddr64b sb_sproot_data1k;
	struct silofs_uaddr64b sb_sproot_data4k;
	struct silofs_uaddr64b sb_sproot_databk;
	uint8_t                sb_reserved[448];
} silofs_attr_aligned64;

struct silofs_sb_lsids {
	struct silofs_lsid32b sb_lsid_inode;
	struct silofs_lsid32b sb_lsid_xanode;
	struct silofs_lsid32b sb_lsid_dtnode;
	struct silofs_lsid32b sb_lsid_ftnode;
	struct silofs_lsid32b sb_lsid_symval;
	struct silofs_lsid32b sb_lsid_data1k;
	struct silofs_lsid32b sb_lsid_data4k;
	struct silofs_lsid32b sb_lsid_databk;
	uint8_t               sb_reserved[768];
} silofs_attr_aligned64;

struct silofs_sb_rootivs {
	struct silofs_iv sb_iv_reserved;
	struct silofs_iv sb_iv_inode;
	struct silofs_iv sb_iv_xanode;
	struct silofs_iv sb_iv_dtnode;
	struct silofs_iv sb_iv_ftnode;
	struct silofs_iv sb_iv_symval;
	struct silofs_iv sb_iv_data1k;
	struct silofs_iv sb_iv_data4k;
	struct silofs_iv sb_iv_databk;
	uint8_t          sb_reserved[368];
} silofs_attr_aligned64;

struct silofs_space_gauges {
	uint64_t sg_nsuper;
	uint64_t sg_nspnode;
	uint64_t sg_nspleaf;
	uint64_t sg_reserved;
	uint64_t sg_ninode;
	uint64_t sg_nxanode;
	uint64_t sg_ndtnode;
	uint64_t sg_nsymval;
	uint64_t sg_nftnode;
	uint64_t sg_ndata1k;
	uint64_t sg_ndata4k;
	uint64_t sg_ndatabk;
	uint64_t sg_reserved2[20];
} silofs_attr_aligned64;

struct silofs_space_stats {
	uint64_t                   sp_btime;
	uint64_t                   sp_ctime;
	uint64_t                   sp_capacity;
	uint64_t                   sp_vspacesize;
	uint64_t                   sp_generation;
	uint8_t                    sp_reserved[216];
	struct silofs_space_gauges sp_lsegs;
	struct silofs_space_gauges sp_bks;
	struct silofs_space_gauges sp_objs;
} silofs_attr_aligned64;

struct silofs_super_block {
	/* 0..512 */
	struct silofs_header      sb_hdr;
	uint64_t                  sb_magic;
	uint64_t                  sb_version;
	uint32_t                  sb_flags;
	uint8_t                   sb_reserved1[4];
	uint8_t                   sb_endianness;
	uint8_t                   sb_reserved2[23];
	uint8_t                   sb_sw_version[64];
	struct silofs_uuid        sb_fs_uuid;
	uint8_t                   sb_reserved3[112];
	struct silofs_name        sb_name;
	/* 512..1K */
	struct silofs_tm64b       sb_fs_birth_tm;
	struct silofs_tm64b       sb_lv_birth_tm;
	struct silofs_uaddr64b    sb_self_uaddr;
	struct silofs_uaddr64b    sb_orig_uaddr;
	struct silofs_lvid        sb_lvid;
	struct silofs_vrange128   sb_vrange;
	uint8_t                   sb_reserved4b[224];
	/* 1K..2K */
	struct silofs_sb_sproots  sb_sproots;
	/* 2K..3K */
	struct silofs_sb_lsids    sb_main_lsid;
	/* 3K..4K */
	struct silofs_sb_rootivs  sb_rootivs;
	uint8_t                   sb_reserved5[512];
	/* 4K..6K */
	struct silofs_space_stats sb_space_stats_curr;
	struct silofs_space_stats sb_space_stats_base;
	/* 7K..8K */
	uint8_t                   sb_reserved6[2048];
} silofs_attr_aligned64;

struct silofs_spmap_ref {
	struct silofs_uaddr64b sr_uaddr;
	uint8_t                sr_reserved[32];
} silofs_attr_aligned32;

struct silofs_spmap_node {
	struct silofs_header    sn_hdr;
	uint8_t                 sn_reserved1[16];
	struct silofs_lsid32b   sn_main_lsid;
	struct silofs_vrange128 sn_vrange;
	uint8_t                 sn_reserved2[48];
	struct silofs_uaddr64b  sn_parent;
	struct silofs_uaddr64b  sn_self;
	uint8_t                 sn_reserved3[768];
	uint8_t                 sn_reserved4[1024];
	uint8_t                 sn_reserved5[2048];
	struct silofs_spmap_ref sn_subrefs[SILOFS_SPMAP_NCHILDS];
	struct silofs_iv        sn_rivs[SILOFS_SPMAP_NCHILDS];
} silofs_attr_aligned64;

struct silofs_bk_state {
	uint64_t state;
} silofs_attr_aligned8;

struct silofs_bk_ref {
	struct silofs_laddr48b bkr_uref;
	struct silofs_bk_state bkr_allocated;
	struct silofs_bk_state bkr_unwritten;
	uint64_t               bkr_dbkref;
	uint8_t                bkr_reserved[24];
} silofs_attr_aligned32;

struct silofs_spmap_leaf {
	struct silofs_header    sl_hdr;
	uint8_t                 sl_reserved1[16];
	struct silofs_lsid32b   sl_main_lsid;
	struct silofs_uaddr64b  sl_parent;
	struct silofs_uaddr64b  sl_self;
	struct silofs_vrange128 sl_vrange;
	uint8_t                 sl_reserved2[816];
	uint8_t                 sl_reserved3[1024];
	uint8_t                 sl_reserved4[2048];
	struct silofs_bk_ref    sl_subrefs[SILOFS_SPMAP_NCHILDS];
	struct silofs_iv        sl_rivs[SILOFS_SPMAP_NCHILDS];
} silofs_attr_aligned64;

struct silofs_inode_times {
	struct silofs_timespec btime;
	struct silofs_timespec atime;
	struct silofs_timespec ctime;
	struct silofs_timespec mtime;
} silofs_attr_aligned64;

struct silofs_inode_xattr {
	struct silofs_vaddr64 ix_vaddr[8];
	uint8_t               ix_reserved[192];
} silofs_attr_aligned64;

struct silofs_inode_dir {
	struct silofs_vaddr64 d_root;
	uint64_t              d_seed;
	uint64_t              d_ndents;
	uint32_t              d_last_index;
	uint32_t              d_flags;
	uint8_t               d_hashfn;
	uint8_t               d_reserved[31];
} silofs_attr_aligned64;

struct silofs_inode_lnk {
	uint8_t               l_head[SILOFS_SYMLNK_HEAD_MAX];
	struct silofs_vaddr64 l_tail[SILOFS_SYMLNK_NPARTS];
	uint8_t               l_reserved[16];
} silofs_attr_aligned64;

struct silofs_inode_file {
	struct silofs_vaddr64 f_slots[32];
	uint8_t               f_reserved[256];
} silofs_attr_aligned8;

union silofs_inode_tail {
	struct silofs_inode_dir  d;
	struct silofs_inode_file f;
	struct silofs_inode_lnk  l;
	uint8_t                  b[512];
} silofs_attr_aligned64;

struct silofs_inode {
	struct silofs_header      i_hdr;
	uint64_t                  i_ino;
	uint64_t                  i_parent;
	uint32_t                  i_uid;
	uint32_t                  i_gid;
	uint32_t                  i_mode;
	uint32_t                  i_flags;
	int64_t                   i_size;
	int64_t                   i_span;
	uint64_t                  i_blocks;
	uint64_t                  i_nlink;
	uint64_t                  i_attributes; /* statx */
	uint32_t                  i_rdev_major;
	uint32_t                  i_rdev_minor;
	uint64_t                  i_revision;
	uint64_t                  i_generation;
	uint8_t                   i_reserved1[16];
	struct silofs_inode_times i_tm;
	uint8_t                   i_reserved2[64];
	struct silofs_inode_xattr i_xa;
	union silofs_inode_tail   i_ta;
} silofs_attr_aligned64;

struct silofs_xattr_entry {
	uint16_t xe_name_len;
	uint16_t xe_reserved;
	uint32_t xe_value_size;
} silofs_attr_aligned8;

struct silofs_xattr_node {
	struct silofs_header      xa_hdr;
	uint64_t                  xa_ino;
	uint16_t                  xa_nents;
	uint8_t                   xa_reserved[38];
	struct silofs_xattr_entry xe[SILOFS_XATTR_NENTS];
} silofs_attr_aligned64;

struct silofs_dir_entry {
	uint64_t de_ino;
	uint32_t de_name_hash_lo;
	uint16_t de_name_len_dt;
	uint16_t de_name_pos;
} silofs_attr_aligned16;

union silofs_dtree_data {
	struct silofs_dir_entry de[SILOFS_DIR_NODE_NENTS];
	uint8_t                 nb[SILOFS_DIR_NODE_NBUF_SIZE];
} silofs_attr_aligned64;

struct silofs_dtree_node {
	struct silofs_header    dn_hdr;
	uint64_t                dn_ino;
	int64_t                 dn_parent;
	uint32_t                dn_node_index;
	uint16_t                dn_nde;
	uint16_t                dn_nnb;
	uint32_t                dn_nactive_childs;
	uint32_t                dn_reserved[5];
	struct silofs_vaddr56   dn_child[SILOFS_DIR_NODE_NCHILDS];
	union silofs_dtree_data dn_data;
} silofs_attr_aligned64;

struct silofs_ftree_node {
	struct silofs_header  fn_hdr;
	uint64_t              fn_refcnt;
	uint64_t              fn_ino;
	int64_t               fn_beg;
	int64_t               fn_end;
	uint32_t              fn_nactive_childs;
	uint8_t               fn_height;
	uint8_t               fn_child_ltype;
	uint8_t               fn_reserved1[10];
	uint8_t               fn_zeros[960];
	struct silofs_vaddr56 fn_child[SILOFS_FILE_NODE_NCHILDS];
} silofs_attr_aligned64;

struct silofs_symlnk_value {
	struct silofs_header sy_hdr;
	uint64_t             sy_parent;
	uint16_t             sy_length;
	uint8_t              sy_reserved1[38];
	uint8_t              sy_value[SILOFS_SYMLNK_PART_MAX];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* 1K data block */
struct silofs_data_block1 {
	uint8_t dat[1024];
} silofs_attr_aligned64;

/* 4K data block */
struct silofs_data_block4 {
	uint8_t dat[4096];
} silofs_attr_aligned64;

/* 64K data block */
struct silofs_data_block64 {
	uint8_t dat[65536];
} silofs_attr_aligned64;

/* single logical block unit */
union silofs_lblock_u {
	uint8_t                    bk[SILOFS_LBK_SIZE];
	struct silofs_inode        inode[SILOFS_NINODE_IN_LBK];
	struct silofs_xattr_node   xan[SILOFS_NXANODE_IN_LBK];
	struct silofs_dtree_node   dtn[SILOFS_NDTNODE_IN_LBK];
	struct silofs_symlnk_value syv[SILOFS_NSYMVAL_IN_LBK];
	struct silofs_ftree_node   ftn[SILOFS_NFRTNODE_IN_LBK];
	struct silofs_data_block1  dbk1[SILOFS_NKB_IN_LBK];
	struct silofs_data_block4  dbk4[SILOFS_NKB_IN_LBK / 4];
	struct silofs_data_block64 dbk64[SILOFS_NKB_IN_LBK / 64];
} silofs_attr_aligned64;

struct silofs_lblock {
	union silofs_lblock_u u;
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* semantic "view" into meta elements */
union silofs_view_u {
	struct silofs_header       hdr;
	struct silofs_super_block  sb;
	struct silofs_spmap_node   sn;
	struct silofs_spmap_leaf   sl;
	struct silofs_inode        in;
	struct silofs_dtree_node   dtn;
	struct silofs_ftree_node   ftn;
	struct silofs_xattr_node   xan;
	struct silofs_symlnk_value syv;
	struct silofs_data_block1  dbk1;
	struct silofs_data_block4  dbk4;
	struct silofs_data_block64 dbk64;
	struct silofs_lblock       lbk;
} silofs_attr_aligned64;

struct silofs_view {
	union silofs_view_u u;
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* repo meta record */
struct silofs_repo_meta {
	uint64_t rm_magic;
	uint32_t rm_version;
	uint32_t rm_mode;
	uint8_t  rm_reserved1[240];
	uint8_t  rm_reserved2[256];
	uint8_t  rm_reserved3[512];
} silofs_attr_aligned64;

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* persistent volume segment check-point node */
struct silofs_chkpt_node {
	struct silofs_header  cpn_hdr;
	uint32_t              cpn_flags;
	uint8_t               cpn_reserved1[12];
	struct silofs_psid32b cpn_id;
	uint8_t               cpn_reserved2[4032];
} silofs_attr_aligned64;

/* b+tree node of persistent volume mapping */
struct silofs_btree_node {
	struct silofs_header   btn_hdr;
	uint32_t               btn_flags;
	uint16_t               btn_nkeys;
	uint16_t               btn_nchilds;
	uint8_t                btn_reserved1[40];
	struct silofs_paddr48b btn_child[SILOFS_BTREE_NODE_NCHILDS];
	struct silofs_laddr48b btn_key[SILOFS_BTREE_NODE_NKEYS];
	uint8_t                btn_reserved3[48];
} silofs_attr_aligned64;

/* laddr-to-paddr mapping entry */
struct silofs_btree_ltop {
	struct silofs_laddr48b laddr;
	struct silofs_paddr48b paddr;
} silofs_attr_aligned16;

/*  b+tree leaf of persistent volume mapping */
struct silofs_btree_leaf {
	struct silofs_header     btl_hdr;
	uint32_t                 btl_flags;
	uint16_t                 btl_nltops;
	uint8_t                  btl_reserved1[106];
	struct silofs_btree_ltop btl_ltop[SILOFS_BTREE_LEAF_NENTS];
} silofs_attr_aligned64;

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* minimal pack-archive index total size in bytes */
#define SILOFS_PAR_INDEX_SIZE_MIN SILOFS_LBK_SIZE

/* maximal pack-archive index total size in bytes */
#define SILOFS_PAR_INDEX_SIZE_MAX (256 * SILOFS_MEGA)

/* pack-archive descriptor */
struct silofs_par_desc256b {
	struct silofs_caddr64b pd_caddr;
	struct silofs_laddr48b pd_laddr;
	uint8_t                pd_reserved[144];
} silofs_attr_aligned64;

/* pac-archive header */
struct silofs_par_hdr1k {
	uint64_t ph_magic;
	uint32_t ph_version;
	uint32_t ph_flags;
	uint64_t ph_ndescs;
	uint64_t ph_descs_csum;
	uint64_t ph_reserved2[123];
	uint64_t ph_hdr_csum;
} silofs_attr_aligned64;

#endif /* SILOFS_DEFS_H_ */
