/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#ifndef SILOFS_ONDISK_H_
#define SILOFS_ONDISK_H_

#include <silofs/ccattr.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* on-disk format version number */
#define SILOFS_FMT_VERSION (1)

/* repo format revision number */
#define SILOFS_REPO_REVISION (1)

/* repo meta-file magic-signature (ASCII: "#SILOFS#") */
#define SILOFS_REPO_META_MAGIC (0x2353464F4C495323L)

/* super-block special magic-signature (ASCII: "@silofs@") */
#define SILOFS_SUPER_MAGIC (0x4073666F6C697340L)

/* file-system fsid magic number (ASCII: "SILO") */
#define SILOFS_FSID_MAGIC (0x4F4C4953U)

/* min/max length of encryption password (FIPS 140-2) */
#define SILOFS_PASSWORD_MIN (8)
#define SILOFS_PASSWORD_MAX (127)

/* max size for names (not including null terminator) */
#define SILOFS_NAME_MAX (511)

/* max size for file-system names (not including null terminator) */
#define SILOFS_FSNAME_MAX (127)

/* max number of uid/gid mapping */
#define SILOFS_NIDS_MAX (1024)

/* max size of path (symbolic link value, including null) */
#define SILOFS_PATH_MAX (4096)

/* max size of mount-path (including null) */
#define SILOFS_MNTPATH_MAX (1920)

/* max path-length of repository-path (including null) */
#define SILOFS_REPOPATH_MAX (1536)

/* size of repository meta-files  */
#define SILOFS_REPO_METAFILE_SIZE (1024)

/* repository meta descriptor-file name */
#define SILOFS_REPO_METAFILE_NAME "meta"

/* repository global lock file name */
#define SILOFS_REPO_LOCKFILE_NAME "lock"

/* repository meta sub-dir name */
#define SILOFS_REPO_DOTSDIR_NAME ".silofs.d"

/* repository blobs sub-directory */
#define SILOFS_REPO_BLOBSDIR_NAME "blobs"

/* max number of hard-links to file or sub-directories */
#define SILOFS_LINK_MAX ((1L << 15) - 1)

/* max number of supplementary groups per each uid (same as NFS) */
#define SILOFS_NSGRP_MAX (16)

/* minimal file-system capacity, in bytes (2G) */
#define SILOFS_CAPACITY_SIZE_MIN (2L * SILOFS_GIGA)

/* maximal file-system capacity, in bytes (64T) */
#define SILOFS_CAPACITY_SIZE_MAX (64L * SILOFS_TERA)

/* small ("sector") meta-block size (1K) */
#define SILOFS_KB_SIZE (1024)

/* bits-shift of logical block */
#define SILOFS_LBK_SHIFT (16)

/* logical block size (64K) */
#define SILOFS_LBK_SIZE (1L << SILOFS_LBK_SHIFT)

/* number of 1K blocks in logical block */
#define SILOFS_NKB_IN_LBK (SILOFS_LBK_SIZE / SILOFS_KB_SIZE)

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

/* on-disk size-shift of inode */
#define SILOFS_INODE_SHIFT (10)

/* on-disk size of inode */
#define SILOFS_INODE_SIZE (1 << SILOFS_INODE_SHIFT)

/* base size of empty directory */
#define SILOFS_DIR_EMPTY_SIZE SILOFS_INODE_SIZE

/* height-limit of file-mapping radix-tree */
#define SILOFS_FILE_HEIGHT_MAX (5)

/* bits-shift of single file-mapping address-space */
#define SILOFS_FILE_MAP_SHIFT (10)

/* number of 1K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD1_NLEAF (4)

/* number of 4K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD2_NLEAF (15)

/* on-disk size of file's tree-node */
#define SILOFS_FTREE_NODE_SIZE (8192U)

/* number of mapping-slots per single file tree node */
#define SILOFS_FTREE_NODE_NCHILDS (1LL << SILOFS_FILE_MAP_SHIFT)

/* maximum number of data-leafs in regular file */
#define SILOFS_FILE_LEAVES_MAX \
	(1LL << (SILOFS_FILE_MAP_SHIFT * (SILOFS_FILE_HEIGHT_MAX - 1)))

/* maximum size in bytes of regular file */
#define SILOFS_FILE_SIZE_MAX ((SILOFS_LBK_SIZE * SILOFS_FILE_LEAVES_MAX) - 1)

/* max number of callbacks for read-write iter operations */
#define SILOFS_FILE_NITER_MAX                                \
	(SILOFS_FILE_HEAD1_NLEAF + SILOFS_FILE_HEAD2_NLEAF + \
	 (SILOFS_IO_SIZE_MAX / SILOFS_LBK_SIZE))

/* user data node sizes via regular file mapping */
#define SILOFS_FILE_DATA_NODE1_SIZE  (1024U)
#define SILOFS_FILE_DATA_NODE4_SIZE  (4096U)
#define SILOFS_FILE_DATA_NODE64_SIZE (65536U)

/* max size of single I/O operation (2M - 64K) */
#define SILOFS_IO_SIZE_MAX ((1UL << 21) - SILOFS_LBK_SIZE)

/* cryptographic hash-128-bits bytes-size */
#define SILOFS_HASH128_LEN (16)

/* cryptographic hash-256-bits bytes-size */
#define SILOFS_HASH256_LEN (32)

/* cryptographic hash-512-bits bytes-size */
#define SILOFS_HASH512_LEN (64)

/* unix-domain socket for mount daemon */
#define SILOFS_MNTSOCK_NAME "silofs-mount"

/* max number of mount-rules */
#define SILOFS_MNTRULE_MAX 1024

/* system-wide limit on number for fuse.silofs mounts */
#define SILOFS_FUSEMNT_MAX 1024

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* format endianness */
enum silofs_endianness {
	SILOFS_ENDIANNESS_LE = 1,
	SILOFS_ENDIANNESS_BE = 2,
};

/* persistent elements sub-types */
enum silofs_ptype {
	SILOFS_PTYPE_NONE   = 0,
	SILOFS_PTYPE_MBR    = 1,
	SILOFS_PTYPE_UBER   = 2,
	SILOFS_PTYPE_BLDESC = 3,
	SILOFS_PTYPE_BTNODE = 4,
	SILOFS_PTYPE_LNODE  = 5,
	SILOFS_PTYPE_LAST   = 6, /* keep last */
};

/* logical elements sub-types */
enum silofs_ltype {
	SILOFS_LTYPE_NONE    = 0,
	SILOFS_LTYPE_SUPER   = 1,
	SILOFS_LTYPE_SPNODE  = 2,
	SILOFS_LTYPE_INODE   = 3,
	SILOFS_LTYPE_XANODE  = 4,
	SILOFS_LTYPE_SYMVAL  = 5,
	SILOFS_LTYPE_DTNODE  = 6,
	SILOFS_LTYPE_FTNODE  = 7,
	SILOFS_LTYPE_DATA1K  = 8,
	SILOFS_LTYPE_DATA4K  = 9,
	SILOFS_LTYPE_DATA64K = 10,
	SILOFS_LTYPE_LAST    = 11, /* keep last */
};

/* btree-node flags */
enum silofs_btnodef {
	SILOFS_BTNODEF_NONE = 0x00,
	SILOFS_BTNODEF_ROOT = 0x01,
};

/* logical space flags */
enum silofs_lspacef {
	SILOFS_LSPACEF_NONE      = 0x00,
	SILOFS_LSPACEF_UNWRITTEN = 0x01,
};

/* name-to-hash functions */
enum silofs_namehfn {
	SILOFS_NAMEHASH_SHA3_256 = 1,
	SILOFS_NAMEHASH_XXH3     = 2,
};

/* super-block flags */
enum silofs_superf {
	SILOFS_SUPERF_NONE   = 0x00,
	SILOFS_SUPERF_FOSSIL = 0x01,
};

/* inode control flags */
enum silofs_inodef {
	SILOFS_INODEF_NONE   = 0x00,
	SILOFS_INODEF_ROOTD  = 0x01,
	SILOFS_INODEF_FTYPE2 = 0x02,
};

/* dir-inode control flags */
enum silofs_dirf {
	SILOFS_DIRF_NONE      = 0x00,
	SILOFS_DIRF_NAME_UTF8 = 0x01,
};

/* encryption cipher settings (libgcrypt values) */
enum silofs_cipher_algo {
	SILOFS_CIPHER_NONE   = 0,
	SILOFS_CIPHER_AES256 = 9,
};

enum silofs_cipher_mode {
	SILOFS_CIPHER_MODE_NONE = 0,
	SILOFS_CIPHER_MODE_CBC  = 3,
	SILOFS_CIPHER_MODE_GCM  = 9,
	SILOFS_CIPHER_MODE_XTS  = 13,
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_sw_version64b {
	uint8_t  sw_revision[48];
	uint32_t sw_reserved;
	uint32_t sw_major;
	uint32_t sw_minor;
	uint32_t sw_sublevel;
};

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
} silofs_attr_aligned16;

struct silofs_hash512 {
	uint8_t hash[SILOFS_HASH512_LEN];
} silofs_attr_aligned64;

struct silofs_name {
	uint8_t name[SILOFS_NAME_MAX + 1];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* cryptographic key (max) size */
#define SILOFS_CRYPTO_KEY_SIZE (64)

struct silofs_ckey {
	uint8_t key[SILOFS_CRYPTO_KEY_SIZE];
} silofs_attr_aligned32;

/* cryptographic IV size */
#define SILOFS_CRYPTO_IV_SIZE (16)

struct silofs_civ {
	uint8_t iv[SILOFS_CRYPTO_IV_SIZE];
} silofs_attr_aligned8;

/* cryptographic AEAD input size */
#define SILOFS_CRYPTO_AAD_SIZE (32)

struct silofs_caad {
	uint8_t aad[SILOFS_CRYPTO_AAD_SIZE];
} silofs_attr_aligned16;

/* cryptographic AEAD output (tag) size */
#define SILOFS_CRYPTO_TAG_SIZE (16)

struct silofs_ctag {
	uint8_t tag[SILOFS_CRYPTO_TAG_SIZE];
} silofs_attr_aligned8;

/* cryptographic MAC size */
#define SILOFS_CRYPTO_MAC_SIZE (32)

struct silofs_mac {
	uint8_t mac[SILOFS_CRYPTO_MAC_SIZE];
} silofs_attr_aligned32;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* universally unique Identifier */
#define SILOFS_UUID_SIZE (16)

struct silofs_uuid {
	uint8_t id[SILOFS_UUID_SIZE];
} silofs_attr_aligned16;

/* layer identifier (UUID) */
struct silofs_layerid {
	struct silofs_uuid uuid;
} silofs_attr_aligned16;

/* unique identifier within layer */
#define SILOFS_UNIQEID_SIZE (16)

struct silofs_uniqid {
	uint8_t id[SILOFS_UNIQEID_SIZE];
} silofs_attr_aligned16;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* blob-identifier */
#define SILOFS_BLOBID_SIZE (48)

struct silofs_blobid48b {
	struct silofs_layerid layerid;
	struct silofs_uniqid  uniqid;
	uint8_t               ptype;
	uint8_t               ltype;
	uint8_t               reserved[12];
	uint16_t              vers;
} silofs_attr_aligned8;

/* exported blob-identifier representation */
struct silofs_blobidx {
	struct silofs_hash256 idx;
} silofs_attr_aligned16;

/* persistent addressing within blob */
struct silofs_paddr64b {
	struct silofs_blobid48b blobid48b;
	int64_t                 pos;
	uint8_t                 reserved[8];
} silofs_attr_aligned64;

/* virtual address (compact) */
struct silofs_laddr56 {
	uint8_t b[7];
};

struct silofs_laddr64 {
	uint64_t off_ltype;
} silofs_attr_aligned8;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* nodes' crypto meta parameters */
struct silofs_nmeta128b {
	struct silofs_ckey nm_ckey;
	struct silofs_civ  nm_civ;
	struct silofs_ctag nm_ctag;
	uint16_t           nm_cipher_algo;
	uint16_t           nm_cipher_mode;
	uint8_t            nm_reserved2[26];
} silofs_attr_aligned32;

/* pnode meta-pointer */
struct silofs_pnptr256b {
	struct silofs_nmeta128b pp_nmeta;
	struct silofs_paddr64b  pp_paddr;
	uint8_t                 pp_reserved[64];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* size of main-boot-record */
#define SILOFS_MBR_SIZE (1024)

/* main-boot-record magic-signature (ASCII: "@SILOFS@") */
#define SILOFS_MBR_MAGIC (0x4053464F4C495340L)

/* main boot record */
struct silofs_mbr1k {
	uint64_t                    mbr_magic;
	uint64_t                    mbr_version;
	struct silofs_uuid          mbr_uuid;
	uint32_t                    mbr_mode;
	uint32_t                    mbr_flags;
	uint8_t                     mbr_reserved1[24];
	struct silofs_sw_version64b mbr_sw_version;
	uint8_t                     mbr_reserved2[128];
	struct silofs_pnptr256b     mbr_root_uber;
	uint8_t                     mbr_reserved3[448];
	struct silofs_hash256       mbr_hash;
	struct silofs_mac           mbr_hmac;
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* size of common meta-data header */
#define SILOFS_HEADER_SIZE (64)

/* magic numbers at meta-objects start (ASCII: "%silofs") */
#define SILOFS_HEADER_MAGIC (0x73666f6c697325)

/* meta-header flags */
enum silofs_hdrf {
	SILOFS_HDRF_NONE  = 0x00,
	SILOFS_HDRF_PNODE = 0x01,
	SILOFS_HDRF_LNODE = 0x02,
	SILOFS_HDRF_CSUM  = 0x04,
};

/* common header to all meta-data nodes */
struct silofs_header {
	uint64_t h_magic;
	uint32_t h_size;
	uint16_t h_flags;
	uint8_t  h_ptype;
	uint8_t  h_ltype;
	uint8_t  h_reserved[36];
	uint64_t h_csum;
} silofs_attr_aligned32;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* uber-node sub-child by vspace */
struct silofs_uber_sub {
	struct silofs_pnptr256b ubs_btroot;
	struct silofs_paddr64b  ubs_bn_nextfree;
	struct silofs_paddr64b  ubs_vn_nextfree;
	uint8_t                 ubs_reserved1[128];
	uint64_t                ubs_bn_count;
	uint64_t                ubs_vn_count;
	uint8_t                 ubs_reserved2[496];
} silofs_attr_aligned64;

/* uber-node */
struct silofs_uber_node {
	struct silofs_header   ub_hdr;
	struct silofs_timespec ub_btime;
	struct silofs_timespec ub_ctime;
	uint64_t               ub_generation;
	uint64_t               ub_capacity;
	uint8_t                ub_reserved1[400];
	uint8_t                ub_reserved2[512];
	struct silofs_uber_sub ub_sub[15];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_space_stats1k {
	uint64_t sp_btime;
	uint64_t sp_ctime;
	uint64_t sp_capacity;
	uint64_t sp_vspacesize;
	uint64_t sp_generation;
	uint8_t  sp_reserved[216];
	uint8_t  sp_reserved2[768];
} silofs_attr_aligned64;

struct silofs_superb_node {
	struct silofs_header s_hdr;
	uint64_t             s_magic;
	uint64_t             s_version;
	uint32_t             s_flags;
	uint8_t              s_reserved1[44];
	struct silofs_tm64b  s_btime;
	uint8_t              s_reserved2[64];
	uint64_t             s_fs_capacity;
	uint64_t             s_fs_usage;
	uint64_t             s_ino_generation;
	uint8_t              s_reserved3[744];
	uint64_t             s_nodes_count[128];
	int64_t              s_apex_voff[128];
	uint8_t              s_reserved4[1024];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* number of sub-refs per each space-mapping node */
#define SILOFS_SPNODE_NREFS (512U)

struct silofs_space_node {
	struct silofs_header sp_hdr;
	int64_t              sp_base_off;
	uint8_t              sp_ref_ltype;
	uint8_t              sp_reserved[55];
	uint8_t              sp_reserved2[896];
	uint16_t             sp_flags[SILOFS_SPNODE_NREFS];
	uint32_t             sp_refcnt[SILOFS_SPNODE_NREFS];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* number of extended-attributes entries in indirect node */
#define SILOFS_XATTR_NENTS (1008)

/* max length of extended attributes value */
#define SILOFS_XATTR_VALUE_MAX (2048)

/* on-disk size of xattr node */
#define SILOFS_XATTR_NODE_SIZE (8192)

/* extended attributes known classes */
enum silofs_xattr_ns {
	SILOFS_XATTR_NONE     = 0,
	SILOFS_XATTR_SECURITY = 1,
	SILOFS_XATTR_SYSTEM   = 2,
	SILOFS_XATTR_TRUSTED  = 3,
	SILOFS_XATTR_USER     = 4,
	SILOFS_XATTR_GNU      = 5,
};

struct silofs_xattr_entry {
	uint16_t xe_name_len;
	uint16_t xe_reserved;
	uint32_t xe_value_size;
} silofs_attr_aligned8;

struct silofs_xattr_node {
	struct silofs_header      xa_hdr;
	uint64_t                  xa_ino;
	uint16_t                  xa_nents;
	uint8_t                   xa_reserved[48];
	struct silofs_xattr_entry xe[SILOFS_XATTR_NENTS];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* bits-shift of children per dir tree-mapping node */
#define SILOFS_DTREE_NODE_SHIFT (6)

/* number of children per dir tree-mapping node */
#define SILOFS_DTREE_NODE_NCHILDS (1 << SILOFS_DTREE_NODE_SHIFT)

/* number of directory-entries in dir's hash-tree node */
#define SILOFS_DTREE_NODE_NENTS (476)

/* max size of names-buffer in dir's tree-mapping node */
#define SILOFS_DTREE_NODE_NBSIZE (7616)

/* on-disk size of directory tree-node */
#define SILOFS_DTREE_NODE_SIZE (8192)

struct silofs_dir_entry {
	uint64_t de_ino;
	uint32_t de_name_hash;
	uint16_t de_name_len_dt;
	uint16_t de_name_pos;
} silofs_attr_aligned16;

union silofs_dtree_data {
	struct silofs_dir_entry de[SILOFS_DTREE_NODE_NENTS];
	uint8_t                 nb[SILOFS_DTREE_NODE_NBSIZE];
} silofs_attr_aligned64;

struct silofs_dtree_node {
	struct silofs_header    dn_hdr;
	uint64_t                dn_ino;
	int64_t                 dn_parent;
	uint32_t                dn_node_index;
	uint16_t                dn_nde;
	uint16_t                dn_nnb;
	uint32_t                dn_nactive_childs;
	uint8_t                 dn_reserved[36];
	union silofs_dtree_data dn_data;
	struct silofs_laddr56   dn_child[SILOFS_DTREE_NODE_NCHILDS];
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
	uint8_t               fn_reserved[26];
	uint8_t               fn_zeros[896];
	struct silofs_laddr56 fn_child[SILOFS_FTREE_NODE_NCHILDS];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* max size of symbolic-link value (including null terminator) */
#define SILOFS_SYMLNK_MAX SILOFS_PATH_MAX

/* max size of symbolic-link value within inode */
#define SILOFS_SYMVAL_HEAD_MAX (480)

/* max size of symbolic-link tail  */
#define SILOFS_SYMVAL_TAIL_MAX (4000)

/* on-disk size of symbolic-link tail-value */
#define SILOFS_SYMVAL_NODE_SIZE (4096)

struct silofs_symval_node {
	struct silofs_header svn_hdr;
	uint64_t             svn_parent;
	uint16_t             svn_length;
	uint8_t              svn_reserved2[22];
	uint8_t              svn_value[SILOFS_SYMVAL_TAIL_MAX];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_inode_times {
	struct silofs_timespec btime;
	struct silofs_timespec atime;
	struct silofs_timespec ctime;
	struct silofs_timespec mtime;
} silofs_attr_aligned64;

struct silofs_inode_xattr {
	struct silofs_laddr64 ix_laddr[8];
	uint8_t               ix_reserved[192];
} silofs_attr_aligned64;

struct silofs_inode_dir {
	struct silofs_laddr64 d_root;
	uint64_t              d_seed;
	uint64_t              d_ndents;
	uint32_t              d_last_index;
	uint32_t              d_flags;
	uint8_t               d_hashfn;
	uint8_t               d_reserved[31];
} silofs_attr_aligned64;

struct silofs_inode_lnk {
	uint8_t               l_head[SILOFS_SYMVAL_HEAD_MAX];
	struct silofs_laddr64 l_tail;
	uint8_t               l_reserved[16];
} silofs_attr_aligned64;

struct silofs_inode_file {
	struct silofs_laddr64 f_slots[32];
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
	uint8_t                   i_reserved1[32];
	struct silofs_inode_times i_tm;
	struct silofs_inode_xattr i_xa;
	union silofs_inode_tail   i_ta;
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* 1K data node */
struct silofs_data_node1 {
	uint8_t dat[1024];
} silofs_attr_aligned64;

/* 4K data node */
struct silofs_data_node4 {
	uint8_t dat[4096];
} silofs_attr_aligned64;

/* 64K data node */
struct silofs_data_node64 {
	uint8_t dat[65536];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* single logical node unit */
union silofs_lblock_u {
#define SILOFS_LBK_N_(n_) (SILOFS_LBK_SIZE / (n_))
	uint8_t                   bk[SILOFS_LBK_SIZE];
	struct silofs_inode       in[SILOFS_LBK_N_(SILOFS_INODE_SIZE)];
	struct silofs_xattr_node  xan[SILOFS_LBK_N_(SILOFS_XATTR_NODE_SIZE)];
	struct silofs_symval_node svn[SILOFS_LBK_N_(SILOFS_SYMVAL_NODE_SIZE)];
	struct silofs_dtree_node  dtn[SILOFS_LBK_N_(SILOFS_DTREE_NODE_SIZE)];
	struct silofs_ftree_node  ftn[SILOFS_LBK_N_(SILOFS_FTREE_NODE_SIZE)];
	struct silofs_data_node1  dn1[SILOFS_NKB_IN_LBK];
	struct silofs_data_node4  dn4[16];
	struct silofs_data_node64 dn64;
#undef SILOFS_LBK_N_
};

struct silofs_lblock {
	union silofs_lblock_u u;
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

/* blob-descriptor obj-ref state flags */
enum silofs_objstatef {
	SILOFS_OBJSTATEF_NONE = 0x00,
	SILOFS_OBJSTATEF_USED = 0x01,
};

/* blob's meta descriptor */
struct silofs_blob_desc {
	struct silofs_header    bld_hdr;
	struct silofs_timespec  bld_btime;
	struct silofs_timespec  bld_ctime;
	uint8_t                 bld_reserved1[32];
	struct silofs_blobid48b bld_prev;
	uint8_t                 bld_reserved2[16];
	struct silofs_blobid48b bld_refblob;
	uint8_t                 bld_reserved3[16];
	uint64_t                bld_blobsize;
	uint32_t                bld_objsize;
	uint32_t                bld_nobjs_max;
	uint32_t                bld_nobjs;
	uint32_t                bld_flags;
	uint8_t                 bld_reserved4[232];
	uint8_t                 bld_obj_state[7680];
} silofs_attr_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* minimal/maximal btree height, including leaf nodes */
#define SILOFS_BTREE_HEIGHT_MIN (1)
#define SILOFS_BTREE_HEIGHT_MAX (8)

/* number of pointers btree mapping-node */
#define SILOFS_BTREE_NODE_NCHILDS (60)

/* number of keys in btree mapping-node */
#define SILOFS_BTREE_NODE_NKEYS (SILOFS_BTREE_NODE_NCHILDS - 1)

/* on-disk size of btree node */
#define SILOFS_BTREE_NODE_SIZE (16384)

/* btree node of persistent volume mapping */
struct silofs_btree_node {
	struct silofs_header    btn_hdr;
	uint64_t                btn_minkey;
	uint32_t                btn_flags;
	uint8_t                 btn_lspace;
	uint8_t                 btn_height;
	uint8_t                 btn_reserved1[2];
	uint16_t                btn_nkeys;
	uint16_t                btn_nchilds;
	uint8_t                 btn_reserved2[172];
	uint64_t                btn_key[SILOFS_BTREE_NODE_NKEYS];
	uint8_t                 btn_reserved3[296];
	struct silofs_pnptr256b btn_child[SILOFS_BTREE_NODE_NCHILDS];
} silofs_attr_aligned64;

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* semantic "view" into pnodes' meta-elements */
union silofs_pview_u {
	struct silofs_header     hdr[2];
	struct silofs_uber_node  ubn;
	struct silofs_blob_desc  bd;
	struct silofs_btree_node btn;
} silofs_attr_aligned64;

struct silofs_pview {
	union silofs_pview_u pv;
} silofs_attr_aligned64;

/* semantic "view" into lnodes' meta-elements */
union silofs_lview_u {
	struct silofs_header      hdr[2];
	struct silofs_mbr1k       mbr;
	struct silofs_superb_node sbn;
	struct silofs_space_node  spn;
	struct silofs_inode       in;
	struct silofs_dtree_node  dtn;
	struct silofs_ftree_node  ftn;
	struct silofs_xattr_node  xan;
	struct silofs_symval_node svn;
	struct silofs_data_node1  dn1;
	struct silofs_data_node4  dn4;
	struct silofs_data_node64 dn64;
	struct silofs_lblock      lbk;
} silofs_attr_aligned64;

struct silofs_lview {
	union silofs_lview_u u;
} silofs_attr_aligned64;

#endif /* SILOFS_ONDISK_H_ */
