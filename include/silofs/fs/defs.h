/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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

#include <stdint.h>

/* current on-disk format version number */
#define SILOFS_FMT_VERSION              (1)

/* main-boot-record magic-signature (ASCII: "@SILOFS@") */
#define SILOFS_MBR_MAGIC                (0x4053464F4C495340L)

/* super-block special magic-signature (ASCII: "@silofs@") */
#define SILOFS_SUPER_MAGIC              (0x4073666F6C697340L)

/* file-system fsid magic number (ASCII: "SILO") */
#define SILOFS_FSID_MAGIC               (0x4F4C4953U)

/* magic numbers at meta-objects start (ASCII: "silo") */
#define SILOFS_STYPE_MAGIC              (0x6F6C6973U)

/* max length of encryption pass-phrase */
#define SILOFS_PASSPHRASE_MAX           (255)

/* max size for names (not including null terminator) */
#define SILOFS_NAME_MAX                 (255)

/* max size of path (symbolic link value, including null) */
#define SILOFS_PATH_MAX                 (4096)

/* max size of mount-path (including null) */
#define SILOFS_MNTPATH_MAX              (1920)

/* max path-length (including null) of repository-path */
#define SILOFS_REPOPATH_MAX             (2032)

/* max number of hard-links to file or sub-directories */
#define SILOFS_LINK_MAX                 (32767)

/* number of octets in UUID */
#define SILOFS_UUID_SIZE                (16)

/* size of common meta-data header */
#define SILOFS_HEADER_SIZE              (16)


/* minimal file-system capacity, in bytes (2G) */
#define SILOFS_CAPACITY_SIZE_MIN        (2L * SILOFS_GIGA)

/* maximal file-system capacity, in bytes (256T) */
#define SILOFS_CAPACITY_SIZE_MAX        (256L * SILOFS_TERA)


/* bits-shift of small (1K) block-size */
#define SILOFS_KB_SHIFT                 (10)

/* small ("sector") meta-block size (1K) */
#define SILOFS_KB_SIZE                  (1 << SILOFS_KB_SHIFT)

/* number of small blocks in block-octet */
#define SILOFS_NKB_IN_BK \
	(SILOFS_BK_SIZE / SILOFS_KB_SIZE)


/* bits-shift of logical block */
#define SILOFS_BK_SHIFT                 (16)

/* logical block size (64K) */
#define SILOFS_BK_SIZE                  (1L << SILOFS_BK_SHIFT)


/* number of blocks within virtual section */
#define SILOFS_NBK_IN_VSEC              (256L)

/* size in bytes of single virtual section (16M) */
#define SILOFS_VSEC_SIZE \
	(SILOFS_NBK_IN_VSEC * SILOFS_BK_SIZE)

/* number of sub-trees per super-block */
#define SILOFS_SUPER_NODE_NCHILDS       (32)

/* number of children per space-mapping node */
#define SILOFS_SPMAP_NODE_NCHILDS       (256)

/* vspace-span of single bottom-level space-node (4G) */
#define SILOFS_SPNODE_VRANGE_SIZE \
	(SILOFS_SPMAP_NODE_NCHILDS * SILOFS_VSEC_SIZE)

/* number of children per space-mapping leaf */
#define SILOFS_SPMAP_LEAF_NCHILDS       SILOFS_NBK_IN_VSEC


/* non-valid ("NIL") logical byte address */
#define SILOFS_OFF_NULL                 (-1)

/* max bit-shift of LBA value */
#define SILOFS_LBA_SHIFT_MAX            (56)

/* non-valid ("NIL") logical block address */
#define SILOFS_LBA_NULL                 ((1L << SILOFS_LBA_SHIFT_MAX) - 1)

/* well-known initial LBA of first super-block */
#define SILOFS_LBA_SB0 \
	(SILOFS_SPMAP_NODE_NCHILDS * SILOFS_NBK_IN_VSEC)


/* "nil" inode number */
#define SILOFS_INO_NULL                 (0)

/* export ino towards vfs of root inode */
#define SILOFS_INO_ROOT                 (1)

/* max number of "pseudo" inodes */
#define SILOFS_INO_PSEUDO_MAX           ((1L << 16) - 1)

/* max valid ino number */
#define SILOFS_INO_MAX                  ((1L << 56) - 1)


/* on-disk size of super-block */
#define SILOFS_SB_SIZE                  SILOFS_BK_SIZE

/* height of super-block at root of mapping tree */
#define SILOFS_SUPER_HEIGHT             (SILOFS_SPNODE_HEIGHT_MAX + 1)

/* max height of node in space mapping tree */
#define SILOFS_SPNODE_HEIGHT_MAX        (4)

/* height of leaf in space mapping tree */
#define SILOFS_SPLEAF_HEIGHT            (1)

/* on-disk size of space-node mapping (32K) */
#define SILOFS_SPNODE_SIZE              (32 * SILOFS_KILO)

/* on-disk size of space-leaf mapping (32K) */
#define SILOFS_SPLEAF_SIZE              (32 * SILOFS_KILO)

/* on-disk size of inode's head */
#define SILOFS_INODE_SIZE               SILOFS_KB_SIZE


/* bits-shift for inode-table children fan-out */
#define SILOFS_ITNODE_SHIFT             (7)

/* number of children per inode-table node */
#define SILOFS_ITNODE_NSLOTS            (1 << SILOFS_ITNODE_SHIFT)

/* number of entries in inode-table node */
#define SILOFS_ITNODE_NENTS             (953)

/* on-disk size of inode-table node */
#define SILOFS_ITNODE_SIZE              (16384)


/* height-limit of file-mapping radix-tree */
#define SILOFS_FILE_HEIGHT_MAX          (4)

/* bits-shift of single file-mapping address-space */
#define SILOFS_FILE_MAP_SHIFT           (10)

/* file's level1 head-mapping block-sizes (1K) */
#define SILOFS_FILE_HEAD1_LEAF_SIZE     (SILOFS_KB_SIZE)

/* number of 1K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD1_NLEAVES       (4)

/* file's level2 head-mapping block-sizes (4K) */
#define SILOFS_FILE_HEAD2_LEAF_SIZE     (4 * SILOFS_KB_SIZE)

/* number of 4K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD2_NLEAVES       (15)

/* file's tree-mapping block-sizes */
#define SILOFS_FILE_TREE_LEAF_SIZE      SILOFS_BK_SIZE

/* number of mapping-slots per single file tree node */
#define SILOFS_FILE_NODE_NCHILDS        (1LL << SILOFS_FILE_MAP_SHIFT)

/* maximum number of data-leafs in regular file */
#define SILOFS_FILE_LEAVES_MAX \
	(1LL << (SILOFS_FILE_MAP_SHIFT * (SILOFS_FILE_HEIGHT_MAX - 1)))

/* maximum size in bytes of regular file */
#define SILOFS_FILE_SIZE_MAX \
	((SILOFS_BK_SIZE * SILOFS_FILE_LEAVES_MAX) - 1)

/* on-disk size of file's radix-tree-node */
#define SILOFS_FILE_RTNODE_SIZE         (8192)


/* base size of empty directory */
#define SILOFS_DIR_EMPTY_SIZE           SILOFS_INODE_SIZE

/* on-disk size of directory tree-node */
#define SILOFS_DIR_NODE_SIZE            (8192)

/* number of directory-entries in dir's hash-tree mapping node  */
#define SILOFS_DIR_NODE_NENTS           (476)

/* bits-shift of children per dir-htree node */
#define SILOFS_DIR_NODE_SHIFT           (6)

/* number of children per dir hash-tree node */
#define SILOFS_DIR_NODE_NCHILDS         (1 << SILOFS_DIR_NODE_SHIFT)

/* maximum depth of directory htree-mapping */
#define SILOFS_DIR_TREE_DEPTH_MAX       (4L)

/* max number of dir htree nodes */
#define SILOFS_DIR_TREE_INDEX_MAX \
	((1L << (SILOFS_DIR_NODE_SHIFT * SILOFS_DIR_TREE_DEPTH_MAX)) - 1)

/* non-valid dir tree node-index */
#define SILOFS_DIR_TREE_INDEX_NULL      (1L << 31)

/* max entries in directory */
#define SILOFS_DIR_ENTRIES_MAX \
	(SILOFS_DIR_NODE_NENTS * SILOFS_DIR_TREE_INDEX_MAX)

/* max value of directory offset */
#define SILOFS_DIR_OFFSET_MAX           (SILOFS_DIR_ENTRIES_MAX + 1)


/* max size of symbolic-link value (including null terminator) */
#define SILOFS_SYMLNK_MAX               SILOFS_PATH_MAX

/* max size of within-inode symbolic-link value  */
#define SILOFS_SYMLNK_HEAD_MAX          (472)

/* max size of symbolic-link part  */
#define SILOFS_SYMLNK_PART_MAX          (960)

/* number of possible symbolic-link parts  */
#define SILOFS_SYMLNK_NPARTS            (5)

/* on-disk size of symlink tail-value */
#define SILOFS_SYMLNK_VAL_SIZE          SILOFS_KB_SIZE


/* number of extended-attributes entries in inode's head */
#define SILOFS_XATTR_INENTS             (32)

/* number of extended-attributes entries in indirect node */
#define SILOFS_XATTR_NENTS              (1016)

/* max length of extended attributes value */
#define SILOFS_XATTR_VALUE_MAX          (4096)

/* on-disk size of xattr node */
#define SILOFS_XATTR_NODE_SIZE          (8192)


/* max size of single I/O operation */
#define SILOFS_IO_SIZE_MAX              ((2UL * SILOFS_UMEGA) - SILOFS_BK_SIZE)


/* size in bytes of opaque meta identifier */
#define SILOFS_METAID_SIZE              (16)



enum silofs_endianness {
	SILOFS_ENDIANNESS_LE    = 1,
	SILOFS_ENDIANNESS_BE    = 2
};

/* file-system logical-elements types */
enum silofs_stype {
	SILOFS_STYPE_NONE       = 0x00,
	SILOFS_STYPE_ANONBK     = 0x01,
	SILOFS_STYPE_DATA1K     = 0x11,
	SILOFS_STYPE_DATA4K     = 0x12,
	SILOFS_STYPE_DATABK     = 0x13,
	SILOFS_STYPE_SUPER      = 0x21,
	SILOFS_STYPE_SPNODE     = 0x22,
	SILOFS_STYPE_SPLEAF     = 0x23,
	SILOFS_STYPE_ITNODE     = 0x31,
	SILOFS_STYPE_INODE      = 0x32,
	SILOFS_STYPE_XANODE     = 0x33,
	SILOFS_STYPE_DTNODE     = 0x34,
	SILOFS_STYPE_FTNODE     = 0x35,
	SILOFS_STYPE_SYMVAL     = 0x36,
	SILOFS_STYPE_MAX, /* keep last */
};

/* common-header flags */
enum silofs_hdrf {
	SILOFS_HDRF_CSUM        = (1 << 0),
};

/* block-reference flags */
enum silofs_bkrf {
	SILOFS_BKRF_NONE        = 0,
};


/* inode control flags */
enum silofs_inodef {
	SILOFS_INODEF_ROOTD     = (1 << 0),
};

/* dir-inode control flags */
enum silofs_dirf {
	SILOFS_DIRF_HASH_SHA256 = (1 << 0),
	SILOFS_DIRF_NAME_UTF8   = (1 << 1),
};

/* extended attributes known classes */
enum silofs_xattr_ns {
	SILOFS_XATTR_NONE       = 0,
	SILOFS_XATTR_SECURITY   = 1,
	SILOFS_XATTR_SYSTEM     = 2,
	SILOFS_XATTR_TRUSTED    = 3,
	SILOFS_XATTR_USER       = 4,
};

/* cryptographic key size */
#define SILOFS_KEY_SIZE         (32)

/* initialization vector size (for AES256) */
#define SILOFS_IV_SIZE          (16)

/* cryptographic hash-128-bits bytes-size */
#define SILOFS_HASH128_LEN      (16)

/* cryptographic hash-256-bits bytes-size */
#define SILOFS_HASH256_LEN      (32)

/* cryptographic hash-512-bits bytes-size */
#define SILOFS_HASH512_LEN      (64)

/* salt size for Key-Derivation-Function */
#define SILOFS_SALT_SIZE        (128)

/* encryption cipher settings (libgcrypt values) */
enum silofs_cipher_algo {
	SILOFS_CIPHER_AES256    = 9,
};

enum silofs_cipher_mode {
	SILOFS_CIPHER_MODE_CBC  = 3,
	SILOFS_CIPHER_MODE_GCM  = 9,
};

/* hash-function type (libgcrypt values) */
enum silofs_md_type {
	SILOFS_MD_NONE          = 0,
	SILOFS_MD_SHA256        = 8,
	SILOFS_MD_SHA3_256      = 313,
	SILOFS_MD_SHA3_512      = 315
};

/* key-derivation functions (libgcrypt values) */
enum silofs_kdf_algos {
	SILOFS_KDF_NONE         = 0,
	SILOFS_KDF_PBKDF2       = 34,
	SILOFS_KDF_SCRYPT       = 48
};


/* unix-domain socket for mount daemon */
#define SILOFS_MNTSOCK_NAME     "silofs-mount"

/* max number of mount-rules */
#define SILOFS_MNTRULE_MAX      1024


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define silofs_aligned          __attribute__ ((__aligned__))
#define silofs_aligned8         __attribute__ ((__aligned__(8)))
#define silofs_aligned16        __attribute__ ((__aligned__(16)))
#define silofs_aligned64        __attribute__ ((__aligned__(64)))
#define silofs_packed           __attribute__ ((__packed__))
#define silofs_packed_aligned   __attribute__ ((__packed__, __aligned__))
#define silofs_packed_aligned4  __attribute__ ((__packed__, __aligned__(4)))
#define silofs_packed_aligned8  __attribute__ ((__packed__, __aligned__(8)))
#define silofs_packed_aligned16 __attribute__ ((__packed__, __aligned__(16)))
#define silofs_packed_aligned32 __attribute__ ((__packed__, __aligned__(32)))
#define silofs_packed_aligned64 __attribute__ ((__packed__, __aligned__(64)))

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


struct silofs_timespec {
	uint64_t t_sec;
	uint64_t t_nsec;
} silofs_packed_aligned16;


struct silofs_hash128 {
	uint8_t hash[SILOFS_HASH128_LEN];
} silofs_packed_aligned32;


struct silofs_hash256 {
	uint8_t hash[SILOFS_HASH256_LEN];
} silofs_packed_aligned32;


struct silofs_hash512 {
	uint8_t hash[SILOFS_HASH512_LEN];
} silofs_packed_aligned64;


struct silofs_uuid {
	uint8_t uu[SILOFS_UUID_SIZE];
} silofs_packed_aligned8;


struct silofs_name {
	uint8_t name[SILOFS_NAME_MAX + 1];
} silofs_packed_aligned8;


struct silofs_key {
	uint8_t key[SILOFS_KEY_SIZE];
} silofs_packed_aligned16;


struct silofs_iv {
	uint8_t iv[SILOFS_IV_SIZE];
} silofs_packed_aligned8;


struct silofs_metaid128 {
	uint64_t id[2];
} silofs_packed_aligned8;


struct silofs_blobid40b {
	struct silofs_metaid128 tree_id;
	struct silofs_metaid128 uniq_id;
	uint32_t                size;
	uint8_t                 height;
	uint8_t                 flags;
	uint16_t                reserved;
} silofs_packed_aligned8;


struct silofs_oaddr48b {
	struct silofs_blobid40b bid;
	uint32_t                pos;
	uint32_t                len;
} silofs_packed_aligned8;


struct silofs_uaddr56b {
	struct silofs_oaddr48b  oaddr;
	uint64_t                voff_stype;
} silofs_packed_aligned8;


struct silofs_vaddr56 {
	uint8_t b[7];
} silofs_packed;


struct silofs_vaddr64 {
	uint64_t voff_stype;
} silofs_packed_aligned8;


struct silofs_vrange128 {
	int64_t beg;
	int64_t end;
} silofs_packed_aligned16;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_header {
	uint32_t                h_magic;
	uint8_t                 h_stype;
	uint8_t                 h_flags;
	uint16_t                h_reserved;
	uint32_t                h_size;
	uint32_t                h_csum;
} silofs_packed_aligned16;


struct silofs_kdf_desc {
	uint32_t                kd_iterations;
	uint32_t                kd_algo;
	uint16_t                kd_subalgo;
	uint16_t                kd_salt_md;
	uint32_t                kd_reserved;
} silofs_packed_aligned16;


struct silofs_kdf_pair {
	struct silofs_kdf_desc  kdf_iv;
	struct silofs_kdf_desc  kdf_key;
} silofs_packed_aligned32;


struct silofs_uobj_ref {
	struct silofs_uaddr56b  uor_uadr;
	uint64_t                uor_reserved;
} silofs_packed_aligned16;


struct silofs_main_bootrec {
	uint64_t                mbr_magic;
	uint64_t                mbr_version;
	struct silofs_uuid      mbr_uuid;
	uint64_t                mbr_flags;
	uint8_t                 mbr_reserved1[216];
	struct silofs_name      mbr_name;
	struct silofs_kdf_pair  mbr_kdf_pair;
	uint32_t                mbr_chiper_algo;
	uint32_t                mbr_chiper_mode;
	uint8_t                 mbr_reserved2[472];
	struct silofs_uobj_ref  mbr_sb_ref;
	uint8_t                 mbr_reserved4[2968];
} silofs_packed_aligned64;


struct silofs_sb_root {
	struct silofs_header    sb_hdr;
	uint64_t                sb_magic;
	uint64_t                sb_version;
	uint64_t                sb_flags;
	uint8_t                 sb_endianness;
	uint8_t                 sb_reserved1[23];
	uint8_t                 sb_sw_version[64];
	struct silofs_uuid      sb_uuid;
	uint8_t                 sb_reserved2[112];
	struct silofs_name      sb_name;
	uint8_t                 sb_reserved3[3584];
} silofs_packed_aligned64;


struct silofs_sb_base {
	uint64_t                sb_birth_time;
	struct silofs_vaddr64   sb_itable_root;
	uint8_t                 sb_reserved1[112];
	uint64_t                sb_total_capacity;
	uint64_t                sb_uspace_nmeta;
	uint8_t                 sb_reserved2[112];
	uint64_t                sb_vspace_ndata;
	uint64_t                sb_vspace_nmeta;
	uint64_t                sb_vspace_nfiles;
	int64_t                 sb_vspace_last;
	uint8_t                 sb_reserved4[224];
	int64_t                 sb_vspa_data1k;
	int64_t                 sb_vspa_data4k;
	int64_t                 sb_vspa_databk;
	int64_t                 sb_vspa_itnode;
	int64_t                 sb_vspa_inode;
	int64_t                 sb_vspa_xanode;
	int64_t                 sb_vspa_dirnode;
	int64_t                 sb_vspa_filenode;
	int64_t                 sb_vspa_symval;
	int64_t                 sb_reserved[23];
	uint8_t                 sb_reserved3[3328];
} silofs_packed_aligned64;


struct silofs_sb_usmap {
	struct silofs_vrange128 su_vrange;
	uint8_t                 su_height;
	uint8_t                 su_pad[15];
	struct silofs_metaid128 su_main_treeid;
	uint8_t                 su_reserved1[16];
	struct silofs_blobid40b su_main_blobid;
	uint8_t                 su_reserved2[24];
	struct silofs_blobid40b su_arch_blobid;
	uint8_t                 su_reserved3[24];
	uint8_t                 su_reserved4[1856];
	struct silofs_uobj_ref  su_child[SILOFS_SUPER_NODE_NCHILDS];
} silofs_packed_aligned64;


struct silofs_sb_hash {
	struct silofs_hash512   sh_fill_hash;
	struct silofs_hash512   sh_pass_hash;
	uint8_t                 sh_reserved[1920];
	uint8_t                 sh_fill[2048];
} silofs_packed_aligned64;


struct silofs_sb_keys {
	uint32_t                sk_cipher_algo;
	uint32_t                sk_cipher_mode;
	uint8_t                 sk_reserved1[104];
	struct silofs_iv        sk_iv[503];
	struct silofs_key       sk_key[257];
} silofs_packed_aligned64;


struct silofs_super_block {
	/* 0..4K */
	struct silofs_sb_root   sb_root;
	/* 4K..8K */
	struct silofs_sb_base   sb_base;
	/* 8K..12K */
	struct silofs_sb_usmap  sb_usm;
	/* 12K..16K */
	struct silofs_sb_hash   sb_hash;
	/* 16K..32K */
	struct silofs_sb_keys   sb_keys;
	/* 32K..64K */
	uint8_t                 sb_tail[32 * 1024];
} silofs_packed_aligned64;


struct silofs_spmap_ref {
	struct silofs_uobj_ref  sr_child;
	uint8_t                 sr_stype_sub;
	uint8_t                 sr_pad2;
	uint16_t                sr_flags;
	uint8_t                 sr_reserved[44];
} silofs_packed_aligned16;


struct silofs_spmap_node {
	struct silofs_header    sn_hdr;
	struct silofs_vrange128 sn_vrange;
	uint8_t                 sn_height;
	uint8_t                 sn_pad[7];
	uint8_t                 sn_reserved1[24];
	struct silofs_blobid40b sn_main_blobid;
	uint8_t                 sn_reserved2[24];
	struct silofs_blobid40b sn_arch_blobid;
	uint8_t                 sn_reserved3[24];
	uint8_t                 sn_reserved4[3904];
	struct silofs_spmap_ref sn_child[SILOFS_SPMAP_NODE_NCHILDS];
} silofs_packed_aligned64;


struct silofs_bk_ref {
	struct silofs_blobid40b br_blobid;
	uint8_t                 br_reserved1[4];
	uint32_t                br_flags;
	uint64_t                br_allocated;
	uint64_t                br_unwritten;
	uint64_t                br_refcnt;
	int64_t                 br_off;
	uint8_t                 br_reserved2[32];
} silofs_packed_aligned16;


struct silofs_spmap_leaf {
	struct silofs_header    sl_hdr;
	struct silofs_vrange128 sl_vrange;
	uint8_t                 sl_stype_sub;
	uint8_t                 sl_reserved1[31];
	struct silofs_blobid40b sl_main_blobid;
	uint8_t                 sl_reserved2[24];
	struct silofs_blobid40b sl_arch_blobid;
	uint8_t                 sl_reserved3[24];
	uint8_t                 sl_reserved4[3904];
	struct silofs_bk_ref    sl_bkr[SILOFS_SPMAP_LEAF_NCHILDS];
} silofs_packed_aligned64;


struct silofs_itable_entry {
	uint64_t                ino;
	struct silofs_vaddr64   vaddr;
} silofs_packed_aligned16;


struct silofs_itable_node {
	struct silofs_header    it_hdr;
	struct silofs_vaddr64   it_parent;
	uint16_t                it_depth;
	uint16_t                it_nents;
	uint16_t                it_nchilds;
	uint16_t                it_pad;
	uint8_t                 it_reserved1[32];
	struct silofs_itable_entry ite[SILOFS_ITNODE_NENTS];
	uint8_t                 it_reserved2[48];
	struct silofs_vaddr64   it_child[SILOFS_ITNODE_NSLOTS];
} silofs_packed_aligned64;


struct silofs_inode_times {
	struct silofs_timespec  btime;
	struct silofs_timespec  atime;
	struct silofs_timespec  ctime;
	struct silofs_timespec  mtime;
} silofs_packed_aligned64;


struct silofs_xattr_entry {
	uint16_t                xe_name_len;
	uint16_t                xe_value_size;
	uint32_t                xe_reserved;
} silofs_packed_aligned8;


struct silofs_inode_xattr {
	uint16_t                ix_nents;
	uint8_t                 ix_pad[6];
	struct silofs_vaddr64   ix_vaddr[4];
	int64_t                 ix_reserved[3];
	struct silofs_xattr_entry ixe[SILOFS_XATTR_INENTS];
} silofs_packed_aligned64;


struct silofs_inode_dir {
	int64_t                 d_root;
	uint64_t                d_ndents;
	uint32_t                d_last_index;
	uint32_t                d_flags;
	uint8_t                 d_reserved[40];
} silofs_packed_aligned64;


struct silofs_inode_lnk {
	uint8_t                 l_head[SILOFS_SYMLNK_HEAD_MAX];
	struct silofs_vaddr64   l_tail[SILOFS_SYMLNK_NPARTS];
} silofs_packed_aligned64;


struct silofs_inode_file {
	struct silofs_vaddr64   f_head1_leaf[SILOFS_FILE_HEAD1_NLEAVES];
	struct silofs_vaddr64   f_head2_leaf[SILOFS_FILE_HEAD2_NLEAVES];
	struct silofs_vaddr64   f_tree_root;
	uint8_t                 f_reserved[352];
} silofs_packed_aligned8;


union silofs_inode_specific {
	struct silofs_inode_dir  d;
	struct silofs_inode_file f;
	struct silofs_inode_lnk  l;
	uint8_t b[512];
} silofs_packed_aligned64;


struct silofs_inode {
	struct silofs_header    i_hdr;
	uint64_t                i_ino;
	uint64_t                i_parent;
	uint32_t                i_uid;
	uint32_t                i_gid;
	uint32_t                i_mode;
	uint32_t                i_flags;
	int64_t                 i_size;
	int64_t                 i_span;
	uint64_t                i_blocks;
	uint64_t                i_nlink;
	uint64_t                i_attributes; /* statx */
	uint32_t                i_rdev_major;
	uint32_t                i_rdev_minor;
	uint64_t                i_revision;
	uint64_t                i_reserved[3];
	struct silofs_inode_times   i_tm;
	struct silofs_inode_xattr   i_xa;
	union silofs_inode_specific i_sp;
} silofs_packed_aligned64;


struct silofs_dir_entry {
	uint64_t                de_ino;
	uint16_t                de_nents;
	uint16_t                de_nprev;
	uint16_t                de_name_len;
	uint8_t                 de_dt;
	uint8_t                 de_reserved;
} silofs_packed_aligned8;


struct silofs_dtree_node {
	struct silofs_header    dn_hdr;
	uint64_t                dn_ino;
	int64_t                 dn_parent;
	uint32_t                dn_node_index;
	uint32_t                dn_flags;
	uint64_t                dn_reserved[3];
	struct silofs_dir_entry de[SILOFS_DIR_NODE_NENTS];
	struct silofs_vaddr64   dn_child[SILOFS_DIR_NODE_NCHILDS];
} silofs_packed_aligned64;


struct silofs_xattr_node {
	struct silofs_header    xa_hdr;
	uint64_t                xa_ino;
	uint16_t                xa_nents;
	uint8_t                 xa_reserved[38];
	struct silofs_xattr_entry xe[SILOFS_XATTR_NENTS];
} silofs_packed_aligned64;


struct silofs_symlnk_value {
	struct silofs_header    sy_hdr;
	uint64_t                sy_parent;
	uint16_t                sy_length;
	uint8_t                 sy_reserved1[38];
	uint8_t                 sy_value[SILOFS_SYMLNK_PART_MAX];
} silofs_packed_aligned64;


struct silofs_ftree_node {
	struct silofs_header    fn_hdr;
	uint64_t                fn_refcnt;
	uint64_t                fn_ino;
	int64_t                 fn_beg;
	int64_t                 fn_end;
	uint8_t                 fn_height;
	uint8_t                 fn_child_stype;
	uint8_t                 fn_reserved1[14];
	uint8_t                 fn_zeros[960];
	struct silofs_vaddr56   fn_child[SILOFS_FILE_NODE_NCHILDS];
} silofs_packed_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* 1K data block */
struct silofs_data_block1 {
	uint8_t dat[SILOFS_KB_SIZE];
} silofs_packed_aligned64;


/* 4K data block */
struct silofs_data_block4 {
	uint8_t dat[4 * SILOFS_KB_SIZE];
} silofs_packed_aligned64;


/* 64K data block */
struct silofs_data_block {
	uint8_t dat[SILOFS_BK_SIZE];
} silofs_packed_aligned64;


/* single 64K block unit */
union silofs_block_u {
	uint8_t bk[SILOFS_BK_SIZE];
	struct silofs_data_block1       db1[SILOFS_NKB_IN_BK];
	struct silofs_data_block        db;
	struct silofs_header            hdr;
	struct silofs_super_block       sb;
	struct silofs_spmap_node        sn;
	struct silofs_spmap_leaf        sl;
} silofs_packed_aligned64;


struct silofs_block {
	union silofs_block_u u;
} silofs_packed_aligned64;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* semantic "view" into meta elements */
union silofs_view {
	struct silofs_header            hdr;
	struct silofs_super_block       sb;
	struct silofs_spmap_node        sn;
	struct silofs_spmap_leaf        sl;
	struct silofs_bk_ref            br;
	struct silofs_inode             in;
	struct silofs_dtree_node        dtn;
	struct silofs_ftree_node        ftn;
	struct silofs_xattr_node        xan;
	struct silofs_symlnk_value      sym;
	struct silofs_itable_node       itn;
	struct silofs_data_block1       db1;
	struct silofs_data_block4       db4;
	struct silofs_data_block        db;
	struct silofs_block             bk;
} silofs_packed_aligned64;

#endif /* SILOFS_DEFS_H_ */
