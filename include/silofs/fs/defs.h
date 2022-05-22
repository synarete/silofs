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
#ifndef SILOFS_DEFS_H_
#define SILOFS_DEFS_H_

#include <stdint.h>

/* current on-disk format version number */
#define SILOFS_FMT_VERSION              (1)

/* current repo format version number */
#define SILOFS_REPO_VERSION             (1)

/* repo meta-file magic-signature (ASCII: "#SILOFS#") */
#define SILOFS_REPO_META_MAGIC          (0x2353464F4C495323L)

/* boot-record magic-signature (ASCII: "@SILOFS@") */
#define SILOFS_BOOT_RECORD_MAGIC        (0x4053464F4C495340L)

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

/* max path-length of repository-path (including null) */
#define SILOFS_REPOPATH_MAX             (1536)

/* max number of hard-links to file or sub-directories */
#define SILOFS_LINK_MAX                 (32767)

/* size of boot-sector file */
#define SILOFS_BOOTSEC_SIZE             (1024)

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
#define SILOFS_NBK_IN_VSEC              (512L)

/* size in bytes of single virtual section (32M) */
#define SILOFS_VSEC_SIZE \
	(SILOFS_NBK_IN_VSEC * SILOFS_BK_SIZE)

/* number of children per space-mapping node */
#define SILOFS_UNODE_NCHILDS            SILOFS_NBK_IN_VSEC

/* vspace-span of single bottom-level space-node (16G) */
#define SILOFS_SPNODE_VRANGE_SIZE \
	(SILOFS_UNODE_NCHILDS * SILOFS_VSEC_SIZE)


/* non-valid ("NIL") logical byte address */
#define SILOFS_OFF_NULL                 (-1)

/* max bit-shift of LBA value */
#define SILOFS_LBA_SHIFT_MAX            (56)

/* non-valid ("NIL") logical block address */
#define SILOFS_LBA_NULL                 ((1L << SILOFS_LBA_SHIFT_MAX) - 1)


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
#define SILOFS_SUPER_HEIGHT             (SILOFS_SPNODE3_HEIGHT + 1)

/* max height of node in space mapping tree */
#define SILOFS_SPNODE3_HEIGHT           (3)

/* min height of node in space mapping tree */
#define SILOFS_SPNODE2_HEIGHT           (2)

/* height of leaf in space mapping tree */
#define SILOFS_SPLEAF_HEIGHT            (1)

/* height of data vblocks */
#define SILOFS_DATABK_HEIGHT            (0)

/* on-disk size of space-node mapping (64K) */
#define SILOFS_SPNODE_SIZE              SILOFS_BK_SIZE

/* on-disk size of space-leaf mapping (64K) */
#define SILOFS_SPLEAF_SIZE              SILOFS_BK_SIZE

/* on-disk size of inode's head */
#define SILOFS_INODE_SIZE               SILOFS_KB_SIZE


/* bits-shift for inode-table children fan-out */
#define SILOFS_ITNODE_SHIFT             (7)

/* number of children per inode-table node */
#define SILOFS_ITNODE_NSLOTS            (1 << SILOFS_ITNODE_SHIFT)

/* number of entries in inode-table node */
#define SILOFS_ITNODE_NENTS             (441)

/* on-disk size of inode-table node */
#define SILOFS_ITNODE_SIZE              (8192)


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

/* max number of callbacks for read-write iter operations */
#define SILOFS_FILE_NITER_MAX \
	(SILOFS_FILE_HEAD1_NLEAVES + SILOFS_FILE_HEAD2_NLEAVES + \
	 (SILOFS_IO_SIZE_MAX / SILOFS_BK_SIZE))


/* base size of empty directory */
#define SILOFS_DIR_EMPTY_SIZE           SILOFS_INODE_SIZE

/* on-disk size of directory tree-node */
#define SILOFS_DIR_NODE_SIZE            (8192)

/* number of directory-entries in dir's hash-tree node */
#define SILOFS_DIR_NODE_NENTS           (240)

/* max size of names-buffer in dir's hash-tree node */
#define SILOFS_DIR_NODE_NBUF_SIZE       (7680)

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


/* number of extended-attributes entries in indirect node */
#define SILOFS_XATTR_NENTS              (504)

/* max length of extended attributes value */
#define SILOFS_XATTR_VALUE_MAX          (2048)

/* on-disk size of xattr node */
#define SILOFS_XATTR_NODE_SIZE          (4096)


/* max size of single I/O operation */
#define SILOFS_IO_SIZE_MAX              ((2UL * SILOFS_UMEGA) - SILOFS_BK_SIZE)


/* boot-sector flags */
enum silofs_bootf {
	SILOFS_BOOTF_NONE       = 0x00,
	SILOFS_BOOTF_KEY_SHA256 = 0x01,
};

enum silofs_endianness {
	SILOFS_ENDIANNESS_LE    = 1,
	SILOFS_ENDIANNESS_BE    = 2
};

/* space packing modes */
enum silofs_pack_mode {
	SILOFS_PACK_NONE        = 0x00,
	SILOFS_PACK_SIMPLE      = 0x01,
};

/* file-system logical-elements types */
enum silofs_stype {
	SILOFS_STYPE_NONE       = 0,
	SILOFS_STYPE_ANONBK     = 1,
	SILOFS_STYPE_DATA1K     = 2,
	SILOFS_STYPE_DATA4K     = 3,
	SILOFS_STYPE_DATABK     = 4,
	SILOFS_STYPE_SUPER      = 5,
	SILOFS_STYPE_STATS      = 6,
	SILOFS_STYPE_SPNODE     = 7,
	SILOFS_STYPE_SPLEAF     = 8,
	SILOFS_STYPE_ITNODE     = 9,
	SILOFS_STYPE_INODE      = 10,
	SILOFS_STYPE_XANODE     = 11,
	SILOFS_STYPE_DTNODE     = 12,
	SILOFS_STYPE_FTNODE     = 13,
	SILOFS_STYPE_SYMVAL     = 14,
	SILOFS_STYPE_MAX, /* keep last */
};

/* common-header flags */
enum silofs_hdrf {
	SILOFS_HDRF_CSUM        = 1,
};

/* super-block flags */
enum silofs_superf {
	SILOFS_SUPERF_NONE      = 0,
	SILOFS_SUPERF_FOSSIL    = 1,
};

/* space-mapping flags */
enum silofs_spmapf {
	SILOFS_SPMAPF_NONE      = 0,
	SILOFS_SPMAPF_ACTIVE    = 1,
};

/* inode control flags */
enum silofs_inodef {
	SILOFS_INODEF_ROOTD     = 1,
};

/* dir-inode control flags */
enum silofs_dirf {
	SILOFS_DIRF_NONE        = 0,
	SILOFS_DIRF_NAME_UTF8   = 1,
};

/* dir-inode hash-functions for names */
enum silofs_dirhfn {
	SILOFS_DIRHASH_SHA256   = 1,
	SILOFS_DIRHASH_XXH64    = 2,
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
#define silofs_aligned32        __attribute__ ((__aligned__(32)))
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
} silofs_packed_aligned16;


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


struct silofs_xid128 {
	uint8_t id[16];
} silofs_packed_aligned8;


struct silofs_xxid256_tas {
	struct silofs_xid128 tree_id;
	struct silofs_xid128 uniq_id;
} silofs_packed_aligned8;


struct silofs_xxid256_cas {
	uint8_t hash[SILOFS_HASH256_LEN];
} silofs_packed_aligned8;


union silofs_xxid256_u {
	struct silofs_xxid256_tas       tid;
	struct silofs_xxid256_cas       cid;
	struct silofs_xid128            xid[2];
} silofs_packed_aligned8;


struct silofs_xxid256 {
	union silofs_xxid256_u u;
} silofs_packed_aligned8;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_vrange128 {
	int64_t                 beg;
	uint64_t                len_height;
} silofs_packed_aligned16;


struct silofs_blobid40b {
	struct silofs_xxid256   xxid;
	uint32_t                size;
	uint32_t                reserved;
} silofs_packed_aligned8;


struct silofs_packid64b {
	struct silofs_blobid40b blobid;
	uint8_t                 pmode;
	uint8_t                 reserved[23];
} silofs_packed_aligned16;


struct silofs_oaddr48b {
	struct silofs_blobid40b blobid;
	uint32_t                pos;
	uint32_t                len;
} silofs_packed_aligned8;


struct silofs_uaddr64b {
	struct silofs_oaddr48b  oaddr;
	int64_t                 voff;
	uint8_t                 stype;
	uint8_t                 height;
	uint8_t                 reserved[6];
} silofs_packed_aligned8;


struct silofs_vaddr56 {
	uint8_t b[7];
} silofs_packed;


struct silofs_vaddr64 {
	uint64_t voff_stype;
} silofs_packed_aligned8;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_kdf_desc {
	uint32_t                        kd_iterations;
	uint32_t                        kd_algo;
	uint16_t                        kd_subalgo;
	uint16_t                        kd_salt_md;
	uint32_t                        kd_reserved;
} silofs_packed_aligned16;


struct silofs_kdf_pair {
	struct silofs_kdf_desc          kdf_iv;
	struct silofs_kdf_desc          kdf_key;
} silofs_packed_aligned32;


struct silofs_bootsec1k {
	uint64_t                        bs_magic;
	uint64_t                        bs_version;
	struct silofs_uuid              bs_uuid;
	uint64_t                        bs_flags;
	uint8_t                         bs_reserved1[24];
	struct silofs_kdf_pair          bs_kdf_pair;
	uint32_t                        bs_chiper_algo;
	uint32_t                        bs_chiper_mode;
	uint8_t                         bs_reserved2[24];
	struct silofs_hash256           bs_key_hash;
	uint8_t                         bs_reserved3[96];
	struct silofs_uaddr64b          bs_sb_uaddr;
	struct silofs_packid64b         bs_sb_packid;
	uint8_t                         bs_rands[128];
	struct silofs_name              bs_metaname;
	uint8_t                         bs_reserved4[224];
	struct silofs_hash256           bs_hash;
} silofs_packed_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_header {
	uint32_t                        h_magic;
	uint8_t                         h_stype;
	uint8_t                         h_flags;
	uint16_t                        h_reserved;
	uint32_t                        h_size;
	uint32_t                        h_csum;
} silofs_packed_aligned16;


struct silofs_spmap_ref {
	struct silofs_uaddr64b          sr_ulink;
	uint8_t                         sr_stype_sub;
	uint8_t                         sr_pad[3];
	uint32_t                        sr_flags;
	uint8_t                         sr_reserved[48];
} silofs_packed_aligned8;


struct silofs_super_block {
	/* 0..2K */
	struct silofs_header            sb_hdr;
	uint64_t                        sb_magic;
	uint64_t                        sb_version;
	uint32_t                        sb_flags;
	uint8_t                         sb_reserved1[4];
	uint8_t                         sb_endianness;
	uint8_t                         sb_reserved2[23];
	uint8_t                         sb_sw_version[64];
	struct silofs_uuid              sb_uuid;
	uint8_t                         sb_reserved3[112];
	struct silofs_name              sb_name;
	uint8_t                         sb_reserved4[512];
	/* 1K..2K */
	struct silofs_uaddr64b          sb_stats_uaddr;
	uint64_t                        sb_birth_time;
	uint64_t                        sb_clone_time;
	uint64_t                        sb_pack_time;
	struct silofs_vaddr64           sb_itable_root;
	uint8_t                         sb_reserved5[928];
	/* 2K..4K */
	struct silofs_vrange128         sb_vrange;
	struct silofs_xid128            sb_treeid;
	uint8_t                         sb_reserved6[32];
	struct silofs_blobid40b         sb_mainblobid;
	uint8_t                         sb_reserved7[24];
	struct silofs_packid64b         sb_mainpackid;
	uint8_t                         sb_reserved8[64];
	struct silofs_uaddr64b          sb_self;
	uint8_t                         sb_reserved9[1728];
	/* 4K..64K */
	struct silofs_spmap_ref         sb_subref[SILOFS_UNODE_NCHILDS];

} silofs_packed_aligned64;


struct silofs_stats_record {
	uint64_t                        sr_timestamp;
	uint64_t                        sr_capacity;
	int64_t                         sr_vspace_end;
	uint64_t                        sr_ndata1k;
	uint64_t                        sr_ndata4k;
	uint64_t                        sr_ndatabk;
	uint64_t                        sr_nsuper;
	uint64_t                        sr_nstats;
	uint64_t                        sr_nspnode;
	uint64_t                        sr_nspleaf;
	uint64_t                        sr_nitnode;
	uint64_t                        sr_ninode;
	uint64_t                        sr_nxanode;
	uint64_t                        sr_ndtnode;
	uint64_t                        sr_nftnode;
	uint64_t                        sr_nsymval;
	uint8_t                         sr_reserved[128];
} silofs_packed_aligned64;


struct silofs_super_stats {
	struct silofs_header            st_hdr;
	uint8_t                         st_reserved1[48];
	uint8_t                         st_reserved2[192];
	struct silofs_stats_record      st_curr;
	struct silofs_stats_record      st_base;
	uint8_t                         st_reserved3[256];
} silofs_packed_aligned64;


struct silofs_spmap_node {
	struct silofs_header            sn_hdr;
	struct silofs_vrange128         sn_vrange;
	uint8_t                         sn_stype_sub;
	uint8_t                         sn_reserved1[31];
	struct silofs_blobid40b         sn_mainblobid;
	uint8_t                         sn_reserved2[24];
	struct silofs_packid64b         sn_mainpackid;
	uint8_t                         sn_reserved3[64];
	struct silofs_uaddr64b          sn_parent;
	struct silofs_uaddr64b          sn_self;
	uint8_t                         sn_reserved4[3712];
	struct silofs_spmap_ref         sn_subref[SILOFS_UNODE_NCHILDS];
} silofs_packed_aligned64;


struct silofs_bk_ref {
	struct silofs_uaddr64b          br_ulink;
	uint64_t                        br_allocated;
	uint64_t                        br_unwritten;
	uint64_t                        br_refcnt;
	int64_t                         br_off;
	uint32_t                        br_flags;
	uint8_t                         br_reserved1[20];
} silofs_packed_aligned8;


struct silofs_spmap_leaf {
	struct silofs_header            sl_hdr;
	struct silofs_vrange128         sl_vrange;
	uint8_t                         sl_stype_sub;
	uint8_t                         sl_reserved1[31];
	struct silofs_blobid40b         sl_mainblobid;
	uint8_t                         sl_reserved2[24];
	struct silofs_packid64b         sl_mainpackid;
	uint8_t                         sl_reserved3[64];
	struct silofs_uaddr64b          sl_parent;
	struct silofs_uaddr64b          sl_self;
	uint8_t                         sl_reserved4[3712];
	struct silofs_bk_ref            sl_subref[SILOFS_UNODE_NCHILDS];
} silofs_packed_aligned64;


struct silofs_itable_entry {
	uint64_t                        ite_ino;
	struct silofs_vaddr64           ite_vaddr;
} silofs_packed_aligned16;


struct silofs_itable_node {
	struct silofs_header            it_hdr;
	struct silofs_vaddr64           it_parent;
	uint16_t                        it_depth;
	uint16_t                        it_nents;
	uint16_t                        it_nchilds;
	uint16_t                        it_pad;
	uint8_t                         it_reserved1[32];
	struct silofs_itable_entry      ite[SILOFS_ITNODE_NENTS];
	uint8_t                         it_reserved2[48];
	struct silofs_vaddr64           it_child[SILOFS_ITNODE_NSLOTS];
} silofs_packed_aligned64;


struct silofs_inode_times {
	struct silofs_timespec  btime;
	struct silofs_timespec  atime;
	struct silofs_timespec  ctime;
	struct silofs_timespec  mtime;
} silofs_packed_aligned64;


struct silofs_inode_xattr {
	struct silofs_vaddr64   ix_vaddr[8];
	uint8_t                 ix_reserved[192];
} silofs_packed_aligned64;


struct silofs_inode_dir {
	uint64_t                d_seed;
	int64_t                 d_root;
	uint64_t                d_ndents;
	uint32_t                d_last_index;
	uint32_t                d_flags;
	uint8_t                 d_hashfn;
	uint8_t                 d_reserved[31];
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
	struct silofs_header            i_hdr;
	uint64_t                        i_ino;
	uint64_t                        i_parent;
	uint32_t                        i_uid;
	uint32_t                        i_gid;
	uint32_t                        i_mode;
	uint32_t                        i_flags;
	int64_t                         i_size;
	int64_t                         i_span;
	uint64_t                        i_blocks;
	uint64_t                        i_nlink;
	uint64_t                        i_attributes; /* statx */
	uint32_t                        i_rdev_major;
	uint32_t                        i_rdev_minor;
	uint64_t                        i_revision;
	uint8_t                         i_reserved1[24];
	struct silofs_inode_times       i_tm;
	uint8_t                         i_reserved2[64];
	struct silofs_inode_xattr       i_xa;
	union silofs_inode_specific     i_sp;
} silofs_packed_aligned64;


struct silofs_xattr_entry {
	uint16_t                        xe_name_len;
	uint16_t                        xe_reserved;
	uint32_t                        xe_value_size;
} silofs_packed_aligned8;


struct silofs_xattr_node {
	struct silofs_header    xa_hdr;
	uint64_t                xa_ino;
	uint16_t                xa_nents;
	uint8_t                 xa_reserved[38];
	struct silofs_xattr_entry xe[SILOFS_XATTR_NENTS];
} silofs_packed_aligned64;


union silofs_dir_entry_name {
	uint16_t                de_name_pos;
	uint8_t                 de_name[12];
} silofs_packed_aligned4;


struct silofs_dir_entry {
	uint64_t                de_ino;
	uint64_t                de_name_hash;
	uint16_t                de_name_len;
	uint8_t                 de_dt;
	uint8_t                 de_pad;
	union silofs_dir_entry_name de_name;
} silofs_packed_aligned32;


union silofs_dtree_data {
	struct silofs_dir_entry de[SILOFS_DIR_NODE_NENTS];
	uint8_t                 nb[SILOFS_DIR_NODE_NBUF_SIZE];
} silofs_packed_aligned64;


struct silofs_dtree_node {
	struct silofs_header    dn_hdr;
	uint64_t                dn_ino;
	int64_t                 dn_parent;
	uint32_t                dn_node_index;
	uint16_t                dn_nde;
	uint16_t                dn_nnb;
	uint64_t                dn_reserved[3];
	struct silofs_vaddr56   dn_child[SILOFS_DIR_NODE_NCHILDS];
	union silofs_dtree_data dn_data;
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
	struct silofs_super_stats       st;
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* repo meta record */
struct silofs_repo_meta {
	uint64_t        rm_magic;
	uint32_t        rm_version;
	uint32_t        rm_flags;
	uint8_t         rm_reserved1[240];
	uint8_t         rm_reserved2[256];
} silofs_packed_aligned64;

#endif /* SILOFS_DEFS_H_ */
