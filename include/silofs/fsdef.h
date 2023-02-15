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
#ifndef SILOFS_FSDEF_H_
#define SILOFS_FSDEF_H_

#include <silofs/ccattr.h>
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

/* max length of encryption password */
#define SILOFS_PASSWORD_MAX             (255)

/* max size for names (not including null terminator) */
#define SILOFS_NAME_MAX                 (255)

/* max size of path (symbolic link value, including null) */
#define SILOFS_PATH_MAX                 (4096)

/* max size of mount-path (including null) */
#define SILOFS_MNTPATH_MAX              (1920)

/* max path-length of repoitory-path (including null) */
#define SILOFS_REPOPATH_MAX             (1536)

/* size of repoitory meta-file descriptor */
#define SILOFS_REPO_METADATA_SIZE       SILOFS_KILO

/* repoitory meta descriptor-file name */
#define SILOFS_REPO_METAFILE_NAME       "meta"

/* repoitory meta sub-dir name */
#define SILOFS_REPO_DOTSDIR_NAME        ".silofs"

/* repoitory objects sub-directory name */
#define SILOFS_REPO_BLOBS_DIRNAME       "blobs"

/* number of sub-dirs within objects directories */
#define SILOFS_REPO_OBJSDIR_NSUBS       (256)


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

/* maximal file-system capacity, in bytes (64T) */
#define SILOFS_CAPACITY_SIZE_MAX        (64L * SILOFS_TERA)

/* maximal size of virtual address space (4P) */
#define SILOFS_VSPACE_SIZE_MAX          (1L << 52)


/* bits-shift of small (1K) block-size */
#define SILOFS_KB_SHIFT                 (10)

/* small ("sector") meta-block size (1K) */
#define SILOFS_KB_SIZE                  (1 << SILOFS_KB_SHIFT)

/* number of 1K blocks in block */
#define SILOFS_NKB_IN_BK \
	(SILOFS_BK_SIZE / SILOFS_KB_SIZE)


/* bits-shift of logical block */
#define SILOFS_BK_SHIFT                 (16)

/* logical block size (64K) */
#define SILOFS_BK_SIZE                  (1L << SILOFS_BK_SHIFT)


/* maximal number of blocks within single blob */
#define SILOFS_NBK_IN_BLOB_MAX          (1024L)

/* maximal size in bytes of single blob (64M) */
#define SILOFS_BLOB_SIZE_MAX \
	(SILOFS_NBK_IN_BLOB_MAX * SILOFS_BK_SIZE)


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
#define SILOFS_SB_SIZE                  (8 * SILOFS_KILO)

/* bits-shift for space-mapping children fan-out */
#define SILOFS_SPMAP_SHIFT              (6)

/* number of children per space-mapping node/leaf */
#define SILOFS_SPMAP_NCHILDS            (1L << SILOFS_SPMAP_SHIFT)

/* number of space-maps per block */
#define SILOFS_NSPMAP_IN_BK             (8)

/* on-disk size of space-node/leaf mapping */
#define SILOFS_SPMAP_SIZE               (8 * SILOFS_KILO)


/* on-disk size-shift of inode */
#define SILOFS_INODE_SHIFT              (10)

/* on-disk size of inode */
#define SILOFS_INODE_SIZE               (1 << SILOFS_INODE_SHIFT)


/* height-limit of file-mapping radix-tree */
#define SILOFS_FILE_HEIGHT_MAX          (4)

/* bits-shift of single file-mapping address-space */
#define SILOFS_FILE_MAP_SHIFT           (10)

/* file's level1 head-mapping block-sizes (1K) */
#define SILOFS_FILE_HEAD1_LEAF_SIZE     (SILOFS_KB_SIZE)

/* number of 1K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD1_NLEAF         (4)

/* file's level2 head-mapping block-sizes (4K) */
#define SILOFS_FILE_HEAD2_LEAF_SIZE     (4 * SILOFS_KB_SIZE)

/* number of 4K leaves in regular-file's head mapping */
#define SILOFS_FILE_HEAD2_NLEAF         (15)

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
	(SILOFS_FILE_HEAD1_NLEAF + SILOFS_FILE_HEAD2_NLEAF + \
	 (SILOFS_IO_SIZE_MAX / SILOFS_BK_SIZE))


/* base size of empty directory */
#define SILOFS_DIR_EMPTY_SIZE           SILOFS_INODE_SIZE

/* on-disk size of directory tree-node */
#define SILOFS_DIR_NODE_SIZE            (8192)

/* number of directory-entries in dir's hash-tree node */
#define SILOFS_DIR_NODE_NENTS           (480)

/* max size of names-buffer in dir's hash-tree node */
#define SILOFS_DIR_NODE_NBUF_SIZE       (7680)

/* bits-shift of children per dir-htree node */
#define SILOFS_DIR_NODE_SHIFT           (6)

/* number of children per dir hash-tree node */
#define SILOFS_DIR_NODE_NCHILDS         (1 << SILOFS_DIR_NODE_SHIFT)

/* maximum depth of directory htree-mapping */
#define SILOFS_DIR_TREE_DEPTH_MAX       (4L)

/* max dir-node index of dir htree nodes (1-based) */
#define SILOFS_DIR_TREE_INDEX_MAX \
	((1L << (SILOFS_DIR_NODE_SHIFT * SILOFS_DIR_TREE_DEPTH_MAX)))

/* non-valid dir tree node-index */
#define SILOFS_DIR_TREE_INDEX_NULL      (0)

/* node-index of dir-tree root */
#define SILOFS_DIR_TREE_INDEX_ROOT      (1)

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


/* cryptographic key size */
#define SILOFS_KEY_SIZE                 (32)

/* initialization vector size (for AES256) */
#define SILOFS_IV_SIZE                  (16)

/* cryptographic hash-128-bits bytes-size */
#define SILOFS_HASH128_LEN              (16)

/* cryptographic hash-256-bits bytes-size */
#define SILOFS_HASH256_LEN              (32)

/* cryptographic hash-512-bits bytes-size */
#define SILOFS_HASH512_LEN              (64)


/* boot-sector flags */
enum silofs_bootf {
	SILOFS_BOOTF_NONE       = 0x00,
	SILOFS_BOOTF_KEY_SHA256 = 0x01,
};

/* format endianness */
enum silofs_endianness {
	SILOFS_ENDIANNESS_LE    = 1,
	SILOFS_ENDIANNESS_BE    = 2,
};

/* file-system logical-elements types */
enum silofs_stype {
	SILOFS_STYPE_NONE       = 0,
	SILOFS_STYPE_SUPER      = 1,
	SILOFS_STYPE_SPNODE     = 2,
	SILOFS_STYPE_SPLEAF     = 3,
	SILOFS_STYPE_RESERVED   = 4,
	SILOFS_STYPE_INODE      = 5,
	SILOFS_STYPE_XANODE     = 6,
	SILOFS_STYPE_SYMVAL     = 7,
	SILOFS_STYPE_DTNODE     = 8,
	SILOFS_STYPE_FTNODE     = 9,
	SILOFS_STYPE_DATA1K     = 10,
	SILOFS_STYPE_DATA4K     = 11,
	SILOFS_STYPE_DATABK     = 12,
	SILOFS_STYPE_ANONBK     = 13,
	SILOFS_STYPE_LAST, /* keep last */
};

/* logical heights of unode mappings */
enum silofs_height {
	SILOFS_HEIGHT_NONE      = 0,
	SILOFS_HEIGHT_VDATA     = 1,
	SILOFS_HEIGHT_SPLEAF    = 2,
	SILOFS_HEIGHT_SPNODE1   = 3,
	SILOFS_HEIGHT_SPNODE2   = 4,
	SILOFS_HEIGHT_SPNODE3   = 5,
	SILOFS_HEIGHT_SPNODE4   = 6,
	SILOFS_HEIGHT_SPNODE5   = 7,
	SILOFS_HEIGHT_SUPER     = 8,
	SILOFS_HEIGHT_LAST, /* keep last */
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


/* encryption cipher settings (libgcrypt values) */
enum silofs_cipher_algo {
	SILOFS_CIPHER_AES256    = 9,
};

enum silofs_cipher_mode {
	SILOFS_CIPHER_MODE_CBC  = 3,
	SILOFS_CIPHER_MODE_GCM  = 9,
	SILOFS_CIPHER_MODE_XTS  = 13,
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
} silofs_packed_aligned16;


struct silofs_key {
	uint8_t key[SILOFS_KEY_SIZE];
} silofs_packed_aligned16;


struct silofs_iv {
	uint8_t iv[SILOFS_IV_SIZE];
} silofs_packed_aligned8;


struct silofs_treeid128 {
	struct silofs_uuid              uuid;
} silofs_packed_aligned8;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_blobid40b {
	struct silofs_treeid128         treeid;
	int64_t                         voff;
	uint32_t                        size;
	uint8_t                         vspace;
	uint8_t                         height;
	uint8_t                         pad[10];
} silofs_packed_aligned8;


struct silofs_oaddr48b {
	struct silofs_blobid40b         blobid;
	uint32_t                        pos;
	uint32_t                        len;
} silofs_packed_aligned8;


struct silofs_uaddr64b {
	struct silofs_oaddr48b          oaddr;
	int64_t                         voff;
	uint8_t                         stype;
	uint8_t                         height;
	uint8_t                         reserved[6];
} silofs_packed_aligned8;


struct silofs_vrange128 {
	int64_t                         beg;
	uint64_t                        len_height;
} silofs_packed_aligned8;


struct silofs_vaddr56 {
	uint8_t                         b[7];
} silofs_packed;


struct silofs_vaddr64 {
	uint64_t                        voff_stype;
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
	struct silofs_blobid40b         bs_sb_cold;
	uint8_t                         bs_reserved4[24];
	uint8_t                         bs_rands[128];
	uint8_t                         bs_reserved5[480];
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


struct silofs_sb_sproots {
	struct silofs_uaddr64b          sb_sproot_reserved;
	struct silofs_uaddr64b          sb_sproot_inode;
	struct silofs_uaddr64b          sb_sproot_xanode;
	struct silofs_uaddr64b          sb_sproot_dtnode;
	struct silofs_uaddr64b          sb_sproot_ftnode;
	struct silofs_uaddr64b          sb_sproot_symval;
	struct silofs_uaddr64b          sb_sproot_data1k;
	struct silofs_uaddr64b          sb_sproot_data4k;
	struct silofs_uaddr64b          sb_sproot_databk;
	uint8_t                         sb_reserved[448];
} silofs_packed_aligned64;


struct silofs_sb_blobids {
	struct silofs_blobid40b         sb_blobid_reserved;
	struct silofs_blobid40b         sb_blobid_inode;
	struct silofs_blobid40b         sb_blobid_xanode;
	struct silofs_blobid40b         sb_blobid_dtnode;
	struct silofs_blobid40b         sb_blobid_ftnode;
	struct silofs_blobid40b         sb_blobid_symval;
	struct silofs_blobid40b         sb_blobid_data1k;
	struct silofs_blobid40b         sb_blobid_data4k;
	struct silofs_blobid40b         sb_blobid_databk;
	uint8_t                         sb_reserved[664];
} silofs_packed_aligned64;


struct silofs_space_gauges {
	uint64_t                        sg_nsuper;
	uint64_t                        sg_nspnode;
	uint64_t                        sg_nspleaf;
	uint64_t                        sg_reserved;
	uint64_t                        sg_ninode;
	uint64_t                        sg_nxanode;
	uint64_t                        sg_ndtnode;
	uint64_t                        sg_nsymval;
	uint64_t                        sg_nftnode;
	uint64_t                        sg_ndata1k;
	uint64_t                        sg_ndata4k;
	uint64_t                        sg_ndatabk;
	uint64_t                        sg_reserved2[20];
} silofs_packed_aligned64;


struct silofs_space_stats {
	uint64_t                        sp_btime;
	uint64_t                        sp_ctime;
	uint64_t                        sp_capacity;
	uint64_t                        sp_vspacesize;
	uint64_t                        sp_generation;
	uint8_t                         sp_reserved[216];
	struct silofs_space_gauges      sp_blobs;
	struct silofs_space_gauges      sp_bks;
	struct silofs_space_gauges      sp_objs;
} silofs_packed_aligned64;


struct silofs_super_block {
	/* 0..512 */
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
	/* 512..1K */
	struct silofs_uaddr64b          sb_self_uaddr;
	struct silofs_uaddr64b          sb_orig_uaddr;
	struct silofs_treeid128         sb_treeid;
	struct silofs_vrange128         sb_vrange;
	uint64_t                        sb_reserved4a;
	uint64_t                        sb_birth_time;
	uint64_t                        sb_clone_time;
	uint64_t                        sb_pack_time;
	uint8_t                         sb_reserved4b[320];
	/* 1K..2K */
	struct silofs_sb_sproots        sb_sproot_uaddr;
	/* 2K..3K */
	struct silofs_sb_blobids        sb_main_blobid;
	/* 3K..4K */
	struct silofs_sb_blobids        sb_cold_blobid;
	/* 4K..6K */
	struct silofs_space_stats       sb_space_stats_curr;
	struct silofs_space_stats       sb_space_stats_base;
	/* 7K..8K */
	uint8_t                         sb_reserved5[2048];
} silofs_packed_aligned64;


struct silofs_spmap_ref {
	struct silofs_uaddr64b          sr_ulink;
	uint8_t                         sr_reserved[56];
} silofs_packed_aligned8;


struct silofs_spmap_node {
	struct silofs_header            sn_hdr;
	uint8_t                         sn_reserved1[8];
	struct silofs_blobid40b         sn_main_blobid;
	struct silofs_blobid40b         sn_cold_blobid;
	struct silofs_vrange128         sn_vrange;
	uint8_t                         sn_reserved2[8];
	struct silofs_uaddr64b          sn_parent;
	struct silofs_uaddr64b          sn_self;
	uint8_t                         sn_reserved3[256];
	struct silofs_spmap_ref         sn_subref[SILOFS_SPMAP_NCHILDS];
} silofs_packed_aligned64;


struct silofs_bk_ref {
	struct silofs_blobid40b         br_uref_blobid;
	struct silofs_blobid40b         br_cold_blobid;
	uint64_t                        br_allocated;
	uint64_t                        br_unwritten;
	uint64_t                        br_refcnt;
	uint8_t                         br_reserved[16];
} silofs_packed_aligned8;


struct silofs_spmap_leaf {
	struct silofs_header            sl_hdr;
	uint8_t                         sl_reserved1[8];
	struct silofs_blobid40b         sl_main_blobid;
	struct silofs_uaddr64b          sl_parent;
	struct silofs_uaddr64b          sl_self;
	struct silofs_vrange128         sl_vrange;
	uint8_t                         sl_reserved2[304];
	struct silofs_bk_ref            sl_subref[SILOFS_SPMAP_NCHILDS];
} silofs_packed_aligned64;


struct silofs_inode_times {
	struct silofs_timespec          btime;
	struct silofs_timespec          atime;
	struct silofs_timespec          ctime;
	struct silofs_timespec          mtime;
} silofs_packed_aligned64;


struct silofs_inode_xattr {
	struct silofs_vaddr64           ix_vaddr[8];
	uint8_t                         ix_reserved[192];
} silofs_packed_aligned64;


struct silofs_inode_dir {
	uint64_t                        d_seed;
	int64_t                         d_root;
	uint64_t                        d_ndents;
	uint32_t                        d_last_index;
	uint32_t                        d_flags;
	uint8_t                         d_hashfn;
	uint8_t                         d_reserved[31];
} silofs_packed_aligned64;


struct silofs_inode_lnk {
	uint8_t                         l_head[SILOFS_SYMLNK_HEAD_MAX];
	struct silofs_vaddr64           l_tail[SILOFS_SYMLNK_NPARTS];
} silofs_packed_aligned64;


struct silofs_inode_file {
	struct silofs_vaddr64           f_head1_leaf[SILOFS_FILE_HEAD1_NLEAF];
	struct silofs_vaddr64           f_head2_leaf[SILOFS_FILE_HEAD2_NLEAF];
	struct silofs_vaddr64           f_tree_root;
	uint8_t                         f_reserved[352];
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
	uint64_t                        i_generation;
	uint8_t                         i_reserved1[16];
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
	struct silofs_header            xa_hdr;
	uint64_t                        xa_ino;
	uint16_t                        xa_nents;
	uint8_t                         xa_reserved[38];
	struct silofs_xattr_entry       xe[SILOFS_XATTR_NENTS];
} silofs_packed_aligned64;


struct silofs_dir_entry {
	uint64_t                        de_ino;
	uint32_t                        de_name_hash;
	uint16_t                        de_name_len_dt;
	uint16_t                        de_name_pos;
} silofs_packed_aligned16;


union silofs_dtree_data {
	struct silofs_dir_entry         de[SILOFS_DIR_NODE_NENTS];
	uint8_t                         nb[SILOFS_DIR_NODE_NBUF_SIZE];
} silofs_packed_aligned64;


struct silofs_dtree_node {
	struct silofs_header            dn_hdr;
	uint64_t                        dn_ino;
	int64_t                         dn_parent;
	uint32_t                        dn_node_index;
	uint16_t                        dn_nde;
	uint16_t                        dn_nnb;
	uint64_t                        dn_reserved[3];
	struct silofs_vaddr56           dn_child[SILOFS_DIR_NODE_NCHILDS];
	union silofs_dtree_data         dn_data;
} silofs_packed_aligned64;


struct silofs_symlnk_value {
	struct silofs_header            sy_hdr;
	uint64_t                        sy_parent;
	uint16_t                        sy_length;
	uint8_t                         sy_reserved1[38];
	uint8_t                         sy_value[SILOFS_SYMLNK_PART_MAX];
} silofs_packed_aligned64;


struct silofs_ftree_node {
	struct silofs_header            fn_hdr;
	uint64_t                        fn_refcnt;
	uint64_t                        fn_ino;
	int64_t                         fn_beg;
	int64_t                         fn_end;
	uint8_t                         fn_height;
	uint8_t                         fn_child_stype;
	uint8_t                         fn_reserved1[14];
	uint8_t                         fn_zeros[960];
	struct silofs_vaddr56           fn_child[SILOFS_FILE_NODE_NCHILDS];
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
	struct silofs_inode             in;
	struct silofs_dtree_node        dtn;
	struct silofs_ftree_node        ftn;
	struct silofs_xattr_node        xan;
	struct silofs_symlnk_value      sym;
	struct silofs_data_block1       db1;
	struct silofs_data_block4       db4;
	struct silofs_data_block        db;
	struct silofs_block             bk;
} silofs_packed_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* repo meta record */
struct silofs_repo_meta {
	uint64_t                        rm_magic;
	uint32_t                        rm_version;
	uint32_t                        rm_mode;
	uint8_t                         rm_reserved1[240];
	uint8_t                         rm_reserved2[256];
	uint8_t                         rm_reserved3[512];
} silofs_packed_aligned64;

#endif /* SILOFS_FSDEF_H_ */
