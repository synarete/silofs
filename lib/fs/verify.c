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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fsdef.h>
#include <silofs/types.h>
#include <silofs/ioctls.h>
#include <silofs/boot.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#ifndef LINK_MAX
#define LINK_MAX 127
#endif


#define BITS_SIZE(a)    (CHAR_BIT * sizeof(a))

#define MEMBER_SIZE(type, member) \
	sizeof(((const type *)NULL)->member)

#define MEMBER_NELEMS(type, member) \
	SILOFS_ARRAY_SIZE(((const type *)NULL)->member)

#define MEMBER_NBITS(type, member) \
	BITS_SIZE(((const type *)NULL)->member)

#define SWORD(a) ((long)(a))

#define REQUIRE_EQ(a, b) \
	SILOFS_STATICASSERT_EQ(SWORD(a), SWORD(b))

#define REQUIRE_LE(a, b) \
	SILOFS_STATICASSERT_LE(SWORD(a), SWORD(b))

#define REQUIRE_LT(a, b) \
	SILOFS_STATICASSERT_LT(SWORD(a), SWORD(b))

#define REQUIRE_GT(a, b) \
	SILOFS_STATICASSERT_GT(SWORD(a), SWORD(b))

#define REQUIRE_GE(a, b) \
	SILOFS_STATICASSERT_GE(SWORD(a), SWORD(b))

#define REQUIRE_LBK_SIZE(a) \
	REQUIRE_EQ(a, SILOFS_LBK_SIZE)

#define REQUIRE_SIZEOF(type, size) \
	REQUIRE_EQ(sizeof(type), size)

#define REQUIRE_SIZEOF_LE(type, size) \
	REQUIRE_LE(sizeof(type), size)

#define REQUIRE_SIZEOF_KB(type) \
	REQUIRE_SIZEOF(type, SILOFS_KB_SIZE)

#define REQUIRE_SIZEOF_NK(type, nk) \
	REQUIRE_SIZEOF(type, (nk) * SILOFS_KILO)

#define REQUIRE_SIZEOF_1K(type) \
	REQUIRE_SIZEOF_NK(type, 1)

#define REQUIRE_SIZEOF_4K(type) \
	REQUIRE_SIZEOF_NK(type, 4)

#define REQUIRE_SIZEOF_8K(type) \
	REQUIRE_SIZEOF_NK(type, 8)

#define REQUIRE_SIZEOF_16K(type) \
	REQUIRE_SIZEOF_NK(type, 16)

#define REQUIRE_SIZEOF_64K(type) \
	REQUIRE_SIZEOF_NK(type, 64)

#define REQUIRE_SIZEOF_LBK(type) \
	REQUIRE_LBK_SIZE(sizeof(type))

#define REQUIRE_MEMBER_SIZE(type, f, size) \
	REQUIRE_EQ(MEMBER_SIZE(type, f), size)

#define REQUIRE_NELEMS(type, f, nelems) \
	REQUIRE_EQ(MEMBER_NELEMS(type, f), nelems)

#define REQUIRE_NBITS(type, f, nbits) \
	REQUIRE_EQ(MEMBER_NBITS(type, f), nbits)

#define ISALIGNED32(off) \
	(((off) % 4) == 0)

#define ISALIGNED64(off) \
	(((off) % 8) == 0)

#define ISOFFSET(type, member, off) \
	(offsetof(type, member) == (off))

#define REQUIRE_XOFFSET(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off))

#define REQUIRE_OFFSET(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED32(off))

#define REQUIRE_OFFSET64(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED64(off))

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void verify_fundamental_types_size(void)
{
	REQUIRE_SIZEOF(uint8_t, 1);
	REQUIRE_SIZEOF(uint16_t, 2);
	REQUIRE_SIZEOF(uint32_t, 4);
	REQUIRE_SIZEOF(uint64_t, 8);
	REQUIRE_SIZEOF(int8_t, 1);
	REQUIRE_SIZEOF(int16_t, 2);
	REQUIRE_SIZEOF(int32_t, 4);
	REQUIRE_SIZEOF(int64_t, 8);
	REQUIRE_SIZEOF(size_t, 8);
	REQUIRE_SIZEOF(loff_t, 8);
	REQUIRE_SIZEOF(ino_t, 8);
}

static void verify_persistent_types_nk(void)
{
	REQUIRE_SIZEOF_8K(struct silofs_super_block);
	REQUIRE_SIZEOF_16K(struct silofs_spmap_node);
	REQUIRE_SIZEOF_16K(struct silofs_spmap_leaf);
	REQUIRE_SIZEOF_1K(struct silofs_inode);
	REQUIRE_SIZEOF_4K(struct silofs_xattr_node);
	REQUIRE_SIZEOF_8K(struct silofs_dtree_node);
	REQUIRE_SIZEOF_8K(struct silofs_ftree_node);
	REQUIRE_SIZEOF_4K(struct silofs_symlnk_value);
	REQUIRE_SIZEOF_1K(struct silofs_data_block1);
	REQUIRE_SIZEOF_4K(struct silofs_data_block4);
	REQUIRE_SIZEOF_64K(struct silofs_data_block64);
}

static void verify_persistent_types_size(void)
{
	REQUIRE_SIZEOF(struct silofs_name, SILOFS_NAME_MAX + 1);
	REQUIRE_SIZEOF(struct silofs_header, SILOFS_HEADER_SIZE);
	REQUIRE_SIZEOF(struct silofs_timespec, 16);
	REQUIRE_SIZEOF(struct silofs_hash128, 16);
	REQUIRE_SIZEOF(struct silofs_hash256, 32);
	REQUIRE_SIZEOF(struct silofs_hash512, 64);
	REQUIRE_SIZEOF(struct silofs_uuid, SILOFS_UUID_SIZE);
	REQUIRE_SIZEOF(struct silofs_kdf_desc, 16);
	REQUIRE_SIZEOF(struct silofs_kdf_pair, 32);
	REQUIRE_SIZEOF(struct silofs_iv, SILOFS_IV_SIZE);
	REQUIRE_SIZEOF(struct silofs_key, SILOFS_KEY_SIZE);
	REQUIRE_SIZEOF(struct silofs_treeid128, 16);
	REQUIRE_SIZEOF(struct silofs_vaddr56, 7);
	REQUIRE_SIZEOF(struct silofs_vaddr64, 8);
	REQUIRE_SIZEOF(struct silofs_vrange128, 16);
	REQUIRE_SIZEOF(struct silofs_blobid40b, 40);
	REQUIRE_SIZEOF(struct silofs_oaddr48b, 48);
	REQUIRE_SIZEOF(struct silofs_uaddr64b, 64);
	REQUIRE_SIZEOF(struct silofs_bootsec1k, SILOFS_BOOTSEC_SIZE);
	REQUIRE_SIZEOF(struct silofs_sb_sproots, 1024);
	REQUIRE_SIZEOF(struct silofs_sb_blobids, 1024);
	REQUIRE_SIZEOF(struct silofs_super_block, SILOFS_SB_SIZE);
	REQUIRE_SIZEOF(struct silofs_space_gauges, 256);
	REQUIRE_SIZEOF(struct silofs_space_stats, 1024);
	REQUIRE_SIZEOF(struct silofs_spmap_ref, 120);
	REQUIRE_SIZEOF(struct silofs_spmap_node, SILOFS_SPMAP_SIZE);
	REQUIRE_SIZEOF(struct silofs_bk_ref, 120);
	REQUIRE_SIZEOF(struct silofs_spmap_leaf, SILOFS_SPMAP_SIZE);
	REQUIRE_SIZEOF_KB(struct silofs_inode);
	REQUIRE_SIZEOF_LBK(struct silofs_lblock);
	REQUIRE_SIZEOF(struct silofs_dir_entry, 16);
	REQUIRE_SIZEOF(struct silofs_xattr_entry, 8);
	REQUIRE_SIZEOF(struct silofs_inode_dir, 64);
	REQUIRE_SIZEOF(struct silofs_inode_file, 512);
	REQUIRE_SIZEOF(struct silofs_inode_lnk, 512);
	REQUIRE_SIZEOF(struct silofs_inode_times, 64);
	REQUIRE_SIZEOF(struct silofs_inode_xattr, 256);
	REQUIRE_SIZEOF(union silofs_inode_specific, 512);
	REQUIRE_SIZEOF(struct silofs_inode, SILOFS_INODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_symlnk_value, SILOFS_SYMLNK_VAL_SIZE);
	REQUIRE_SIZEOF(struct silofs_xattr_node, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_ftree_node, SILOFS_FILE_RTNODE_SIZE);
	REQUIRE_SIZEOF(union silofs_dtree_data, SILOFS_DIR_NODE_NBUF_SIZE);
	REQUIRE_SIZEOF(struct silofs_dtree_node, SILOFS_DIR_NODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_block4, SILOFS_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_block64, SILOFS_FILE_TREE_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_repo_meta, SILOFS_REPO_METADATA_SIZE);
}

static void verify_persistent_types_members(void)
{
	REQUIRE_NBITS(struct silofs_header, h_stype, 8);
	REQUIRE_NBITS(struct silofs_bk_ref, br_allocated, SILOFS_NKB_IN_LBK);
	REQUIRE_NBITS(struct silofs_bk_ref, br_unwritten, SILOFS_NKB_IN_LBK);
	REQUIRE_MEMBER_SIZE(struct silofs_bk_ref, br_dbkref, 8);
	REQUIRE_NELEMS(struct silofs_ftree_node,
	               fn_child, SILOFS_FILE_NODE_NCHILDS);
	REQUIRE_NELEMS(union silofs_dtree_data, de, SILOFS_DIR_NODE_NENTS);
	REQUIRE_NELEMS(struct silofs_dtree_node,
	               dn_child, SILOFS_DIR_NODE_NCHILDS);
}

static void verify_persistent_types_alignment1(void)
{
	REQUIRE_OFFSET64(struct silofs_spmap_ref, sr_ulink, 0);
	REQUIRE_OFFSET64(struct silofs_bk_ref, br_uref, 0);
	REQUIRE_OFFSET64(struct silofs_bk_ref, br_allocated, 48);
	REQUIRE_OFFSET64(struct silofs_bk_ref, br_unwritten, 56);
	REQUIRE_OFFSET64(struct silofs_bk_ref, br_dbkref, 64);
}

static void verify_persistent_types_alignment2(void)
{
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_magic, 0);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_version, 8);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_uuid, 16);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_flags, 32);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_kdf_pair, 64);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_chiper_algo, 96);
	REQUIRE_OFFSET(struct silofs_bootsec1k, bs_chiper_mode, 100);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_key_hash, 128);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_sb_uaddr, 256);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_rands, 384);
	REQUIRE_OFFSET64(struct silofs_bootsec1k, bs_reserved5, 512);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_magic, 16);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_version, 24);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_sw_version, 64);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_uuid, 128);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_name, 256);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_self_uaddr, 512);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_orig_uaddr, 576);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_treeid, 640);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_vrange, 656);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_birth_time, 680);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_clone_time, 688);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_sproot_uaddr, 1024);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_main_blobid, 2048);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_space_stats_curr, 4096);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_space_stats_base, 5120);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_btime, 0);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_ctime, 8);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_capacity, 16);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_vspacesize, 24);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_generation, 32);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_blobs, 256);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_bks, 512);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_objs, 768);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_main_blobid, 24);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_vrange, 64);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_parent, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_self, 192);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_subref, 1024);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_main_blobid, 24);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_parent, 64);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_self, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_vrange, 192);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_subref, 1024);
}

static void verify_persistent_types_alignment3(void)
{
	REQUIRE_OFFSET(struct silofs_inode, i_hdr, 0);
	REQUIRE_OFFSET(struct silofs_inode, i_ino, 16);
	REQUIRE_OFFSET(struct silofs_inode, i_parent, 24);
	REQUIRE_OFFSET(struct silofs_inode, i_uid, 32);
	REQUIRE_OFFSET(struct silofs_inode, i_gid, 36);
	REQUIRE_OFFSET(struct silofs_inode, i_mode, 40);
	REQUIRE_OFFSET(struct silofs_inode, i_flags, 44);
	REQUIRE_OFFSET(struct silofs_inode, i_size, 48);
	REQUIRE_OFFSET(struct silofs_inode, i_span, 56);
	REQUIRE_OFFSET(struct silofs_inode, i_blocks, 64);
	REQUIRE_OFFSET(struct silofs_inode, i_nlink, 72);
	REQUIRE_OFFSET(struct silofs_inode, i_attributes, 80);
	REQUIRE_OFFSET64(struct silofs_inode, i_tm, 128);
	REQUIRE_OFFSET64(struct silofs_inode, i_xa, 256);
	REQUIRE_OFFSET64(struct silofs_inode, i_sp, 512);
	REQUIRE_OFFSET(struct silofs_dir_entry, de_ino, 0);
	REQUIRE_OFFSET(struct silofs_dir_entry, de_name_hash, 8);
	REQUIRE_XOFFSET(struct silofs_dir_entry, de_name_len_dt, 12);
	REQUIRE_XOFFSET(struct silofs_dir_entry, de_name_pos, 14);
	REQUIRE_OFFSET(struct silofs_dtree_node, dn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_child, 64);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_data, 512);
	REQUIRE_OFFSET(struct silofs_ftree_node, fn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_zeros, 64);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_child, 1024);
	REQUIRE_OFFSET(struct silofs_inode_xattr, ix_vaddr, 0);
	REQUIRE_OFFSET(struct silofs_xattr_node, xa_hdr, 0);
	REQUIRE_OFFSET(struct silofs_xattr_node, xe, 64);
	REQUIRE_OFFSET64(struct silofs_symlnk_value, sy_value, 64);
}

static void verify_ioctl_types_size(void)
{
	REQUIRE_SIZEOF(struct silofs_ioc_query, 2048);
	REQUIRE_SIZEOF(struct silofs_ioc_clone, 32);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_query, SILOFS_IOC_SIZE_MAX);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_clone, SILOFS_IOC_SIZE_MAX);
}

static void verify_journal_types(void)
{
	REQUIRE_SIZEOF(struct silofs_journal_ent, 256);
}

static void verify_defs_consistency(void)
{
	REQUIRE_EQ(CHAR_BIT, 8);
	REQUIRE_EQ(SILOFS_NSPMAP_IN_LBK * SILOFS_SPMAP_SIZE, SILOFS_LBK_SIZE);
	REQUIRE_LT(SILOFS_DIR_TREE_DEPTH_MAX, SILOFS_HASH256_LEN);
	REQUIRE_LT(SILOFS_DIR_TREE_INDEX_MAX, INT32_MAX);
	REQUIRE_GT(SILOFS_DIR_ENTRIES_MAX, SILOFS_LINK_MAX);
	REQUIRE_LT(SILOFS_XATTR_VALUE_MAX, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_EQ(SILOFS_FILE_SIZE_MAX, 64 * SILOFS_TERA - 1);
	REQUIRE_EQ(SILOFS_BLOB_SIZE_MAX, 8 * SILOFS_MEGA);
	REQUIRE_EQ(SILOFS_LBK_SIZE * SILOFS_SPMAP_NCHILDS,
	           SILOFS_BLOB_SIZE_MAX);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MIN, 2 * SILOFS_GIGA);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MAX, 64 * SILOFS_TERA);
	REQUIRE_LT(SILOFS_CAPACITY_SIZE_MAX, SILOFS_VSPACE_SIZE_MAX);
	REQUIRE_EQ(SILOFS_VSPACE_SIZE_MAX, 256 * SILOFS_PETA);

	REQUIRE_EQ(SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF,
	           SILOFS_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_EQ((SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF) +
	           (SILOFS_FILE_HEAD2_LEAF_SIZE * SILOFS_FILE_HEAD2_NLEAF),
	           SILOFS_FILE_TREE_LEAF_SIZE);
}

static void verify_external_constants(void)
{
	REQUIRE_EQ(SILOFS_NAME_MAX, NAME_MAX);
	REQUIRE_EQ(SILOFS_PATH_MAX, PATH_MAX);
	REQUIRE_GE(SILOFS_LINK_MAX, LINK_MAX);
	REQUIRE_GE(SILOFS_NAME_MAX, XATTR_NAME_MAX);
	REQUIRE_GE(SILOFS_XATTR_VALUE_MAX, XATTR_SIZE_MAX / 32);
	REQUIRE_EQ(SILOFS_CIPHER_AES256, GCRY_CIPHER_AES256);
	REQUIRE_EQ(SILOFS_CIPHER_MODE_CBC, GCRY_CIPHER_MODE_CBC);
	REQUIRE_EQ(SILOFS_CIPHER_MODE_GCM, GCRY_CIPHER_MODE_GCM);
	REQUIRE_EQ(SILOFS_CIPHER_MODE_XTS, GCRY_CIPHER_MODE_XTS);
	REQUIRE_EQ(SILOFS_MD_SHA256, GCRY_MD_SHA256);
	REQUIRE_EQ(SILOFS_MD_SHA3_256, GCRY_MD_SHA3_256);
	REQUIRE_EQ(SILOFS_MD_SHA3_512, GCRY_MD_SHA3_512);
	REQUIRE_EQ(SILOFS_KDF_PBKDF2, GCRY_KDF_PBKDF2);
	REQUIRE_EQ(SILOFS_KDF_SCRYPT, GCRY_KDF_SCRYPT);
}

void silofs_lib_verify_defs(void)
{
	verify_fundamental_types_size();
	verify_persistent_types_nk();
	verify_persistent_types_size();
	verify_persistent_types_members();
	verify_persistent_types_alignment1();
	verify_persistent_types_alignment2();
	verify_persistent_types_alignment3();
	verify_ioctl_types_size();
	verify_journal_types();
	verify_defs_consistency();
	verify_external_constants();
}

