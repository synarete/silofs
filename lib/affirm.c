/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include <linux/limits.h>
#include <sys/types.h>
#include <limits.h>
#include <endian.h>
#include <gcrypt.h>
#include <silofs/ondisk.h>
#include <silofs/ioctls.h>
#include "infra.h"

#ifndef LINK_MAX
#define LINK_MAX 127
#endif

#define BITS_SIZE(a) (CHAR_BIT * sizeof(a))

#define MEMBER_SIZE(type, member) sizeof(((const type *)nullptr)->member)

#define MEMBER_NELEMS(type, member) \
	SILOFS_ARRAY_SIZE(((const type *)nullptr)->member)

#define MEMBER_NBITS(type, member) BITS_SIZE(((const type *)nullptr)->member)

#define SWORD(a) ((long)(a))

#define REQUIRE_EQ(a, b) SILOFS_STATICASSERT_EQ(SWORD(a), SWORD(b))

#define REQUIRE_LE(a, b) SILOFS_STATICASSERT_LE(SWORD(a), SWORD(b))

#define REQUIRE_LT(a, b) SILOFS_STATICASSERT_LT(SWORD(a), SWORD(b))

#define REQUIRE_GT(a, b) SILOFS_STATICASSERT_GT(SWORD(a), SWORD(b))

#define REQUIRE_GE(a, b) SILOFS_STATICASSERT_GE(SWORD(a), SWORD(b))

#define REQUIRE_SIZEOF(type, size) REQUIRE_EQ(sizeof(type), size)

#define REQUIRE_SIZEOF_LE(type, size) REQUIRE_LE(sizeof(type), size)

#define REQUIRE_SIZEOF_NK(type, nk) REQUIRE_SIZEOF(type, (nk) * SILOFS_KILO)

#define REQUIRE_SIZEOF_1K(type) REQUIRE_SIZEOF_NK(type, 1)

#define REQUIRE_SIZEOF_4K(type) REQUIRE_SIZEOF_NK(type, 4)

#define REQUIRE_SIZEOF_8K(type) REQUIRE_SIZEOF_NK(type, 8)

#define REQUIRE_SIZEOF_16K(type) REQUIRE_SIZEOF_NK(type, 16)

#define REQUIRE_SIZEOF_64K(type) REQUIRE_SIZEOF_NK(type, 64)

#define REQUIRE_MEMBER_SIZE(type, f, size) \
	REQUIRE_EQ(MEMBER_SIZE(type, f), size)

#define REQUIRE_NELEMS(type, f, nelems) \
	REQUIRE_EQ(MEMBER_NELEMS(type, f), nelems)

#define REQUIRE_NBITS(type, f, nbits) REQUIRE_EQ(MEMBER_NBITS(type, f), nbits)

#define ISALIGNED32(off) (((off) % 4) == 0)

#define ISALIGNED64(off) (((off) % 8) == 0)

#define ISOFFSET(type, member, off) (offsetof(type, member) == (off))

#define REQUIRE_OFFSETXX(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off))

#define REQUIRE_OFFSET32(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED32(off))

#define REQUIRE_OFFSET64(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED64(off))

void silofs_affirm_ondisk_format(void);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void affirm_fundamental_types(void)
{
	REQUIRE_EQ(CHAR_BIT, 8);
	REQUIRE_SIZEOF(uint8_t, 1);
	REQUIRE_SIZEOF(uint16_t, 2);
	REQUIRE_SIZEOF(uint32_t, 4);
	REQUIRE_SIZEOF(uint64_t, 8);
	REQUIRE_SIZEOF(int8_t, 1);
	REQUIRE_SIZEOF(int16_t, 2);
	REQUIRE_SIZEOF(int32_t, 4);
	REQUIRE_SIZEOF(int64_t, 8);
	REQUIRE_SIZEOF(size_t, 8);
	REQUIRE_SIZEOF(off_t, 8);
	REQUIRE_SIZEOF(ino_t, 8);
}

static void affirm_external_constants(void)
{
	REQUIRE_GE(SILOFS_NAME_MAX, NAME_MAX);
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

static void affirm_ondisk_defs(void)
{
	REQUIRE_EQ(SILOFS_NSPMAP_IN_LBK * SILOFS_SPMAP_SIZE, SILOFS_LBK_SIZE);
	REQUIRE_LT(SILOFS_DIR_TREE_DEPTH_MAX, SILOFS_HASH256_LEN);
	REQUIRE_LT(SILOFS_DIR_TREE_INDEX_MAX, INT32_MAX);
	REQUIRE_GT(SILOFS_DIR_ENTRIES_MAX, SILOFS_LINK_MAX);
	REQUIRE_LT(SILOFS_XATTR_VALUE_MAX, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_EQ(SILOFS_FILE_SIZE_MAX, 64 * SILOFS_PETA - 1);
	REQUIRE_EQ(SILOFS_LSEG_SIZE_MAX, 4 * SILOFS_MEGA);
	REQUIRE_EQ(SILOFS_LSEG_SIZE_MAX,
	           SILOFS_LBK_SIZE * SILOFS_SPMAP_NCHILDS);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MIN, 2 * SILOFS_GIGA);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MAX, 64 * SILOFS_TERA);
	REQUIRE_LT(SILOFS_CAPACITY_SIZE_MAX, SILOFS_VSPACE_SIZE_MAX / 2);
	REQUIRE_EQ(SILOFS_VSPACE_SIZE_MAX, 256 * SILOFS_PETA);
	REQUIRE_EQ(SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF,
	           SILOFS_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_EQ((SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF) +
	                   (SILOFS_FILE_HEAD2_LEAF_SIZE *
	                    SILOFS_FILE_HEAD2_NLEAF),
	           SILOFS_FILE_TREE_LEAF_SIZE);
}

static void affirm_ondisk_base_types(void)
{
	REQUIRE_SIZEOF(struct silofs_name, SILOFS_NAME_MAX + 1);
	REQUIRE_SIZEOF(struct silofs_tm64b, 64);
	REQUIRE_SIZEOF(struct silofs_timespec, 16);
	REQUIRE_SIZEOF(struct silofs_hash128, 16);
	REQUIRE_SIZEOF(struct silofs_hash256, 32);
	REQUIRE_SIZEOF(struct silofs_hash512, 64);
	REQUIRE_SIZEOF(struct silofs_iv, SILOFS_IV_SIZE);
	REQUIRE_SIZEOF(struct silofs_key, SILOFS_KEY_SIZE);
	REQUIRE_SIZEOF(struct silofs_uuid, SILOFS_UUID_SIZE);
	REQUIRE_SIZEOF(struct silofs_lblock, SILOFS_LBK_SIZE);
}

static void affirm_ondisk_addrs(void)
{
	REQUIRE_SIZEOF(struct silofs_svolid, 16);
	REQUIRE_SIZEOF(struct silofs_blobid, 56);
	REQUIRE_SIZEOF(struct silofs_vaddr56, 7);
	REQUIRE_SIZEOF(struct silofs_vaddr64, 8);
	REQUIRE_SIZEOF(struct silofs_lrange128, 16);
	REQUIRE_SIZEOF(struct silofs_lsid64b, 64);
	REQUIRE_SIZEOF(struct silofs_laddr96b, 96);
	REQUIRE_SIZEOF(struct silofs_uaddr128b, 128);
	REQUIRE_SIZEOF(struct silofs_paddr64b, 64);
	REQUIRE_SIZEOF(struct silofs_bcursor128b, 128);
}

static void affirm_ondisk_headers(void)
{
	REQUIRE_OFFSET32(struct silofs_header, h_magic, 0);
	REQUIRE_OFFSET32(struct silofs_header, h_size, 4);
	REQUIRE_OFFSET32(struct silofs_header, h_mtype, 8);
	REQUIRE_OFFSETXX(struct silofs_header, h_flags, 10);
	REQUIRE_OFFSET32(struct silofs_header, h_csum, 28);
	REQUIRE_SIZEOF(struct silofs_header, SILOFS_HEADER_SIZE);
	REQUIRE_SIZEOF(struct silofs_repo_meta, SILOFS_REPO_METAFILE_SIZE);
}

static void affirm_ondisk_spmaps(void)
{
	REQUIRE_OFFSET64(struct silofs_spmap_ref, sr_uaddr, 0);
	REQUIRE_SIZEOF(struct silofs_spmap_ref, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_main_lsid, 32);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_lrange, 96);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_parent, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_self, 256);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_subrefs, 2048);
	REQUIRE_SIZEOF(struct silofs_spmap_node, SILOFS_SPMAP_SIZE);
	REQUIRE_OFFSET64(struct silofs_lbk_ref, lbr_subref, 0);
	REQUIRE_SIZEOF(struct silofs_lbk_ref, 160);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_lrange, 32);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_refmtype, 48);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_main_lsid, 64);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_parent, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_self, 256);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_lbrs, 1024);
	REQUIRE_SIZEOF(struct silofs_spmap_leaf, SILOFS_SPMAP_SIZE);
	REQUIRE_SIZEOF_16K(struct silofs_spmap_node);
	REQUIRE_SIZEOF_16K(struct silofs_spmap_leaf);
}

static void affirm_ondisk_gbr(void)
{
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_magic, 0);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_version, 8);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_uuid, 16);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_kind, 32);
	REQUIRE_OFFSET32(struct silofs_gbr1k, gbr_flags, 36);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_cipher_algo, 40);
	REQUIRE_OFFSET32(struct silofs_gbr1k, gbr_cipher_mode, 44);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_main_iv, 48);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_main_key, 64);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_sb_addr, 128);
	REQUIRE_OFFSET64(struct silofs_gbr1k, gbr_root, 256);
	REQUIRE_SIZEOF(struct silofs_gbr1k, SILOFS_MBR_SIZE);
}

static void affirm_ondisk_uber(void)
{
	REQUIRE_SIZEOF(struct silofs_bcursor128b, 128);
	REQUIRE_OFFSET64(struct silofs_uber_block, ub_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_uber_block, ub_btime, 32);
	REQUIRE_OFFSET64(struct silofs_uber_block, ub_ctime, 48);
	REQUIRE_OFFSET64(struct silofs_uber_block, ub_generation, 64);
	REQUIRE_OFFSET64(struct silofs_uber_block, ub_bcursor, 128);
	REQUIRE_OFFSET64(struct silofs_uber_block, ub_key, 4096);
	REQUIRE_GT(MEMBER_NELEMS(struct silofs_uber_block, ub_bcursor),
	           SILOFS_MTYPE_LAST);
	REQUIRE_SIZEOF_8K(struct silofs_uber_block);
}

static void affirm_ondisk_super(void)
{
	REQUIRE_OFFSET64(struct silofs_super_block, sb_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_magic, 32);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_version, 40);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_sw_version, 64);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_btime_curr, 512);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_btime_prev, 576);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_btime_base, 640);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_lv_curr, 704);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_lv_prev, 760);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_lrange, 816);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_sproots, 1024);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_main_lsid, 3072);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_space_stats_curr, 4096);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_space_stats_prev, 5120);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_name, 7680);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_btime, 0);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_ctime, 8);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_capacity, 16);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_vspacesize, 24);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_generation, 32);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_lsegs, 256);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_bks, 512);
	REQUIRE_OFFSET64(struct silofs_space_stats1k, sp_objs, 768);
	REQUIRE_SIZEOF(struct silofs_sb_sproots, 2048);
	REQUIRE_SIZEOF(struct silofs_sb_lsids, 1024);
	REQUIRE_SIZEOF(struct silofs_space_gauges256, 256);
	REQUIRE_SIZEOF(struct silofs_space_stats1k, 1024);
	REQUIRE_SIZEOF(struct silofs_super_block, SILOFS_SB_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_super_block);
}

static void affirm_ondisk_lsmap(void)
{
	REQUIRE_NBITS(struct silofs_lbk_meta, lbm_allocated,
	              SILOFS_NKB_IN_LBK);
	REQUIRE_NBITS(struct silofs_lbk_meta, lbm_unwritten,
	              SILOFS_NKB_IN_LBK);
	REQUIRE_MEMBER_SIZE(struct silofs_lbk_meta, lbm_refcnt, 8);
	REQUIRE_SIZEOF(struct silofs_lbk_state, 8);
	REQUIRE_OFFSET64(struct silofs_lbk_meta, lbm_allocated, 0);
	REQUIRE_OFFSET64(struct silofs_lbk_meta, lbm_unwritten, 8);
	REQUIRE_OFFSET64(struct silofs_lbk_meta, lbm_refcnt, 16);
	REQUIRE_SIZEOF(struct silofs_lbk_meta, 56);
	REQUIRE_OFFSET64(struct silofs_lsmap, lsm_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_lsmap, lsm_lrange, 32);
	REQUIRE_OFFSET64(struct silofs_lsmap, lsm_refmtype, 48);
	REQUIRE_OFFSET64(struct silofs_lsmap, lsm_lbms, 64);
	REQUIRE_OFFSET64(struct silofs_lsmap, lsm_keys, 4096);
	REQUIRE_SIZEOF_64K(struct silofs_lsmap);
}

static void affirm_ondisk_inode(void)
{
	REQUIRE_OFFSET64(struct silofs_inode, i_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_inode, i_ino, 32);
	REQUIRE_OFFSET64(struct silofs_inode, i_parent, 40);
	REQUIRE_OFFSET64(struct silofs_inode, i_uid, 48);
	REQUIRE_OFFSET32(struct silofs_inode, i_gid, 52);
	REQUIRE_OFFSET64(struct silofs_inode, i_mode, 56);
	REQUIRE_OFFSET32(struct silofs_inode, i_flags, 60);
	REQUIRE_OFFSET64(struct silofs_inode, i_size, 64);
	REQUIRE_OFFSET32(struct silofs_inode, i_span, 72);
	REQUIRE_OFFSET64(struct silofs_inode, i_blocks, 80);
	REQUIRE_OFFSET64(struct silofs_inode, i_nlink, 88);
	REQUIRE_OFFSET64(struct silofs_inode, i_attributes, 96);
	REQUIRE_OFFSET64(struct silofs_inode, i_tm, 128);
	REQUIRE_OFFSET64(struct silofs_inode, i_xa, 256);
	REQUIRE_OFFSET64(struct silofs_inode, i_ta, 512);
	REQUIRE_OFFSET64(struct silofs_inode_dir, d_root, 0);
	REQUIRE_OFFSET64(struct silofs_inode_dir, d_seed, 8);
	REQUIRE_OFFSET64(struct silofs_inode_dir, d_ndents, 16);
	REQUIRE_OFFSET64(struct silofs_inode_xattr, ix_vaddr, 0);
	REQUIRE_SIZEOF(struct silofs_inode_dir, 64);
	REQUIRE_SIZEOF(struct silofs_inode_xattr, 256);
	REQUIRE_SIZEOF(struct silofs_inode_file, 512);
	REQUIRE_SIZEOF(struct silofs_inode_lnk, 512);
	REQUIRE_SIZEOF(struct silofs_inode_times, 64);
	REQUIRE_SIZEOF(union silofs_inode_tail, 512);
	REQUIRE_SIZEOF(struct silofs_inode, SILOFS_INODE_SIZE);
	REQUIRE_SIZEOF_1K(struct silofs_inode);
}

static void affirm_ondisk_dir(void)
{
	REQUIRE_OFFSET64(struct silofs_dir_entry, de_ino, 0);
	REQUIRE_OFFSET64(struct silofs_dir_entry, de_name_hash_dt, 8);
	REQUIRE_OFFSET32(struct silofs_dir_entry, de_name_len, 12);
	REQUIRE_OFFSETXX(struct silofs_dir_entry, de_name_pos, 14);
	REQUIRE_SIZEOF(struct silofs_dir_entry, 16);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_data, 128);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_child, 7744);
	REQUIRE_NELEMS(union silofs_dtree_data, de, SILOFS_DIR_NODE_NENTS);
	REQUIRE_NELEMS(struct silofs_dtree_node, dn_child,
	               SILOFS_DIR_NODE_NCHILDS);
	REQUIRE_SIZEOF(union silofs_dtree_data, SILOFS_DIR_NODE_NBSIZE);
	REQUIRE_SIZEOF(struct silofs_dtree_node, SILOFS_DIR_NODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_dtree_node);
}

static void affirm_ondisk_file(void)
{
	REQUIRE_NELEMS(struct silofs_ftree_node, fn_child,
	               SILOFS_FILE_NODE_NCHILDS);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_refcnt, 32);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_ino, 40);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_beg, 48);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_end, 56);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_nactive_childs, 64);
	REQUIRE_OFFSET32(struct silofs_ftree_node, fn_height, 68);
	REQUIRE_OFFSETXX(struct silofs_ftree_node, fn_child_mtype, 69);

	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_zeros, 128);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_child, 1024);
	REQUIRE_SIZEOF(struct silofs_ftree_node, SILOFS_FILE_RTNODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_ftree_node);
	REQUIRE_SIZEOF(struct silofs_data_block1, SILOFS_FILE_HEAD1_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_block4, SILOFS_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_block64, SILOFS_FILE_TREE_LEAF_SIZE);
	REQUIRE_SIZEOF_1K(struct silofs_data_block1);
	REQUIRE_SIZEOF_4K(struct silofs_data_block4);
	REQUIRE_SIZEOF_64K(struct silofs_data_block64);
}

static void affirm_ondisk_symlnk(void)
{
	REQUIRE_OFFSET64(struct silofs_symlnk_value, sy_value, 64);
	REQUIRE_SIZEOF(struct silofs_symlnk_value, SILOFS_SYMLNK_VAL_SIZE);
	REQUIRE_SIZEOF_4K(struct silofs_symlnk_value);
}

static void affirm_ondisk_xattr(void)
{
	REQUIRE_SIZEOF(struct silofs_xattr_entry, 8);
	REQUIRE_OFFSET64(struct silofs_xattr_node, xa_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_xattr_node, xe, 128);
	REQUIRE_SIZEOF(struct silofs_xattr_node, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_xattr_node);
}

static void affirm_ondisk_btnode(void)
{
	REQUIRE_OFFSET64(struct silofs_btree_node_crypt, btc_key, 0);
	REQUIRE_OFFSET64(struct silofs_btree_node_crypt, btc_iv, 64);
	REQUIRE_OFFSET64(struct silofs_btree_node_crypt, btc_cipher_algo, 80);
	REQUIRE_OFFSET32(struct silofs_btree_node_crypt, btc_cipher_mode, 84);
	REQUIRE_SIZEOF(struct silofs_btree_node_crypt, 96);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_flags, 32);
	REQUIRE_OFFSET32(struct silofs_btree_node, btn_mtype, 36);
	REQUIRE_OFFSETXX(struct silofs_btree_node, btn_height, 38);
	REQUIRE_OFFSETXX(struct silofs_btree_node, btn_nkeys, 40);
	REQUIRE_OFFSETXX(struct silofs_btree_node, btn_nchilds, 41);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_key, 128);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_child, 512);
	REQUIRE_SIZEOF(struct silofs_btree_node, SILOFS_BTREE_NODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_btree_node);
}

static void affirm_ondisk_bldesc(void)
{
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_btime, 32);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_ctime, 48);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_prev, 64);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_refblob, 120);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_blobsize, 176);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_objsize, 184);
	REQUIRE_OFFSET32(struct silofs_blob_desc, bld_nobjs_max, 188);
	REQUIRE_OFFSET32(struct silofs_blob_desc, bld_nobjs, 192);
	REQUIRE_OFFSET32(struct silofs_blob_desc, bld_flags, 196);
	REQUIRE_OFFSET32(struct silofs_blob_desc, bld_refmtype, 200);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_obj_state, 256);
	REQUIRE_SIZEOF_8K(struct silofs_blob_desc);
}

static void affirm_ondisk_archive(void)
{
	REQUIRE_OFFSET64(struct silofs_ar_desc256b, ad_paddr, 0);
	REQUIRE_OFFSET64(struct silofs_ar_desc256b, ad_laddr, 64);
	REQUIRE_OFFSET64(struct silofs_ar_desc256b, ad_len, 160);
	REQUIRE_SIZEOF(struct silofs_ar_desc256b, 256);

	REQUIRE_OFFSET64(struct silofs_arix_block, ab_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_arix_block, ab_btime, 32);
	REQUIRE_OFFSET64(struct silofs_arix_block, ab_flags, 48);
	REQUIRE_OFFSET32(struct silofs_arix_block, ab_ndescs, 52);
	REQUIRE_OFFSET32(struct silofs_arix_block, ab_next, 64);
	REQUIRE_OFFSET64(struct silofs_arix_block, ab_descs, 256);
	REQUIRE_SIZEOF_64K(struct silofs_arix_block);
}

static void affirm_ioctl_types(void)
{
	REQUIRE_SIZEOF(struct silofs_ioc_query, 2048);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_query, SILOFS_IOC_SIZE_MAX);
	REQUIRE_SIZEOF(struct silofs_ioc_forkfs, 256);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_forkfs, SILOFS_IOC_SIZE_MAX);
}

void silofs_affirm_ondisk_format(void)
{
	affirm_external_constants();
	affirm_fundamental_types();
	affirm_ondisk_defs();
	affirm_ondisk_base_types();
	affirm_ondisk_addrs();
	affirm_ondisk_headers();
	affirm_ondisk_spmaps();
	affirm_ondisk_gbr();
	affirm_ondisk_uber();
	affirm_ondisk_super();
	affirm_ondisk_lsmap();
	affirm_ondisk_inode();
	affirm_ondisk_dir();
	affirm_ondisk_file();
	affirm_ondisk_symlnk();
	affirm_ondisk_xattr();
	affirm_ondisk_btnode();
	affirm_ondisk_bldesc();
	affirm_ondisk_archive();
	affirm_ioctl_types();
}
