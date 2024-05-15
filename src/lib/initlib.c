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
#include <silofs/configs.h>
#include <silofs/libsilofs.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <errno.h>
#include <limits.h>
#include <endian.h>

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

#define REQUIRE_SIZEOF(type, size) \
	REQUIRE_EQ(sizeof(type), size)

#define REQUIRE_SIZEOF_LE(type, size) \
	REQUIRE_LE(sizeof(type), size)

#define REQUIRE_SIZEOF_NK(type, nk) \
	REQUIRE_SIZEOF(type, (nk) * SILOFS_KILO)

#define REQUIRE_SIZEOF_1K(type) \
	REQUIRE_SIZEOF_NK(type, 1)

#define REQUIRE_SIZEOF_4K(type) \
	REQUIRE_SIZEOF_NK(type, 4)

#define REQUIRE_SIZEOF_8K(type) \
	REQUIRE_SIZEOF_NK(type, 8)

#define REQUIRE_SIZEOF_32K(type) \
	REQUIRE_SIZEOF_NK(type, 32)

#define REQUIRE_SIZEOF_64K(type) \
	REQUIRE_SIZEOF_NK(type, 64)

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

static void validate_fundamental_types_size(void)
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

static void validate_persistent_types_nk(void)
{
	REQUIRE_SIZEOF_4K(struct silofs_btree_node);
	REQUIRE_SIZEOF_8K(struct silofs_btree_leaf);
	REQUIRE_SIZEOF_8K(struct silofs_super_block);
	REQUIRE_SIZEOF_32K(struct silofs_spmap_node);
	REQUIRE_SIZEOF_32K(struct silofs_spmap_leaf);
	REQUIRE_SIZEOF_1K(struct silofs_inode);
	REQUIRE_SIZEOF_4K(struct silofs_xattr_node);
	REQUIRE_SIZEOF_8K(struct silofs_dtree_node);
	REQUIRE_SIZEOF_8K(struct silofs_ftree_node);
	REQUIRE_SIZEOF_4K(struct silofs_symlnk_value);
	REQUIRE_SIZEOF_1K(struct silofs_data_block1);
	REQUIRE_SIZEOF_4K(struct silofs_data_block4);
	REQUIRE_SIZEOF_64K(struct silofs_data_block64);
	REQUIRE_SIZEOF_1K(struct silofs_pack_meta1k);
}

static void validate_persistent_types_size1(void)
{
	REQUIRE_SIZEOF(struct silofs_name, SILOFS_NAME_MAX + 1);
	REQUIRE_SIZEOF(struct silofs_header, SILOFS_HEADER_SIZE);
	REQUIRE_SIZEOF(struct silofs_oaddr32b, 32);
	REQUIRE_SIZEOF(struct silofs_caddr64b, 64);
	REQUIRE_SIZEOF(struct silofs_btree_ltop, 80);
	REQUIRE_SIZEOF(struct silofs_btree_node, SILOFS_BTREE_NODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_btree_leaf, SILOFS_BTREE_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_pack_desc256b, 256);
}

static void validate_persistent_types_size2(void)
{
	REQUIRE_SIZEOF(struct silofs_timespec, 16);
	REQUIRE_SIZEOF(struct silofs_hash128, 16);
	REQUIRE_SIZEOF(struct silofs_hash256, 32);
	REQUIRE_SIZEOF(struct silofs_hash512, 64);
	REQUIRE_SIZEOF(struct silofs_kdf_desc, 16);
	REQUIRE_SIZEOF(struct silofs_kdf_pair, 32);
	REQUIRE_SIZEOF(struct silofs_iv, SILOFS_IV_SIZE);
	REQUIRE_SIZEOF(struct silofs_key, SILOFS_KEY_SIZE);
	REQUIRE_SIZEOF(struct silofs_uuid, SILOFS_UUID_SIZE);
	REQUIRE_SIZEOF(struct silofs_lvid, 16);
	REQUIRE_SIZEOF(struct silofs_ovid, 16);
	REQUIRE_SIZEOF(struct silofs_vaddr56, 7);
	REQUIRE_SIZEOF(struct silofs_vaddr64, 8);
	REQUIRE_SIZEOF(struct silofs_vrange128, 16);
	REQUIRE_SIZEOF(struct silofs_lsegid32b, 32);
	REQUIRE_SIZEOF(struct silofs_laddr48b, 48);
	REQUIRE_SIZEOF(struct silofs_uaddr64b, 64);
	REQUIRE_SIZEOF(struct silofs_bootrec1k, SILOFS_BOOTREC_SIZE);
	REQUIRE_SIZEOF(struct silofs_sb_sproots, 1024);
	REQUIRE_SIZEOF(struct silofs_sb_lsegids, 1024);
	REQUIRE_SIZEOF(struct silofs_sb_rootivs, 512);
	REQUIRE_SIZEOF(struct silofs_super_block, SILOFS_SB_SIZE);
	REQUIRE_SIZEOF(struct silofs_space_gauges, 256);
	REQUIRE_SIZEOF(struct silofs_space_stats, 1024);
	REQUIRE_SIZEOF(struct silofs_spmap_ref, 96);
	REQUIRE_SIZEOF(struct silofs_spmap_node, SILOFS_SPMAP_SIZE);
	REQUIRE_SIZEOF(struct silofs_bk_ref, 96);
	REQUIRE_SIZEOF(struct silofs_spmap_leaf, SILOFS_SPMAP_SIZE);
	REQUIRE_SIZEOF(struct silofs_inode, SILOFS_KB_SIZE);
	REQUIRE_SIZEOF(struct silofs_lblock, SILOFS_LBK_SIZE);
	REQUIRE_SIZEOF(struct silofs_dir_entry, 16);
	REQUIRE_SIZEOF(struct silofs_xattr_entry, 8);
	REQUIRE_SIZEOF(struct silofs_inode_dir, 64);
	REQUIRE_SIZEOF(struct silofs_inode_file, 512);
	REQUIRE_SIZEOF(struct silofs_inode_lnk, 512);
	REQUIRE_SIZEOF(struct silofs_inode_times, 64);
	REQUIRE_SIZEOF(struct silofs_inode_xattr, 256);
	REQUIRE_SIZEOF(union silofs_inode_tail, 512);
	REQUIRE_SIZEOF(struct silofs_inode, SILOFS_INODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_symlnk_value, SILOFS_SYMLNK_VAL_SIZE);
	REQUIRE_SIZEOF(struct silofs_xattr_node, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_ftree_node, SILOFS_FILE_RTNODE_SIZE);
	REQUIRE_SIZEOF(union silofs_dtree_data, SILOFS_DIR_NODE_NBUF_SIZE);
	REQUIRE_SIZEOF(struct silofs_dtree_node, SILOFS_DIR_NODE_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_block4, SILOFS_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_block64, SILOFS_FILE_TREE_LEAF_SIZE);
	REQUIRE_SIZEOF(struct silofs_repo_meta, SILOFS_REPO_METAFILE_SIZE);
}

static void validate_persistent_types_members(void)
{
	REQUIRE_NBITS(struct silofs_header, h_type, 8);
	REQUIRE_NBITS(struct silofs_bk_ref, bkr_allocated, SILOFS_NKB_IN_LBK);
	REQUIRE_NBITS(struct silofs_bk_ref, bkr_unwritten, SILOFS_NKB_IN_LBK);
	REQUIRE_MEMBER_SIZE(struct silofs_bk_ref, bkr_dbkref, 8);
	REQUIRE_NELEMS(struct silofs_ftree_node,
	               fn_child, SILOFS_FILE_NODE_NCHILDS);
	REQUIRE_NELEMS(union silofs_dtree_data, de, SILOFS_DIR_NODE_NENTS);
	REQUIRE_NELEMS(struct silofs_dtree_node,
	               dn_child, SILOFS_DIR_NODE_NCHILDS);
}

static void validate_persistent_types_alignment1(void)
{
	REQUIRE_OFFSET64(struct silofs_spmap_ref, sr_uaddr, 0);
	REQUIRE_OFFSET64(struct silofs_bk_ref, bkr_uref, 0);
	REQUIRE_OFFSET64(struct silofs_bk_ref, bkr_allocated, 48);
	REQUIRE_OFFSET64(struct silofs_bk_ref, bkr_unwritten, 56);
	REQUIRE_OFFSET64(struct silofs_bk_ref, bkr_dbkref, 64);
}

static void validate_persistent_types_alignment2(void)
{
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_magic, 0);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_version, 8);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_flags, 16);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_chiper_algo, 24);
	REQUIRE_OFFSET(struct silofs_bootrec1k, br_chiper_mode, 28);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_kdf_pair, 32);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_sb_uaddr, 64);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_sb_riv, 128);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_rands, 256);
	REQUIRE_OFFSET64(struct silofs_bootrec1k, br_reserved2, 512);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_magic, 16);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_version, 24);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_sw_version, 64);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_uuid, 128);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_name, 256);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_self_uaddr, 512);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_orig_uaddr, 576);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_lvid, 640);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_vrange, 656);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_birth_time, 680);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_clone_time, 688);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_sproots, 1024);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_main_lsegid, 2048);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_rootivs, 3072);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_space_stats_curr, 4096);
	REQUIRE_OFFSET64(struct silofs_super_block, sb_space_stats_base, 5120);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_btime, 0);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_ctime, 8);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_capacity, 16);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_vspacesize, 24);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_generation, 32);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_lsegs, 256);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_bks, 512);
	REQUIRE_OFFSET64(struct silofs_space_stats, sp_objs, 768);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_main_lsegid, 32);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_vrange, 64);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_parent, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_self, 192);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_subrefs, 4096);
	REQUIRE_OFFSET64(struct silofs_spmap_node, sn_rivs, 28672);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_main_lsegid, 32);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_parent, 64);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_self, 128);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_vrange, 192);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_subrefs, 4096);
	REQUIRE_OFFSET64(struct silofs_spmap_leaf, sl_rivs, 28672);
}

static void validate_persistent_types_alignment3(void)
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
	REQUIRE_OFFSET64(struct silofs_inode, i_ta, 512);
	REQUIRE_OFFSET(struct silofs_inode_dir, d_root, 0);
	REQUIRE_OFFSET(struct silofs_inode_dir, d_seed, 8);
	REQUIRE_OFFSET(struct silofs_inode_dir, d_ndents, 16);
	REQUIRE_OFFSET(struct silofs_dir_entry, de_ino, 0);
	REQUIRE_OFFSET(struct silofs_dir_entry, de_name_hash_lo, 8);
	REQUIRE_OFFSET(struct silofs_dir_entry, de_name_len_dt, 12);
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

static void validate_persistent_types_alignment4(void)
{
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_nkeys, 16);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_child, 64);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_key, 1792);
	REQUIRE_OFFSET64(struct silofs_btree_leaf, btl_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_btree_leaf, btl_ltop, 32);
}

static void validate_ioctl_types_size(void)
{
	REQUIRE_SIZEOF(struct silofs_ioc_query, 2048);
	REQUIRE_SIZEOF(struct silofs_ioc_clone, 512);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_query, SILOFS_IOC_SIZE_MAX);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_clone, SILOFS_IOC_SIZE_MAX);
}

static void validate_defs_consistency(void)
{
	REQUIRE_EQ(CHAR_BIT, 8);
	REQUIRE_EQ(SILOFS_NSPMAP_IN_LBK * SILOFS_SPMAP_SIZE, SILOFS_LBK_SIZE);
	REQUIRE_LT(SILOFS_DIR_TREE_DEPTH_MAX, SILOFS_HASH256_LEN);
	REQUIRE_LT(SILOFS_DIR_TREE_INDEX_MAX, INT32_MAX);
	REQUIRE_GT(SILOFS_DIR_ENTRIES_MAX, SILOFS_LINK_MAX);
	REQUIRE_LT(SILOFS_XATTR_VALUE_MAX, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_EQ(SILOFS_FILE_SIZE_MAX, 64 * SILOFS_TERA - 1);
	REQUIRE_EQ(SILOFS_LSEG_SIZE_MAX, 16 * SILOFS_MEGA);
	REQUIRE_EQ(SILOFS_LBK_SIZE * SILOFS_SPMAP_NCHILDS,
	           SILOFS_LSEG_SIZE_MAX);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MIN, 2 * SILOFS_GIGA);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MAX, 64 * SILOFS_TERA);
	REQUIRE_LT(SILOFS_CAPACITY_SIZE_MAX, SILOFS_VSPACE_SIZE_MAX / 2);
	REQUIRE_EQ(SILOFS_VSPACE_SIZE_MAX, 256 * SILOFS_PETA);

	REQUIRE_EQ(SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF,
	           SILOFS_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_EQ((SILOFS_FILE_HEAD1_LEAF_SIZE * SILOFS_FILE_HEAD1_NLEAF) +
	           (SILOFS_FILE_HEAD2_LEAF_SIZE * SILOFS_FILE_HEAD2_NLEAF),
	           SILOFS_FILE_TREE_LEAF_SIZE);
}

static void validate_external_constants(void)
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

static void validate_defs(void)
{
	validate_fundamental_types_size();
	validate_persistent_types_nk();
	validate_persistent_types_size1();
	validate_persistent_types_size2();
	validate_persistent_types_members();
	validate_persistent_types_alignment1();
	validate_persistent_types_alignment2();
	validate_persistent_types_alignment3();
	validate_persistent_types_alignment4();
	validate_ioctl_types_size();
	validate_defs_consistency();
	validate_external_constants();
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define SILOFS_NOFILES_MIN      (512)

static int errno_or_errnum(int errnum)
{
	return (errno > 0) ? -errno : -abs(errnum);
}

static int check_endianess32(uint32_t val, const char *str)
{
	char buf[16] = "";
	const uint32_t val_le = htole32(val);

	for (size_t i = 0; i < 4; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess64(uint64_t val, const char *str)
{
	char buf[16] = "";
	const uint64_t val_le = htole64(val);

	for (size_t i = 0; i < 8; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess(void)
{
	int err;

	err = check_endianess64(SILOFS_REPO_META_MAGIC, "#SILOFS#");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_BOOT_RECORD_MAGIC, "@SILOFS@");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_PACK_META_MAGIC, "%silofs%");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_SUPER_MAGIC, "@silofs@");
	if (err) {
		return err;
	}
	err = check_endianess32(SILOFS_FSID_MAGIC, "SILO");
	if (err) {
		return err;
	}
	err = check_endianess32(SILOFS_META_MAGIC, "silo");
	if (err) {
		return err;
	}
	return 0;
}

static int check_sysconf(void)
{
	long val;
	long page_shift = 0;
	const long page_size_min = SILOFS_PAGE_SIZE_MIN;
	const long page_shift_min = SILOFS_PAGE_SHIFT_MIN;
	const long page_shift_max = SILOFS_PAGE_SHIFT_MAX;
	const long cl_size_min = SILOFS_CACHELINE_SIZE_MIN;
	const long cl_size_max = SILOFS_CACHELINE_SIZE_MAX;

	errno = 0;
	val = silofs_sc_phys_pages();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEM);
	}
	val = silofs_sc_avphys_pages();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEM);
	}
	val = silofs_sc_l1_dcache_linesize();
	if ((val < cl_size_min) || (val > cl_size_max)) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	val = silofs_sc_page_size();
	if ((val < page_size_min) || (val % page_size_min)) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	for (long shift = page_shift_min; shift <= page_shift_max; ++shift) {
		if (val == (1L << shift)) {
			page_shift = val;
			break;
		}
	}
	if (page_shift == 0) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	val = silofs_sc_nproc_onln();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEDIUM);
	}
	val = silofs_sc_iov_max();
	if (val < SILOFS_IOV_MAX) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	return 0;
}

static int check_system_page_size(void)
{
	long page_size;
	const size_t page_shift[] = { 12, 13, 14, 16 };

	page_size = silofs_sc_page_size();
	if (page_size > SILOFS_LBK_SIZE) {
		return -SILOFS_EOPNOTSUPP;
	}
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(page_shift); ++i) {
		if (page_size == (1L << page_shift[i])) {
			return 0;
		}
	}
	return -SILOFS_EOPNOTSUPP;
}

static int check_proc_rlimits(void)
{
	struct rlimit rlim;
	int err;

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_MEGA) {
		return -SILOFS_ENOMEM;
	}
	err = silofs_sys_getrlimit(RLIMIT_NOFILE, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_NOFILES_MIN) {
		return -SILOFS_ENFILE;
	}
	return 0;
}

static int init_libsilofs(void)
{
	int err;

	err = check_endianess();
	if (err) {
		return err;
	}
	err = check_sysconf();
	if (err) {
		return err;
	}
	err = check_system_page_size();
	if (err) {
		return err;
	}
	err = check_proc_rlimits();
	if (err) {
		return err;
	}
	err = silofs_init_gcrypt();
	if (err) {
		return err;
	}
	return 0;
}

static bool g_libsilofs_init;

int silofs_init_lib(void)
{
	int ret = 0;

	if (!g_libsilofs_init) {
		validate_defs();
		ret = init_libsilofs();
		g_libsilofs_init = (ret == 0);
	}
	return ret;
}

