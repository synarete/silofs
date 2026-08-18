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
#include <silofs/configs.h>
#include <linux/un.h>
#include <limits.h>
#include <endian.h>
#include <gcrypt.h>

#include <silofs/consts.h>
#include <silofs/macros.h>
#include <silofs/ondisk.h>
#include <silofs/ioctls.h>

#ifndef LINK_MAX
#define LINK_MAX 127
#endif

#define BITS_SIZE(a) (CHAR_BIT * sizeof(a))

#define MEMBER_SIZE(type, member) sizeof(((const type *)nullptr)->member)

#define MEMBER_NELEMS(type, member) \
	SILOFS_ARRAY_SIZE(((const type *)nullptr)->member)

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

#define REQUIRE_TYPE_NBITS(type_, nbits_) \
	REQUIRE_EQ(BITS_SIZE(type_), nbits_)

#define ISALIGNED32(off) (((off) % 4) == 0)

#define ISALIGNED64(off) (((off) % 8) == 0)

#define ISOFFSET(type, member, off) (offsetof(type, member) == (off))

#define REQUIRE_OFFSETXX(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off))

#define REQUIRE_OFFSET32(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED32(off))

#define REQUIRE_OFFSET64(type, member, off) \
	SILOFS_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED64(off))

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void validate_fundamental_types(void)
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

	REQUIRE_TYPE_NBITS(uint8_t, 8);
	REQUIRE_TYPE_NBITS(uint16_t, 16);
	REQUIRE_TYPE_NBITS(uint32_t, 32);
	REQUIRE_TYPE_NBITS(uint64_t, 64);
}

static void validate_external_constants(void)
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

	REQUIRE_LT(sizeof(SILOFS_MNTSOCK_NAME), UNIX_PATH_MAX);
}

static void validate_ondisk_defs(void)
{
	REQUIRE_LT(SILOFS_XATTR_VALUE_MAX, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_EQ(SILOFS_FILE_SIZE_MAX, 64 * SILOFS_PETA - 1);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MIN, 2 * SILOFS_GIGA);
	REQUIRE_EQ(SILOFS_CAPACITY_SIZE_MAX, 64 * SILOFS_TERA);
	REQUIRE_EQ(SILOFS_FILE_DATA_NODE4_SIZE,
	           SILOFS_FILE_DATA_NODE1_SIZE * SILOFS_FILE_HEAD1_NLEAF);
	REQUIRE_EQ(SILOFS_FILE_DATA_NODE64_SIZE,
	           (SILOFS_FILE_DATA_NODE1_SIZE * SILOFS_FILE_HEAD1_NLEAF) +
	                   (SILOFS_FILE_DATA_NODE4_SIZE *
	                    SILOFS_FILE_HEAD2_NLEAF));
}

static void validate_ondisk_base_types(void)
{
	REQUIRE_SIZEOF(struct silofs_name, SILOFS_NAME_MAX + 1);
	REQUIRE_SIZEOF(struct silofs_sw_version64b, 64);
	REQUIRE_SIZEOF(struct silofs_tm64b, 64);
	REQUIRE_SIZEOF(struct silofs_timespec16b, 16);
	REQUIRE_SIZEOF(struct silofs_hash128, 16);
	REQUIRE_SIZEOF(struct silofs_hash256, 32);
	REQUIRE_SIZEOF(struct silofs_hash512, 64);
	REQUIRE_SIZEOF(struct silofs_civ, SILOFS_CRYPTO_IV_SIZE);
	REQUIRE_SIZEOF(struct silofs_ckey, SILOFS_CRYPTO_KEY_SIZE);
	REQUIRE_SIZEOF(struct silofs_uuid, SILOFS_UUID_SIZE);
	REQUIRE_SIZEOF(struct silofs_lblock, SILOFS_LBK_SIZE);
	REQUIRE_SIZEOF(struct silofs_pblock, SILOFS_PBK_SIZE);
}

static void validate_ondisk_addrs(void)
{
	REQUIRE_SIZEOF(struct silofs_layerid, 16);
	REQUIRE_SIZEOF(struct silofs_uniqid, 16);
	REQUIRE_SIZEOF(struct silofs_uniqid, SILOFS_UNIQEID_SIZE);
	REQUIRE_SIZEOF(struct silofs_blobid48b, 48);
	REQUIRE_SIZEOF(struct silofs_blobid48b, SILOFS_BLOBID_SIZE);
	REQUIRE_SIZEOF(struct silofs_laddr56, 7);
	REQUIRE_SIZEOF(struct silofs_laddr64, 8);
	REQUIRE_SIZEOF(struct silofs_paddr64b, 64);
	REQUIRE_SIZEOF(struct silofs_pnptr256b, 256);
}

static void validate_ondisk_pnptr(void)
{
	REQUIRE_OFFSET64(struct silofs_nmeta128b, nm_ckey, 0);
	REQUIRE_OFFSET64(struct silofs_nmeta128b, nm_civ, 64);
	REQUIRE_OFFSET64(struct silofs_nmeta128b, nm_cipher_algo, 96);
	REQUIRE_OFFSETXX(struct silofs_nmeta128b, nm_cipher_mode, 98);
	REQUIRE_SIZEOF(struct silofs_nmeta128b, 128);
	REQUIRE_OFFSET64(struct silofs_pnptr256b, pp_nmeta, 0);
	REQUIRE_OFFSET64(struct silofs_pnptr256b, pp_paddr, 128);
	REQUIRE_SIZEOF(struct silofs_pnptr256b, 256);
}

static void validate_ondisk_headers(void)
{
	REQUIRE_OFFSET64(struct silofs_header, h_magic, 0);
	REQUIRE_OFFSET64(struct silofs_header, h_size, 8);
	REQUIRE_OFFSET32(struct silofs_header, h_flags, 12);
	REQUIRE_OFFSETXX(struct silofs_header, h_ptype, 14);
	REQUIRE_OFFSETXX(struct silofs_header, h_ltype, 15);
	REQUIRE_OFFSETXX(struct silofs_header, h_csum, 56);
	REQUIRE_SIZEOF(struct silofs_header, SILOFS_HEADER_SIZE);
	REQUIRE_SIZEOF(struct silofs_repo_meta, SILOFS_REPO_METAFILE_SIZE);
}

static void validate_ondisk_mbr(void)
{
	REQUIRE_OFFSET64(struct silofs_mbr1k, mbr_magic, 0);
	REQUIRE_OFFSET64(struct silofs_mbr1k, mbr_version, 8);
	REQUIRE_OFFSET64(struct silofs_mbr1k, mbr_uuid, 16);
	REQUIRE_OFFSET64(struct silofs_mbr1k, mbr_mode, 32);
	REQUIRE_OFFSET32(struct silofs_mbr1k, mbr_flags, 36);
	REQUIRE_OFFSET32(struct silofs_mbr1k, mbr_sw_version, 64);
	REQUIRE_OFFSET64(struct silofs_mbr1k, mbr_root_uber, 256);
	REQUIRE_OFFSET64(struct silofs_mbr1k, mbr_reserved3, 512);
	REQUIRE_SIZEOF_1K(struct silofs_mbr1k);
	REQUIRE_SIZEOF(struct silofs_mbr1k, SILOFS_MBR_SIZE);
}

static void validate_ondisk_uber_node(void)
{
	REQUIRE_OFFSET64(struct silofs_uber_sub, ubs_btroot, 0);
	REQUIRE_OFFSET64(struct silofs_uber_sub, ubs_bn_nextfree, 256);
	REQUIRE_OFFSET64(struct silofs_uber_sub, ubs_vn_nextfree, 320);
	REQUIRE_OFFSET64(struct silofs_uber_sub, ubs_bn_count, 512);
	REQUIRE_OFFSET64(struct silofs_uber_sub, ubs_vn_count, 520);
	REQUIRE_SIZEOF(struct silofs_uber_sub, 1024);
	REQUIRE_OFFSET64(struct silofs_uber_node, ub_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_uber_node, ub_btime, 64);
	REQUIRE_OFFSET64(struct silofs_uber_node, ub_ctime, 80);
	REQUIRE_OFFSET64(struct silofs_uber_node, ub_generation, 96);
	REQUIRE_OFFSET64(struct silofs_uber_node, ub_capacity, 104);
	REQUIRE_OFFSET64(struct silofs_uber_node, ub_sub, 1024);
	REQUIRE_SIZEOF_16K(struct silofs_uber_node);
}

static void validate_ondisk_uspace_node(void)
{
	REQUIRE_SIZEOF(struct silofs_uspace_desc, 64);
	REQUIRE_SIZEOF(struct silofs_uspace_descs, 128);
	REQUIRE_OFFSET64(struct silofs_uspace_node, us_hdr, 0);

	REQUIRE_SIZEOF_8K(struct silofs_uspace_node);
}

static void validate_ondisk_btree_node(void)
{
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_minkey, 64);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_flags, 72);
	REQUIRE_OFFSET32(struct silofs_btree_node, btn_lspace, 76);
	REQUIRE_OFFSETXX(struct silofs_btree_node, btn_height, 77);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_nkeys, 80);
	REQUIRE_OFFSETXX(struct silofs_btree_node, btn_nchilds, 82);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_key, 256);
	REQUIRE_OFFSET64(struct silofs_btree_node, btn_child, 1024);
	REQUIRE_SIZEOF(struct silofs_btree_node, SILOFS_BTREE_NODE_SIZE);
	REQUIRE_SIZEOF_16K(struct silofs_btree_node);
}

static void validate_ondisk_blob_desc(void)
{
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_btime, 64);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_ctime, 80);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_prev, 128);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_refblob, 192);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_blobsize, 256);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_objsize, 264);
	REQUIRE_OFFSET32(struct silofs_blob_desc, bld_nobjs_max, 268);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_nobjs, 272);
	REQUIRE_OFFSET32(struct silofs_blob_desc, bld_flags, 276);
	REQUIRE_OFFSET64(struct silofs_blob_desc, bld_obj_state, 512);
	REQUIRE_SIZEOF_8K(struct silofs_blob_desc);
}

static void validate_ondisk_superb_node(void)
{
	REQUIRE_OFFSET64(struct silofs_superb_node, s_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_magic, 64);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_version, 72);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_flags, 80);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_btime, 128);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_fs_capacity, 256);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_fs_usage, 264);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_ino_generation, 272);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_nodes_count, 1024);
	REQUIRE_MEMBER_SIZE(struct silofs_superb_node, s_nodes_count, 1024);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_apex_voff, 2048);
	REQUIRE_OFFSET64(struct silofs_superb_node, s_reserved4, 3072);
	REQUIRE_SIZEOF_4K(struct silofs_superb_node);
}

static void validate_ondisk_space_node(void)
{
	REQUIRE_OFFSET64(struct silofs_space_node, sp_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_space_node, sp_base_off, 64);
	REQUIRE_OFFSET64(struct silofs_space_node, sp_ref_ltype, 72);
	REQUIRE_OFFSET64(struct silofs_space_node, sp_flags, 1024);
	REQUIRE_OFFSET64(struct silofs_space_node, sp_refcnt, 2048);
	REQUIRE_SIZEOF_4K(struct silofs_space_node);
}

static void validate_ondisk_inode(void)
{
	REQUIRE_OFFSET64(struct silofs_inode, i_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_inode, i_ino, 64);
	REQUIRE_OFFSET64(struct silofs_inode, i_parent, 72);
	REQUIRE_OFFSET64(struct silofs_inode, i_uid, 80);
	REQUIRE_OFFSET32(struct silofs_inode, i_gid, 84);
	REQUIRE_OFFSET64(struct silofs_inode, i_mode, 88);
	REQUIRE_OFFSET32(struct silofs_inode, i_flags, 92);
	REQUIRE_OFFSET64(struct silofs_inode, i_size, 96);
	REQUIRE_OFFSET32(struct silofs_inode, i_span, 104);
	REQUIRE_OFFSET64(struct silofs_inode, i_blocks, 112);
	REQUIRE_OFFSET64(struct silofs_inode, i_nlink, 120);
	REQUIRE_OFFSET64(struct silofs_inode, i_attributes, 128);
	REQUIRE_OFFSET64(struct silofs_inode, i_rdev_major, 136);
	REQUIRE_OFFSET32(struct silofs_inode, i_rdev_minor, 140);
	REQUIRE_OFFSET32(struct silofs_inode, i_revision, 144);
	REQUIRE_OFFSET64(struct silofs_inode, i_generation, 152);
	REQUIRE_OFFSET64(struct silofs_inode, i_tm, 192);
	REQUIRE_OFFSET64(struct silofs_inode, i_xa, 256);
	REQUIRE_OFFSET64(struct silofs_inode, i_ta, 384);
	REQUIRE_OFFSET64(struct silofs_inode_dir, d_root, 0);
	REQUIRE_OFFSET64(struct silofs_inode_dir, d_seed, 8);
	REQUIRE_OFFSET64(struct silofs_inode_dir, d_ndents, 16);
	REQUIRE_OFFSET64(struct silofs_inode_xattr, ix_laddr, 0);
	REQUIRE_SIZEOF(struct silofs_inode_dir, 64);
	REQUIRE_SIZEOF(struct silofs_inode_xattr, 128);
	REQUIRE_SIZEOF(struct silofs_inode_times, 64);
	REQUIRE_SIZEOF(struct silofs_inode_file, 512);
	REQUIRE_SIZEOF(struct silofs_inode_lnk, 640);
	REQUIRE_SIZEOF(union silofs_inode_tail, 640);
	REQUIRE_SIZEOF(struct silofs_inode, SILOFS_INODE_SIZE);
	REQUIRE_SIZEOF_1K(struct silofs_inode);
}

static void validate_ondisk_dtree_node(void)
{
	REQUIRE_OFFSET64(struct silofs_dir_entry, de_ino, 0);
	REQUIRE_OFFSET64(struct silofs_dir_entry, de_name_hash, 8);
	REQUIRE_OFFSET32(struct silofs_dir_entry, de_name_len_dt, 12);
	REQUIRE_OFFSETXX(struct silofs_dir_entry, de_name_pos, 14);
	REQUIRE_SIZEOF(struct silofs_dir_entry, 16);

	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_ino, 64);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_parent, 72);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_node_index, 80);
	REQUIRE_OFFSET32(struct silofs_dtree_node, dn_nde, 84);
	REQUIRE_OFFSETXX(struct silofs_dtree_node, dn_nnb, 86);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_nactive_childs, 88);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_data, 128);
	REQUIRE_OFFSET64(struct silofs_dtree_node, dn_child, 7744);
	REQUIRE_NELEMS(union silofs_dtree_data, de, SILOFS_DTREE_NODE_NENTS);
	REQUIRE_NELEMS(struct silofs_dtree_node, dn_child,
	               SILOFS_DTREE_NODE_NCHILDS);
	REQUIRE_SIZEOF(union silofs_dtree_data, SILOFS_DTREE_NODE_NBSIZE);
	REQUIRE_SIZEOF(struct silofs_dtree_node, SILOFS_DTREE_NODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_dtree_node);
}

static void validate_ondisk_ftree_node(void)
{
	REQUIRE_NELEMS(struct silofs_ftree_node, fn_child,
	               SILOFS_FTREE_NODE_NCHILDS);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_refcnt, 64);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_ino, 72);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_beg, 80);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_end, 88);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_nactive_childs, 96);
	REQUIRE_OFFSET32(struct silofs_ftree_node, fn_height, 100);
	REQUIRE_OFFSETXX(struct silofs_ftree_node, fn_child_ltype, 101);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_zeros, 128);
	REQUIRE_OFFSET64(struct silofs_ftree_node, fn_child, 1024);
	REQUIRE_SIZEOF(struct silofs_ftree_node, SILOFS_FTREE_NODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_ftree_node);
}

static void validate_ondisk_data_node(void)
{
	REQUIRE_SIZEOF(struct silofs_data_node1, SILOFS_FILE_DATA_NODE1_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_node4, SILOFS_FILE_DATA_NODE4_SIZE);
	REQUIRE_SIZEOF(struct silofs_data_node64,
	               SILOFS_FILE_DATA_NODE64_SIZE);
	REQUIRE_SIZEOF_1K(struct silofs_data_node1);
	REQUIRE_SIZEOF_4K(struct silofs_data_node4);
	REQUIRE_SIZEOF_64K(struct silofs_data_node64);
}

static void validate_ondisk_symval_node(void)
{
	REQUIRE_OFFSET64(struct silofs_symval_node, svn_parent, 64);
	REQUIRE_OFFSET64(struct silofs_symval_node, svn_length, 72);
	REQUIRE_OFFSET64(struct silofs_symval_node, svn_value, 96);
	REQUIRE_SIZEOF(struct silofs_symval_node, SILOFS_SYMVAL_NODE_SIZE);
	REQUIRE_SIZEOF_4K(struct silofs_symval_node);

	REQUIRE_GT(SILOFS_SYMVAL_HEAD_MAX + SILOFS_SYMVAL_TAIL_MAX,
	           SILOFS_SYMLNK_MAX);
}

static void validate_ondisk_xattr_node(void)
{
	REQUIRE_SIZEOF(struct silofs_xattr_entry, 8);
	REQUIRE_OFFSET64(struct silofs_xattr_node, xa_hdr, 0);
	REQUIRE_OFFSET64(struct silofs_xattr_node, xa_ino, 64);
	REQUIRE_OFFSET64(struct silofs_xattr_node, xa_nents, 72);
	REQUIRE_OFFSET64(struct silofs_xattr_node, xe, 128);
	REQUIRE_SIZEOF(struct silofs_xattr_node, SILOFS_XATTR_NODE_SIZE);
	REQUIRE_SIZEOF_8K(struct silofs_xattr_node);
}

static void validate_ioctl_types(void)
{
	REQUIRE_SIZEOF(struct silofs_ioc_query, 2048);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_query, SILOFS_IOC_SIZE_MAX);
	REQUIRE_SIZEOF(struct silofs_ioc_forkfs, 1024);
	REQUIRE_SIZEOF_LE(struct silofs_ioc_forkfs, SILOFS_IOC_SIZE_MAX);
}

silofs_attr_used static void validate_ondisk_format(void)
{
	validate_external_constants();
	validate_fundamental_types();
	validate_ondisk_defs();
	validate_ondisk_base_types();
	validate_ondisk_addrs();
	validate_ondisk_pnptr();
	validate_ondisk_pnptr();
	validate_ondisk_headers();
	validate_ondisk_mbr();
	validate_ondisk_uber_node();
	validate_ondisk_uspace_node();
	validate_ondisk_btree_node();
	validate_ondisk_blob_desc();
	validate_ondisk_space_node();
	validate_ondisk_superb_node();
	validate_ondisk_inode();
	validate_ondisk_dtree_node();
	validate_ondisk_ftree_node();
	validate_ondisk_data_node();
	validate_ondisk_symval_node();
	validate_ondisk_xattr_node();
	validate_ioctl_types();
}
