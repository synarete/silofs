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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void sb_assign(struct silofs_super_block *sb,
                      const struct silofs_super_block *sb_other)
{
	memcpy(sb, sb_other, sizeof(*sb));
}

static uint64_t sb_magic(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_magic);
}

static void sb_set_magic(struct silofs_super_block *sb, uint64_t magic)
{
	sb->sb_magic = silofs_cpu_to_le64(magic);
}

static long sb_version(const struct silofs_super_block *sb)
{
	return (long)silofs_le64_to_cpu(sb->sb_version);
}

static void sb_set_version(struct silofs_super_block *sb, long version)
{
	sb->sb_version = silofs_cpu_to_le64((uint64_t)version);
}

static enum silofs_superf sb_flags(const struct silofs_super_block *sb)
{
	const uint32_t flags = silofs_le32_to_cpu(sb->sb_flags);

	return (enum silofs_superf)flags;
}

static void sb_set_flags(struct silofs_super_block *sb,
                         enum silofs_superf flags)
{
	sb->sb_flags = silofs_cpu_to_le32((uint32_t)flags);
}

static void sb_add_flags(struct silofs_super_block *sb,
                         enum silofs_superf flags)
{
	sb_set_flags(sb, flags | sb_flags(sb));
}

static void sb_set_swversion(struct silofs_super_block *sb,
                             const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(sb->sb_sw_version) - 1;

	memcpy(sb->sb_sw_version, sw_version, min(len, len_max));
}

static void sb_generate_uuid(struct silofs_super_block *sb)
{
	silofs_uuid_generate(&sb->sb_uuid);
}

int silofs_sb_check_version(const struct silofs_super_block *sb)
{
	if (sb_magic(sb) != SILOFS_SUPER_MAGIC) {
		return -EINVAL;
	}
	if (sb_version(sb) != SILOFS_FMT_VERSION) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

bool silofs_sb_test_flags(const struct silofs_super_block *sb,
                          enum silofs_superf mask)
{
	return (mask == (sb_flags(sb) & mask));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_vrange(const struct silofs_super_block *sb,
                      struct silofs_vrange *out_vrange)
{
	silofs_vrange128_parse(&sb->sb_vrange, out_vrange);
}

static void sb_set_vrange(struct silofs_super_block *sb,
                          const struct silofs_vrange *vrange)
{
	silofs_vrange128_set(&sb->sb_vrange, vrange);
}

static enum silofs_height sb_height(const struct silofs_super_block *sb)
{
	struct silofs_vrange vrange;

	sb_vrange(sb, &vrange);
	return vrange.height;
}

static void sb_treeid(const struct silofs_super_block *sb,
                      struct silofs_treeid *out_treeid)
{
	silofs_treeid128_parse(&sb->sb_treeid, out_treeid);
}

static void sb_set_treeid(struct silofs_super_block *sb,
                          const struct silofs_treeid *treeid)
{
	silofs_treeid128_set(&sb->sb_treeid, treeid);
}

static void sb_self(const struct silofs_super_block *sb,
                    struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sb->sb_self_uaddr, out_uaddr);
}

static void sb_set_self(struct silofs_super_block *sb,
                        const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sb->sb_self_uaddr, uaddr);
}

static void sb_origin(const struct silofs_super_block *sb,
                      struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sb->sb_orig_uaddr, out_uaddr);
}

static void sb_set_origin(struct silofs_super_block *sb,
                          const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sb->sb_orig_uaddr, uaddr);
}

static void sb_generate_treeid(struct silofs_super_block *sb)
{
	struct silofs_treeid treeid;

	silofs_treeid_generate(&treeid);
	sb_set_treeid(sb, &treeid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobid40b *
sb_mainblobid_by(const struct silofs_super_block *sb, enum silofs_stype stype)
{
	const struct silofs_blobid40b *ret;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		ret = &sb->sb_main_blobid.sb_blobid_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		ret = &sb->sb_main_blobid.sb_blobid_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		ret = &sb->sb_main_blobid.sb_blobid_databk;
		break;
	case SILOFS_STYPE_ITNODE:
		ret = &sb->sb_main_blobid.sb_blobid_itnode;
		break;
	case SILOFS_STYPE_INODE:
		ret = &sb->sb_main_blobid.sb_blobid_inode;
		break;
	case SILOFS_STYPE_XANODE:
		ret = &sb->sb_main_blobid.sb_blobid_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		ret = &sb->sb_main_blobid.sb_blobid_dtnode;
		break;
	case SILOFS_STYPE_FTNODE:
		ret = &sb->sb_main_blobid.sb_blobid_ftnode;
		break;
	case SILOFS_STYPE_SYMVAL:
		ret = &sb->sb_main_blobid.sb_blobid_symval;
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static struct silofs_blobid40b *
sb_mainblobid_by2(struct silofs_super_block *sb, enum silofs_stype stype)
{
	const struct silofs_blobid40b *bid = sb_mainblobid_by(sb, stype);

	return unconst(bid);
}

static void sb_main_blobid(const struct silofs_super_block *sb,
                           enum silofs_stype stype,
                           struct silofs_blobid *out_blobid)
{
	const struct silofs_blobid40b *bid = sb_mainblobid_by(sb, stype);

	if (likely(bid != NULL)) {
		silofs_blobid40b_parse(bid, out_blobid);
	} else {
		silofs_blobid_reset(out_blobid);
	}
}

static void sb_set_main_blobid(struct silofs_super_block *sb,
                               enum silofs_stype stype,
                               const struct silofs_blobid *blobid)
{
	struct silofs_blobid40b *bid = sb_mainblobid_by2(sb, stype);

	if (likely(bid != NULL)) {
		silofs_blobid40b_set(bid, blobid);
	}
}

static void sb_reset_main_blobids(struct silofs_super_block *sb)
{
	struct silofs_blobid40b *bid;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		bid = sb_mainblobid_by2(sb, stype);
		if (bid != NULL) {
			silofs_blobid40b_reset(bid);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_blobid40b *
sb_cold_blobid_by(const struct silofs_super_block *sb, enum silofs_stype stype)
{
	const struct silofs_blobid40b *ret;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		ret = &sb->sb_cold_blobid.sb_blobid_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		ret = &sb->sb_cold_blobid.sb_blobid_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		ret = &sb->sb_cold_blobid.sb_blobid_databk;
		break;
	case SILOFS_STYPE_ITNODE:
		ret = &sb->sb_cold_blobid.sb_blobid_itnode;
		break;
	case SILOFS_STYPE_INODE:
		ret = &sb->sb_cold_blobid.sb_blobid_inode;
		break;
	case SILOFS_STYPE_XANODE:
		ret = &sb->sb_cold_blobid.sb_blobid_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		ret = &sb->sb_cold_blobid.sb_blobid_dtnode;
		break;
	case SILOFS_STYPE_FTNODE:
		ret = &sb->sb_cold_blobid.sb_blobid_ftnode;
		break;
	case SILOFS_STYPE_SYMVAL:
		ret = &sb->sb_cold_blobid.sb_blobid_symval;
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static struct silofs_blobid40b *
sb_cold_blobid_by2(struct silofs_super_block *sb, enum silofs_stype stype)
{
	const struct silofs_blobid40b *bid = sb_cold_blobid_by(sb, stype);

	return unconst(bid);
}

static void sb_cold_blobid(const struct silofs_super_block *sb,
                           enum silofs_stype stype,
                           struct silofs_blobid *out_blobid)
{
	const struct silofs_blobid40b *bid = sb_cold_blobid_by(sb, stype);

	if (likely(bid != NULL)) {
		silofs_blobid40b_parse(bid, out_blobid);
	} else {
		silofs_blobid_reset(out_blobid);
	}
}

static void sb_set_cold_blobid(struct silofs_super_block *sb,
                               enum silofs_stype stype,
                               const struct silofs_blobid *blobid)
{
	struct silofs_blobid40b *bid = sb_cold_blobid_by2(sb, stype);

	if (likely(bid != NULL)) {
		silofs_blobid40b_set(bid, blobid);
	}
}

static void sb_reset_cold_blobids(struct silofs_super_block *sb)
{
	struct silofs_blobid40b *bid;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		bid = sb_cold_blobid_by2(sb, stype);
		if (bid != NULL) {
			silofs_blobid40b_reset(bid);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr64b *
sb_sproot_by(const struct silofs_super_block *sb, enum silofs_stype stype)
{
	const struct silofs_uaddr64b *ret;

	switch (stype) {
	case SILOFS_STYPE_ITNODE:
		ret = &sb->sb_sproot_uaddr.sb_sproot_itnode;
		break;
	case SILOFS_STYPE_INODE:
		ret = &sb->sb_sproot_uaddr.sb_sproot_inode;
		break;
	case SILOFS_STYPE_XANODE:
		ret = &sb->sb_sproot_uaddr.sb_sproot_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		ret = &sb->sb_sproot_uaddr.sb_sproot_dtnode;
		break;
	case SILOFS_STYPE_FTNODE:
		ret = &sb->sb_sproot_uaddr.sb_sproot_ftnode;
		break;
	case SILOFS_STYPE_SYMVAL:
		ret = &sb->sb_sproot_uaddr.sb_sproot_symval;
		break;
	case SILOFS_STYPE_DATA1K:
		ret = &sb->sb_sproot_uaddr.sb_sproot_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		ret = &sb->sb_sproot_uaddr.sb_sproot_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		ret = &sb->sb_sproot_uaddr.sb_sproot_databk;
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static struct silofs_uaddr64b *
sb_sproot_by2(struct silofs_super_block *sb, enum silofs_stype stype)
{
	const struct silofs_uaddr64b *uadr = sb_sproot_by(sb, stype);

	return unconst(uadr);
}

static void sb_sproot_of(const struct silofs_super_block *sb,
                         enum silofs_stype stype,
                         struct silofs_uaddr *out_uaddr)
{
	const struct silofs_uaddr64b *uadr = sb_sproot_by(sb, stype);

	if (likely(uadr != NULL)) {
		silofs_uaddr64b_parse(uadr, out_uaddr);
	} else {
		silofs_uaddr_reset(out_uaddr);
	}
}

static void sb_set_sproot_of(struct silofs_super_block *sb,
                             enum silofs_stype stype,
                             const struct silofs_uaddr *uaddr)
{
	struct silofs_uaddr64b *uadr = sb_sproot_by2(sb, stype);

	if (likely(uadr != NULL)) {
		silofs_uaddr64b_set(uadr, uaddr);
	}
}

static void sb_reset_sproots(struct silofs_super_block *sb)
{
	struct silofs_uaddr64b *uadr;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		uadr = sb_sproot_by2(sb, stype);
		if (uadr != NULL) {
			silofs_uaddr64b_set(uadr, silofs_uaddr_none());
		}
	}
}

static void sb_clone_sproots(struct silofs_super_block *sb,
                             const struct silofs_super_block *sb_other)
{
	struct silofs_uaddr uaddr;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (stype_isvnode(stype)) {
			sb_sproot_of(sb_other, stype, &uaddr);
			sb_set_sproot_of(sb, stype, &uaddr);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_init(struct silofs_super_block *sb)
{
	sb_set_magic(sb, SILOFS_SUPER_MAGIC);
	sb_set_version(sb, SILOFS_FMT_VERSION);
	sb_set_flags(sb, SILOFS_SUPERF_NONE);
	sb_set_swversion(sb, silofs_version.string);
	sb_generate_uuid(sb);
	sb->sb_endianness = SILOFS_ENDIANNESS_LE;
	sb_reset_sproots(sb);
	sb_generate_treeid(sb);
	sb_reset_main_blobids(sb);
	sb_reset_cold_blobids(sb);
	silofs_uaddr64b_reset(&sb->sb_self_uaddr);
	silofs_uaddr64b_reset(&sb->sb_orig_uaddr);
}

static void sb_set_birth_time(struct silofs_super_block *sb, time_t btime)
{
	sb->sb_birth_time = silofs_cpu_to_le64((uint64_t)btime);
}

static void sb_set_clone_time(struct silofs_super_block *sb, time_t btime)
{
	sb->sb_clone_time = silofs_cpu_to_le64((uint64_t)btime);
}

static void sb_itable_root(const struct silofs_super_block *sb,
                           struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_parse(&sb->sb_itable_root, out_vaddr);
}

static void sb_set_itable_root(struct silofs_super_block *sb,
                               const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&sb->sb_itable_root, vaddr);
}

static void sb_setup_fresh(struct silofs_super_block *sb)
{
	sb_set_birth_time(sb, silofs_time_now());
	sb_set_itable_root(sb, silofs_vaddr_none());
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_sproot(const struct silofs_uaddr *uaddr)
{
	if (uaddr_isnull(uaddr)) {
		return 0;
	}
	if ((uaddr->stype != SILOFS_STYPE_SPNODE) ||
	    (uaddr->height != (SILOFS_HEIGHT_SUPER - 1))) {
		log_err("bad spnode root: stype=%d height=%d",
		        (int)uaddr->stype, (int)uaddr->height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_sb_sproots(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		sb_sproot_of(sb, stype, &uaddr);
		err = verify_sproot(&uaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int verify_sb_self(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;

	sb_self(sb, &uaddr);
	if (uaddr_isnull(&uaddr) || !stype_issuper(uaddr.stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_sb_origin(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;

	sb_origin(sb, &uaddr);
	if (!uaddr_isnull(&uaddr) && !stype_issuper(uaddr.stype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_sb_height(const struct silofs_super_block *sb)
{
	const enum silofs_height height = sb_height(sb);

	if (height != SILOFS_HEIGHT_SUPER) {
		log_err("illegal sb height: height=%lu", height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_super_block(const struct silofs_super_block *sb)
{
	int err;

	err = verify_sb_height(sb);
	if (err) {
		return err;
	}
	err = verify_sb_self(sb);
	if (err) {
		return err;
	}
	err = verify_sb_origin(sb);
	if (err) {
		return err;
	}
	err = verify_sb_sproots(sb);
	if (err) {
		return err;
	}
	err = silofs_verify_space_stats(&sb->sb_space_stats_curr);
	if (err) {
		return err;
	}
	err = silofs_verify_space_stats(&sb->sb_space_stats_base);
	if (err) {
		return err;
	}
	/* TODO: complete me */
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_sbi_add_flags(struct silofs_sb_info *sbi,
                          enum silofs_superf flags)
{
	sb_add_flags(sbi->sb, flags);
	sbi_dirtify(sbi);
}

bool silofs_sbi_test_flags(const struct silofs_sb_info *sbi,
                           enum silofs_superf flags)
{
	return (sb_flags(sbi->sb) & flags) == flags;
}

int silof_sbi_check_mut_fs(const struct silofs_sb_info *sbi)
{
	const unsigned long ms_mask = MS_RDONLY;
	const enum silofs_superf sf_mask = SILOFS_SUPERF_FOSSIL;

	if ((sbi->sb_ms_flags & ms_mask) == ms_mask) {
		return -EROFS;
	}
	if (silofs_sb_test_flags(sbi->sb, sf_mask)) {
		return -EROFS;
	}
	return 0;
}

/*
 * Special case where data-node has been unmapped due to forget, yet it still
 * had a live ref-count due to on-going I/O operation.
 */
static int sbi_fixup_cached_vi(const struct silofs_sb_info *sbi,
                               struct silofs_vnode_info *vi)
{
	if (!vi->v_si.s_ce.ce_forgot) {
		return 0;
	}
	if (silofs_vi_refcnt(vi)) {
		return 0;
	}
	silofs_cache_forget_vi(sbi_cache(sbi), vi);
	return -ENOENT;
}

static int sbi_lookup_cached_vi(const struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi;
	int err;

	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	vi = silofs_cache_lookup_vi(sbi_cache(sbi), vaddr);
	if (vi == NULL) {
		return -ENOENT;
	}
	err = sbi_fixup_cached_vi(sbi, vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int sbi_lookup_cached_ii(const struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = sbi_lookup_cached_vi(sbi, vaddr, &vi);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vi(vi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_forget_cached_vi(struct silofs_sb_info *sbi,
                                 struct silofs_vnode_info *vi)
{
	if (vi != NULL) {
		silofs_cache_forget_vi(sbi_cache(sbi), vi);
	}
}

static void sbi_forget_cached_ii(struct silofs_sb_info *sbi,
                                 struct silofs_inode_info *ii)
{
	if (ii != NULL) {
		sbi_forget_cached_vi(sbi, ii_to_vi(ii));
	}
}

int silofs_sbi_shut(struct silofs_sb_info *sbi)
{
	const struct silofs_uber *uber = sbi_uber(sbi);

	log_dbg("shut-super: op_count=%lu", uber->ub_ops.op_count);
	silofs_itbi_reinit(&sbi->sb_itbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_treeid(const struct silofs_sb_info *sbi,
                       struct silofs_treeid *out_treeid)
{
	sb_treeid(sbi->sb, out_treeid);
}

int silofs_sbi_main_blob(const struct silofs_sb_info *sbi,
                         enum silofs_stype vspace,
                         struct silofs_blobid *out_blobid)
{
	sb_main_blobid(sbi->sb, vspace, out_blobid);
	return blobid_isnull(out_blobid) ? -ENOENT : 0;
}

void silofs_sbi_bind_main_blob(struct silofs_sb_info *sbi,
                               enum silofs_stype vspace,
                               const struct silofs_blobid *blobid)
{
	sb_set_main_blobid(sbi->sb, vspace, blobid);
	sbi_dirtify(sbi);
}

bool silofs_sbi_has_main_blob(const struct silofs_sb_info *sbi,
                              enum silofs_stype vspace)
{
	struct silofs_blobid blob_id;

	silofs_sbi_main_blob(sbi, vspace, &blob_id);
	return (blobid_size(&blob_id) > 0);
}

int silofs_sbi_cold_blob(const struct silofs_sb_info *sbi,
                         enum silofs_stype vspace,
                         struct silofs_blobid *out_blobid)
{
	sb_cold_blobid(sbi->sb, vspace, out_blobid);
	return !blobid_isnull(out_blobid) ? 0 : -ENOENT;
}

void silofs_sbi_bind_cold_blob(struct silofs_sb_info *sbi,
                               enum silofs_stype vspace,
                               const struct silofs_blobid *blobid)
{
	sb_set_cold_blobid(sbi->sb, vspace, blobid);
	silofs_ui_seal_meta(&sbi->sb_ui);
}

static size_t sb_slot_of(const struct silofs_super_block *sb, loff_t voff)
{
	struct silofs_vrange vrange;
	ssize_t span;

	sb_vrange(sb, &vrange);
	span = silofs_height_to_space_span(vrange.height - 1);
	return (size_t)(voff / span);
}

static loff_t
sbi_bpos_of_child(const struct silofs_sb_info *sbi, loff_t voff)
{
	const size_t slot = sb_slot_of(sbi->sb, voff);

	return (long)slot * SILOFS_SPMAP_SIZE;
}

static loff_t
sbi_base_voff_of_child(const struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_vrange vrange;

	silofs_unused(sbi);
	silofs_vrange_of_spmap(&vrange, SILOFS_HEIGHT_SUPER - 1, voff);
	return vrange.beg;
}

void silofs_sbi_main_child_at(const struct silofs_sb_info *sbi,
                              loff_t voff, enum silofs_stype vspace,
                              struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid blobid;
	const loff_t bpos = sbi_bpos_of_child(sbi, voff);
	const loff_t base = sbi_base_voff_of_child(sbi, voff);

	silofs_sbi_main_blob(sbi, vspace, &blobid);
	uaddr_setup(out_uaddr, &blobid, bpos,
	            SILOFS_STYPE_SPNODE, SILOFS_HEIGHT_SUPER - 1, base);
}

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
                         enum silofs_stype vstype,
                         struct silofs_uaddr *out_uaddr)
{
	sb_sproot_of(sbi->sb, vstype, out_uaddr);
	return !uaddr_isnull(out_uaddr) ? 0 : -ENOENT;
}

void silofs_sbi_bind_sproot(struct silofs_sb_info *sbi,
                            enum silofs_stype vstype,
                            const struct silofs_spnode_info *sni)
{
	const struct silofs_uaddr *uaddr = sni_uaddr(sni);

	sb_set_sproot_of(sbi->sb, vstype, uaddr);
	sbi_dirtify(sbi);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_resolve_itable_root(struct silofs_sb_info *sbi,
                                   struct silofs_vaddr *out_vaddr)
{
	struct silofs_vaddr vaddr;
	enum silofs_stype stype;

	sb_itable_root(sbi->sb, &vaddr);

	stype = vaddr_stype(&vaddr);
	if (vaddr_isnull(&vaddr) || !stype_isitnode(stype)) {
		log_err("non valid itable-root: off=0x%lx stype=%d",
		        vaddr_off(&vaddr), stype);
		return -SILOFS_EFSCORRUPTED;
	}
	vaddr_assign(out_vaddr, &vaddr);
	return 0;
}

int silofs_sbi_reload_itable(struct silofs_sb_info *sbi)
{
	struct silofs_vaddr vaddr;
	int err;

	err = sbi_resolve_itable_root(sbi, &vaddr);
	if (err) {
		return err;
	}
	err = silofs_reload_itable_at(sbi, &vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_format_itable(struct silofs_sb_info *sbi)
{
	struct silofs_vaddr vaddr;
	int err;

	err = silofs_format_itable_root(sbi, &vaddr);
	if (err) {
		return err;
	}
	sb_set_itable_root(sbi->sb, &vaddr);
	sbi_dirtify(sbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_check_stage(const struct silofs_sb_info *sbi,
                           enum silofs_stage_mode stg_mode)
{
	int err = 0;

	if (stg_mode & SILOFS_STAGE_RW) {
		err = silof_sbi_check_mut_fs(sbi);
	}
	return err;
}

static int sbi_check_stage_vnode(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_mode stg_mode)
{
	return vaddr_isnull(vaddr) ? -ENOENT : sbi_check_stage(sbi, stg_mode);
}

static int sbi_check_stage_inode(struct silofs_sb_info *sbi, ino_t ino,
                                 enum silofs_stage_mode stg_mode)
{
	return ino_isnull(ino) ? -ENOENT : sbi_check_stage(sbi, stg_mode);
}

static int sbi_check_staged_inode(const struct silofs_inode_info *ii,
                                  enum silofs_stage_mode stg_mode)
{
	int err = 0;

	if (stg_mode & SILOFS_STAGE_RW) {
		err = silof_ii_isimmutable(ii) ? -EACCES : 0;
	}
	return err;
}

static int
sbi_resolve_stage_vnode(struct silofs_sb_info *sbi,
                        const struct silofs_vaddr *vaddr,
                        enum silofs_stage_mode stg_mode,
                        silofs_dqid_t dqid,
                        struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_sbi_resolve_voa(sbi, vaddr, stg_mode, &voa);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_vi(sbi, vaddr, &vi);
	if (!err) {
		goto out_ok;  /* cache hit */
	}
	err = silofs_sbi_require_stable_at(sbi, vaddr, stg_mode);
	if (err) {
		return err;
	}
	err = silofs_sbi_stage_vnode_at(sbi, vaddr, stg_mode, dqid, true, &vi);
	if (err) {
		return err;
	}
out_ok:
	*out_vi = vi;
	return 0;
}

int silofs_sbi_stage_vnode(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_mode stg_mode, silofs_dqid_t dqid,
                           struct silofs_vnode_info **out_vi)
{
	int err;

	err = sbi_check_stage_vnode(sbi, vaddr, stg_mode);
	if (err) {
		return err;
	}
	err = sbi_resolve_stage_vnode(sbi, vaddr, stg_mode, dqid, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_inode(struct silofs_sb_info *sbi, ino_t ino,
                           enum silofs_stage_mode stg_mode,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = {
		.ino = ino,
	};
	struct silofs_ivoaddr ivoa = {
		.ino = ino
	};
	int err;

	err = sbi_check_stage_inode(sbi, ino, stg_mode);
	if (err) {
		return err;
	}
	err = silofs_resolve_iaddr(sbi, ino, &iaddr);
	if (err) {
		return err;
	}
	err = silofs_sbi_resolve_voa(sbi, &iaddr.vaddr,
	                             stg_mode, &ivoa.voa);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_ii(sbi, &iaddr.vaddr, out_ii);
	if (!err) {
		return 0;
	}
	err = silofs_sbi_require_stable_at(sbi, &ivoa.voa.vaddr, stg_mode);
	if (err) {
		return err;
	}
	err = silofs_sbi_stage_inode_at(sbi, ivoa.ino, &ivoa.voa.vaddr,
	                                stg_mode, out_ii);
	if (err) {
		return err;
	}
	err = sbi_check_staged_inode(*out_ii, stg_mode);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_cached_ii(struct silofs_sb_info *sbi, ino_t ino,
                               struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = {
		.ino = ino,
	};
	int err;

	err = silofs_resolve_iaddr(sbi, ino, &iaddr);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_ii(sbi, &iaddr.vaddr, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_check_itype(const struct silofs_sb_info *sbi, mode_t mode)
{
	const mode_t sup = S_IFDIR | S_IFREG | S_IFLNK |
	                   S_IFSOCK | S_IFIFO | S_IFCHR | S_IFBLK;

	/*
	 * TODO-0031: Filter supported modes based on mount flags
	 */
	silofs_unused(sbi);

	return (((mode & S_IFMT) | sup) == sup) ? 0 : -EOPNOTSUPP;
}

int silofs_sbi_spawn_vnode(struct silofs_sb_info *sbi,
                           enum silofs_stype stype, silofs_dqid_t dqid,
                           struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_sbi_claim_vnode(sbi, stype, dqid, &vi);
	if (err) {
		return err;
	}
	silofs_vi_stamp_mark_visible(vi);
	silofs_vi_set_dqid(vi, dqid);
	*out_vi = vi;
	return 0;
}

int silofs_sbi_spawn_inode(struct silofs_sb_info *sbi,
                           const struct silofs_creds *creds, ino_t parent_ino,
                           mode_t parent_mode, mode_t mode, dev_t rdev,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = sbi_check_itype(sbi, mode);
	if (err) {
		return err;
	}
	err = silofs_sbi_claim_inode(sbi, &ii);
	if (err) {
		return err;
	}
	silofs_ii_stamp_mark_visible(ii);
	silofs_ii_setup_by(ii, creds, parent_ino, parent_mode, mode, rdev);
	*out_ii = ii;
	return 0;
}

static int sbi_discard_inode_at(struct silofs_sb_info *sbi,
                                const struct silofs_iaddr *iaddr)
{
	int err;

	err = silofs_discard_ino(sbi, iaddr->ino);
	if (err) {
		return err;
	}
	err = silofs_sbi_reclaim_vspace(sbi, &iaddr->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_remove_inode(struct silofs_sb_info *sbi,
                            struct silofs_inode_info *ii)
{
	struct silofs_iaddr iaddr;
	int err;

	silofs_ii_iaddr(ii, &iaddr);
	err = sbi_discard_inode_at(sbi, &iaddr);
	if (err) {
		return err;
	}
	sbi_forget_cached_ii(sbi, ii);
	return 0;
}

static int sbi_reclaim_vspace(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_voaddr voa;
	int err;

	err = silofs_sbi_resolve_voa(sbi, vaddr, SILOFS_STAGE_RO, &voa);
	if (err) {
		return err;
	}
	err = silofs_sbi_reclaim_vspace(sbi, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_remove_vnode_of(struct silofs_sb_info *sbi,
                               struct silofs_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = sbi_reclaim_vspace(sbi, vi_vaddr(vi));
	vi_decref(vi);
	return err;
}

int silofs_sbi_remove_vnode(struct silofs_sb_info *sbi,
                            struct silofs_vnode_info *vi)
{
	int err;

	err = sbi_remove_vnode_of(sbi, vi);
	if (err) {
		return err;
	}
	sbi_forget_cached_vi(sbi, vi);
	return 0;
}

int silofs_sbi_remove_vnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_vnode_info *vi = NULL;

	err = sbi_lookup_cached_vi(sbi, vaddr, &vi);
	if (!err) {
		err = silofs_sbi_remove_vnode(sbi, vi);
	} else {
		err = sbi_reclaim_vspace(sbi, vaddr);
	}
	return err;
}

static int sbi_stage_spleaf(struct silofs_sb_info *sbi,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stage_mode stg_mode,
                            struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni = NULL;

	return silofs_sbi_stage_spmaps_at(sbi, vaddr, stg_mode, &sni, out_sli);
}

static int sbi_stage_rdo_spleaf(struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_spleaf_info **out_sli)
{
	return sbi_stage_spleaf(sbi, vaddr, SILOFS_STAGE_RO, out_sli);
}

static int sbi_stage_mut_spleaf(struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_spleaf_info **out_sli)
{
	return sbi_stage_spleaf(sbi, vaddr, SILOFS_STAGE_RW, out_sli);
}

int silofs_sbi_test_unwritten(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_rdo_spleaf(sbi, vaddr, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_sbi_clear_unwritten(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_mut_spleaf(sbi, vaddr, &sli);
	if (err) {
		return err;
	}
	silofs_sli_clear_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_sbi_mark_unwritten(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_mut_spleaf(sbi, vaddr, &sli);
	if (err) {
		return err;
	}
	silofs_sli_mark_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_sbi_test_lastref(struct silofs_sb_info *sbi,
                            const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_rdo_spleaf(sbi, vaddr, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_last_refcnt(sli, vaddr);
	return 0;
}

int silofs_sbi_test_shared(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_rdo_spleaf(sbi, vaddr, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_shared_refcnt(sli, vaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_update_owner(struct silofs_sb_info *sbi,
                             const struct silofs_fs_args *args)
{
	sbi->sb_owner.uid = args->uid;
	sbi->sb_owner.gid = args->gid;
	sbi->sb_owner.pid = args->pid;
	sbi->sb_owner.umask = args->umask;
}

static void sbi_update_mntflags(struct silofs_sb_info *sbi,
                                const struct silofs_fs_args *args)
{
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;

	if (args->lazytime) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (args->noexec) {
		ms_flag_with |= MS_NOEXEC;
	} else {
		ms_flag_dont |= MS_NOEXEC;
	}
	if (args->nosuid) {
		ms_flag_with |= MS_NOSUID;
	} else {
		ms_flag_dont |= MS_NOSUID;
	}
	if (args->nodev) {
		ms_flag_with |= MS_NODEV;
	} else {
		ms_flag_dont |= MS_NODEV;
	}
	if (args->rdonly) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	sbi->sb_ms_flags |= ms_flag_with;
	sbi->sb_ms_flags &= ~ms_flag_dont;
}

static void sbi_update_ctlflags(struct silofs_sb_info *sbi,
                                const struct silofs_fs_args *args)
{
	if (args->kcopy) {
		sbi->sb_ctl_flags |= SILOFS_SBCF_KCOPY;
	}
	if (args->allowother) {
		sbi->sb_ctl_flags |= SILOFS_SBCF_ALLOWOTHER;
	}
	if (args->allowadmin) {
		sbi->sb_ctl_flags |= SILOFS_SBCF_ALLOWADMIN;
	}
}

static void sbi_setup_by_args(struct silofs_sb_info *sbi,
                              const struct silofs_fs_args *args)
{
	sbi_update_owner(sbi, args);
	sbi_update_mntflags(sbi, args);
	sbi_update_ctlflags(sbi, args);
}

void silofs_sbi_bind_uber(struct silofs_sb_info *sbi,
                          struct silofs_uber *uber)
{
	silofs_ui_bind_uber(&sbi->sb_ui, uber);
	sbi_setup_by_args(sbi, uber->ub_args);
}

void silofs_sbi_dirtify(struct silofs_sb_info *sbi)
{
	ui_dirtify(&sbi->sb_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_zero_stamp_view(struct silofs_sb_info *sbi)
{
	union silofs_view *view = sbi->sb_ui.u_si.s_view;

	silofs_zero_stamp_meta(view, SILOFS_STYPE_SUPER);
}

static void sbi_assign_vspace_span(struct silofs_sb_info *sbi)
{
	struct silofs_vrange vrange;

	silofs_vrange_of_space(&vrange, SILOFS_HEIGHT_SUPER, 0);
	sb_set_vrange(sbi->sb, &vrange);
}

static void sbi_setup_spstats(struct silofs_sb_info *sbi)
{
	silofs_sti_setup_spawned(&sbi->sb_sti, sbi);
}

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi)
{
	sbi_zero_stamp_view(sbi);
	sb_init(sbi->sb);
	sb_set_self(sbi->sb, sbi_uaddr(sbi));
	sb_setup_fresh(sbi->sb);
	sbi_setup_spstats(sbi);
	sbi_assign_vspace_span(sbi);
	sbi_dirtify(sbi);
}

void silofs_sbi_setup_btime(struct silofs_sb_info *sbi)
{
	sb_set_birth_time(sbi->sb, silofs_time_now());
	sbi_dirtify(sbi);
}

void silofs_sbi_setup_ctime(struct silofs_sb_info *sbi)
{
	sb_set_clone_time(sbi->sb, silofs_time_now());
	sbi_dirtify(sbi);
}

static void ucred_copyto(const struct silofs_ucred *ucred,
                         struct silofs_ucred *other)
{
	memcpy(other, ucred, sizeof(*other));
}

static void sbi_update_by(struct silofs_sb_info *sbi,
                          const struct silofs_sb_info *sbi_other)
{
	ucred_copyto(&sbi_other->sb_owner, &sbi->sb_owner);
	silofs_itbi_update_by(&sbi->sb_itbi, &sbi_other->sb_itbi);
	sbi->sb_ctl_flags = sbi_other->sb_ctl_flags;
	sbi->sb_ms_flags = sbi_other->sb_ms_flags;
}

void silofs_sbi_make_clone(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other)
{
	struct silofs_super_block *sb = sbi->sb;
	const struct silofs_super_block *sb_other = sbi_other->sb;

	sbi_update_by(sbi, sbi_other);
	sb_assign(sb, sb_other);
	sb_clone_sproots(sb, sb_other);
	sb_generate_treeid(sb);
	sb_reset_main_blobids(sb);
	sb_reset_cold_blobids(sb);
	sb_set_self(sb, sbi_uaddr(sbi));
	sb_set_origin(sb, sbi_uaddr(sbi_other));
	sbi_dirtify(sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_xinit(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	return silofs_itbi_init(&sbi->sb_itbi, alloc);
}

void silofs_sbi_xfini(struct silofs_sb_info *sbi)
{
	silofs_itbi_fini(&sbi->sb_itbi);
}


