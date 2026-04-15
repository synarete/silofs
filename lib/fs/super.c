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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <silofs/base.h>
#include <silofs/fs.h>
#include <silofs/run.h>

static void tm64b_htox(struct silofs_tm64b *tm64, const struct tm *tm)
{
	tm64->tm_sec      = silofs_cpu_to_le16((uint16_t)tm->tm_sec);
	tm64->tm_min      = silofs_cpu_to_le16((uint16_t)tm->tm_min);
	tm64->tm_hour     = (uint8_t)(tm->tm_hour);
	tm64->tm_mday     = (uint8_t)(tm->tm_mday);
	tm64->tm_mon      = (uint8_t)(tm->tm_mon);
	tm64->tm_wday     = (uint8_t)(tm->tm_wday);
	tm64->tm_year     = silofs_cpu_to_le32((uint32_t)tm->tm_year);
	tm64->tm_yday     = silofs_cpu_to_le32((uint32_t)tm->tm_yday);
	tm64->tm_gmtoff   = silofs_cpu_to_le64((uint64_t)tm->tm_gmtoff);
	tm64->tm_reserved = 0;
}

static void tm64b_xtoh(const struct silofs_tm64b *tm64, struct tm *tm)
{
	tm->tm_sec    = (int)silofs_le16_to_cpu(tm64->tm_sec);
	tm->tm_min    = (int)silofs_le16_to_cpu(tm64->tm_min);
	tm->tm_hour   = (int)(tm64->tm_hour);
	tm->tm_mday   = (int)(tm64->tm_mday);
	tm->tm_mon    = (int)(tm64->tm_mon);
	tm->tm_wday   = (int)(tm64->tm_wday);
	tm->tm_year   = (int)silofs_le32_to_cpu(tm64->tm_year);
	tm->tm_yday   = (int)silofs_le32_to_cpu(tm64->tm_yday);
	tm->tm_gmtoff = (long)silofs_le64_to_cpu(tm64->tm_gmtoff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static void
sb_set_flags(struct silofs_super_block *sb, enum silofs_superf flags)
{
	sb->sb_flags = silofs_cpu_to_le32((uint32_t)flags);
}

static void
sb_add_flags(struct silofs_super_block *sb, enum silofs_superf flags)
{
	sb_set_flags(sb, flags | sb_flags(sb));
}

static void
sb_set_swversion(struct silofs_super_block *sb, const char *sw_version)
{
	const size_t len     = silofs_str_length(sw_version);
	const size_t len_max = ARRAY_SIZE(sb->sb_sw_version) - 1;

	memcpy(sb->sb_sw_version, sw_version, silofs_min(len, len_max));
}

int silofs_sb_check_version(const struct silofs_super_block *sb)
{
	if (sb_magic(sb) != SILOFS_SUPER_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
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

static void sb_lrange(const struct silofs_super_block *sb,
                      struct silofs_lrange *out_lrange)
{
	silofs_lrange128_xtoh(&sb->sb_lrange, out_lrange);
}

static void sb_set_lrange(struct silofs_super_block *sb,
                          const struct silofs_lrange *lrange)
{
	silofs_lrange128_htox(&sb->sb_lrange, lrange);
}

static enum silofs_height sb_height(const struct silofs_super_block *sb)
{
	struct silofs_lrange lrange;

	sb_lrange(sb, &lrange);
	return lrange.height;
}

static void sb_lv_prev(const struct silofs_super_block *sb,
                       struct silofs_blobid *out_blobid)
{
	silofs_blobid56b_xtoh(&sb->sb_lv_prev, out_blobid);
}

static void sb_set_lv_prev(struct silofs_super_block *sb,
                           const struct silofs_blobid *blobid)
{
	silofs_blobid56b_htox(&sb->sb_lv_prev, blobid);
}

static void sb_lv_curr(const struct silofs_super_block *sb,
                       struct silofs_blobid *out_blobid)
{
	silofs_blobid56b_xtoh(&sb->sb_lv_curr, out_blobid);
}

static void sb_set_lv_curr(struct silofs_super_block *sb,
                           const struct silofs_blobid *blobid)
{
	silofs_blobid56b_htox(&sb->sb_lv_curr, blobid);
}

static void sb_set_lv_ids(struct silofs_super_block *sb,
                          const struct silofs_blobid *blobid)
{
	sb_set_lv_prev(sb, blobid);
	sb_set_lv_curr(sb, blobid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsid64b *
sb_mainsilofs_lsid_by(const struct silofs_super_block *sb,
                      enum silofs_vtype vtype)
{
	const struct silofs_lsid64b *ret;

	switch (vtype) {
	case SILOFS_VTYPE_LSMAP:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_lsmap;
		break;
	case SILOFS_VTYPE_INODE:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_inode;
		break;
	case SILOFS_VTYPE_XANODE:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_xanode;
		break;
	case SILOFS_VTYPE_DTNODE:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_dtnode;
		break;
	case SILOFS_VTYPE_SYMVAL:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_symval;
		break;
	case SILOFS_VTYPE_FTNODE:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_ftnode;
		break;
	case SILOFS_VTYPE_DATA1K:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_data1k;
		break;
	case SILOFS_VTYPE_DATA4K:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_data4k;
		break;
	case SILOFS_VTYPE_DATA64K:
		ret = &sb->sb_main_lsid.sb_silofs_lsid_data64k;
		break;
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_SPNODE2:
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
	case SILOFS_VTYPE_LAST:
	default:
		ret = nullptr;
		break;
	}
	return ret;
}

static struct silofs_lsid64b *
sb_mainsilofs_lsid_by2(struct silofs_super_block *sb, enum silofs_vtype vtype)
{
	const struct silofs_lsid64b *lsid64 = sb_mainsilofs_lsid_by(sb, vtype);

	return unconst(lsid64);
}

static void sb_main_lsid(const struct silofs_super_block *sb,
                         enum silofs_vtype vtype, struct silofs_lsid *out_lsid)
{
	const struct silofs_lsid64b *lsid64 = sb_mainsilofs_lsid_by(sb, vtype);

	if (likely(lsid64 != nullptr)) {
		silofs_lsid64b_xtoh(lsid64, out_lsid);
	} else {
		silofs_lsid_reset(out_lsid);
	}
}

static void
sb_set_main_lsid(struct silofs_super_block *sb, enum silofs_vtype vtype,
                 const struct silofs_lsid *lsid)
{
	struct silofs_lsid64b *bid = sb_mainsilofs_lsid_by2(sb, vtype);

	if (likely(bid != nullptr)) {
		silofs_lsid64b_htox(bid, lsid);
	}
}

static void sb_reset_main_lsids(struct silofs_super_block *sb)
{
	struct silofs_lsid64b *bid;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		bid = sb_mainsilofs_lsid_by2(sb, vtype);
		if (bid != nullptr) {
			silofs_lsid64b_reset(bid);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr128b *
sb_sproot_by(const struct silofs_super_block *sb, enum silofs_vtype vtype)
{
	const struct silofs_uaddr128b *ret;

	switch (vtype) {
	case SILOFS_VTYPE_LSMAP:
		ret = &sb->sb_sproots.sb_sproot_lsmap;
		break;
	case SILOFS_VTYPE_INODE:
		ret = &sb->sb_sproots.sb_sproot_inode;
		break;
	case SILOFS_VTYPE_XANODE:
		ret = &sb->sb_sproots.sb_sproot_xanode;
		break;
	case SILOFS_VTYPE_DTNODE:
		ret = &sb->sb_sproots.sb_sproot_dtnode;
		break;
	case SILOFS_VTYPE_FTNODE:
		ret = &sb->sb_sproots.sb_sproot_ftnode;
		break;
	case SILOFS_VTYPE_SYMVAL:
		ret = &sb->sb_sproots.sb_sproot_symval;
		break;
	case SILOFS_VTYPE_DATA1K:
		ret = &sb->sb_sproots.sb_sproot_data1k;
		break;
	case SILOFS_VTYPE_DATA4K:
		ret = &sb->sb_sproots.sb_sproot_data4k;
		break;
	case SILOFS_VTYPE_DATA64K:
		ret = &sb->sb_sproots.sb_sproot_data64k;
		break;
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
	case SILOFS_VTYPE_SPNODE2:
	case SILOFS_VTYPE_LAST:
	default:
		ret = nullptr;
		break;
	}
	return ret;
}

static struct silofs_uaddr128b *
sb_mut_sproot_by(struct silofs_super_block *sb, enum silofs_vtype vtype)
{
	const struct silofs_uaddr128b *uaddr128 = sb_sproot_by(sb, vtype);

	return unconst(uaddr128);
}

static void
sb_sproot_of(const struct silofs_super_block *sb, enum silofs_vtype vtype,
             struct silofs_uaddr *out_uaddr)
{
	const struct silofs_uaddr128b *uaddr128 = sb_sproot_by(sb, vtype);

	if (likely(uaddr128 != nullptr)) {
		silofs_uaddr128b_xtoh(uaddr128, out_uaddr);
	} else {
		silofs_uaddr_reset(out_uaddr);
	}
}

static void
sb_set_sproot_of(struct silofs_super_block *sb, enum silofs_vtype vtype,
                 const struct silofs_uaddr *uaddr)
{
	struct silofs_uaddr128b *uaddr128 = sb_mut_sproot_by(sb, vtype);

	if (likely(uaddr128 != nullptr)) {
		silofs_uaddr128b_htox(uaddr128, uaddr);
	}
}

static void sb_reset_sproots(struct silofs_super_block *sb)
{
	struct silofs_uaddr128b *uaddr128;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		uaddr128 = sb_mut_sproot_by(sb, vtype);
		if (uaddr128 != nullptr) {
			silofs_uaddr128b_htox(uaddr128, silofs_uaddr_none());
		}
	}
}

static void sb_clone_sproots(struct silofs_super_block *sb,
                             const struct silofs_super_block *sb_other)
{
	struct silofs_uaddr uaddr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (silofs_vtype_isvnode(vtype)) {
			sb_sproot_of(sb_other, vtype, &uaddr);
			sb_set_sproot_of(sb, vtype, &uaddr);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
sb_init(struct silofs_super_block *sb, const struct silofs_blobid *blobid)
{
	sb_set_magic(sb, SILOFS_SUPER_MAGIC);
	sb_set_version(sb, SILOFS_FMT_VERSION);
	sb_set_flags(sb, SILOFS_SUPERF_NONE);
	sb_set_swversion(sb, silofs_version.string);
	sb_set_lv_ids(sb, blobid);
	sb->sb_endianness = SILOFS_ENDIANNESS_LE;
	sb_reset_sproots(sb);
	sb_reset_main_lsids(sb);
}

static void sb_btime_curr(const struct silofs_super_block *sb, struct tm *tm)
{
	tm64b_xtoh(&sb->sb_btime_curr, tm);
}

static void
sb_set_btime_curr(struct silofs_super_block *sb, const struct tm *tm)
{
	tm64b_htox(&sb->sb_btime_curr, tm);
}

static void
sb_set_btime_prev(struct silofs_super_block *sb, const struct tm *tm)
{
	tm64b_htox(&sb->sb_btime_prev, tm);
}

static void sb_btime_base(const struct silofs_super_block *sb, struct tm *tm)
{
	tm64b_xtoh(&sb->sb_btime_base, tm);
}

static void
sb_set_btime_base(struct silofs_super_block *sb, const struct tm *tm)
{
	tm64b_htox(&sb->sb_btime_base, tm);
}

static void
sb_set_birth_tms(struct silofs_super_block *sb, const struct tm *tm)
{
	sb_set_btime_curr(sb, tm);
	sb_set_btime_prev(sb, tm);
	sb_set_btime_base(sb, tm);
}

static void sb_clone_tms(struct silofs_super_block *sb,
                         const struct silofs_super_block *sb_other)
{
	struct tm tm;

	sb_btime_base(sb_other, &tm);
	sb_set_btime_base(sb, &tm);

	sb_btime_curr(sb_other, &tm);
	sb_set_btime_prev(sb, &tm);
}

static void sb_clone_raw(struct silofs_super_block *sb,
                         const struct silofs_super_block *sb_other)
{
	struct silofs_blobid blobid;

	sb_lv_curr(sb, &blobid);
	memcpy(sb, sb_other, sizeof(*sb));
	sb_set_lv_curr(sb, &blobid);
	sb_lv_curr(sb_other, &blobid);
	sb_set_lv_prev(sb, &blobid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_sproot(const struct silofs_uaddr *uaddr)
{
	const enum silofs_height height = silofs_uaddr_height(uaddr);
	const enum silofs_vtype vtype   = silofs_uaddr_vtype(uaddr);

	if (silofs_uaddr_isnull(uaddr)) {
		return 0;
	}
	if ((vtype != SILOFS_VTYPE_SPNODE) ||
	    (height != (SILOFS_HEIGHT_SUPER - 1))) {
		log_err("bad spnode root: vtype=%d height=%d", (int)vtype,
		        (int)height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int sb_verify_sproots(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype)) {
			continue;
		}
		sb_sproot_of(sb, vtype, &uaddr);
		err = verify_sproot(&uaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int sb_verify_height(const struct silofs_super_block *sb)
{
	const enum silofs_height height = sb_height(sb);

	if (height != SILOFS_HEIGHT_SUPER) {
		log_err("illegal sb height: height=%d", height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_super_block(const struct silofs_super_block *sb)
{
	int err;

	err = sb_verify_height(sb);
	if (err) {
		return err;
	}
	err = sb_verify_sproots(sb);
	if (err) {
		return err;
	}
	err = silofs_verify_space_stats(&sb->sb_space_stats_curr);
	if (err) {
		return err;
	}
	err = silofs_verify_space_stats(&sb->sb_space_stats_prev);
	if (err) {
		return err;
	}
	/* TODO: complete me */
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_sbi_add_flags(struct silofs_sb_info *sbi, enum silofs_superf flags)
{
	sb_add_flags(sbi->sb, flags);
	silofs_sbi_markdirty(sbi);
}

bool silofs_sbi_test_flags(const struct silofs_sb_info *sbi,
                           enum silofs_superf flags)
{
	return (sb_flags(sbi->sb) & flags) == flags;
}

bool silofs_sbi_is_fossil(const struct silofs_sb_info *sbi)
{
	return silofs_sb_test_flags(sbi->sb, SILOFS_SUPERF_FOSSIL);
}

int silof_sbi_check_mut_fs(const struct silofs_sb_info *sbi)
{
	return silofs_sbi_is_fossil(sbi) ? -SILOFS_EROFS : 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void uaddr_setup_super(struct silofs_uaddr *out_uaddr,
                              const struct silofs_blobid *blobid)
{
	struct silofs_lsid lsid;

	silofs_lsid_setup(&lsid, blobid, 0);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

void silofs_sbi_resolve_refs(const struct silofs_sb_info *sbi,
                             struct silofs_sb_refs *out_refs)
{
	struct silofs_blobid blobid;

	sb_lv_prev(sbi->sb, &blobid);
	uaddr_setup_super(&out_refs->prev, &blobid);
	sb_lv_curr(sbi->sb, &blobid);
	uaddr_setup_super(&out_refs->curr, &blobid);
}

void silofs_sbi_self_blobid(const struct silofs_sb_info *sbi,
                            struct silofs_blobid *out_blobid)
{
	sb_lv_curr(sbi->sb, out_blobid);
}

void silofs_sbi_self_layerid(const struct silofs_sb_info *sbi,
                             struct silofs_layerid *out_layerid)
{
	struct silofs_blobid blobid;

	silofs_sbi_self_blobid(sbi, &blobid);
	silofs_layerid_assign(out_layerid, &blobid.layerid);
}

int silofs_sbi_main_lseg(const struct silofs_sb_info *sbi,
                         enum silofs_vtype vspace,
                         struct silofs_lsid *out_lsid)
{
	sb_main_lsid(sbi->sb, vspace, out_lsid);
	return silofs_lsid_isnull(out_lsid) ? -SILOFS_ENOENT : 0;
}

void silofs_sbi_bind_main_lseg(struct silofs_sb_info *sbi,
                               enum silofs_vtype vspace,
                               const struct silofs_lsid *lsid)
{
	sb_set_main_lsid(sbi->sb, vspace, lsid);
	silofs_sbi_markdirty(sbi);
}

bool silofs_sbi_has_main_lseg(const struct silofs_sb_info *sbi,
                              enum silofs_vtype vspace)
{
	struct silofs_lsid lseg_id;

	silofs_sbi_main_lseg(sbi, vspace, &lseg_id);
	return (silofs_lsid_size(&lseg_id) > 0);
}

static size_t sb_slot_of(const struct silofs_super_block *sb, off_t voff)
{
	struct silofs_lrange lrange;
	ssize_t span;

	sb_lrange(sb, &lrange);
	span = silofs_height_to_space_span(lrange.height - 1);
	return (size_t)(voff / span);
}

static off_t sbi_bpos_of_child(const struct silofs_sb_info *sbi, off_t voff)
{
	const size_t slot = sb_slot_of(sbi->sb, voff);

	return (long)slot * SILOFS_SPMAP_SIZE;
}

static off_t
sbi_base_voff_of_child(const struct silofs_sb_info *sbi, off_t voff)
{
	struct silofs_lrange lrange;

	silofs_unused(sbi);
	silofs_lrange_of_spmap(&lrange, SILOFS_HEIGHT_SUPER - 1, voff);
	return lrange.beg;
}

static void
sbi_sproot_of(const struct silofs_sb_info *sbi, enum silofs_vtype vtype,
              struct silofs_uaddr *out_uaddr)
{
	sb_sproot_of(sbi->sb, vtype, out_uaddr);
}

static void
sbi_main_uaddr(const struct silofs_sb_info *sbi, off_t voff,
               enum silofs_vtype vspace, struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const off_t bpos = sbi_bpos_of_child(sbi, voff);
	const off_t base = sbi_base_voff_of_child(sbi, voff);

	silofs_sbi_main_lseg(sbi, vspace, &lsid);
	silofs_uaddr_setup(out_uaddr, &lsid, bpos, base);
}

void silofs_sbi_resolve_main_at(const struct silofs_sb_info *sbi, off_t voff,
                                enum silofs_vtype vspace,
                                struct silofs_uaddr *out_uaddr)
{
	sbi_main_uaddr(sbi, voff, vspace, out_uaddr);
}

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
                         enum silofs_vtype vtype,
                         struct silofs_uaddr *out_uaddr)
{
	sbi_sproot_of(sbi, vtype, out_uaddr);
	return !silofs_uaddr_isnull(out_uaddr) ? 0 : -SILOFS_ENOENT;
}

int silofs_sbi_resolve_child(const struct silofs_sb_info *sbi,
                             enum silofs_vtype vtype,
                             struct silofs_uaddr *out_uaddr)
{
	sbi_sproot_of(sbi, vtype, out_uaddr);
	return !silofs_uaddr_isnull(out_uaddr) ? 0 : -SILOFS_ENOENT;
}

void silofs_sbi_bind_child(struct silofs_sb_info *sbi, enum silofs_vtype vtype,
                           const struct silofs_uaddr *uaddr)
{
	sb_set_sproot_of(sbi->sb, vtype, uaddr);
	silofs_sbi_markdirty(sbi);
}

bool silofs_sbi_ismutable_lsid(const struct silofs_sb_info *sbi,
                               const struct silofs_lsid *lsid)
{
	struct silofs_layerid layerid;

	silofs_sbi_self_layerid(sbi, &layerid);
	return silofs_lsid_has_layerid(lsid, &layerid);
}

bool silofs_sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
                                const struct silofs_laddr *laddr)
{
	return silofs_sbi_ismutable_lsid(sbi, &laddr->lsid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
do_stage_spleaf(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
                enum silofs_stg_mode stg_mode,
                struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf_of(task, vaddr, stg_mode, out_sli);
}

static void lsmap_vaddr_of(const struct silofs_spleaf_info *sli,
                           struct silofs_vaddr *out_vaddr)
{
	struct silofs_lrange lrange;
	enum silofs_vtype refvtype;

	refvtype = silofs_sli_refvtype(sli);
	silofs_sli_get_lrange(sli, &lrange);
	silofs_vaddr_of_lsmap(out_vaddr, refvtype, lrange.beg);
}

static int do_stage_lsmap_of(struct silofs_task_ctx *task,
                             const struct silofs_spleaf_info *sli,
                             enum silofs_stg_mode stg_mode,
                             struct silofs_lsmap_info **out_lsi)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vni = nullptr;
	int err;

	lsmap_vaddr_of(sli, &vaddr);
	err = silofs_stage_vnode(task, nullptr, &vaddr, stg_mode, &vni);
	if (err) {
		return err;
	}
	*out_lsi = silofs_lsi_from_vni(vni);
	return 0;
}

static int
stage_lsmap_of(struct silofs_task_ctx *task, struct silofs_spleaf_info *sli,
               enum silofs_stg_mode stg_mode,
               struct silofs_lsmap_info **out_lsi)
{
	int err;

	silofs_sli_incref(sli);
	err = do_stage_lsmap_of(task, sli, stg_mode, out_lsi);
	silofs_sli_decref(sli);
	silofs_assert_ok(err);
	return err;
}

static int stage_spleaf_lsmap(struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr,
                              enum silofs_stg_mode stg_mode,
                              struct silofs_spleaf_info **out_sli,
                              struct silofs_lsmap_info **out_lsi)
{
	int err;

	err = do_stage_spleaf(task, vaddr, stg_mode, out_sli);
	if (err) {
		return err;
	}
	err = stage_lsmap_of(task, *out_sli, stg_mode, out_lsi);
	if (err) {
		return err;
	}
	return 0;
}

static int
stage_lsmap(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
            enum silofs_stg_mode stg_mode, struct silofs_lsmap_info **out_lsi)
{
	struct silofs_spleaf_info *sli = nullptr;

	return stage_spleaf_lsmap(task, vaddr, stg_mode, &sli, out_lsi);
}

int silofs_test_unwritten_at(struct silofs_task_ctx *task,
                             const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_lsmap_info *lsi = nullptr;
	int err;

	err = stage_lsmap(task, vaddr, SILOFS_STG_CUR, &lsi);
	if (err) {
		return err;
	}
	*out_res = silofs_lsi_has_unwritten_at(lsi, vaddr);
	return 0;
}

int silofs_clear_unwritten_at(struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_lsmap_info *lsi = nullptr;
	int err;

	err = stage_lsmap(task, vaddr, SILOFS_STG_COW, &lsi);
	if (err) {
		return err;
	}
	silofs_lsi_clear_unwritten_at(lsi, vaddr);
	return 0;
}

int silofs_mark_unwritten_at(struct silofs_task_ctx *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_lsmap_info *lsi = nullptr;
	int err;

	err = stage_lsmap(task, vaddr, SILOFS_STG_COW, &lsi);
	if (err) {
		return err;
	}
	silofs_lsi_mark_unwritten_at(lsi, vaddr);
	return 0;
}

int silofs_test_last_allocated(struct silofs_task_ctx *task,
                               const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_lsmap_info *lsi = nullptr;
	int err;

	err = stage_lsmap(task, vaddr, SILOFS_STG_CUR, &lsi);
	if (err) {
		return err;
	}
	*out_res = silofs_lsi_is_last_allocated(lsi, vaddr);
	return 0;
}

int silofs_test_shared_dbkref(struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = nullptr;
	struct silofs_lsmap_info *lsi  = nullptr;
	size_t refcnt                  = 0;
	int err;

	*out_res = false;
	if (!silofs_vaddr_isdata64k(vaddr)) {
		return 0;
	}
	err = stage_spleaf_lsmap(task, vaddr, SILOFS_STG_CUR, &sli, &lsi);
	if (err) {
		return err;
	}
	refcnt   = silofs_lsi_refcnt_at(lsi, vaddr);
	*out_res = (refcnt > 1);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_sbi_uaddr(const struct silofs_sb_info *sbi)
{
	return silofs_uni_uaddr(&sbi->sb_uni);
}

const struct silofs_laddr *silofs_sbi_laddr(const struct silofs_sb_info *sbi)
{
	return silofs_uni_laddr(&sbi->sb_uni);
}

static const struct silofs_blobid *sbi_blobid(const struct silofs_sb_info *sbi)
{
	return &sbi->sb_uni.un_uaddr.laddr.lsid.blobid;
}

void silofs_sbi_incref(struct silofs_sb_info *sbi)
{
	if (likely(sbi != nullptr)) {
		silofs_lni_incref(&sbi->sb_uni.un_lni);
	}
}

void silofs_sbi_decref(struct silofs_sb_info *sbi)
{
	if (likely(sbi != nullptr)) {
		silofs_lni_decref(&sbi->sb_uni.un_lni);
	}
}

void silofs_sbi_markdirty(struct silofs_sb_info *sbi)
{
	silofs_uni_markdirty(&sbi->sb_uni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_setup_birth_tms_now(struct silofs_sb_info *sbi)
{
	struct tm now;

	silofs_localtime_now(&now);
	sb_set_birth_tms(sbi->sb, &now);
	silofs_sbi_markdirty(sbi);
}

static void sbi_set_lv_birth(struct silofs_sb_info *sbi)
{
	struct tm now;

	silofs_localtime_now(&now);
	sb_set_btime_curr(sbi->sb, &now);
	silofs_sbi_markdirty(sbi);
}

static void sbi_assign_vspace_span(struct silofs_sb_info *sbi)
{
	struct silofs_lrange lrange;

	silofs_lrange_of_space(&lrange, SILOFS_HEIGHT_SUPER, 0);
	sb_set_lrange(sbi->sb, &lrange);
}

static void sbi_setup_spstats(struct silofs_sb_info *sbi)
{
	silofs_sbst_setup_spawned(sbi);
}

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi)
{
	sb_init(sbi->sb, sbi_blobid(sbi));
	sbi_setup_spstats(sbi);
	sbi_setup_birth_tms_now(sbi);
	sbi_assign_vspace_span(sbi);
	silofs_sbi_markdirty(sbi);
}

static void sbi_make_fork_of(struct silofs_sb_info *sbi,
                             const struct silofs_sb_info *sbi_other)
{
	struct silofs_super_block *sb             = sbi->sb;
	const struct silofs_super_block *sb_other = sbi_other->sb;

	sb_clone_raw(sb, sb_other);
	sb_clone_sproots(sb, sb_other);
	sb_clone_tms(sb, sb_other);
	sb_reset_main_lsids(sb);
	silofs_sbi_markdirty(sbi);
}

void silofs_sbi_make_fork_of(struct silofs_sb_info *sbi_new,
                             const struct silofs_sb_info *sbi_cur)
{
	sbi_make_fork_of(sbi_new, sbi_cur);
	sbi_set_lv_birth(sbi_new);
	silofs_sbst_setup_forked(sbi_new, sbi_cur);
	silofs_sbst_account_super(sbi_new);
	silofs_sbst_force_into_sb(sbi_new);
}

void silofs_sbi_resolve_lmap(const struct silofs_sb_info *sbi,
                             struct silofs_spmap_lmap *out_lmap)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	enum silofs_vtype vtype   = SILOFS_VTYPE_NONE;
	unsigned int cnt          = 0;

	while (++vtype < SILOFS_VTYPE_LAST) {
		sbi_sproot_of(sbi, vtype, &uaddr);
		if (silofs_uaddr_isnull(&uaddr)) {
			continue;
		}
		silofs_laddr_assign(&out_lmap->laddr[cnt], &uaddr.laddr);
		out_lmap->len[cnt] = silofs_laddr_len(&uaddr.laddr);
		cnt++;
	}
	out_lmap->cnt = cnt;
}
