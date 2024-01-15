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
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>


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
		return -SILOFS_EINVAL;
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
	silofs_vrange128_xtoh(&sb->sb_vrange, out_vrange);
}

static void sb_set_vrange(struct silofs_super_block *sb,
                          const struct silofs_vrange *vrange)
{
	silofs_vrange128_htox(&sb->sb_vrange, vrange);
}

static enum silofs_height sb_height(const struct silofs_super_block *sb)
{
	struct silofs_vrange vrange;

	sb_vrange(sb, &vrange);
	return vrange.height;
}

static void sb_lvid(const struct silofs_super_block *sb,
                    struct silofs_lvid *out_lvid)
{
	silofs_lvid_assign(out_lvid, &sb->sb_lvid);
}

static void sb_set_lvid(struct silofs_super_block *sb,
                        const struct silofs_lvid *lvid)
{
	silofs_lvid_assign(&sb->sb_lvid, lvid);
}

static void sb_self(const struct silofs_super_block *sb,
                    struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&sb->sb_self_uaddr, out_uaddr);
}

static void sb_set_self(struct silofs_super_block *sb,
                        const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&sb->sb_self_uaddr, uaddr);
	sb_set_lvid(sb, &uaddr->laddr.lsegid.lvid);
}

static void sb_origin(const struct silofs_super_block *sb,
                      struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_xtoh(&sb->sb_orig_uaddr, out_uaddr);
}

static void sb_set_origin(struct silofs_super_block *sb,
                          const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_htox(&sb->sb_orig_uaddr, uaddr);
}

static void sb_generate_lvid(struct silofs_super_block *sb)
{
	struct silofs_lvid lvid;

	silofs_lvid_generate(&lvid);
	sb_set_lvid(sb, &lvid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsegid32b *
sb_mainlsegid_by(const struct silofs_super_block *sb, enum silofs_ltype ltype)
{
	const struct silofs_lsegid32b *ret;

	switch (ltype) {
	case SILOFS_LTYPE_DATA1K:
		ret = &sb->sb_main_lsegid.sb_lsegid_data1k;
		break;
	case SILOFS_LTYPE_DATA4K:
		ret = &sb->sb_main_lsegid.sb_lsegid_data4k;
		break;
	case SILOFS_LTYPE_DATABK:
		ret = &sb->sb_main_lsegid.sb_lsegid_databk;
		break;
	case SILOFS_LTYPE_INODE:
		ret = &sb->sb_main_lsegid.sb_lsegid_inode;
		break;
	case SILOFS_LTYPE_XANODE:
		ret = &sb->sb_main_lsegid.sb_lsegid_xanode;
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = &sb->sb_main_lsegid.sb_lsegid_dtnode;
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = &sb->sb_main_lsegid.sb_lsegid_ftnode;
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = &sb->sb_main_lsegid.sb_lsegid_symval;
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static struct silofs_lsegid32b *
sb_mainlsegid_by2(struct silofs_super_block *sb, enum silofs_ltype ltype)
{
	const struct silofs_lsegid32b *bid = sb_mainlsegid_by(sb, ltype);

	return unconst(bid);
}

static void sb_main_lsegid(const struct silofs_super_block *sb,
                           enum silofs_ltype ltype,
                           struct silofs_lsegid *out_lsegid)
{
	const struct silofs_lsegid32b *bid = sb_mainlsegid_by(sb, ltype);

	if (likely(bid != NULL)) {
		silofs_lsegid32b_xtoh(bid, out_lsegid);
	} else {
		silofs_lsegid_reset(out_lsegid);
	}
}

static void sb_set_main_lsegid(struct silofs_super_block *sb,
                               enum silofs_ltype ltype,
                               const struct silofs_lsegid *lsegid)
{
	struct silofs_lsegid32b *bid = sb_mainlsegid_by2(sb, ltype);

	if (likely(bid != NULL)) {
		silofs_lsegid32b_htox(bid, lsegid);
	}
}

static void sb_reset_main_lsegids(struct silofs_super_block *sb)
{
	struct silofs_lsegid32b *bid;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		bid = sb_mainlsegid_by2(sb, ltype);
		if (bid != NULL) {
			silofs_lsegid32b_reset(bid);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr64b *
sb_sproot_by(const struct silofs_super_block *sb, enum silofs_ltype ltype)
{
	const struct silofs_uaddr64b *ret;

	switch (ltype) {
	case SILOFS_LTYPE_INODE:
		ret = &sb->sb_sproots.sb_sproot_inode;
		break;
	case SILOFS_LTYPE_XANODE:
		ret = &sb->sb_sproots.sb_sproot_xanode;
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = &sb->sb_sproots.sb_sproot_dtnode;
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = &sb->sb_sproots.sb_sproot_ftnode;
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = &sb->sb_sproots.sb_sproot_symval;
		break;
	case SILOFS_LTYPE_DATA1K:
		ret = &sb->sb_sproots.sb_sproot_data1k;
		break;
	case SILOFS_LTYPE_DATA4K:
		ret = &sb->sb_sproots.sb_sproot_data4k;
		break;
	case SILOFS_LTYPE_DATABK:
		ret = &sb->sb_sproots.sb_sproot_databk;
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static struct silofs_uaddr64b *
sb_sproot_by2(struct silofs_super_block *sb, enum silofs_ltype ltype)
{
	const struct silofs_uaddr64b *uaddr64 = sb_sproot_by(sb, ltype);

	return unconst(uaddr64);
}

static void sb_sproot_of(const struct silofs_super_block *sb,
                         enum silofs_ltype ltype,
                         struct silofs_uaddr *out_uaddr)
{
	const struct silofs_uaddr64b *uaddr64 = sb_sproot_by(sb, ltype);

	if (likely(uaddr64 != NULL)) {
		silofs_uaddr64b_xtoh(uaddr64, out_uaddr);
	} else {
		silofs_uaddr_reset(out_uaddr);
	}
}

static void sb_set_sproot_of(struct silofs_super_block *sb,
                             enum silofs_ltype ltype,
                             const struct silofs_uaddr *uaddr)
{
	struct silofs_uaddr64b *uaddr64 = sb_sproot_by2(sb, ltype);

	if (likely(uaddr64 != NULL)) {
		silofs_uaddr64b_htox(uaddr64, uaddr);
	}
}

static void sb_reset_sproots(struct silofs_super_block *sb)
{
	struct silofs_uaddr64b *uaddr64;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		uaddr64 = sb_sproot_by2(sb, ltype);
		if (uaddr64 != NULL) {
			silofs_uaddr64b_htox(uaddr64, silofs_uaddr_none());
		}
	}
}

static void sb_clone_sproots(struct silofs_super_block *sb,
                             const struct silofs_super_block *sb_other)
{
	struct silofs_uaddr uaddr;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (ltype_isvnode(ltype)) {
			sb_sproot_of(sb_other, ltype, &uaddr);
			sb_set_sproot_of(sb, ltype, &uaddr);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_iv *
sb_rootiv_by(const struct silofs_super_block *sb, enum silofs_ltype ltype)
{
	const struct silofs_iv *ret;

	switch (ltype) {
	case SILOFS_LTYPE_INODE:
		ret = &sb->sb_rootivs.sb_iv_inode;
		break;
	case SILOFS_LTYPE_XANODE:
		ret = &sb->sb_rootivs.sb_iv_xanode;
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = &sb->sb_rootivs.sb_iv_dtnode;
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = &sb->sb_rootivs.sb_iv_ftnode;
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = &sb->sb_rootivs.sb_iv_symval;
		break;
	case SILOFS_LTYPE_DATA1K:
		ret = &sb->sb_rootivs.sb_iv_data1k;
		break;
	case SILOFS_LTYPE_DATA4K:
		ret = &sb->sb_rootivs.sb_iv_data4k;
		break;
	case SILOFS_LTYPE_DATABK:
		ret = &sb->sb_rootivs.sb_iv_databk;
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static struct silofs_iv *
sb_rootiv_by2(struct silofs_super_block *sb, enum silofs_ltype ltype)
{
	const struct silofs_iv *ret = sb_rootiv_by(sb, ltype);

	return unconst(ret);
}

static void sb_rootiv_of(const struct silofs_super_block *sb,
                         enum silofs_ltype ltype, struct silofs_iv *out_iv)
{
	const struct silofs_iv *iv = sb_rootiv_by(sb, ltype);

	if (likely(iv != NULL)) {
		silofs_iv_assign(out_iv, iv);
	} else {
		silofs_iv_reset(out_iv);
	}
}

static void sb_set_rootiv_of(struct silofs_super_block *sb,
                             enum silofs_ltype ltype,
                             const struct silofs_iv *iv_src)
{
	struct silofs_iv *iv_dst = sb_rootiv_by2(sb, ltype);

	if (likely(iv_dst != NULL)) {
		silofs_iv_assign(iv_dst, iv_src);
	}
}

static void sb_gen_rootiv_of(struct silofs_super_block *sb,
                             enum silofs_ltype ltype)
{
	struct silofs_iv iv;

	silofs_gen_random_ivs(&iv, 1);
	sb_set_rootiv_of(sb, ltype, &iv);
}

static void sb_gen_rootivs(struct silofs_super_block *sb)
{
	enum silofs_ltype ltype;

	for (ltype = SILOFS_LTYPE_NONE; ltype < SILOFS_LTYPE_LAST; ++ltype) {
		sb_gen_rootiv_of(sb, ltype);
	}
}

static void sb_clone_rootivs(struct silofs_super_block *sb,
                             const struct silofs_super_block *sb_other)
{
	struct silofs_iv iv;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (ltype_isvnode(ltype)) {
			sb_rootiv_of(sb_other, ltype, &iv);
			sb_set_rootiv_of(sb, ltype, &iv);
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
	sb_gen_rootivs(sb);
	sb_generate_lvid(sb);
	sb_reset_main_lsegids(sb);
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

static void sb_setup_fresh(struct silofs_super_block *sb)
{
	sb_set_birth_time(sb, silofs_time_now());
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_sproot(const struct silofs_uaddr *uaddr)
{
	const enum silofs_height height = uaddr_height(uaddr);
	const enum silofs_ltype ltype = uaddr->laddr.ltype;

	if (uaddr_isnull(uaddr)) {
		return 0;
	}
	if ((ltype != SILOFS_LTYPE_SPNODE) ||
	    (height != (SILOFS_HEIGHT_SUPER - 1))) {
		log_err("bad spnode root: ltype=%d height=%d",
		        (int)ltype, (int)height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int sb_verify_sproots(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		sb_sproot_of(sb, ltype, &uaddr);
		err = verify_sproot(&uaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int sb_verify_self(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;

	sb_self(sb, &uaddr);
	if (uaddr_isnull(&uaddr) || !ltype_issuper(uaddr.laddr.ltype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int sb_verify_origin(const struct silofs_super_block *sb)
{
	struct silofs_uaddr uaddr;

	sb_origin(sb, &uaddr);
	if (!uaddr_isnull(&uaddr) && !ltype_issuper(uaddr.laddr.ltype)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int sb_verify_height(const struct silofs_super_block *sb)
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

	err = sb_verify_height(sb);
	if (err) {
		return err;
	}
	err = sb_verify_self(sb);
	if (err) {
		return err;
	}
	err = sb_verify_origin(sb);
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
	const struct silofs_fsenv *fsenv = sbi_fsenv(sbi);
	const unsigned long ms_mask = MS_RDONLY;

	if ((fsenv->fse_ms_flags & ms_mask) == ms_mask) {
		return -SILOFS_EROFS;
	}
	if (silofs_sb_test_flags(sbi->sb, SILOFS_SUPERF_FOSSIL)) {
		return -SILOFS_EROFS;
	}
	return 0;
}

int silofs_sbi_shut(struct silofs_sb_info *sbi)
{
	const struct silofs_fsenv *fsenv = NULL;

	if (sbi != NULL) {
		fsenv = sbi_fsenv(sbi);
		log_dbg("shut-super: op_count=%lu",
		        fsenv->fse_op_stat.op_count);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_get_lvid(const struct silofs_sb_info *sbi,
                         struct silofs_lvid *out_lvid)
{
	sb_lvid(sbi->sb, out_lvid);
}

int silofs_sbi_main_lseg(const struct silofs_sb_info *sbi,
                         enum silofs_ltype vspace,
                         struct silofs_lsegid *out_lsegid)
{
	sb_main_lsegid(sbi->sb, vspace, out_lsegid);
	return lsegid_isnull(out_lsegid) ? -SILOFS_ENOENT : 0;
}

void silofs_sbi_bind_main_lseg(struct silofs_sb_info *sbi,
                               enum silofs_ltype vspace,
                               const struct silofs_lsegid *lsegid)
{
	sb_set_main_lsegid(sbi->sb, vspace, lsegid);
	sbi_dirtify(sbi);
}

bool silofs_sbi_has_main_lseg(const struct silofs_sb_info *sbi,
                              enum silofs_ltype vspace)
{
	struct silofs_lsegid lseg_id;

	silofs_sbi_main_lseg(sbi, vspace, &lseg_id);
	return (lsegid_size(&lseg_id) > 0);
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

static void sbi_sproot_of(const struct silofs_sb_info *sbi,
                          enum silofs_ltype ltype,
                          struct silofs_uaddr *out_uaddr)
{
	sb_sproot_of(sbi->sb, ltype, out_uaddr);
}

static void sbi_rootiv_of(const struct silofs_sb_info *sbi,
                          enum silofs_ltype ltype, struct silofs_iv *out_iv)
{
	sb_rootiv_of(sbi->sb, ltype, out_iv);
}

static void sbi_main_ulink(const struct silofs_sb_info *sbi,
                           loff_t voff, enum silofs_ltype vspace,
                           struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsegid lsegid;
	const loff_t bpos = sbi_bpos_of_child(sbi, voff);
	const loff_t base = sbi_base_voff_of_child(sbi, voff);

	silofs_sbi_main_lseg(sbi, vspace, &lsegid);
	uaddr_setup(out_uaddr, &lsegid, bpos, SILOFS_LTYPE_SPNODE, base);

	silofs_assert_eq(lsegid.height, SILOFS_HEIGHT_SUPER - 1);
}

void silofs_sbi_resolve_main_at(const struct silofs_sb_info *sbi,
                                loff_t voff, enum silofs_ltype vspace,
                                struct silofs_ulink *out_ulink)
{
	sbi_main_ulink(sbi, voff, vspace, &out_ulink->uaddr);
	sbi_rootiv_of(sbi, vspace, &out_ulink->riv);
}

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
                         enum silofs_ltype vltype,
                         struct silofs_uaddr *out_uaddr)
{
	sbi_sproot_of(sbi, vltype, out_uaddr);
	return !uaddr_isnull(out_uaddr) ? 0 : -SILOFS_ENOENT;
}

int silofs_sbi_resolve_child(const struct silofs_sb_info *sbi,
                             enum silofs_ltype vltype,
                             struct silofs_ulink *out_ulink)
{
	sbi_sproot_of(sbi, vltype, &out_ulink->uaddr);
	sbi_rootiv_of(sbi, vltype, &out_ulink->riv);
	return !uaddr_isnull(&out_ulink->uaddr) ? 0 : -SILOFS_ENOENT;
}

void silofs_sbi_bind_child(struct silofs_sb_info *sbi,
                           enum silofs_ltype vltype,
                           const struct silofs_ulink *ulink)
{
	sb_set_sproot_of(sbi->sb, vltype, &ulink->uaddr);
	sb_set_rootiv_of(sbi->sb, vltype, &ulink->riv);
	sbi_dirtify(sbi);
}

bool silofs_sbi_ismutable_lsegid(const struct silofs_sb_info *sbi,
                                 const struct silofs_lsegid *lsegid)
{
	struct silofs_lvid lvid;

	silofs_sbi_get_lvid(sbi, &lvid);
	return silofs_lsegid_has_lvid(lsegid, &lvid);
}

bool silofs_sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
                                const struct silofs_laddr *laddr)
{
	return silofs_sbi_ismutable_lsegid(sbi, &laddr->lsegid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stage_spleaf(struct silofs_task *task,
                        const struct silofs_vaddr *vaddr,
                        enum silofs_stg_mode stg_mode,
                        struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf_of(task, vaddr, stg_mode, out_sli);
}

int silofs_test_unwritten_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stage_spleaf(task, vaddr, SILOFS_STG_CUR, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_clear_unwritten_at(struct silofs_task *task,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stage_spleaf(task, vaddr, SILOFS_STG_COW, &sli);
	if (err) {
		return err;
	}
	silofs_sli_clear_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_mark_unwritten_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stage_spleaf(task, vaddr, SILOFS_STG_COW, &sli);
	if (err) {
		return err;
	}
	silofs_sli_mark_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_test_last_allocated(struct silofs_task *task,
                               const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stage_spleaf(task, vaddr, SILOFS_STG_CUR, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_is_last_allocated(sli, vaddr);
	return 0;
}

int silofs_test_shared_dbkref(struct silofs_task *task,
                              const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	size_t dbkref = 0;
	int err;

	*out_res = false;
	if (!vaddr_isdatabk(vaddr)) {
		return 0;
	}
	err = stage_spleaf(task, vaddr, SILOFS_STG_CUR, &sli);
	if (err) {
		return err;
	}
	dbkref = silofs_sli_dbkref_at(sli, vaddr);
	*out_res = (dbkref > 1);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_incref(struct silofs_sb_info *sbi)
{
	if (likely(sbi != NULL)) {
		silofs_lni_incref(&sbi->sb_ui.u_lni);
	}
}

void silofs_sbi_decref(struct silofs_sb_info *sbi)
{
	if (likely(sbi != NULL)) {
		silofs_lni_decref(&sbi->sb_ui.u_lni);
	}
}

void silofs_sbi_dirtify(struct silofs_sb_info *sbi)
{
	ui_dirtify(&sbi->sb_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

void silofs_sbi_clone_from(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other)
{
	struct silofs_super_block *sb = sbi->sb;
	const struct silofs_super_block *sb_other = sbi_other->sb;

	sb_assign(sb, sb_other);
	sb_clone_sproots(sb, sb_other);
	sb_clone_rootivs(sb, sb_other);
	sb_generate_lvid(sb);
	sb_reset_main_lsegids(sb);
	sb_set_self(sb, sbi_uaddr(sbi));
	sb_set_origin(sb, sbi_uaddr(sbi_other));
	sbi_dirtify(sbi);
}

