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
#include <silofs/fs/private.h>
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
		return -EFSCORRUPTED;
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

static size_t sb_height(const struct silofs_super_block *sb)
{
	struct silofs_vrange vrange;

	sb_vrange(sb, &vrange);
	return vrange.height;
}

static bool sb_in_vrange(const struct silofs_super_block *sb, loff_t voff)
{
	struct silofs_vrange vrange;

	sb_vrange(sb, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

static void sb_treeid(const struct silofs_super_block *sb,
                      struct silofs_xid *out_xid)
{
	silofs_xid128_parse(&sb->sb_treeid, out_xid);
}

static void sb_set_treeid(struct silofs_super_block *sb,
                          const struct silofs_xid *xid)
{
	silofs_xid128_set(&sb->sb_treeid, xid);
}

static void sb_main_blobid(const struct silofs_super_block *sb,
                           struct silofs_blobid *out_blobid)
{
	silofs_blobid40b_parse(&sb->sb_mainblobid, out_blobid);
}

static void sb_set_main_blobid(struct silofs_super_block *sb,
                               const struct silofs_blobid *blobid)
{
	silofs_blobid40b_set(&sb->sb_mainblobid, blobid);
}

static void sb_main_packid(const struct silofs_super_block *sb,
                           struct silofs_packid *out_packid)
{
	silofs_packid64b_parse(&sb->sb_mainpackid, out_packid);
}

static void sb_set_main_packid(struct silofs_super_block *sb,
                               const struct silofs_packid *packid)
{
	silofs_packid64b_set(&sb->sb_mainpackid, packid);
}

static void sb_self(const struct silofs_super_block *sb,
                    struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sb->sb_self, out_uaddr);
}

static void sb_set_self(struct silofs_super_block *sb,
                        const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sb->sb_self, uaddr);
}

static void sb_reset_main_blobid(struct silofs_super_block *sb)
{
	silofs_blobid40b_reset(&sb->sb_mainblobid);
}

static size_t sb_slot_of(const struct silofs_super_block *sb, loff_t voff)
{
	struct silofs_vrange vrange;
	const long nslots = (long)ARRAY_SIZE(sb->sb_subref);
	size_t slot;
	long span;
	long roff;

	sb_vrange(sb, &vrange);
	span = (long)vrange.len;
	roff = off_diff(vrange.beg, voff);
	slot = (size_t)((roff * nslots) / span);
	silofs_assert_lt(slot, nslots);
	return slot;
}

static struct silofs_spmap_ref *
sb_subref_at(const struct silofs_super_block *sb, size_t slot)
{
	const struct silofs_spmap_ref *spr = &sb->sb_subref[slot];

	return unconst(spr);
}

static struct silofs_spmap_ref *
sb_subref_of(const struct silofs_super_block *sb, loff_t voff)
{
	return sb_subref_at(sb, sb_slot_of(sb, voff));
}

static void sb_resolve_subref(const struct silofs_super_block *sb,
                              loff_t voff, struct silofs_uaddr *out_ulink)
{
	static struct silofs_spmap_ref *spr = NULL;

	if (sb_in_vrange(sb, voff)) {
		spr = sb_subref_of(sb, voff);
		silofs_spr_ulink(spr, out_ulink);
	} else {
		silofs_uaddr_reset(out_ulink);
	}
}

static void sb_set_subref(struct silofs_super_block *sb, loff_t voff,
                          const struct silofs_uaddr *ulink)
{
	struct silofs_spmap_ref *spr = sb_subref_of(sb, voff);

	silofs_spr_set_ulink(spr, ulink);
}

static size_t sb_num_active_slots(const struct silofs_super_block *sb)
{
	struct silofs_uaddr ulink;
	size_t nslots_active = 0;
	const size_t nslots_max = ARRAY_SIZE(sb->sb_subref);
	static struct silofs_spmap_ref *spr = NULL;

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = sb_subref_at(sb, slot);
		silofs_spr_ulink(spr, &ulink);
		if (uaddr_isnull(&ulink)) {
			break;
		}
		nslots_active++;
	}
	return nslots_active;
}

static void sb_generate_treeid(struct silofs_super_block *sb)
{
	struct silofs_xid xid;

	silofs_xid_generate(&xid);
	sb_set_treeid(sb, &xid);
}

static void sb_bind_subref_of(struct silofs_super_block *sb, loff_t voff,
                              const struct silofs_uaddr *ulink)
{
	sb_set_subref(sb, voff, ulink);
}

static void sb_stats_uaddr(const struct silofs_super_block *sb,
                           struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sb->sb_stats_uaddr, out_uaddr);
}

static void sb_set_stats_uaddr(struct silofs_super_block *sb,
                               const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sb->sb_stats_uaddr, uaddr);
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
	sb_generate_treeid(sb);
	sb_reset_main_blobid(sb);
	silofs_uaddr64b_reset(&sb->sb_self);
	silofs_spr_initn(sb->sb_subref, ARRAY_SIZE(sb->sb_subref));
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

int silofs_verify_super_block(const struct silofs_super_block *sb)
{
	size_t height;
	size_t nactive_slots;

	height = sb_height(sb);
	if (height != SILOFS_SUPER_HEIGHT) {
		log_err("illegal sb height: height=%lu", height);
		return -EFSCORRUPTED;
	}
	nactive_slots = sb_num_active_slots(sb);
	if (nactive_slots >= ARRAY_SIZE(sb->sb_subref)) {
		return -EFSCORRUPTED;
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
	silofs_cache_forget_vnode(sbi_cache(sbi), vi);
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
	vi = silofs_cache_lookup_vnode(sbi_cache(sbi), vaddr);
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
	int err;
	struct silofs_vnode_info *vi = NULL;

	silofs_assert(!vaddr_isnull(vaddr));
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
		silofs_cache_forget_vnode(sbi_cache(sbi), vi);
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
	const struct silofs_fs_uber *uber = sbi_uber(sbi);

	log_dbg("shut-super: op_count=%lu", uber->ub_ops.op_count);
	silofs_itbl_reinit(&sbi->sb_itbl);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_treeid(const struct silofs_sb_info *sbi,
                       struct silofs_xid *out_xid)
{
	sb_treeid(sbi->sb, out_xid);
}

void silofs_sbi_main_blob(const struct silofs_sb_info *sbi,
                          struct silofs_blobid *out_blobid)
{
	sb_main_blobid(sbi->sb, out_blobid);
}

void silofs_sbi_bind_main_blob(struct silofs_sb_info *sbi,
                               const struct silofs_blobid *blobid)
{
	sb_set_main_blobid(sbi->sb, blobid);
	sbi_dirtify(sbi);
}

bool silofs_sbi_has_main_blob(const struct silofs_sb_info *sbi)
{
	struct silofs_blobid blob_id;

	silofs_sbi_main_blob(sbi, &blob_id);
	return (blobid_size(&blob_id) > 0);
}

int silofs_sbi_main_pack(const struct silofs_sb_info *sbi,
                         struct silofs_packid *out_packid)
{
	sb_main_packid(sbi->sb, out_packid);
	return !packid_isnull(out_packid) ? 0 : -ENOENT;
}

void silofs_sbi_bind_main_pack(struct silofs_sb_info *sbi,
                               const struct silofs_packid *packid)
{
	sb_set_main_packid(sbi->sb, packid);
}

void silofs_sbi_self(const struct silofs_sb_info *sbi,
                     struct silofs_uaddr *out_uaddr)
{
	sb_self(sbi->sb, out_uaddr);
}

size_t silofs_sbi_space_tree_height(const struct silofs_sb_info *sbi)
{
	return sb_height(sbi->sb);
}

static loff_t
sbi_bpos_of_child(const struct silofs_sb_info *sbi, loff_t voff)
{
	const size_t slot = sb_slot_of(sbi->sb, voff);

	return (long)slot * SILOFS_SPNODE_SIZE;
}

static loff_t
sbi_base_voff_of_child(const struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_vrange vrange;
	const size_t child_height = silofs_sbi_space_tree_height(sbi) - 1;

	silofs_assert_eq(child_height, SILOFS_SPNODE3_HEIGHT);

	silofs_vrange_setup_by(&vrange, child_height, voff);
	return vrange.beg;
}

void silofs_sbi_main_child_at(const struct silofs_sb_info *sbi,
                              loff_t voff, struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid blobid;
	const loff_t base = sbi_base_voff_of_child(sbi, voff);

	silofs_sbi_main_blob(sbi, &blobid);
	silofs_uaddr_setup(out_uaddr, &blobid, sbi_bpos_of_child(sbi, voff),
	                   SILOFS_STYPE_SPNODE, SILOFS_SPNODE3_HEIGHT, base);
}

void silofs_sbi_bind_child(struct silofs_sb_info *sbi,
                           const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	sni_vrange(sni, &vrange);
	sb_bind_subref_of(sbi->sb, vrange.beg, sni_uaddr(sni));
	sbi_dirtify(sbi);
}

int silofs_sbi_subref_of(const struct silofs_sb_info *sbi,
                         loff_t voff, struct silofs_uaddr *out_ulink)
{
	sb_resolve_subref(sbi->sb, voff, out_ulink);
	return uaddr_isnull(out_ulink) ? -ENOENT : 0;
}

bool silofs_sbi_has_child_at(const struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_uaddr ulink;

	sb_resolve_subref(sbi->sb, voff, &ulink);
	return !uaddr_isnull(&ulink);
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
		return -EFSCORRUPTED;
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
                           enum silofs_stage_flags stg_flags)
{
	int err = 0;

	if (stg_flags & SILOFS_STAGE_MUTABLE) {
		err = silof_sbi_check_mut_fs(sbi);
	}
	return err;
}

static int sbi_check_stage_vnode(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_flags stg_flags)
{
	return vaddr_isnull(vaddr) ? -ENOENT : sbi_check_stage(sbi, stg_flags);
}

static int sbi_check_stage_inode(struct silofs_sb_info *sbi, ino_t ino,
                                 enum silofs_stage_flags stg_flags)
{
	return ino_isnull(ino) ? -ENOENT : sbi_check_stage(sbi, stg_flags);
}

static int sbi_check_staged_inode(const struct silofs_inode_info *ii,
                                  enum silofs_stage_flags stg_flags)
{
	return ((stg_flags & SILOFS_STAGE_MUTABLE) &&
	        silof_ii_isimmutable(ii)) ? -EACCES : 0;
}

int silofs_sbi_stage_vnode(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_flags stg_flags,
                           struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa;
	int err;

	err = sbi_check_stage_vnode(sbi, vaddr, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_sbi_resolve_voa(sbi, vaddr, stg_flags, &voa);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_vi(sbi, vaddr, out_vi);
	if (!err) {
		return 0;  /* cache hit */
	}
	err = silofs_sbi_stage_vnode_at(sbi, &voa, stg_flags, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_inode(struct silofs_sb_info *sbi, ino_t ino,
                           enum silofs_stage_flags stg_flags,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = {
		.ino = ino,
	};
	struct silofs_ivoaddr ivoa = {
		.ino = ino
	};
	int err;

	err = sbi_check_stage_inode(sbi, ino, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_resolve_iaddr(sbi, ino, &iaddr);
	if (err) {
		return err;
	}
	err = silofs_sbi_resolve_voa(sbi, &iaddr.vaddr,
	                             stg_flags, &ivoa.voa);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_ii(sbi, &iaddr.vaddr, out_ii);
	if (!err) {
		return 0;
	}
	err = silofs_sbi_stage_inode_at(sbi, &ivoa, stg_flags, out_ii);
	if (err) {
		return err;
	}
	err = sbi_check_staged_inode(*out_ii, stg_flags);
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

int silofs_sbi_spawn_vnode(struct silofs_sb_info *sbi, enum silofs_stype stype,
                           struct silofs_vnode_info **out_vi)
{
	int err;

	err = silofs_sbi_claim_vnode(sbi, stype, out_vi);
	if (err) {
		return err;
	}
	silofs_vi_stamp_mark_visible(*out_vi);
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
	silofs_vi_stamp_mark_visible(ii_to_vi(ii));
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

	err = silofs_sbi_resolve_voa(sbi, vaddr, SILOFS_STAGE_RDONLY, &voa);
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

int silofs_sbi_test_unwritten(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr, bool *out_res)
{
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	int err;

	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
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
	const loff_t voff = vaddr_off(vaddr);
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;
	int err;

	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
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
	const loff_t voff = vaddr_off(vaddr);
	int err;

	err = silofs_sbi_stage_spleaf(sbi, voff, SILOFS_STAGE_MUTABLE, &sli);
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
	const loff_t voff = vaddr_off(vaddr);
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	int err;

	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_last_refcnt(sli, vaddr);
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
		sbi->sb_ctl_flags |= SILOFS_F_KCOPY;
	}
	if (args->allowother) {
		sbi->sb_ctl_flags |= SILOFS_F_ALLOWOTHER;
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
                          struct silofs_fs_uber *uber)
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

	silofs_vrange_setup_by(&vrange, SILOFS_SUPER_HEIGHT, 0);
	sb_set_vrange(sbi->sb, &vrange);
}

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi)
{
	sbi_zero_stamp_view(sbi);
	sb_init(sbi->sb);
	sb_set_self(sbi->sb, sbi_uaddr(sbi));
	sb_setup_fresh(sbi->sb);
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

int silofs_sbi_stats_uaddr(const struct silofs_sb_info *sbi,
                           struct silofs_uaddr *out_uaddr)
{
	sb_stats_uaddr(sbi->sb, out_uaddr);
	return !uaddr_isnull(out_uaddr) ? 0 : -ENOENT;
}

void silofs_sbi_set_stats_uaddr(struct silofs_sb_info *sbi,
                                const struct silofs_uaddr *uaddr)
{
	sb_set_stats_uaddr(sbi->sb, uaddr);
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
	silofs_itbl_update_by(&sbi->sb_itbl, &sbi_other->sb_itbl);
	sbi->sb_ctl_flags = sbi_other->sb_ctl_flags;
	sbi->sb_ms_flags = sbi_other->sb_ms_flags;
	sbi->sb_mntime = sbi_other->sb_mntime;
}

void silofs_sbi_make_clone(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other)
{
	struct silofs_super_block *sb = sbi->sb;

	sbi_update_by(sbi, sbi_other);
	sb_assign(sb, sbi_other->sb);
	sb_generate_treeid(sb);
	sb_reset_main_blobid(sb);
	sb_set_self(sb, sbi_uaddr(sbi));
	sbi_dirtify(sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_xinit(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	int err;

	sbi->sb_sti = NULL;
	err = silofs_itbl_init(&sbi->sb_itbl, alloc);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_sbi_xfini(struct silofs_sb_info *sbi)
{
	silofs_itbl_fini(&sbi->sb_itbl);
	silofs_sbi_bind_stats(sbi, NULL);
}

void silofs_sbi_bind_stats(struct silofs_sb_info *sbi,
                           struct silofs_spstats_info *sti)
{
	if (sbi->sb_sti != NULL) {
		sti_decref(sbi->sb_sti);
		sbi->sb_sti = NULL;
	}
	if (sti != NULL) {
		sti_incref(sti);
		sbi->sb_sti = sti;
	}
}


