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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/spclaim.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t sb_root_magic(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_root.sb_magic);
}

static void sb_root_set_magic(struct silofs_super_block *sb, uint64_t magic)
{
	sb->sb_root.sb_magic = silofs_cpu_to_le64(magic);
}

static long sb_root_version(const struct silofs_super_block *sb)
{
	return (long)silofs_le64_to_cpu(sb->sb_root.sb_version);
}

static void sb_root_set_version(struct silofs_super_block *sb, long version)
{
	sb->sb_root.sb_version = silofs_cpu_to_le64((uint64_t)version);
}

static enum silofs_superf sb_root_flags(const struct silofs_super_block *sb)
{
	const uint32_t flags = silofs_le32_to_cpu(sb->sb_root.sb_flags);

	return (enum silofs_superf)flags;
}

static void sb_root_set_flags(struct silofs_super_block *sb,
                              enum silofs_superf flags)
{
	sb->sb_root.sb_flags = silofs_cpu_to_le32((uint32_t)flags);
}

static void sb_root_add_flags(struct silofs_super_block *sb,
                              enum silofs_superf flags)
{
	sb_root_set_flags(sb, flags | sb_root_flags(sb));
}

static void sb_root_set_swversion(struct silofs_super_block *sb,
                                  const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(sb->sb_root.sb_sw_version) - 1;

	memcpy(sb->sb_root.sb_sw_version, sw_version, min(len, len_max));
}

static void sb_root_generate_uuid(struct silofs_super_block *sb)
{
	silofs_uuid_generate(&sb->sb_root.sb_uuid);
}

int silofs_sb_check_root(const struct silofs_super_block *sb)
{
	if (sb_root_magic(sb) != SILOFS_SUPER_MAGIC) {
		return -EINVAL;
	}
	if (sb_root_version(sb) != SILOFS_FMT_VERSION) {
		return -EFSCORRUPTED;
	}
	return 0;
}

bool silofs_sb_test_flags(const struct silofs_super_block *sb,
                          enum silofs_superf mask)
{
	return (mask == (sb_root_flags(sb) & mask));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_rand_setup_fill(struct silofs_super_block *sb)
{
	silofs_getentropy(sb->sb_rand.sb_fill, sizeof(sb->sb_rand.sb_fill));
}

static void sb_rand_calc_fill_hash(const struct silofs_super_block *sb,
                                   const struct silofs_mdigest *md,
                                   struct silofs_hash512 *out_hash)
{
	silofs_sha3_512_of(md, sb->sb_rand.sb_fill,
	                   sizeof(sb->sb_rand.sb_fill), out_hash);
}

static void sb_rand_set_fill_hash(struct silofs_super_block *sb,
                                  const struct silofs_hash512 *hash)
{
	silofs_hash512_assign(&sb->sb_rand.sb_hash, hash);
}

static bool sb_rand_has_hash(const struct silofs_super_block *sb,
                             const struct silofs_hash512 *hash)
{
	return silofs_hash512_isequal(&sb->sb_rand.sb_hash, hash);
}

static void sb_rand_setup(struct silofs_super_block *sb,
                          const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash;

	sb_rand_setup_fill(sb);
	sb_rand_calc_fill_hash(sb, md, &hash);
	sb_rand_set_fill_hash(sb, &hash);
}

int silofs_sb_check_rand(const struct silofs_super_block *sb,
                         const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash;

	sb_rand_calc_fill_hash(sb, md, &hash);
	return sb_rand_has_hash(sb, &hash) ? 0 : -EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_umap_vrange(const struct silofs_super_block *sb,
                           struct silofs_vrange *out_vrange)
{
	silofs_vrange128_parse(&sb->sb_umap.sb_vrange, out_vrange);
}

static void sb_umap_set_vrange(struct silofs_super_block *sb,
                               const struct silofs_vrange *vrange)
{
	silofs_assert_eq(vrange->height, SILOFS_SUPER_HEIGHT);

	silofs_vrange128_set(&sb->sb_umap.sb_vrange, vrange);
}

static size_t sb_umap_height(const struct silofs_super_block *sb)
{
	struct silofs_vrange vrange;

	sb_umap_vrange(sb, &vrange);
	return vrange.height;
}

static bool sb_umap_in_vrange(const struct silofs_super_block *sb, loff_t voff)
{
	struct silofs_vrange vrange;

	sb_umap_vrange(sb, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

static void sb_umap_treeid(const struct silofs_super_block *sb,
                           struct silofs_xid *out_xid)
{
	silofs_xid128_parse(&sb->sb_umap.sb_treeid, out_xid);
}

static void sb_umap_set_treeid(struct silofs_super_block *sb,
                               const struct silofs_xid *xid)
{
	silofs_xid128_set(&sb->sb_umap.sb_treeid, xid);
}

static void sb_umap_main_blobid(const struct silofs_super_block *sb,
                                struct silofs_blobid *out_blobid)
{
	silofs_blobid40b_parse(&sb->sb_umap.sb_mainblobid, out_blobid);
}

static void sb_umap_set_main_blobid(struct silofs_super_block *sb,
                                    const struct silofs_blobid *blobid)
{
	silofs_blobid40b_set(&sb->sb_umap.sb_mainblobid, blobid);
}

static void sb_umap_self(const struct silofs_super_block *sb,
                         struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&sb->sb_umap.sb_self, out_uaddr);
}

static void sb_umap_set_self(struct silofs_super_block *sb,
                             const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&sb->sb_umap.sb_self, uaddr);
}

static void sb_umap_reset_main_blobid(struct silofs_super_block *sb)
{
	silofs_blobid40b_reset(&sb->sb_umap.sb_mainblobid);
}

static size_t sb_umap_slot_of(const struct silofs_super_block *sb, loff_t voff)
{
	struct silofs_vrange vrange;
	const long nslots = (long)ARRAY_SIZE(sb->sb_umap.sb_subref);
	size_t slot;
	long span;
	long roff;

	sb_umap_vrange(sb, &vrange);
	span = (long)vrange.len;
	roff = off_diff(vrange.beg, voff);
	slot = (size_t)((roff * nslots) / span);
	silofs_assert_lt(slot, nslots);
	return slot;
}

static struct silofs_spmap_ref *
sb_umap_ref_at(const struct silofs_super_block *sb, size_t slot)
{
	const struct silofs_spmap_ref *spr = &sb->sb_umap.sb_subref[slot];

	return unconst(spr);
}

static struct silofs_spmap_ref *
sb_umap_ref_of(const struct silofs_super_block *sb, loff_t voff)
{
	return sb_umap_ref_at(sb, sb_umap_slot_of(sb, voff));
}

static void sb_umap_subref_at(const struct silofs_super_block *sb, size_t slot,
                              struct silofs_ulink *out_ulink)
{
	silofs_spr_ulink(sb_umap_ref_at(sb, slot), out_ulink);
}

static void sb_umap_subref_of(const struct silofs_super_block *sb,
                              loff_t voff, struct silofs_ulink *out_ulink)
{
	if (sb_umap_in_vrange(sb, voff)) {
		sb_umap_subref_at(sb, sb_umap_slot_of(sb, voff), out_ulink);
	} else {
		silofs_ulink_reset(out_ulink);
	}
}

static void sb_umap_set_subref(struct silofs_super_block *sb, loff_t voff,
                               const struct silofs_ulink *ulink)
{
	struct silofs_spmap_ref *spr = sb_umap_ref_of(sb, voff);

	silofs_spr_set_ulink(spr, ulink, ulink->child.stype);
}

static size_t sb_umap_num_active_slots(const struct silofs_super_block *sb)
{
	struct silofs_ulink ulink;
	size_t nslots_active = 0;
	const size_t nslots_max = ARRAY_SIZE(sb->sb_umap.sb_subref);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		sb_umap_subref_at(sb, slot, &ulink);
		if (uaddr_isnull(&ulink.child)) {
			break;
		}
		nslots_active++;
	}
	return nslots_active;
}

static void sb_umap_generate_treeid(struct silofs_super_block *sb)
{
	struct silofs_xid xid;

	silofs_xid_generate(&xid);
	sb_umap_set_treeid(sb, &xid);
}

static void sb_bind_subref_of(struct silofs_super_block *sb,
                              loff_t voff, const struct silofs_ulink *ulink)
{
	sb_umap_set_subref(sb, voff, ulink);
}

static void sb_umap_rebind_packid(struct silofs_super_block *sb, loff_t voff,
                                  const struct silofs_packid *packid)
{
	struct silofs_spmap_ref *spr = sb_umap_ref_of(sb, voff);

	silofs_spr_set_packid(spr, packid);
}

static int sb_umap_lookup_packid(const struct silofs_super_block *sb,
                                 const struct silofs_blobid *blobid,
                                 struct silofs_packid *out_packid)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	const struct silofs_spmap_ref *spr = NULL;
	const struct silofs_blobid *child_blobid;
	const size_t nslots_max = ARRAY_SIZE(sb->sb_umap.sb_subref);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		spr = sb_umap_ref_at(sb, slot);
		silofs_spr_packid(spr, &packid);
		if (packid_isnull(&packid)) {
			continue;
		}
		silofs_spr_ulink(spr, &ulink);
		child_blobid = uaddr_blobid(&ulink.child);
		if (blobid_isequal(blobid, child_blobid)) {
			packid_assign(out_packid, &packid);
			return 0;
		}
	}
	return -ENOENT;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_init(struct silofs_super_block *sb)
{
	sb_root_set_magic(sb, SILOFS_SUPER_MAGIC);
	sb_root_set_version(sb, SILOFS_FMT_VERSION);
	sb_root_set_flags(sb, SILOFS_SUPERF_NONE);
	sb_root_set_swversion(sb, silofs_version.string);
	sb_root_generate_uuid(sb);
	sb->sb_root.sb_endianness = SILOFS_ENDIANNESS_LE;

	sb_umap_generate_treeid(sb);
	sb_umap_reset_main_blobid(sb);
	silofs_uaddr64b_reset(&sb->sb_umap.sb_self);
	silofs_spr_initn(sb->sb_umap.sb_subref,
	                 ARRAY_SIZE(sb->sb_umap.sb_subref));
}

static void sb_set_birth_time(struct silofs_super_block *sb, time_t btime)
{
	sb->sb_base.sb_birth_time = silofs_cpu_to_le64((uint64_t)btime);
}

static void sb_itable_root(const struct silofs_super_block *sb,
                           struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_parse(&sb->sb_base.sb_itable_root, out_vaddr);
}

static void sb_set_itable_root(struct silofs_super_block *sb,
                               const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&sb->sb_base.sb_itable_root, vaddr);
}

static size_t sb_uspace_nmeta(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_uspace_nmeta);
}

static void sb_set_uspace_nmeta(struct silofs_super_block *sb, size_t nmeta)
{
	sb->sb_base.sb_uspace_nmeta = silofs_cpu_to_le64(nmeta);
}

static size_t sb_vspace_nmeta(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_vspace_nmeta);
}

static void sb_set_vspace_nmeta(struct silofs_super_block *sb, size_t nmeta)
{
	sb->sb_base.sb_vspace_nmeta = silofs_cpu_to_le64(nmeta);
}

static size_t sb_vspace_nfiles(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_vspace_nfiles);
}

static void sb_set_vspace_nfiles(struct silofs_super_block *sb, size_t nfiles)
{
	sb->sb_base.sb_vspace_nfiles = silofs_cpu_to_le64(nfiles);
}

static size_t sb_vspace_ndata(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_vspace_ndata);
}

static void sb_set_vspace_ndata(struct silofs_super_block *sb, size_t ndata)
{
	sb->sb_base.sb_vspace_ndata = silofs_cpu_to_le64(ndata);
}

loff_t silofs_sb_vspace_last(const struct silofs_super_block *sb)
{
	return silofs_off_to_cpu(sb->sb_base.sb_vspace_last);
}

static void sb_set_vspace_last(struct silofs_super_block *sb, loff_t voff)
{
	sb->sb_base.sb_vspace_last = silofs_cpu_to_off(voff);
}

static size_t sb_total_capacity(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_total_capacity);
}

static void sb_set_total_capacity(struct silofs_super_block *sb, size_t cap)
{
	sb->sb_base.sb_total_capacity = silofs_cpu_to_le64(cap);
}

static void sb_setup_fresh(struct silofs_super_block *sb,
                           time_t btime, size_t capacity)
{
	sb_set_birth_time(sb, btime);
	sb_set_itable_root(sb, silofs_vaddr_none());
	sb_set_uspace_nmeta(sb, sizeof(*sb));
	sb_set_vspace_last(sb, 0);
	sb_set_total_capacity(sb, capacity);
	sb_set_vspace_ndata(sb, 0);
	sb_set_vspace_nmeta(sb, 0);
	sb_set_vspace_nfiles(sb, 0);
}

static void sb_space_stat(const struct silofs_super_block *sb,
                          struct silofs_space_stat *out_spst)
{
	out_spst->uspace_nmeta = (ssize_t)sb_uspace_nmeta(sb);
	out_spst->vspace_ndata = (ssize_t)sb_vspace_ndata(sb);
	out_spst->vspace_nmeta = (ssize_t)sb_vspace_nmeta(sb);
	out_spst->vspace_nfiles = (ssize_t)sb_vspace_nfiles(sb);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int64_t *
sb_vspa_last_of(const struct silofs_super_block *sb, enum silofs_stype stype)
{
	const int64_t *vspa_last;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		vspa_last = &sb->sb_base.sb_vspa_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		vspa_last = &sb->sb_base.sb_vspa_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		vspa_last = &sb->sb_base.sb_vspa_databk;
		break;
	case SILOFS_STYPE_ITNODE:
		vspa_last = &sb->sb_base.sb_vspa_itnode;
		break;
	case SILOFS_STYPE_INODE:
		vspa_last = &sb->sb_base.sb_vspa_inode;
		break;
	case SILOFS_STYPE_XANODE:
		vspa_last = &sb->sb_base.sb_vspa_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		vspa_last = &sb->sb_base.sb_vspa_dirnode;
		break;
	case SILOFS_STYPE_FTNODE:
		vspa_last = &sb->sb_base.sb_vspa_filenode;
		break;
	case SILOFS_STYPE_SYMVAL:
		vspa_last = &sb->sb_base.sb_vspa_symval;
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		vspa_last = NULL;
		break;
	}
	return unconst(vspa_last);
}

loff_t silofs_sb_vlast_by_stype(const struct silofs_super_block *sb,
                                enum silofs_stype stype)
{
	const int64_t *vspa_last = sb_vspa_last_of(sb, stype);

	silofs_assert_not_null(vspa_last);
	return (vspa_last != NULL) ? silofs_off_to_cpu(*vspa_last) : 0;
}

void silofs_sb_set_voff_last(struct silofs_super_block *sb,
                             enum silofs_stype stype, loff_t voff_last)
{
	int64_t *vspa_last = sb_vspa_last_of(sb, stype);

	silofs_assert_not_null(vspa_last);
	if (vspa_last != NULL) {
		*vspa_last = silofs_cpu_to_off(voff_last);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_super_block(const struct silofs_super_block *sb)
{
	size_t height;
	size_t nactive_slots;

	height = sb_umap_height(sb);
	if (height != SILOFS_SUPER_HEIGHT) {
		log_err("illegal sb height: height=%lu", height);
		return -EFSCORRUPTED;
	}
	nactive_slots = sb_umap_num_active_slots(sb);
	if (nactive_slots >= ARRAY_SIZE(sb->sb_umap.sb_subref)) {
		return -EFSCORRUPTED;
	}
	/* TODO: complete me */
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_sbi_space_stat(const struct silofs_sb_info *sbi,
                           struct silofs_space_stat *out_sp_st)
{
	sb_space_stat(sbi->sb, out_sp_st);
}

size_t silofs_sbi_nused_bytes(const struct silofs_sb_info *sbi)
{
	ssize_t sum;
	struct silofs_space_stat sp_st;

	silofs_sbi_space_stat(sbi, &sp_st);
	sum = sp_st.uspace_nmeta + sp_st.vspace_nmeta + sp_st.vspace_ndata;
	return (size_t)sum;
}

size_t silofs_sbi_vspace_capacity(const struct silofs_sb_info *sbi)
{
	return sb_total_capacity(sbi->sb);
}

fsfilcnt_t silofs_sbi_inodes_limit(const struct silofs_sb_info *sbi)
{
	const size_t inode_size = SILOFS_INODE_SIZE;

	return (silofs_sbi_vspace_capacity(sbi) / inode_size) >> 2;
}

fsfilcnt_t silofs_sbi_inodes_current(const struct silofs_sb_info *sbi)
{
	return sb_vspace_nfiles(sbi->sb);
}

static size_t safe_sum(size_t cur, ssize_t dif)
{
	size_t val = cur;

	if (dif > 0) {
		val += (size_t)dif;
		silofs_assert_gt(val, cur);
	} else if (dif < 0) {
		val -= (size_t)(-dif);
		silofs_assert_lt(val, cur);
	}
	return val;
}

static void sbi_dirtify(struct silofs_sb_info *sbi)
{
	silofs_sbi_dirtify(sbi);
}

void silofs_sbi_update_stats(struct silofs_sb_info *sbi,
                             const struct silofs_space_stat *spst_dif)
{
	size_t cur;
	ssize_t dif;
	struct silofs_super_block *sb = sbi->sb;

	dif = spst_dif->uspace_nmeta;
	if (dif) {
		cur = sb_uspace_nmeta(sb);
		sb_set_uspace_nmeta(sb, safe_sum(cur, dif));
	}
	dif = spst_dif->vspace_ndata;
	if (dif) {
		cur = sb_vspace_ndata(sb);
		sb_set_vspace_ndata(sb, safe_sum(cur, dif));
	}
	dif = spst_dif->vspace_nmeta;
	if (dif) {
		cur = sb_vspace_nmeta(sb);
		sb_set_vspace_nmeta(sb, safe_sum(cur, dif));
	}
	dif = spst_dif->vspace_nfiles;
	if (dif) {
		cur = sb_vspace_nfiles(sb);
		sb_set_vspace_nfiles(sb, safe_sum(cur, dif));
	}
	sbi_dirtify(sbi);
}

void silofs_sbi_add_flags(struct silofs_sb_info *sbi, enum silofs_superf f)
{
	sb_root_add_flags(sbi->sb, f);
	sbi_dirtify(sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t sbi_cache_ndirty(const struct silofs_sb_info *sbi)
{
	const struct silofs_cache *cache = sbi_cache(sbi);

	return cache->c_dq.dq_accum_nbytes;
}

static int sbi_lookup_cached_vi(const struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_vnode_info **out_vi)
{
	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	*out_vi = silofs_cache_lookup_vnode(sbi_cache(sbi), vaddr);
	if (*out_vi == NULL) {
		return -ENOENT;
	}
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

int silofs_sbi_commit_dirty(struct silofs_sb_info *sbi)
{
	int err;

	err = silofs_apex_flush_dirty(sbi_apex(sbi), SILOFS_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: ndirty=%lu err=%d",
		        sbi_cache_ndirty(sbi), err);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_calc_allowed_vrange(const struct silofs_sb_info *sbi,
                                    struct silofs_vrange *out_vrange)
{
	size_t length;
	struct silofs_vrange sb_vrange;
	const size_t capacity = sb_total_capacity(sbi->sb);

	sb_umap_vrange(sbi->sb, &sb_vrange);

	length = min(sb_vrange.len, 2 * capacity);
	silofs_vrange_setup(out_vrange, sb_vrange.height, sb_vrange.beg,
	                    off_end(sb_vrange.beg, length));
}

static int
sbi_resolve_unformatted_end(const struct silofs_sb_info *sbi, loff_t *out_voff)
{
	struct silofs_vrange allowed_vrange;

	sbi_calc_allowed_vrange(sbi, &allowed_vrange);
	*out_voff = silofs_sb_vspace_last(sbi->sb);
	return (*out_voff < allowed_vrange.end) ? 0 : -ENOSPC;
}

void silofs_sbi_vspace_range(const struct silofs_sb_info *sbi,
                             struct silofs_vrange *out_vrange)
{
	sbi_calc_allowed_vrange(sbi, out_vrange);
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
	const struct silofs_fs_apex *apex = sbi_apex(sbi);

	log_dbg("shut-super: op_count=%lu", apex->ap_ops.op_count);
	silofs_itbi_reinit(&sbi->s_itbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_treeid(const struct silofs_sb_info *sbi,
                       struct silofs_xid *out_xid)
{
	sb_umap_treeid(sbi->sb, out_xid);
}

void silofs_sbi_main_blob(const struct silofs_sb_info *sbi,
                          struct silofs_blobid *out_blobid)
{
	sb_umap_main_blobid(sbi->sb, out_blobid);
}

void silofs_sbi_bind_main_blob(struct silofs_sb_info *sbi,
                               const struct silofs_blobid *blobid)
{
	sb_umap_set_main_blobid(sbi->sb, blobid);
	sbi_dirtify(sbi);
}

bool silofs_sbi_has_main_blob(const struct silofs_sb_info *sbi)
{
	struct silofs_blobid blob_id;

	silofs_sbi_main_blob(sbi, &blob_id);
	return (blobid_size(&blob_id) > 0);
}

void silofs_sbi_self(const struct silofs_sb_info *sbi,
                     struct silofs_uaddr *out_uaddr)
{
	sb_umap_self(sbi->sb, out_uaddr);
}

size_t silofs_sbi_space_tree_height(const struct silofs_sb_info *sbi)
{
	return sb_umap_height(sbi->sb);
}

static loff_t
sbi_bpos_of_child_spnode(const struct silofs_sb_info *sbi, loff_t voff)
{
	const size_t slot = sb_umap_slot_of(sbi->sb, voff);

	return (long)slot * SILOFS_SPNODE_SIZE;
}

static loff_t
sbi_base_voff_of_child(const struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_vrange vrange;
	const size_t child_height = silofs_sbi_space_tree_height(sbi) - 1;

	silofs_assert_eq(child_height, SILOFS_SPNODE_HEIGHT_MAX);

	silofs_vrange_setup_by(&vrange, child_height, voff);
	return vrange.beg;
}

void silofs_sbi_main_child_at(const struct silofs_sb_info *sbi,
                              loff_t voff, struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid blobid;
	loff_t base;
	loff_t bpos;

	silofs_sbi_main_blob(sbi, &blobid);
	base = sbi_base_voff_of_child(sbi, voff);
	bpos = sbi_bpos_of_child_spnode(sbi, voff);
	silofs_uaddr_setup(out_uaddr, &blobid, SILOFS_STYPE_SPNODE,
	                   SILOFS_SPNODE_HEIGHT_MAX, base, bpos);
}

static int flush_dirty_cache(struct silofs_sb_info *sbi, bool all)
{
	return silofs_apex_flush_dirty(sbi_apex(sbi), all ? SILOFS_F_NOW : 0);
}

static void sbi_update_vspace_last(struct silofs_sb_info *sbi, loff_t voff)
{
	const loff_t voff_last = silofs_sb_vspace_last(sbi->sb);

	if (voff > voff_last) {
		sb_set_vspace_last(sbi->sb, voff);
		sbi_dirtify(sbi);
	}
}

static void sbi_update_vlast_by_spnode(struct silofs_sb_info *sbi,
                                       const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	silofs_sni_vspace_range(sni, &vrange);
	sbi_update_vspace_last(sbi, vrange.beg);
}

void silofs_sbi_update_vlast_by_spleaf(struct silofs_sb_info *sbi,
                                       const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	sbi_update_vspace_last(sbi, vrange.end);
}

void silofs_sbi_bind_child(struct silofs_sb_info *sbi,
                           const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;
	struct silofs_ulink ulink;

	silofs_sni_vspace_range(sni, &vrange);
	silofs_ulink_setup(&ulink, sbi_uaddr(sbi), sni_uaddr(sni));

	sb_bind_subref_of(sbi->sb, vrange.beg, &ulink);
	sbi_update_vlast_by_spnode(sbi, sni);
	sbi_dirtify(sbi);
}

static int sbi_format_head_spmaps_of(struct silofs_sb_info *sbi)
{
	int err;
	loff_t voff = -1;

	err = silofs_sbi_expand_vspace(sbi, SILOFS_STYPE_DATABK, &voff);
	if (err) {
		log_err("failed to format head spmaps: err=%d", err);
	}
	return err;
}

int silofs_sbi_format_spmaps(struct silofs_sb_info *sbi)
{
	int err;

	err = sbi_format_head_spmaps_of(sbi);
	if (err) {
		return err;
	}
	err = flush_dirty_cache(sbi, true);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_subref_of(const struct silofs_sb_info *sbi, loff_t voff,
                         struct silofs_ulink *out_ulink)
{
	sb_umap_subref_of(sbi->sb, voff, out_ulink);

	return uaddr_isnull(&out_ulink->child) ? -ENOENT : 0;
}

bool silofs_sbi_has_child_at(const struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_ulink ulink;

	sb_umap_subref_of(sbi->sb, voff, &ulink);
	return !uaddr_isnull(&ulink.child);
}

void silofs_sbi_rebind_packid(struct silofs_sb_info *sbi, loff_t voff,
                              const struct silofs_packid *packid)
{
	sb_umap_rebind_packid(sbi->sb, voff, packid);
	sbi_dirtify(sbi);
}

int silofs_sbi_lookup_packid(const struct silofs_sb_info *sbi,
                             const struct silofs_blobid *blobid,
                             struct silofs_packid *out_packid)
{
	return sb_umap_lookup_packid(sbi->sb, blobid, out_packid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_expand_vspace(struct silofs_sb_info *sbi,
                             enum silofs_stype stype, loff_t *out_voff)
{
	int err;
	loff_t voff = -1;
	struct silofs_vaddr vaddr;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;

	err = sbi_resolve_unformatted_end(sbi, &voff);
	if (err) {
		return err;
	}
	vaddr_setup(&vaddr, stype, voff);
	err = silofs_sbi_require_spmaps_at(sbi, &vaddr, stg_flags);
	if (err) {
		log_dbg("can not expand space: voff=0x%lx err=%d", voff, err);
		return err;
	}
	*out_voff = voff;
	return 0;
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
	int err;
	struct silofs_vaddr vaddr;

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
	int err;
	struct silofs_vaddr vaddr;

	err = silofs_format_itable_root(sbi, &vaddr);
	if (err) {
		return err;
	}
	sb_set_itable_root(sbi->sb, &vaddr);
	sbi_dirtify(sbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_dirtify(struct silofs_sb_info *sbi)
{
	ui_dirtify(&sbi->s_ui);
}

void silofs_sbi_init_commons(struct silofs_sb_info *sbi)
{
	silofs_bootsec_init(&sbi->s_bsec);
	sbi->s_owner.uid = getuid();
	sbi->s_owner.gid = getgid();
	sbi->s_owner.pid = getpid();
	sbi->s_owner.umask = 0002;
	sbi->s_ctl_flags = 0;
	sbi->s_ms_flags = 0;
	sbi->s_mntime = 0;
}

static void sbi_fini_commons(struct silofs_sb_info *sbi)
{
	silofs_bootsec_fini(&sbi->s_bsec);
	sbi->s_ctl_flags = 0;
	sbi->s_ms_flags = 0;
	sbi->sb = NULL;
}

static int sbi_init_iti(struct silofs_sb_info *sbi)
{
	return silofs_itbi_init(&sbi->s_itbi, sbi->s_alif);
}

static void sbi_fini_iti(struct silofs_sb_info *sbi)
{
	silofs_itbi_fini(&sbi->s_itbi);
}

static void sbi_bind_by(struct silofs_sb_info *sbi,
                        struct silofs_fs_apex *apex)
{
	sbi->s_ui.u_ti.t_apex = apex;
	sbi->s_alif = apex->ap_alif;
}

int silofs_sbi_xinit(struct silofs_sb_info *sbi, struct silofs_fs_apex *apex)
{
	sbi_bind_by(sbi, apex);
	return sbi_init_iti(sbi);
}

void silofs_sbi_fini(struct silofs_sb_info *sbi)
{
	sbi_fini_iti(sbi);
	sbi_fini_commons(sbi);
}

bool silofs_sbi_isrofs(const struct silofs_sb_info *sbi)
{
	const unsigned long mask = MS_RDONLY;

	return ((sbi->s_ms_flags & mask) == mask);
}

void silofs_sbi_attach_ubi(struct silofs_sb_info *sbi,
                           struct silofs_ubk_info *ubi)
{
	struct silofs_unode_info *ui = &sbi->s_ui;

	silofs_ui_attach_bk(ui, ubi);
	silofs_ui_bind_view(ui);
	sbi->sb = &ui->u_ti.t_view->sb;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_check_stage(const struct silofs_sb_info *sbi,
                           enum silofs_stage_flags stg_flags)
{
	int err = 0;

	if (stg_flags & SILOFS_STAGE_MUTABLE) {
		err = silof_check_writable_fs(sbi);
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

int silofs_stage_vnode(struct silofs_sb_info *sbi,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_vnode_info **out_vi)
{
	struct silofs_uvaddr uva;
	int err;

	err = sbi_check_stage_vnode(sbi, vaddr, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_sbi_resolve_uva(sbi, vaddr, stg_flags, &uva);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_vi(sbi, vaddr, out_vi);
	if (!err) {
		return 0;  /* cache hit */
	}
	err = silofs_sbi_stage_vnode_at(sbi, &uva, stg_flags, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_inode(struct silofs_sb_info *sbi, ino_t ino,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = {
		.ino = ino,
	};
	struct silofs_iuvaddr iuva = {
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
	err = silofs_sbi_resolve_uva(sbi, &iaddr.vaddr,
	                             stg_flags, &iuva.uva);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_ii(sbi, &iaddr.vaddr, out_ii);
	if (!err) {
		return 0;
	}
	err = silofs_sbi_stage_inode_at(sbi, &iuva, stg_flags, out_ii);
	if (err) {
		return err;
	}
	err = sbi_check_staged_inode(*out_ii, stg_flags);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_cached_inode(struct silofs_sb_info *sbi, ino_t ino,
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

int silofs_spawn_vnode(struct silofs_sb_info *sbi, enum silofs_stype stype,
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

int silofs_spawn_inode(struct silofs_sb_info *sbi,
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

int silofs_remove_inode(struct silofs_sb_info *sbi,
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
	struct silofs_uvaddr uva;
	int err;

	err = silofs_sbi_resolve_uva(sbi, vaddr, SILOFS_STAGE_RDONLY, &uva);
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

int silofs_remove_vnode(struct silofs_sb_info *sbi,
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

int silofs_remove_vnode_at(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_vnode_info *vi = NULL;

	err = sbi_lookup_cached_vi(sbi, vaddr, &vi);
	if (!err) {
		err = silofs_remove_vnode(sbi, vi);
	} else {
		err = sbi_reclaim_vspace(sbi, vaddr);
	}
	return err;
}

int silofs_probe_unwritten(struct silofs_sb_info *sbi,
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

int silofs_clear_unwritten(struct silofs_sb_info *sbi,
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

int silofs_mark_unwritten(struct silofs_sb_info *sbi,
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

int silofs_refcnt_islast_at(struct silofs_sb_info *sbi,
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
	sbi->s_owner.uid = args->uid;
	sbi->s_owner.gid = args->gid;
	sbi->s_owner.pid = args->pid;
	sbi->s_owner.umask = args->umask;
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
	sbi->s_ms_flags |= ms_flag_with;
	sbi->s_ms_flags &= ~ms_flag_dont;
}

static void sbi_update_ctlflags(struct silofs_sb_info *sbi,
                                const struct silofs_fs_args *args)
{
	if (args->kcopy) {
		sbi->s_ctl_flags |= SILOFS_F_KCOPY;
	}
	if (args->allowother) {
		sbi->s_ctl_flags |= SILOFS_F_ALLOWOTHER;
	}
}

void silofs_sbi_update_by_args(struct silofs_sb_info *sbi,
                               const struct silofs_fs_args *args)
{
	sbi_update_owner(sbi, args);
	sbi_update_mntflags(sbi, args);
	sbi_update_ctlflags(sbi, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_mdigest *
sbi_mdigest(const struct silofs_sb_info *sbi)
{
	return &sbi->s_ui.u_ti.t_apex->ap_crypto->md;
}

static void sbi_zero_stamp_sb_view(struct silofs_sb_info *sbi)
{
	union silofs_view *view = sbi->s_ui.u_ti.t_view;

	silofs_zero_stamp_view(view, SILOFS_STYPE_SUPER);
}

static void sbi_assign_vspace_span(struct silofs_sb_info *sbi)
{
	struct silofs_vrange vrange;

	silofs_vrange_setup_by(&vrange, SILOFS_SUPER_HEIGHT, 0);
	sb_umap_set_vrange(sbi->sb, &vrange);
}

void silofs_sbi_update_birth_time(struct silofs_sb_info *sbi, time_t btime)
{
	sb_set_birth_time(sbi->sb, btime);
	sbi_dirtify(sbi);
}

void silofs_sbi_name(const struct silofs_sb_info *sbi,
                     struct silofs_namestr *out_name)
{
	return silofs_bootsec_name(&sbi->s_bsec, out_name);
}

void silofs_sbi_set_name(struct silofs_sb_info *sbi,
                         const struct silofs_namestr *name)
{
	silofs_bootsec_set_name(&sbi->s_bsec, name);
	sbi_dirtify(sbi);
}

bool silofs_sbi_has_name(const struct silofs_sb_info *sbi,
                         const struct silofs_namestr *name)
{
	return silofs_bootsec_has_name(&sbi->s_bsec, name);
}

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi,
                              size_t capacity, time_t btime)
{
	sbi_zero_stamp_sb_view(sbi);
	sb_init(sbi->sb);
	sb_umap_set_self(sbi->sb, sbi_uaddr(sbi));
	sb_setup_fresh(sbi->sb, silofs_time_now(), capacity);
	sb_rand_setup(sbi->sb, sbi_mdigest(sbi));
	sbi_assign_vspace_span(sbi);
	sb_set_birth_time(sbi->sb, btime);
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
	ucred_copyto(&sbi_other->s_owner, &sbi->s_owner);
	silofs_itbi_update_by(&sbi->s_itbi, &sbi_other->s_itbi);
	sbi->s_ctl_flags = sbi_other->s_ctl_flags;
	sbi->s_ms_flags = sbi_other->s_ms_flags;
	sbi->s_mntime = sbi_other->s_mntime;
}

static void sbi_regenerate_post_dup(const struct silofs_sb_info *sbi)
{
	struct silofs_super_block *sb = sbi->sb;

	sb_umap_generate_treeid(sb);
	sb_umap_reset_main_blobid(sb);
	sb_umap_set_self(sb, sbi_uaddr(sbi));
}

void silofs_sbi_clone_from(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other)
{
	silofs_assert(!silofs_sbi_has_main_blob(sbi));

	silofs_ui_clone_into(&sbi_other->s_ui, &sbi->s_ui);
	sbi_update_by(sbi, sbi_other);
	sbi_regenerate_post_dup(sbi);
	sbi_dirtify(sbi);

	silofs_assert(!silofs_sbi_has_main_blob(sbi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_save_bootsec(const struct silofs_sb_info *sbi)
{
	const struct silofs_bootsec *bsec = &sbi->s_bsec;
	struct silofs_namestr nstr;

	silofs_namebuf_str(&bsec->name, &nstr);
	return silofs_repo_save_bsec(sbi_repo(sbi), bsec, &nstr);
}

int silofs_sbi_load_bootsec(struct silofs_sb_info *sbi,
                            const struct silofs_namestr *name)
{
	return silofs_repo_load_bsec(sbi_repo(sbi), name, &sbi->s_bsec);
}
