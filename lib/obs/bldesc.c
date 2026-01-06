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
#include "infra.h"
#include "addr.h"
#include "bldesc.h"

static void
bld_set_btime(struct silofs_blob_desc *bld, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &bld->bld_btime);
}

static void
bld_set_ctime(struct silofs_blob_desc *bld, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &bld->bld_ctime);
}

static void
bld_set_prev(struct silofs_blob_desc *bld, const struct silofs_blobid *blobid)
{
	silofs_blobid_copyto(blobid, &bld->bld_prev);
}

static void bld_reset_prev(struct silofs_blob_desc *bld)
{
	bld_set_prev(bld, silofs_blobid_none());
}

static void bld_refblob(const struct silofs_blob_desc *bld,
                        struct silofs_blobid          *out_blobid)
{
	silofs_blobid_copyto(&bld->bld_prev, out_blobid);
}

static void bld_set_refblob(struct silofs_blob_desc    *bld,
                            const struct silofs_blobid *blobid)
{
	silofs_blobid_copyto(blobid, &bld->bld_refblob);
}

static void bld_reset_refblob(struct silofs_blob_desc *bld)
{
	bld_set_refblob(bld, silofs_blobid_none());
}

static bool bld_has_refblob(const struct silofs_blob_desc *bld,
                            const struct silofs_blobid    *blobid)
{
	struct silofs_blobid ref;

	bld_refblob(bld, &ref);
	return silofs_blobid_isequal(&ref, blobid);
}

static void bld_set_blobsize(struct silofs_blob_desc *bld, size_t sz)
{
	bld->bld_blobsize = silofs_cpu_to_le64(sz);
}

static size_t bld_objsize(const struct silofs_blob_desc *bld)
{
	return silofs_le32_to_cpu(bld->bld_objsize);
}

static void bld_set_objsize(struct silofs_blob_desc *bld, size_t sz)
{
	bld->bld_objsize = silofs_cpu_to_le32((uint32_t)sz);
}

static size_t bld_nobjs_max(const struct silofs_blob_desc *bld)
{
	return silofs_le32_to_cpu(bld->bld_nobjs_max);
}

static void bld_set_nobjs_max(struct silofs_blob_desc *bld, size_t n)
{
	bld->bld_nobjs_max = silofs_cpu_to_le32((uint32_t)n);
}

static size_t bld_nobjs(const struct silofs_blob_desc *bld)
{
	return silofs_le32_to_cpu(bld->bld_nobjs);
}

static void bld_set_nobjs(struct silofs_blob_desc *bld, size_t n)
{
	silofs_assert_le(n, bld_nobjs_max(bld));

	bld->bld_nobjs = silofs_cpu_to_le32((uint32_t)n);
}

static void bld_inc_nobjs(struct silofs_blob_desc *bld)
{
	bld_set_nobjs(bld, bld_nobjs(bld) + 1);
}

static void bld_dec_nobjs(struct silofs_blob_desc *bld)
{
	bld_set_nobjs(bld, bld_nobjs(bld) - 1);
}

static enum silofs_mtype bld_refmtype(const struct silofs_blob_desc *bld)
{
	const uint8_t refmtype = bld->bld_refmtype;

	return (enum silofs_mtype)refmtype;
}

static void
bld_set_refmtype(struct silofs_blob_desc *bld, enum silofs_mtype refmtype)
{
	bld->bld_refmtype = (uint8_t)refmtype;
}

static bool
bld_has_refmtype(const struct silofs_blob_desc *bld, enum silofs_mtype mtype)
{
	return (mtype == bld_refmtype(bld));
}

static size_t bld_calc_obj_state_max(const struct silofs_blob_desc *bld,
                                     enum silofs_mtype              refmtype)
{
	const size_t lim = ARRAY_SIZE(bld->bld_obj_state);
	const size_t msz = silofs_mtype_size(refmtype);

	return (msz == SILOFS_LBK_SIZE) ? silofs_min_u64(lim, 4096) : lim;
}

static void bld_reset_obj_state(struct silofs_blob_desc *bld)
{
	memset(bld->bld_obj_state, 0, sizeof(bld->bld_obj_state));
}

static bool bld_is_valid_slot(const struct silofs_blob_desc *bld, size_t slot)
{
	return (slot < bld_nobjs_max(bld));
}

static off_t bld_slot_to_pos(const struct silofs_blob_desc *bld, size_t slot)
{
	off_t pos = SILOFS_OFF_NULL;

	if (likely(bld_is_valid_slot(bld, slot))) {
		pos = silofs_off_end(0, slot * bld_objsize(bld));
	}
	return pos;
}

static off_t bld_pos_max(const struct silofs_blob_desc *bld)
{
	return silofs_off_end(0, bld_nobjs_max(bld) * bld_objsize(bld));
}

static bool bld_is_valid_pos(const struct silofs_blob_desc *bld, off_t pos)
{
	size_t objsz;

	if (pos < 0) {
		return false;
	}
	if (pos >= bld_pos_max(bld)) {
		return false;
	}
	objsz = bld_objsize(bld);
	if ((size_t)pos % objsz) {
		return false;
	}
	return true;
}

static size_t bld_pos_to_slot(const struct silofs_blob_desc *bld, off_t pos)
{
	size_t slot;

	if (bld_is_valid_pos(bld, pos)) {
		slot = ((size_t)pos / bld_objsize(bld));
	} else {
		slot = bld_nobjs_max(bld);
	}
	return slot;
}

static enum silofs_objstatef
bld_obj_state_at(const struct silofs_blob_desc *bld, size_t slot)
{
	uint8_t obsf = SILOFS_OBJSTATEF_NONE;

	if (likely(bld_is_valid_slot(bld, slot))) {
		obsf = bld->bld_obj_state[slot];
	}
	return (enum silofs_objstatef)obsf;
}

static void bld_set_obj_state_at(struct silofs_blob_desc *bld, size_t slot,
                                 enum silofs_objstatef obsf)
{
	if (likely(bld_is_valid_slot(bld, slot))) {
		bld->bld_obj_state[slot] = (uint8_t)obsf;
	}
}

static bool
bld_has_free_slot_at(const struct silofs_blob_desc *bld, size_t slot)
{
	return bld_obj_state_at(bld, slot) == SILOFS_OBJSTATEF_NONE;
}

static bool bld_has_free_slot_by(const struct silofs_blob_desc *bld, off_t pos)
{
	return bld_has_free_slot_at(bld, bld_pos_to_slot(bld, pos));
}

static bool bld_has_free_slot(const struct silofs_blob_desc *bld)
{
	return bld_nobjs(bld) < bld_nobjs_max(bld);
}

static bool
bld_has_used_slot_at(const struct silofs_blob_desc *bld, size_t slot)
{
	return (bld_obj_state_at(bld, slot) & SILOFS_OBJSTATEF_USED) > 0;
}

static bool bld_has_used_slot_by(const struct silofs_blob_desc *bld, off_t pos)
{
	return bld_has_used_slot_at(bld, bld_pos_to_slot(bld, pos));
}

static bool bld_has_used_slot(const struct silofs_blob_desc *bld)
{
	return bld_nobjs(bld) > 0;
}

static size_t bld_find_free_slot(const struct silofs_blob_desc *bld)
{
	const size_t nobjs_max = bld_nobjs_max(bld);
	const size_t nobjs_cur = bld_nobjs(bld);
	size_t       slot;

	for (slot = nobjs_cur; slot < nobjs_max; ++slot) {
		if (bld_has_free_slot_at(bld, slot)) {
			return slot;
		}
	}
	for (slot = 0; slot < nobjs_cur; ++slot) {
		if (bld_has_free_slot_at(bld, slot)) {
			return slot;
		}
	}
	return nobjs_max;
}

static off_t bld_find_free_pos(const struct silofs_blob_desc *bld)
{
	return bld_slot_to_pos(bld, bld_find_free_slot(bld));
}

static void bld_mark_free_slot(struct silofs_blob_desc *bld, size_t slot)
{
	bld_set_obj_state_at(bld, slot, SILOFS_OBJSTATEF_NONE);
}

static void bld_mark_free_slot_by(struct silofs_blob_desc *bld, off_t pos)
{
	bld_mark_free_slot(bld, bld_pos_to_slot(bld, pos));
}

static void bld_mark_used_slot(struct silofs_blob_desc *bld, size_t slot)
{
	bld_set_obj_state_at(bld, slot, SILOFS_OBJSTATEF_USED);
}

static void bld_mark_used_slot_by(struct silofs_blob_desc *bld, off_t pos)
{
	bld_mark_used_slot(bld, bld_pos_to_slot(bld, pos));
}

static void bld_paddr_at(const struct silofs_blob_desc *bld, off_t pos,
                         struct silofs_paddr *out_paddr)
{
	struct silofs_blobid blobid;

	if (!bld_is_valid_pos(bld, pos)) {
		pos = SILOFS_OFF_NULL;
	}
	bld_refblob(bld, &blobid);
	silofs_paddr_init(out_paddr, &blobid, pos);
}

static void bld_setup(struct silofs_blob_desc *bld)
{
	bld_reset_prev(bld);
	bld_reset_refblob(bld);
	bld_set_blobsize(bld, 0);
	bld_set_objsize(bld, 0);
	bld_set_nobjs_max(bld, 0);
	bld_set_nobjs(bld, 0);
	bld_set_refmtype(bld, SILOFS_MTYPE_NONE);
	bld_reset_obj_state(bld);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void bdi_setup_spawned(struct silofs_bldesc_info *bdi)
{
	bld_setup(bdi->bld);
	silofs_bdi_dirtify(bdi);
}

void silofs_bdi_dirtify(struct silofs_bldesc_info *bdi)
{
	silofs_pni_dirtify(&bdi->bld_pni);
}

void silofs_bdi_undirtify(struct silofs_bldesc_info *bdi)
{
	silofs_pni_undirtify(&bdi->bld_pni);
}

void silofs_bdi_setup_spawned(struct silofs_bldesc_info *bdi,
                              enum silofs_mtype          refmtype)
{
	struct timespec now;
	const size_t    obj_size  = silofs_mtype_size(refmtype);
	const size_t    nobjs_max = bld_calc_obj_state_max(bdi->bld, refmtype);
	const size_t    blob_size = obj_size * nobjs_max;

	silofs_clock_real_now(&now);
	bld_set_btime(bdi->bld, &now);
	bld_set_ctime(bdi->bld, &now);
	bld_set_blobsize(bdi->bld, blob_size);
	bld_set_objsize(bdi->bld, obj_size);
	bld_set_nobjs_max(bdi->bld, nobjs_max);
	bld_set_nobjs(bdi->bld, 0);
	bld_set_refmtype(bdi->bld, refmtype);
	bld_reset_obj_state(bdi->bld);
	silofs_bdi_dirtify(bdi);
}

void silofs_bdi_set_refblob(struct silofs_bldesc_info  *bdi,
                            const struct silofs_blobid *blobid)
{
	bld_set_refblob(bdi->bld, blobid);
	silofs_bdi_dirtify(bdi);
}

int silofs_bdi_find_free(const struct silofs_bldesc_info *bdi,
                         struct silofs_paddr             *out_paddr)
{
	const struct silofs_blob_desc *bld = bdi->bld;
	off_t                          pos;

	silofs_paddr_reset(out_paddr);
	if (!bld_has_free_slot(bld)) {
		return -SILOFS_ENOSPC;
	}
	pos = bld_find_free_pos(bld);
	if (silofs_off_isnull(pos)) {
		return -SILOFS_ENOSPC;
	}
	bld_paddr_at(bdi->bld, pos, out_paddr);
	return 0;
}

static bool bdi_is_valid_paddr(const struct silofs_bldesc_info *bdi,
                               const struct silofs_paddr       *paddr)
{
	if (!bld_has_refmtype(bdi->bld, paddr->mtype)) {
		return false;
	}
	if (!bld_is_valid_pos(bdi->bld, paddr->pos)) {
		return false;
	}
	if (!bld_has_refblob(bdi->bld, &paddr->blobid)) {
		return false;
	}
	return true;
}

int silofs_bdi_test_free(const struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr       *paddr)
{
	if (!bdi_is_valid_paddr(bdi, paddr)) {
		return -SILOFS_EINVAL;
	}
	if (!bld_has_free_slot(bdi->bld)) {
		return -SILOFS_ENOSPC;
	}
	if (!bld_has_free_slot_by(bdi->bld, paddr->pos)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_bdi_mark_free(struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr *paddr)
{
	if (!bdi_is_valid_paddr(bdi, paddr)) {
		return -SILOFS_EINVAL;
	}
	if (!bld_has_used_slot(bdi->bld)) {
		return -SILOFS_ENOENT;
	}
	if (!bld_has_free_slot_by(bdi->bld, paddr->pos)) {
		return -SILOFS_ENOENT;
	}
	bld_mark_used_slot_by(bdi->bld, paddr->pos);
	bld_inc_nobjs(bdi->bld);
	silofs_bdi_dirtify(bdi);
	return 0;
}

int silofs_bdi_mark_used(struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr *paddr)
{
	if (!bdi_is_valid_paddr(bdi, paddr)) {
		return -SILOFS_EINVAL;
	}
	if (!bld_has_free_slot(bdi->bld)) {
		return -SILOFS_ENOENT;
	}
	if (!bld_has_used_slot_by(bdi->bld, paddr->pos)) {
		return -SILOFS_ENOENT;
	}
	bld_mark_free_slot_by(bdi->bld, paddr->pos);
	bld_dec_nobjs(bdi->bld);
	silofs_bdi_dirtify(bdi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_bldesc_info *
silofs_lookup_cached_bldesc(struct silofs_pcache      *pcache,
                            const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BLDESC);
	pni = silofs_pcache_lookup_pnode(pcache, paddr);
	return silofs_bdi_from_pni(pni);
}

struct silofs_bldesc_info *
silofs_create_cached_bldesc(struct silofs_pcache      *pcache,
                            const struct silofs_pmeta *pmeta, bool spawn)
{
	struct silofs_pnode_info  *pni;
	struct silofs_bldesc_info *bdi;

	pni = silofs_pcache_create_pnode(pcache, pmeta);
	bdi = silofs_bdi_from_pni(pni);
	if ((bdi != nullptr) && spawn) {
		bdi_setup_spawned(bdi);
	}
	return bdi;
}

void silofs_forget_cached_bldesc(struct silofs_pcache      *pcache,
                                 struct silofs_bldesc_info *bdi)
{
	silofs_pcache_delete_pnode(pcache, &bdi->bld_pni);
}
