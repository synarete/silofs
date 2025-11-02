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
#include "infra.h"
#include "addr.h"
#include "bldesc.h"

static void bd_setup_hdr(struct silofs_blob_desc *bd)
{
	silofs_hdr_setup(&bd->bd_hdr, SILOFS_MTYPE_BDESC, sizeof(*bd));
}

static void
bd_set_btime(struct silofs_blob_desc *bd, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &bd->bd_btime);
}

static void
bd_set_ctime(struct silofs_blob_desc *bd, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &bd->bd_ctime);
}

static void
bd_set_prev(struct silofs_blob_desc *bd, const struct silofs_blobid *blobid)
{
	silofs_blobid_copyto(blobid, &bd->bd_prev);
}

static void bd_reset_prev(struct silofs_blob_desc *bd)
{
	bd_set_prev(bd, silofs_blobid_none());
}

static void
bd_refblob(const struct silofs_blob_desc *bd, struct silofs_blobid *out_blobid)
{
	silofs_blobid_copyto(&bd->bd_prev, out_blobid);
}

static void
bd_set_refblob(struct silofs_blob_desc *bd, const struct silofs_blobid *blobid)
{
	silofs_blobid_copyto(blobid, &bd->bd_refblob);
}

static void bd_reset_refblob(struct silofs_blob_desc *bd)
{
	bd_set_refblob(bd, silofs_blobid_none());
}

static bool bd_has_refblob(const struct silofs_blob_desc *bd,
                           const struct silofs_blobid *blobid)
{
	struct silofs_blobid ref;

	bd_refblob(bd, &ref);
	return silofs_blobid_isequal(&ref, blobid);
}

static void bd_set_blobsize(struct silofs_blob_desc *bd, size_t sz)
{
	bd->bd_blobsize = silofs_cpu_to_le64(sz);
}

static size_t bd_objsize(const struct silofs_blob_desc *bd)
{
	return silofs_le32_to_cpu(bd->bd_objsize);
}

static void bd_set_objsize(struct silofs_blob_desc *bd, size_t sz)
{
	bd->bd_objsize = silofs_cpu_to_le32((uint32_t)sz);
}

static size_t bd_nobjs_max(const struct silofs_blob_desc *bd)
{
	return silofs_le32_to_cpu(bd->bd_nobjs_max);
}

static void bd_set_nobjs_max(struct silofs_blob_desc *bd, size_t n)
{
	bd->bd_nobjs_max = silofs_cpu_to_le32((uint32_t)n);
}

static size_t bd_nobjs(const struct silofs_blob_desc *bd)
{
	return silofs_le32_to_cpu(bd->bd_nobjs);
}

static void bd_set_nobjs(struct silofs_blob_desc *bd, size_t n)
{
	silofs_assert_le(n, bd_nobjs_max(bd));

	bd->bd_nobjs = silofs_cpu_to_le32((uint32_t)n);
}

static void bd_inc_nobjs(struct silofs_blob_desc *bd)
{
	bd_set_nobjs(bd, bd_nobjs(bd) + 1);
}

static void bd_dec_nobjs(struct silofs_blob_desc *bd)
{
	bd_set_nobjs(bd, bd_nobjs(bd) - 1);
}

static enum silofs_mtype bd_refmtype(const struct silofs_blob_desc *bd)
{
	const uint16_t refmtype = silofs_le16_to_cpu(bd->bd_refmtype);

	return (enum silofs_mtype)refmtype;
}

static void
bd_set_refmtype(struct silofs_blob_desc *bd, enum silofs_mtype refmtype)
{
	bd->bd_refmtype = silofs_cpu_to_le16((uint16_t)refmtype);
}

static bool
bd_has_refmtype(const struct silofs_blob_desc *bd, enum silofs_mtype mtype)
{
	return (mtype == bd_refmtype(bd));
}

static size_t bd_calc_obj_state_max(const struct silofs_blob_desc *bd,
                                    enum silofs_mtype refmtype)
{
	const size_t lim = ARRAY_SIZE(bd->bd_obj_state);
	const size_t msz = silofs_mtype_size(refmtype);

	return (msz == SILOFS_LBK_SIZE) ? silofs_min_u64(lim, 4096) : lim;
}

static void bd_reset_obj_state(struct silofs_blob_desc *bd)
{
	memset(bd->bd_obj_state, 0, sizeof(bd->bd_obj_state));
}

static bool bd_is_valid_slot(const struct silofs_blob_desc *bd, size_t slot)
{
	return (slot < bd_nobjs_max(bd));
}

static off_t bd_slot_to_pos(const struct silofs_blob_desc *bd, size_t slot)
{
	off_t pos = SILOFS_OFF_NULL;

	if (likely(bd_is_valid_slot(bd, slot))) {
		pos = silofs_off_end(0, slot * bd_objsize(bd));
	}
	return pos;
}

static off_t bd_pos_max(const struct silofs_blob_desc *bd)
{
	return silofs_off_end(0, bd_nobjs_max(bd) * bd_objsize(bd));
}

static bool bd_is_valid_pos(const struct silofs_blob_desc *bd, off_t pos)
{
	size_t objsz;

	if (pos < 0) {
		return false;
	}
	if (pos >= bd_pos_max(bd)) {
		return false;
	}
	objsz = bd_objsize(bd);
	if ((size_t)pos % objsz) {
		return false;
	}
	return true;
}

static size_t bd_pos_to_slot(const struct silofs_blob_desc *bd, off_t pos)
{
	size_t slot;

	if (bd_is_valid_pos(bd, pos)) {
		slot = ((size_t)pos / bd_objsize(bd));
	} else {
		slot = bd_nobjs_max(bd);
	}
	return slot;
}

static enum silofs_objstatef
bd_obj_state_at(const struct silofs_blob_desc *bd, size_t slot)
{
	uint8_t obsf = SILOFS_OBJSTATEF_NONE;

	if (likely(bd_is_valid_slot(bd, slot))) {
		obsf = bd->bd_obj_state[slot];
	}
	return (enum silofs_objstatef)obsf;
}

static void bd_set_obj_state_at(struct silofs_blob_desc *bd, size_t slot,
                                enum silofs_objstatef obsf)
{
	if (likely(bd_is_valid_slot(bd, slot))) {
		bd->bd_obj_state[slot] = (uint8_t)obsf;
	}
}

static bool bd_has_free_slot_at(const struct silofs_blob_desc *bd, size_t slot)
{
	return bd_obj_state_at(bd, slot) == SILOFS_OBJSTATEF_NONE;
}

static bool bd_has_free_slot_by(const struct silofs_blob_desc *bd, off_t pos)
{
	return bd_has_free_slot_at(bd, bd_pos_to_slot(bd, pos));
}

static bool bd_has_free_slot(const struct silofs_blob_desc *bd)
{
	return bd_nobjs(bd) < bd_nobjs_max(bd);
}

static bool bd_has_used_slot_at(const struct silofs_blob_desc *bd, size_t slot)
{
	return (bd_obj_state_at(bd, slot) & SILOFS_OBJSTATEF_USED) > 0;
}

static bool bd_has_used_slot_by(const struct silofs_blob_desc *bd, off_t pos)
{
	return bd_has_used_slot_at(bd, bd_pos_to_slot(bd, pos));
}

static bool bd_has_used_slot(const struct silofs_blob_desc *bd)
{
	return bd_nobjs(bd) > 0;
}

static size_t bd_find_free_slot(const struct silofs_blob_desc *bd)
{
	const size_t nobjs_max = bd_nobjs_max(bd);
	const size_t nobjs_cur = bd_nobjs(bd);
	size_t slot;

	for (slot = nobjs_cur; slot < nobjs_max; ++slot) {
		if (bd_has_free_slot_at(bd, slot)) {
			return slot;
		}
	}
	for (slot = 0; slot < nobjs_cur; ++slot) {
		if (bd_has_free_slot_at(bd, slot)) {
			return slot;
		}
	}
	return nobjs_max;
}

static off_t bd_find_free_pos(const struct silofs_blob_desc *bd)
{
	return bd_slot_to_pos(bd, bd_find_free_slot(bd));
}

static void bd_mark_free_slot(struct silofs_blob_desc *bd, size_t slot)
{
	bd_set_obj_state_at(bd, slot, SILOFS_OBJSTATEF_NONE);
}

static void bd_mark_free_slot_by(struct silofs_blob_desc *bd, off_t pos)
{
	bd_mark_free_slot(bd, bd_pos_to_slot(bd, pos));
}

static void bd_mark_used_slot(struct silofs_blob_desc *bd, size_t slot)
{
	bd_set_obj_state_at(bd, slot, SILOFS_OBJSTATEF_USED);
}

static void bd_mark_used_slot_by(struct silofs_blob_desc *bd, off_t pos)
{
	bd_mark_used_slot(bd, bd_pos_to_slot(bd, pos));
}

static void bd_init(struct silofs_blob_desc *bd)
{
	bd_setup_hdr(bd);
	bd_reset_prev(bd);
	bd_reset_refblob(bd);
	bd_set_blobsize(bd, 0);
	bd_set_objsize(bd, 0);
	bd_set_nobjs_max(bd, 0);
	bd_set_nobjs(bd, 0);
	bd_set_refmtype(bd, SILOFS_MTYPE_NONE);
	bd_reset_obj_state(bd);
}

static void bd_fini(struct silofs_blob_desc *bd)
{
	bd_reset_prev(bd);
	bd_reset_refblob(bd);
	bd_set_nobjs(bd, 0);
	bd_reset_obj_state(bd);
}

static struct silofs_blob_desc *bd_malloc(struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd;

	bd = silofs_memalloc(alloc, sizeof(*bd), SILOFS_ALLOCF_BZERO);
	return bd;
}

static void bd_free(struct silofs_blob_desc *bd, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bd, sizeof(*bd), SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_blob_desc *bd_new(struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd;

	bd = bd_malloc(alloc);
	if (bd != nullptr) {
		bd_init(bd);
	}
	return bd;
}

static void bd_del(struct silofs_blob_desc *bd, struct silofs_alloc *alloc)
{
	bd_fini(bd);
	bd_free(bd, alloc);
}

static void bd_baddr_at(const struct silofs_blob_desc *bd, off_t pos,
                        struct silofs_baddr *out_baddr)
{
	struct silofs_blobid blobid;

	if (!bd_is_valid_pos(bd, pos)) {
		pos = SILOFS_OFF_NULL;
	}
	bd_refblob(bd, &blobid);
	silofs_baddr_init(out_baddr, &blobid, pos);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_bldesc_info *bdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_bldesc_info *bdi = nullptr;

	bdi = silofs_memalloc(alloc, sizeof(*bdi), 0);
	return bdi;
}

static void
bdi_free(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bdi, sizeof(*bdi), 0);
}

static void
bdi_init(struct silofs_bldesc_info *bdi, const struct silofs_baddr *baddr)
{
	silofs_assert(!silofs_baddr_isnull(baddr));

	silofs_bni_init(&bdi->bd_bni, baddr);
	bdi->bd = nullptr;
}

static void bdi_fini(struct silofs_bldesc_info *bdi)
{
	silofs_bni_fini(&bdi->bd_bni);
	bdi->bd = nullptr;
}

struct silofs_bldesc_info *
silofs_bdi_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd = nullptr;
	struct silofs_bldesc_info *bdi = nullptr;

	bd = bd_new(alloc);
	if (bd == nullptr) {
		return nullptr;
	}
	bdi = bdi_malloc(alloc);
	if (bdi == nullptr) {
		bd_del(bd, alloc);
		return nullptr;
	}
	bdi_init(bdi, baddr);
	bdi->bd = bd;
	return bdi;
}

void silofs_bdi_del(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd = bdi->bd;

	bdi_fini(bdi);
	bdi_free(bdi, alloc);
	bd_del(bd, alloc);
}

void silofs_bdi_dirtify(struct silofs_bldesc_info *bdi)
{
	silofs_bni_dirtify(&bdi->bd_bni);
}

void silofs_bdi_undirtify(struct silofs_bldesc_info *bdi)
{
	silofs_bni_undirtify(&bdi->bd_bni);
}

static struct silofs_bldesc_info *
bdi_unconst(const struct silofs_bldesc_info *p)
{
	union {
		const struct silofs_bldesc_info *p;
		struct silofs_bldesc_info *q;
	} u = { .p = p };

	return u.q;
}

struct silofs_bldesc_info *
silofs_bdi_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_bldesc_info *bdi = nullptr;

	if (bni != nullptr) {
		bdi = container_of2(bni, struct silofs_bldesc_info, bd_bni);
	}
	return bdi_unconst(bdi);
}

void silofs_bdi_set_dq(struct silofs_bldesc_info *bdi,
                       struct silofs_dirtyq *dq)
{
	silofs_bni_set_dq(&bdi->bd_bni, dq);
}

void silofs_bdi_setup_spawned(struct silofs_bldesc_info *bdi,
                              enum silofs_mtype refmtype)
{
	struct timespec now;
	const size_t obj_size = silofs_mtype_size(refmtype);
	const size_t nobjs_max = bd_calc_obj_state_max(bdi->bd, refmtype);
	const size_t blob_size = obj_size * nobjs_max;

	silofs_clock_real_now(&now);
	bd_set_btime(bdi->bd, &now);
	bd_set_ctime(bdi->bd, &now);
	bd_set_blobsize(bdi->bd, blob_size);
	bd_set_objsize(bdi->bd, obj_size);
	bd_set_nobjs_max(bdi->bd, nobjs_max);
	bd_set_nobjs(bdi->bd, 0);
	bd_set_refmtype(bdi->bd, refmtype);
	bd_reset_obj_state(bdi->bd);
	silofs_bdi_dirtify(bdi);
}

void silofs_bdi_set_refblob(struct silofs_bldesc_info *bdi,
                            const struct silofs_blobid *blobid)
{
	bd_set_refblob(bdi->bd, blobid);
	silofs_bdi_dirtify(bdi);
}

int silofs_bdi_find_free(const struct silofs_bldesc_info *bdi,
                         struct silofs_baddr *out_baddr)
{
	const struct silofs_blob_desc *bd = bdi->bd;
	off_t pos;

	silofs_baddr_reset(out_baddr);
	if (!bd_has_free_slot(bd)) {
		return -SILOFS_ENOSPC;
	}
	pos = bd_find_free_pos(bd);
	if (silofs_off_isnull(pos)) {
		return -SILOFS_ENOSPC;
	}
	bd_baddr_at(bdi->bd, pos, out_baddr);
	return 0;
}

static bool bdi_is_valid_baddr(const struct silofs_bldesc_info *bdi,
                               const struct silofs_baddr *baddr)
{
	if (!bd_has_refmtype(bdi->bd, baddr->mtype)) {
		return false;
	}
	if (!bd_is_valid_pos(bdi->bd, baddr->pos)) {
		return false;
	}
	if (!bd_has_refblob(bdi->bd, &baddr->blobid)) {
		return false;
	}
	return true;
}

int silofs_bdi_test_free(const struct silofs_bldesc_info *bdi,
                         const struct silofs_baddr *baddr)
{
	if (!bdi_is_valid_baddr(bdi, baddr)) {
		return -SILOFS_EINVAL;
	}
	if (!bd_has_free_slot(bdi->bd)) {
		return -SILOFS_ENOSPC;
	}
	if (!bd_has_free_slot_by(bdi->bd, baddr->pos)) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

int silofs_bdi_mark_free(struct silofs_bldesc_info *bdi,
                         const struct silofs_baddr *baddr)
{
	if (!bdi_is_valid_baddr(bdi, baddr)) {
		return -SILOFS_EINVAL;
	}
	if (!bd_has_used_slot(bdi->bd)) {
		return -SILOFS_ENOENT;
	}
	if (!bd_has_free_slot_by(bdi->bd, baddr->pos)) {
		return -SILOFS_ENOENT;
	}
	bd_mark_used_slot_by(bdi->bd, baddr->pos);
	bd_inc_nobjs(bdi->bd);
	silofs_bdi_dirtify(bdi);
	return 0;
}

int silofs_bdi_mark_used(struct silofs_bldesc_info *bdi,
                         const struct silofs_baddr *baddr)
{
	if (!bdi_is_valid_baddr(bdi, baddr)) {
		return -SILOFS_EINVAL;
	}
	if (!bd_has_free_slot(bdi->bd)) {
		return -SILOFS_ENOENT;
	}
	if (!bd_has_used_slot_by(bdi->bd, baddr->pos)) {
		return -SILOFS_ENOENT;
	}
	bd_mark_free_slot_by(bdi->bd, baddr->pos);
	bd_dec_nobjs(bdi->bd);
	silofs_bdi_dirtify(bdi);
	return 0;
}
