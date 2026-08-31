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
#include <sys/mount.h>
#include <silofs/pstor.h>

static void usn_blobid(const struct silofs_uspace_node *usn,
                       struct silofs_blobid *out_blobid)
{
	silofs_blobid48b_xtoh(&usn->us_blobid, out_blobid);
}

static void usn_set_blobid(struct silofs_uspace_node *usn,
                           const struct silofs_blobid *blobid)
{
	silofs_blobid48b_htox(&usn->us_blobid, blobid);
}

static bool usn_has_blobid(const struct silofs_uspace_node *usn,
                           const struct silofs_blobid *blobid2)
{
	struct silofs_blobid blobid;

	usn_blobid(usn, &blobid);
	return silofs_blobid_isequal(&blobid, blobid2);
}

static void
usn_set_btime(struct silofs_uspace_node *usn, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &usn->us_btime);
}

static void
usn_set_ctime(struct silofs_uspace_node *usn, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &usn->us_ctime);
}

static off_t usn_baseoff(const struct silofs_uspace_node *usn)
{
	return silofs_off_to_cpu(usn->us_baseoff);
}

static void usn_set_baseoff(struct silofs_uspace_node *usn, off_t off)
{
	silofs_assert_ge(off, 0);
	silofs_assert_lt(off, INT32_MAX / 2);
	usn->us_baseoff = silofs_cpu_to_off(off);
}

static size_t usn_count(const struct silofs_uspace_node *usn)
{
	return silofs_le32_to_cpu(usn->us_count);
}

static size_t usn_count_max(const struct silofs_uspace_node *usn)
{
	return (64 * ARRAY_SIZE(usn->us_state));
}

static void usn_set_count(struct silofs_uspace_node *usn, size_t count)
{
	silofs_assert_le(count, usn_count_max(usn));
	usn->us_count = silofs_cpu_to_le32((uint32_t)count);
}

static void usn_inc_count(struct silofs_uspace_node *usn)
{
	usn_set_count(usn, usn_count(usn) + 1);
}

static void usn_dec_count(struct silofs_uspace_node *usn)
{
	usn_set_count(usn, usn_count(usn) - 1);
}

static void
usn_set_prev(struct silofs_uspace_node *usn, const struct silofs_pnptr *pnptr)
{
	silofs_pnptr256b_htox(&usn->us_prev, pnptr);
}

static void usn_reset_prev(struct silofs_uspace_node *usn)
{
	usn_set_prev(usn, silofs_pnptr_none());
}

static uint64_t usn_state_at(const struct silofs_uspace_node *usn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(usn->us_state));

	return silofs_le64_to_cpu(usn->us_state[slot]);
}

static void
usn_set_state_at(struct silofs_uspace_node *usn, size_t slot, uint64_t state)
{
	silofs_assert_lt(slot, ARRAY_SIZE(usn->us_state));

	usn->us_state[slot] = silofs_cpu_to_le64(state);
}

static void usn_reset_state(struct silofs_uspace_node *usn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(usn->us_state); ++slot) {
		usn_set_state_at(usn, slot, 0);
	}
}

static void
usn_setup(struct silofs_uspace_node *usn, const struct silofs_blobid *blobid,
          const struct timespec *ts)
{
	usn_set_blobid(usn, blobid);
	usn_set_btime(usn, ts);
	usn_set_ctime(usn, ts);
	usn_set_baseoff(usn, SILOFS_PBK_SIZE);
	usn_set_count(usn, 0);
	usn_reset_prev(usn);
	usn_reset_state(usn);
}

static uint32_t usn_index_max(const struct silofs_uspace_node *usn)
{
	return (uint32_t)usn_count_max(usn);
}

static size_t
usn_index_to_slot(const struct silofs_uspace_node *usn, uint32_t idx)
{
	const size_t slot = idx / 64;

	silofs_assert_lt(slot, ARRAY_SIZE(usn->us_state));
	return slot;
}

static uint64_t
usn_index_to_mask(const struct silofs_uspace_node *usn, uint32_t idx)
{
	const uint64_t mask = 1UL << (idx % 64);

	silofs_unused(usn);
	return mask;
}

static bool
usn_isused_index(const struct silofs_uspace_node *usn, uint32_t idx)
{
	const size_t slot    = usn_index_to_slot(usn, idx);
	const uint64_t mask  = usn_index_to_mask(usn, idx);
	const uint64_t state = usn_state_at(usn, slot);

	return ((state & mask) == mask);
}

static bool
usn_isfree_index(const struct silofs_uspace_node *usn, uint32_t idx)
{
	return !usn_isused_index(usn, idx);
}

static void usn_set_used_index(struct silofs_uspace_node *usn, uint32_t idx)
{
	const size_t slot    = usn_index_to_slot(usn, idx);
	const uint64_t mask  = usn_index_to_mask(usn, idx);
	const uint64_t state = usn_state_at(usn, slot);

	silofs_assert((state & mask) == 0);
	usn_set_state_at(usn, slot, state | mask);
}

static void usn_set_free_index(struct silofs_uspace_node *usn, uint32_t idx)
{
	const size_t slot    = usn_index_to_slot(usn, idx);
	const uint64_t mask  = usn_index_to_mask(usn, idx);
	const uint64_t state = usn_state_at(usn, slot);

	silofs_assert((state & mask) == mask);
	usn_set_state_at(usn, slot, state & ~mask);
}

static uint32_t usn_find_free_index(const struct silofs_uspace_node *usn)
{
	const uint32_t idx_max = usn_index_max(usn);

	for (uint32_t idx = 0; idx < idx_max; ++idx) {
		if (usn_isfree_index(usn, idx)) {
			return idx;
		}
	}
	return idx_max;
}

static bool usn_has_free(const struct silofs_uspace_node *usn)
{
	return (usn_count(usn) < usn_count_max(usn));
}

static uint32_t usn_take_free(struct silofs_uspace_node *usn)
{
	const uint32_t idx_max = usn_index_max(usn);
	uint32_t idx;

	if (!usn_has_free(usn)) {
		return idx_max;
	}
	idx = usn_find_free_index(usn);
	if (idx >= idx_max) {
		return idx_max;
	}
	usn_set_used_index(usn, idx);
	usn_inc_count(usn);
	return idx;
}

static void usn_give_used(struct silofs_uspace_node *usn, uint32_t idx)
{
	usn_set_free_index(usn, idx);
	usn_dec_count(usn);
}

static void usn_paddr_from_index(const struct silofs_uspace_node *usn,
                                 uint32_t idx, struct silofs_paddr *out_paddr)
{
	struct silofs_blobid blobid;
	size_t ssz;
	off_t pos;

	usn_blobid(usn, &blobid);
	ssz = silofs_blobid_slotsize(&blobid);
	pos = usn_baseoff(usn) + (off_t)(idx * ssz);

	silofs_paddr_init(out_paddr, &blobid, pos);
}

static uint32_t usn_paddr_to_index(const struct silofs_uspace_node *usn,
                                   const struct silofs_paddr *paddr)
{
	struct silofs_blobid blobid;
	const uint32_t idx_max = usn_index_max(usn);
	ssize_t ssz;
	off_t off, pos;

	usn_blobid(usn, &blobid);
	ssz = (ssize_t)silofs_blobid_slotsize(&blobid);
	if (ssz <= 0) {
		return idx_max;
	}

	pos = paddr->pos;
	off = usn_baseoff(usn);
	if (pos < off) {
		return idx_max;
	}

	pos = pos - off;
	if ((pos % ssz) != 0) {
		return idx_max;
	}

	return (uint32_t)(pos / ssz);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_usi_incref(struct silofs_uspace_info *usi)
{
	silofs_pni_incref(&usi->us_pni);
}

void silofs_usi_decref(struct silofs_uspace_info *usi)
{
	silofs_pni_decref(&usi->us_pni);
}

void silofs_usi_setdirty(struct silofs_uspace_info *usi)
{
	silofs_pni_setdirty(&usi->us_pni);
}

void silofs_usi_cleardirty(struct silofs_uspace_info *usi)
{
	silofs_pni_cleardirty(&usi->us_pni);
}

void silofs_usi_update_spawned(struct silofs_uspace_info *usi,
                               const struct silofs_blobid *blobid)
{
	struct timespec ts;

	silofs_clock_gettime_real(&ts);
	usn_setup(usi->usn, blobid, &ts);
	silofs_usi_setdirty(usi);
}

int silofs_usi_grab_space(struct silofs_uspace_info *usi,
                          struct silofs_paddr *out_paddr)
{
	const uint32_t idx_max = usn_index_max(usi->usn);
	uint32_t idx;

	idx = usn_take_free(usi->usn);
	if (idx >= idx_max) {
		return -SILOFS_ENOSPC;
	}

	usn_paddr_from_index(usi->usn, idx, out_paddr);
	silofs_usi_setdirty(usi);
	return 0;
}

int silofs_usi_drop_space(struct silofs_uspace_info *usi,
                          const struct silofs_paddr *paddr)
{
	const uint32_t idx_max = usn_index_max(usi->usn);
	uint32_t idx;

	if (!usn_has_blobid(usi->usn, &paddr->blobid)) {
		return -SILOFS_ENOENT;
	}

	idx = usn_paddr_to_index(usi->usn, paddr);
	if (idx >= idx_max) {
		return -SILOFS_EINVAL;
	}

	if (!usn_isused_index(usi->usn, idx)) {
		return -SILOFS_ENOENT;
	}

	usn_give_used(usi->usn, idx);
	silofs_usi_setdirty(usi);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
ubs_btroot(const struct silofs_uber_sub *ubs, struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr256b_xtoh(&ubs->ubs_btroot, out_pnptr);
}

static void
ubs_set_btroot(struct silofs_uber_sub *ubs, const struct silofs_pnptr *pnptr)
{
	silofs_pnptr256b_htox(&ubs->ubs_btroot, pnptr);
}

static void ubs_bn_nextfree(const struct silofs_uber_sub *ubs,
                            struct silofs_paddr *out_paddr)
{
	silofs_paddr64b_xtoh(&ubs->ubs_bn_nextfree, out_paddr);
}

static void ubs_set_bn_nextfree(struct silofs_uber_sub *ubs,
                                const struct silofs_paddr *paddr)
{
	silofs_paddr64b_htox(&ubs->ubs_bn_nextfree, paddr);
}

static void ubs_vn_nextfree(const struct silofs_uber_sub *ubs,
                            struct silofs_paddr *out_paddr)
{
	silofs_paddr64b_xtoh(&ubs->ubs_vn_nextfree, out_paddr);
}

static void ubs_set_vn_nextfree(struct silofs_uber_sub *ubs,
                                const struct silofs_paddr *paddr)
{
	silofs_paddr64b_htox(&ubs->ubs_vn_nextfree, paddr);
}

static uint64_t ubs_bn_count(const struct silofs_uber_sub *ubs)
{
	return silofs_le64_to_cpu(ubs->ubs_bn_count);
}

static void ubs_set_bn_count(struct silofs_uber_sub *ubs, uint64_t n)
{
	ubs->ubs_bn_count = silofs_cpu_to_le64(n);
}

static uint64_t ubs_vn_count(const struct silofs_uber_sub *ubs)
{
	return silofs_le64_to_cpu(ubs->ubs_vn_count);
}

static void ubs_set_vn_count(struct silofs_uber_sub *ubs, uint64_t n)
{
	ubs->ubs_vn_count = silofs_cpu_to_le64(n);
}

static void ubs_reset(struct silofs_uber_sub *ubs)
{
	ubs_set_btroot(ubs, silofs_pnptr_none());
	ubs_set_bn_nextfree(ubs, silofs_paddr_none());
	ubs_set_vn_nextfree(ubs, silofs_paddr_none());
	ubs_set_bn_count(ubs, 0);
	ubs_set_vn_count(ubs, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
ubn_slot_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	size_t slot;

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		slot = 0;
		break;
	case SILOFS_LTYPE_SPNODE:
		slot = 1;
		break;
	case SILOFS_LTYPE_INODE:
		slot = 2;
		break;
	case SILOFS_LTYPE_XANODE:
		slot = 3;
		break;
	case SILOFS_LTYPE_DTNODE:
		slot = 4;
		break;
	case SILOFS_LTYPE_SYMVAL:
		slot = 5;
		break;
	case SILOFS_LTYPE_FTNODE:
		slot = 6;
		break;
	case SILOFS_LTYPE_DATA1K:
		slot = 7;
		break;
	case SILOFS_LTYPE_DATA4K:
		slot = 8;
		break;
	case SILOFS_LTYPE_DATA64K:
		slot = 9;
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		slot = ARRAY_SIZE(ubn->ub_sub) - 1;
		break;
	}
	silofs_assert_lt(slot, SILOFS_LTYPE_LAST);
	return slot;
}

static void
ubn_set_btime(struct silofs_uber_node *ubn, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ubn->ub_btime);
}

static void
ubn_set_ctime(struct silofs_uber_node *ubn, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ubn->ub_ctime);
}

static uint64_t ubn_generation(const struct silofs_uber_node *ubn)
{
	return silofs_le64_to_cpu(ubn->ub_generation);
}

static void ubn_set_generation(struct silofs_uber_node *ubn, uint64_t gn)
{
	ubn->ub_generation = silofs_cpu_to_le64(gn);
}

static void ubn_set_capacity(struct silofs_uber_node *ubn, uint64_t cap)
{
	ubn->ub_capacity = silofs_cpu_to_le64(cap);
}

static void ubn_inc_generation(struct silofs_uber_node *ubn)
{
	ubn_set_generation(ubn, ubn_generation(ubn) + 1);
}

static const struct silofs_uber_sub *
ubn_sub_at(const struct silofs_uber_node *ubn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_sub));

	return &ubn->ub_sub[slot];
}

static const struct silofs_uber_sub *
ubn_sub_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	return ubn_sub_at(ubn, ubn_slot_of(ubn, ltype));
}

static struct silofs_uber_sub *
ubn_mut_sub_at(struct silofs_uber_node *ubn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_sub));

	return &ubn->ub_sub[slot];
}

static struct silofs_uber_sub *
ubn_mut_sub_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	return ubn_mut_sub_at(ubn, ubn_slot_of(ubn, ltype));
}

static void ubn_btroot(const struct silofs_uber_node *ubn, size_t slot,
                       struct silofs_pnptr *out_pnptr)
{
	ubs_btroot(ubn_sub_at(ubn, slot), out_pnptr);
}

static void
ubn_btroot_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype,
              struct silofs_pnptr *out_pnptr)
{
	const size_t slot = ubn_slot_of(ubn, ltype);

	ubn_btroot(ubn, slot, out_pnptr);
}

static void ubn_set_btroot(struct silofs_uber_node *ubn, size_t slot,
                           const struct silofs_pnptr *pnptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_sub));

	ubs_set_btroot(ubn_mut_sub_at(ubn, slot), pnptr);
}

static void
ubn_set_btroot_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                  const struct silofs_pnptr *pnptr)
{
	ubn_set_btroot(ubn, ubn_slot_of(ubn, ltype), pnptr);
}

static void ubn_bn_nextfree(const struct silofs_uber_node *ubn, size_t slot,
                            struct silofs_paddr *out_paddr)
{
	ubs_bn_nextfree(ubn_sub_at(ubn, slot), out_paddr);
}

static void
ubn_bn_nextfree_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                   struct silofs_paddr *out_paddr)
{
	ubn_bn_nextfree(ubn, ubn_slot_of(ubn, ltype), out_paddr);
}

static void ubn_set_bn_nextfree(struct silofs_uber_node *ubn, size_t slot,
                                const struct silofs_paddr *paddr)
{
	ubs_set_bn_nextfree(ubn_mut_sub_at(ubn, slot), paddr);
}

static void
ubn_set_bn_nextfree_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                       const struct silofs_paddr *paddr)
{
	const size_t slot = ubn_slot_of(ubn, ltype);

	ubn_set_bn_nextfree(ubn, slot, paddr);
}

static void ubn_vn_nextfree(const struct silofs_uber_node *ubn, size_t slot,
                            struct silofs_paddr *out_paddr)
{
	ubs_vn_nextfree(ubn_sub_at(ubn, slot), out_paddr);
}

static void
ubn_vn_nextfree_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                   struct silofs_paddr *out_paddr)
{
	ubn_vn_nextfree(ubn, ubn_slot_of(ubn, ltype), out_paddr);
}

static void ubn_set_vn_nextfree(struct silofs_uber_node *ubn, size_t slot,
                                const struct silofs_paddr *paddr)
{
	ubs_set_vn_nextfree(ubn_mut_sub_at(ubn, slot), paddr);
}

static void
ubn_set_vn_nextfree_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                       const struct silofs_paddr *paddr)
{
	ubn_set_vn_nextfree(ubn, ubn_slot_of(ubn, ltype), paddr);
}

static uint64_t
ubn_bn_count_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	return ubs_bn_count(ubn_sub_of(ubn, ltype));
}

static void
ubn_inc_bn_count_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	const uint64_t bn_count = ubn_bn_count_of(ubn, ltype);

	silofs_assert_lt(bn_count, UINT64_MAX / 2);
	ubs_set_bn_count(ubn_mut_sub_of(ubn, ltype), bn_count + 1);
}

static void
ubn_dec_bn_count_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	const uint64_t bn_count = ubn_bn_count_of(ubn, ltype);

	silofs_assert_gt(bn_count, 0);
	ubs_set_bn_count(ubn_mut_sub_of(ubn, ltype), bn_count - 1);
}

static uint64_t
ubn_vn_count_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	return ubs_vn_count(ubn_sub_of(ubn, ltype));
}

static void
ubn_inc_vn_count_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	const uint64_t vn_count = ubn_vn_count_of(ubn, ltype);

	silofs_assert_lt(vn_count, UINT64_MAX / 2);
	ubs_set_vn_count(ubn_mut_sub_of(ubn, ltype), vn_count + 1);
}

static void
ubn_dec_vn_count_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype)
{
	const uint64_t vn_count = ubn_vn_count_of(ubn, ltype);

	silofs_assert_gt(vn_count, 0);
	ubs_set_vn_count(ubn_mut_sub_of(ubn, ltype), vn_count - 1);
}

static void ubn_reset_stat(struct silofs_uber_node *ubn, size_t slot)
{
	ubs_reset(ubn_mut_sub_at(ubn, slot));
}

static void ubn_reset_stats(struct silofs_uber_node *ubn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ubn->ub_sub); ++slot) {
		ubn_reset_stat(ubn, slot);
	}
}

static void ubn_setup(struct silofs_uber_node *ubn, const struct timespec *ts)
{
	ubn_set_generation(ubn, 0);
	ubn_set_capacity(ubn, 0);
	ubn_set_btime(ubn, ts);
	ubn_set_ctime(ubn, ts);
	ubn_reset_stats(ubn);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_layerid *
silofs_ubi_layerid(const struct silofs_uber_info *ubi)
{
	return silofs_pni_layerid(&ubi->ub_pni);
}

void silofs_ubi_incref(struct silofs_uber_info *ubi)
{
	silofs_pni_incref(&ubi->ub_pni);
}

void silofs_ubi_decref(struct silofs_uber_info *ubi)
{
	silofs_pni_decref(&ubi->ub_pni);
}

void silofs_ubi_setdirty(struct silofs_uber_info *ubi)
{
	silofs_pni_setdirty(&ubi->ub_pni);
}

void silofs_ubi_cleardirty(struct silofs_uber_info *ubi)
{
	silofs_pni_cleardirty(&ubi->ub_pni);
}

void silofs_ubi_update_spawned(struct silofs_uber_info *ubi)
{
	struct timespec now;

	silofs_clock_gettime_real(&now);
	ubn_setup(ubi->ubn, &now);
	silofs_ubi_setdirty(ubi);
}

void silofs_ubi_btroot_of(const struct silofs_uber_info *ubi,
                          enum silofs_ltype ltype,
                          struct silofs_pnptr *out_pnptr)
{
	ubn_btroot_of(ubi->ubn, ltype, out_pnptr);
}

static void ubi_inc_generation(struct silofs_uber_info *ubi)
{
	ubn_inc_generation(ubi->ubn);
	silofs_ubi_setdirty(ubi);
}

static void
ubi_set_btroot(struct silofs_uber_info *ubi, enum silofs_ltype ltype,
               const struct silofs_pnptr *pnptr)
{
	ubn_set_btroot_of(ubi->ubn, ltype, pnptr);
	ubi_inc_generation(ubi);
}

static enum silofs_ltype vspace_of(const struct silofs_pnptr *pnptr)
{
	return pnptr->paddr.blobid.stype.ltype;
}

bool silofs_ubi_has_btroot(const struct silofs_uber_info *ubi,
                           const struct silofs_pnptr *pnptr)
{
	struct silofs_pnptr root_pnptr = {};

	silofs_ubi_btroot_of(ubi, vspace_of(pnptr), &root_pnptr);
	return silofs_pnptr_isequal(pnptr, &root_pnptr);
}

void silofs_ubi_set_btroot(struct silofs_uber_info *ubi,
                           const struct silofs_pnptr *pnptr)
{
	if (!silofs_ubi_has_btroot(ubi, pnptr)) {
		ubi_set_btroot(ubi, vspace_of(pnptr), pnptr);
	}
}

void silofs_ubi_set_btroot_by(struct silofs_uber_info *ubi,
                              const struct silofs_btnode_info *bti)
{
	silofs_ubi_set_btroot(ubi, silofs_bti_self(bti));
}

static void ubi_set_nextfree(struct silofs_uber_info *ubi,
                             const struct silofs_paddr *paddr)
{
	const struct silofs_blobid *blobid = &paddr->blobid;
	const enum silofs_ltype ltype      = blobid->stype.ltype;

	if (blobid->stype.ptype == SILOFS_PTYPE_LNODE) {
		ubn_set_vn_nextfree_of(ubi->ubn, ltype, paddr);
	} else {
		ubn_set_bn_nextfree_of(ubi->ubn, ltype, paddr);
	}
	ubi_inc_generation(ubi);
}

void silofs_ubi_start_free_space_at(struct silofs_uber_info *ubi,
                                    const struct silofs_paddr *paddr)
{
	ubi_set_nextfree(ubi, paddr);
}

static void ubi_nextfree_of(const struct silofs_uber_info *ubi,
                            const struct silofs_stype *stype,
                            struct silofs_paddr *out_paddr)
{
	if (stype->ptype == SILOFS_PTYPE_LNODE) {
		ubn_vn_nextfree_of(ubi->ubn, stype->ltype, out_paddr);
	} else {
		silofs_assert_eq(stype->ptype, SILOFS_PTYPE_BTNODE);
		ubn_bn_nextfree_of(ubi->ubn, stype->ltype, out_paddr);
	}
}

void silofs_ubi_consume_nextfree(struct silofs_uber_info *ubi,
                                 const struct silofs_stype *stype,
                                 struct silofs_paddr *out_paddr)
{
	struct silofs_paddr paddr_nxt;

	ubi_nextfree_of(ubi, stype, out_paddr);
	silofs_paddr_next(out_paddr, &paddr_nxt);
	ubi_set_nextfree(ubi, &paddr_nxt);
}

void silofs_ubi_inc_count_by(struct silofs_uber_info *ubi,
                             const struct silofs_blobid *blobid)
{
	const enum silofs_ltype ltype = blobid->stype.ltype;

	if (blobid->stype.ptype == SILOFS_PTYPE_LNODE) {
		ubn_inc_vn_count_of(ubi->ubn, ltype);
	} else {
		silofs_assert_eq(blobid->stype.ptype, SILOFS_PTYPE_BTNODE);
		ubn_inc_bn_count_of(ubi->ubn, ltype);
	}
	ubi_inc_generation(ubi);
}

void silofs_ubi_dec_count_by(struct silofs_uber_info *ubi,
                             const struct silofs_blobid *blobid)
{
	const enum silofs_ltype ltype = blobid->stype.ltype;

	if (blobid->stype.ptype == SILOFS_PTYPE_LNODE) {
		ubn_dec_vn_count_of(ubi->ubn, ltype);
	} else {
		silofs_assert_eq(blobid->stype.ptype, SILOFS_PTYPE_BTNODE);
		ubn_dec_bn_count_of(ubi->ubn, ltype);
	}
	ubi_inc_generation(ubi);
}

void silofs_ubi_stat_of(const struct silofs_uber_info *ubi,
                        enum silofs_ltype ltype,
                        struct silofs_uber_stat *out_stat)
{
	memset(out_stat, 0, sizeof(*out_stat));
	if (!silofs_ltype_isnone(ltype)) {
		out_stat->bn = ubn_bn_count_of(ubi->ubn, ltype);
		out_stat->vn = ubn_vn_count_of(ubi->ubn, ltype);
	}
}

void silofs_ubi_collect_stats(const struct silofs_uber_info *ubi,
                              struct silofs_uber_stats *out_stats)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	silofs_memzero(out_stats, sizeof(*out_stats));

	while (++ltype < SILOFS_LTYPE_LAST) {
		silofs_ubi_stat_of(ubi, ltype, &out_stats->st[ltype]);
	}
}

static bool ubi_onsame_layer(const struct silofs_uber_info *ubi,
                             const struct silofs_pnode_info *pni)
{
	const struct silofs_layerid *ub_layerid = silofs_ubi_layerid(ubi);
	const struct silofs_layerid *pn_layerid = silofs_pni_layerid(pni);

	return silofs_layerid_isequal(ub_layerid, pn_layerid);
}

bool silofs_ubi_onsame_layer(const struct silofs_uber_info *ubi,
                             const struct silofs_btnode_info *bti)
{
	return ubi_onsame_layer(ubi, &bti->btn_pni);
}

int silofs_validate_uber(const struct silofs_uber_info *ubi)
{
	/* TODO: writeme */
	silofs_unused(ubi);
	return 0;
}
