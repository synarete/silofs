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

static void ubs_bn_spdesc(const struct silofs_uber_sub *ubs,
                          struct silofs_spdesc *out_spdesc)
{
	silofs_spdesc_xtoh(&ubs->ubs_bn_spdesc, out_spdesc);
}

static void ubs_set_bn_spdesc(struct silofs_uber_sub *ubs,
                              const struct silofs_spdesc *spdesc)
{
	silofs_spdesc_htox(&ubs->ubs_bn_spdesc, spdesc);
}

static void ubs_vn_spdesc(const struct silofs_uber_sub *ubs,
                          struct silofs_spdesc *out_spdesc)
{
	silofs_spdesc_xtoh(&ubs->ubs_vn_spdesc, out_spdesc);
}

static void ubs_set_vn_spdesc(struct silofs_uber_sub *ubs,
                              const struct silofs_spdesc *spdesc)
{
	silofs_spdesc_htox(&ubs->ubs_vn_spdesc, spdesc);
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
	ubs_set_bn_spdesc(ubs, silofs_spdesc_none());
	ubs_set_vn_spdesc(ubs, silofs_spdesc_none());
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

static void ubn_bn_spdesc(const struct silofs_uber_node *ubn, size_t slot,
                          struct silofs_spdesc *out_spdesc)
{
	ubs_bn_spdesc(ubn_sub_at(ubn, slot), out_spdesc);
}

static void
ubn_bn_spdesc_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                 struct silofs_spdesc *out_spdesc)
{
	ubn_bn_spdesc(ubn, ubn_slot_of(ubn, ltype), out_spdesc);
}

static void ubn_set_bn_spdesc(struct silofs_uber_node *ubn, size_t slot,
                              const struct silofs_spdesc *spdesc)
{
	ubs_set_bn_spdesc(ubn_mut_sub_at(ubn, slot), spdesc);
}

static void
ubn_set_bn_spdesc_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                     const struct silofs_spdesc *spdesc)
{
	const size_t slot = ubn_slot_of(ubn, ltype);

	ubn_set_bn_spdesc(ubn, slot, spdesc);
}

static void ubn_vn_spdesc(const struct silofs_uber_node *ubn, size_t slot,
                          struct silofs_spdesc *out_spdesc)
{
	ubs_vn_spdesc(ubn_sub_at(ubn, slot), out_spdesc);
}

static void
ubn_vn_spdesc_of(const struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                 struct silofs_spdesc *out_spdesc)
{
	ubn_vn_spdesc(ubn, ubn_slot_of(ubn, ltype), out_spdesc);
}

static void ubn_set_vn_spdesc(struct silofs_uber_node *ubn, size_t slot,
                              const struct silofs_spdesc *spdesc)
{
	ubs_set_vn_spdesc(ubn_mut_sub_at(ubn, slot), spdesc);
}

static void
ubn_set_vn_spdesc_of(struct silofs_uber_node *ubn, enum silofs_ltype ltype,
                     const struct silofs_spdesc *spdesc)
{
	ubn_set_vn_spdesc(ubn, ubn_slot_of(ubn, ltype), spdesc);
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

const struct silofs_pnptr *silofs_ubi_self(const struct silofs_uber_info *ubi)
{
	silofs_assume_not_null(ubi);
	return silofs_pni_self(&ubi->ub_pni);
}

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

void silofs_ubi_update_spawned(struct silofs_uber_info *ubi)
{
	struct timespec now;

	silofs_clock_gettime_real(&now);
	ubn_setup(ubi->ubn, &now);
	silofs_ubi_setdirty(ubi);
}

void silofs_ubi_setdirty(struct silofs_uber_info *ubi)
{
	silofs_pni_setdirty(&ubi->ub_pni);
}

void silofs_ubi_cleardirty(struct silofs_uber_info *ubi)
{
	silofs_pni_cleardirty(&ubi->ub_pni);
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

void silofs_ubi_spdesc_of(const struct silofs_uber_info *ubi,
                          const struct silofs_stype *stype,
                          struct silofs_spdesc *out_spdesc)
{
	if (stype->ptype == SILOFS_PTYPE_LNODE) {
		ubn_vn_spdesc_of(ubi->ubn, stype->ltype, out_spdesc);
	} else {
		silofs_assert_eq(stype->ptype, SILOFS_PTYPE_BTNODE);
		ubn_bn_spdesc_of(ubi->ubn, stype->ltype, out_spdesc);
	}
}

void silofs_ubi_start_spdesc(struct silofs_uber_info *ubi,
                             const struct silofs_paddr *paddr)
{
	struct silofs_spdesc spdesc = {};

	silofs_spdesc_setup1(&spdesc, paddr);
	silofs_ubi_update_spdesc(ubi, &spdesc);
}

void silofs_ubi_update_spdesc(struct silofs_uber_info *ubi,
                              const struct silofs_spdesc *spdesc)
{
	const struct silofs_blobid *blobid = &spdesc->beg.blobid;
	const enum silofs_ltype ltype      = blobid->stype.ltype;

	if (blobid->stype.ptype == SILOFS_PTYPE_LNODE) {
		ubn_set_vn_spdesc_of(ubi->ubn, ltype, spdesc);
	} else {
		silofs_assert_eq(blobid->stype.ptype, SILOFS_PTYPE_BTNODE);
		ubn_set_bn_spdesc_of(ubi->ubn, ltype, spdesc);
	}
	ubi_inc_generation(ubi);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_ubref_init(struct silofs_uber_ref *ubref)
{
	ubref->ubi       = nullptr;
	ubref->ctl_flags = 0;
	ubref->ms_flags  = 0;
	return silofs_rwlock_init(&ubref->rwlock);
}

void silofs_ubref_fini(struct silofs_uber_ref *ubref)
{
	silofs_rwlock_fini(&ubref->rwlock);
	silofs_ubref_update(ubref, nullptr);
	ubref->ctl_flags = 0;
	ubref->ms_flags  = 0;
}

void silofs_ubref_update(struct silofs_uber_ref *ubref,
                         struct silofs_uber_info *ubi_new)
{
	struct silofs_uber_info *ubi_cur = ubref->ubi;

	if (ubi_cur != nullptr) {
		silofs_ubi_decref(ubi_cur);
	}
	if (ubi_new != nullptr) {
		silofs_ubi_incref(ubi_new);
	}
	ubref->ubi = ubi_new;
}

static void ubref_derive_ms_flags(struct silofs_uber_ref *ubref)
{
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;

	if (ubref->ctl_flags & SILOFS_F_LAZYTIME) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (ubref->ctl_flags & SILOFS_F_ALLOW_EXEC) {
		ms_flag_dont |= MS_NOEXEC;
	} else {
		ms_flag_with |= MS_NOEXEC;
	}
	if (ubref->ctl_flags & SILOFS_F_ALLOW_SUID) {
		ms_flag_dont |= MS_NOSUID;
	} else {
		ms_flag_with |= MS_NOSUID;
	}
	if (ubref->ctl_flags & SILOFS_F_ALLOW_DEV) {
		ms_flag_dont |= MS_NODEV;
	} else {
		ms_flag_with |= MS_NODEV;
	}
	if (ubref->ctl_flags & SILOFS_F_RDONLY) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	ubref->ms_flags = ms_flag_with & ~ms_flag_dont;
}

void silofs_ubref_set_ctlflags(struct silofs_uber_ref *ubref,
                               enum silofs_flags ctl_flags)
{
	ubref->ctl_flags = ctl_flags;
	ubref_derive_ms_flags(ubref);
}

static bool ubref_has_ctlflags(const struct silofs_uber_ref *ubref,
                               enum silofs_flags ctl_flags_mask)
{
	return (ubref->ctl_flags & ctl_flags_mask) == ctl_flags_mask;
}

bool silofs_ubref_is_rdonly(const struct silofs_uber_ref *ubref)
{
	return ubref_has_ctlflags(ubref, SILOFS_F_RDONLY);
}

void silofs_ubref_rwlock(struct silofs_uber_ref *ubref, bool ex)
{
	if (ex) {
		silofs_rwlock_wrlock(&ubref->rwlock);
	} else {
		silofs_rwlock_rdlock(&ubref->rwlock);
	}
}

void silofs_ubref_rwunlock(struct silofs_uber_ref *ubref)
{
	silofs_rwlock_unlock(&ubref->rwlock);
}
