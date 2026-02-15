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
#include "addr.h"
#include "btnode.h"
#include "uber.h"

static void ubv_btroot(const struct silofs_uber_vspace *ubv,
                       struct silofs_btnptr *out_btnptr)
{
	silofs_btnptr256b_xtoh(&ubv->ub_btroot, out_btnptr);
}

static void ubv_set_btroot(struct silofs_uber_vspace *ubv,
                           const struct silofs_btnptr *btnptr)
{
	silofs_btnptr256b_htox(&ubv->ub_btroot, btnptr);
}

static void ubv_set_bn_spdesc(struct silofs_uber_vspace *ubv,
                              const struct silofs_spdesc *spdesc)
{
	silofs_spdesc_htox(&ubv->ub_bn_spdesc, spdesc);
}

static void ubv_set_vn_spdesc(struct silofs_uber_vspace *ubv,
                              const struct silofs_spdesc *spdesc)
{
	silofs_spdesc_htox(&ubv->ub_vn_spdesc, spdesc);
}

static void ubv_reset(struct silofs_uber_vspace *ubv)
{
	ubv_set_btroot(ubv, silofs_btnptr_none());
	ubv_set_bn_spdesc(ubv, silofs_spdesc_none());
	ubv_set_vn_spdesc(ubv, silofs_spdesc_none());
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
ubn_slot_of(const struct silofs_uber_node *ubn, enum silofs_mtype vtype)
{
	size_t slot;

	switch (vtype) {
	case SILOFS_MTYPE_LSMAP:
		slot = 0;
		break;
	case SILOFS_MTYPE_INODE:
		slot = 1;
		break;
	case SILOFS_MTYPE_XANODE:
		slot = 2;
		break;
	case SILOFS_MTYPE_DTNODE:
		slot = 3;
		break;
	case SILOFS_MTYPE_SYMVAL:
		slot = 4;
		break;
	case SILOFS_MTYPE_FTNODE:
		slot = 5;
		break;
	case SILOFS_MTYPE_DATA1K:
		slot = 6;
		break;
	case SILOFS_MTYPE_DATA4K:
		slot = 7;
		break;
	case SILOFS_MTYPE_DATABK:
		slot = 8;
		break;
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_MBR:
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BLDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_LAST:
	default:
		slot = ARRAY_SIZE(ubn->ub_vspace) - 1;
		break;
	}
	silofs_assert_lt(slot, SILOFS_MTYPE_LAST);
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

static const struct silofs_uber_vspace *
ubn_vspace_at(const struct silofs_uber_node *ubn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_vspace));

	return &ubn->ub_vspace[slot];
}

static struct silofs_uber_vspace *
ubn_vspace_at2(struct silofs_uber_node *ubn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_vspace));

	return &ubn->ub_vspace[slot];
}

static void ubn_btroot(const struct silofs_uber_node *ubn, size_t slot,
                       struct silofs_btnptr *out_btnptr)
{
	ubv_btroot(ubn_vspace_at(ubn, slot), out_btnptr);
}

static void
ubn_btroot_of(const struct silofs_uber_node *ubn, enum silofs_mtype vtype,
              struct silofs_btnptr *out_btnptr)
{
	const size_t slot = ubn_slot_of(ubn, vtype);

	silofs_assert(silofs_mtype_isvnode(vtype));
	ubn_btroot(ubn, slot, out_btnptr);
}

static void ubn_set_btroot(struct silofs_uber_node *ubn, size_t slot,
                           const struct silofs_btnptr *btnptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_vspace));

	ubv_set_btroot(ubn_vspace_at2(ubn, slot), btnptr);
}

static void
ubn_set_btroot_of(struct silofs_uber_node *ubn, enum silofs_mtype vtype,
                  const struct silofs_btnptr *btnptr)
{
	const size_t slot = ubn_slot_of(ubn, vtype);

	silofs_assert(silofs_mtype_isvnode(vtype));
	ubn_set_btroot(ubn, slot, btnptr);
}

static void ubn_set_bn_spdesc(struct silofs_uber_node *ubn, size_t slot,
                              const struct silofs_spdesc *spdesc)
{
	ubv_set_bn_spdesc(ubn_vspace_at2(ubn, slot), spdesc);
}

static void
ubn_set_bn_spdesc_of(struct silofs_uber_node *ubn, enum silofs_mtype vtype,
                     const struct silofs_spdesc *spdesc)
{
	const size_t slot = ubn_slot_of(ubn, vtype);

	silofs_assert(silofs_mtype_isvnode(vtype));
	ubn_set_bn_spdesc(ubn, slot, spdesc);
}

static void ubn_set_vn_spdesc(struct silofs_uber_node *ubn, size_t slot,
                              const struct silofs_spdesc *spdesc)
{
	ubv_set_vn_spdesc(ubn_vspace_at2(ubn, slot), spdesc);
}

static void
ubn_set_vn_spdesc_of(struct silofs_uber_node *ubn, enum silofs_mtype vtype,
                     const struct silofs_spdesc *spdesc)
{
	const size_t slot = ubn_slot_of(ubn, vtype);

	silofs_assert(silofs_mtype_isvnode(vtype));
	ubn_set_vn_spdesc(ubn, slot, spdesc);
}

static void ubn_reset_vspace(struct silofs_uber_node *ubn, size_t slot)
{
	ubv_reset(ubn_vspace_at2(ubn, slot));
}

static void ubn_reset_vspaces(struct silofs_uber_node *ubn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ubn->ub_vspace); ++slot) {
		ubn_reset_vspace(ubn, slot);
	}
}

static void ubn_setup(struct silofs_uber_node *ubn, const struct timespec *ts)
{
	ubn_set_generation(ubn, 0);
	ubn_set_capacity(ubn, 0);
	ubn_set_btime(ubn, ts);
	ubn_set_ctime(ubn, ts);
	ubn_reset_vspaces(ubn);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ubi_incref(struct silofs_uber_info *ubi)
{
	silofs_pni_incref(&ubi->ub_pni);
}

void silofs_ubi_decref(struct silofs_uber_info *ubi)
{
	silofs_pni_decref(&ubi->ub_pni);
}

static void ubi_setup_spawned(struct silofs_uber_info *ubi)
{
	struct timespec now;

	silofs_clock_real_now(&now);
	ubn_setup(ubi->ubn, &now);
	silofs_ubi_dirtify(ubi);
}

void silofs_ubi_dirtify(struct silofs_uber_info *ubi)
{
	silofs_pni_dirtify(&ubi->ub_pni);
}

void silofs_ubi_undirtify(struct silofs_uber_info *ubi)
{
	silofs_pni_undirtify(&ubi->ub_pni);
}

void silofs_ubi_set_btroot(struct silofs_uber_info *ubi,
                           enum silofs_mtype vtype,
                           const struct silofs_btnptr *btnptr)
{
	ubn_set_btroot_of(ubi->ubn, vtype, btnptr);
	ubn_inc_generation(ubi->ubn);
	silofs_ubi_dirtify(ubi);
}

void silofs_ubi_set_btroot_by(struct silofs_uber_info *ubi,
                              const struct silofs_btnode_info *bti)
{
	struct silofs_btnptr btnptr;

	silofs_bti_self(bti, &btnptr);
	silofs_ubi_set_btroot(ubi, silofs_bti_vspace(bti), &btnptr);
}

void silofs_ubi_btroot_of(const struct silofs_uber_info *ubi,
                          enum silofs_mtype vtype,
                          struct silofs_btnptr *out_btnptr)
{
	ubn_btroot_of(ubi->ubn, vtype, out_btnptr);
}

void silofs_ubi_set_bndesc(struct silofs_uber_info *ubi,
                           enum silofs_mtype vtype,
                           const struct silofs_spdesc *spdesc)
{
	ubn_set_bn_spdesc_of(ubi->ubn, vtype, spdesc);
	ubn_inc_generation(ubi->ubn);
	silofs_ubi_dirtify(ubi);
}

void silofs_ubi_set_vndesc(struct silofs_uber_info *ubi,
                           enum silofs_mtype vtype,
                           const struct silofs_spdesc *spdesc)
{
	ubn_set_vn_spdesc_of(ubi->ubn, vtype, spdesc);
	ubn_inc_generation(ubi->ubn);
	silofs_ubi_dirtify(ubi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_info *
silofs_lookup_cached_uber(struct silofs_pcache *pcache,
                          const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_UBER);
	pni = silofs_pcache_lookup_pnode(pcache, paddr);
	return silofs_ubi_from_pni(pni);
}

struct silofs_uber_info *
silofs_create_cached_uber(struct silofs_pcache *pcache,
                          const struct silofs_nodeptr *nodeptr, bool spawn)
{
	struct silofs_pnode_info *pni;
	struct silofs_uber_info *ubi;

	pni = silofs_pcache_create_pnode(pcache, nodeptr);
	ubi = silofs_ubi_from_pni(pni);
	if ((ubi != nullptr) && spawn) {
		ubi_setup_spawned(ubi);
	}
	return ubi;
}

void silofs_forget_cached_uber(struct silofs_pcache *pcache,
                               struct silofs_uber_info *ubi)
{
	silofs_pcache_delete_pnode(pcache, &ubi->ub_pni);
}
