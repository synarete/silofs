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
#include "uber.h"

static size_t ubn_slot_of(enum silofs_mtype mtype)
{
	switch (mtype) {
	case SILOFS_MTYPE_SUPER:
		return 1;
	case SILOFS_MTYPE_SPNODE:
		return 2;
	case SILOFS_MTYPE_SPLEAF:
		return 3;
	case SILOFS_MTYPE_LSMAP:
		return 4;
	case SILOFS_MTYPE_INODE:
		return 5;
	case SILOFS_MTYPE_XANODE:
		return 6;
	case SILOFS_MTYPE_DTNODE:
		return 7;
	case SILOFS_MTYPE_SYMVAL:
		return 8;
	case SILOFS_MTYPE_FTNODE:
		return 9;
	case SILOFS_MTYPE_DATA1K:
		return 10;
	case SILOFS_MTYPE_DATA4K:
		return 11;
	case SILOFS_MTYPE_DATABK:
		return 12;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_MBR:
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BLDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_LAST:
	default:
		break;
	}
	return 0;
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

static void ubn_inc_generation(struct silofs_uber_node *ubn)
{
	ubn_set_generation(ubn, ubn_generation(ubn) + 1);
}

static void ubn_get_child(const struct silofs_uber_node *ubn, size_t slot,
                          struct silofs_nodeptr *out_nodeptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_child));

	silofs_nodeptr256b_xtoh(&ubn->ub_child[slot], out_nodeptr);
}

static void
ubn_get_child_of(const struct silofs_uber_node *ubn, enum silofs_mtype mtype,
                 struct silofs_nodeptr *out_nodeptr)
{
	const size_t slot = ubn_slot_of(mtype);

	silofs_assert(silofs_mtype_isvnode2(mtype));
	silofs_assert_gt(slot, 0);

	ubn_get_child(ubn, slot, out_nodeptr);
}

static void ubn_set_child(struct silofs_uber_node *ubn, size_t slot,
                          const struct silofs_nodeptr *nodeptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ubn->ub_child));

	silofs_nodeptr256b_htox(&ubn->ub_child[slot], nodeptr);
}

static void
ubn_set_child_of(struct silofs_uber_node *ubn, enum silofs_mtype mtype,
                 const struct silofs_nodeptr *nodeptr)
{
	const size_t slot = ubn_slot_of(mtype);

	silofs_assert(silofs_mtype_isvnode2(mtype));
	silofs_assert_gt(slot, 0);

	ubn_set_child(ubn, slot, nodeptr);
}

static void ubn_reset_child(struct silofs_uber_node *ubn, size_t slot)
{
	ubn_set_child(ubn, slot, silofs_nodeptr_none());
}

static void ubn_reset_childs(struct silofs_uber_node *ubn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ubn->ub_child); ++slot) {
		ubn_reset_child(ubn, slot);
	}
}

static void ubn_setup(struct silofs_uber_node *ubn, const struct timespec *ts)
{
	ubn_set_generation(ubn, 0);
	ubn_set_btime(ubn, ts);
	ubn_set_ctime(ubn, ts);
	ubn_reset_childs(ubn);
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

void silofs_ubi_set_child(struct silofs_uber_info *ubi,
                          enum silofs_mtype mtype,
                          const struct silofs_nodeptr *nodeptr)
{
	ubn_set_child_of(ubi->ubn, mtype, nodeptr);
	ubn_inc_generation(ubi->ubn);
	silofs_ubi_dirtify(ubi);
}

void silofs_ubi_get_child(const struct silofs_uber_info *ubi,
                          enum silofs_mtype mtype,
                          struct silofs_nodeptr *out_nodeptr)
{
	ubn_get_child_of(ubi->ubn, mtype, out_nodeptr);
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
