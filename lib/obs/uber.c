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

static size_t ub_slot_of(enum silofs_mtype mtype)
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
ub_set_btime(struct silofs_uber_node *ub, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ub->ub_btime);
}

static void
ub_set_ctime(struct silofs_uber_node *ub, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ub->ub_ctime);
}

static uint64_t ub_generation(const struct silofs_uber_node *ub)
{
	return silofs_le64_to_cpu(ub->ub_generation);
}

static void ub_set_generation(struct silofs_uber_node *ub, uint64_t gn)
{
	ub->ub_generation = silofs_cpu_to_le64(gn);
}

static void ub_inc_generation(struct silofs_uber_node *ub)
{
	ub_set_generation(ub, ub_generation(ub) + 1);
}

static void ub_get_child(const struct silofs_uber_node *ub, size_t slot,
                         struct silofs_nodeptr *out_nodeptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ub->ub_child));

	silofs_nodeptr256b_xtoh(&ub->ub_child[slot], out_nodeptr);
}

static void
ub_get_child_of(const struct silofs_uber_node *ub, enum silofs_mtype mtype,
                struct silofs_nodeptr *out_nodeptr)
{
	const size_t slot = ub_slot_of(mtype);

	silofs_assert(silofs_mtype_isvnode2(mtype));
	silofs_assert_gt(slot, 0);

	ub_get_child(ub, slot, out_nodeptr);
}

static void ub_set_child(struct silofs_uber_node *ub, size_t slot,
                         const struct silofs_nodeptr *nodeptr)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ub->ub_child));

	silofs_nodeptr256b_htox(&ub->ub_child[slot], nodeptr);
}

static void
ub_set_child_of(struct silofs_uber_node *ub, enum silofs_mtype mtype,
                const struct silofs_nodeptr *nodeptr)
{
	const size_t slot = ub_slot_of(mtype);

	silofs_assert(silofs_mtype_isvnode2(mtype));
	silofs_assert_gt(slot, 0);

	ub_set_child(ub, slot, nodeptr);
}

static void ub_reset_child(struct silofs_uber_node *ub, size_t slot)
{
	ub_set_child(ub, slot, silofs_nodeptr_none());
}

static void ub_reset_childs(struct silofs_uber_node *ub)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ub->ub_child); ++slot) {
		ub_reset_child(ub, slot);
	}
}

static void ub_setup(struct silofs_uber_node *ub, const struct timespec *ts)
{
	ub_set_generation(ub, 0);
	ub_set_btime(ub, ts);
	ub_set_ctime(ub, ts);
	ub_reset_childs(ub);
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
	ub_setup(ubi->ub, &now);
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
	ub_set_child_of(ubi->ub, mtype, nodeptr);
	ub_inc_generation(ubi->ub);
	silofs_ubi_dirtify(ubi);
}

void silofs_ubi_get_child(const struct silofs_uber_info *ubi,
                          enum silofs_mtype mtype,
                          struct silofs_nodeptr *out_nodeptr)
{
	ub_get_child_of(ubi->ub, mtype, out_nodeptr);
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
