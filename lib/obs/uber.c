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

static void
ub_set_btime(struct silofs_uber_block *ub, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ub->ub_btime);
}

static void
ub_set_ctime(struct silofs_uber_block *ub, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ub->ub_ctime);
}

static uint64_t ub_generation(const struct silofs_uber_block *ub)
{
	return silofs_le64_to_cpu(ub->ub_generation);
}

static void ub_set_generation(struct silofs_uber_block *ub, uint64_t gn)
{
	ub->ub_generation = silofs_cpu_to_le64(gn);
}

static void ub_inc_generation(struct silofs_uber_block *ub)
{
	ub_set_generation(ub, ub_generation(ub) + 1);
}

static const struct silofs_ckey *
ub_key_of(const struct silofs_uber_block *ub, uint32_t idx)
{
	return &ub->ub_key[idx % ARRAY_SIZE(ub->ub_key)];
}

static void ub_setup_keys(struct silofs_uber_block *ub)
{
	silofs_generate_keys(ub->ub_key, ARRAY_SIZE(ub->ub_key));
}

static void ub_setup(struct silofs_uber_block *ub, const struct timespec *ts)
{
	ub_set_generation(ub, 0);
	ub_set_btime(ub, ts);
	ub_set_ctime(ub, ts);
	ub_setup_keys(ub);

	ub_inc_generation(ub);
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

void silofs_ubi_key_of(const struct silofs_uber_info *ubi,
                       enum silofs_mtype mtype, struct silofs_ckey *out_key)
{
	silofs_ckey_assign(out_key, ub_key_of(ubi->ub, (uint32_t)mtype));
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
                          const struct silofs_pnodeptr *pnodeptr, bool spawn)
{
	struct silofs_pnode_info *pni;
	struct silofs_uber_info *ubi;

	pni = silofs_pcache_create_pnode(pcache, pnodeptr);
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
