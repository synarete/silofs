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

static struct silofs_bcursor128b *
ub_bcursor_at(struct silofs_uber_block *ub, size_t slot)
{
	struct silofs_bcursor128b *bcursor = nullptr;

	if (likely(slot < ARRAY_SIZE(ub->ub_bcursor))) {
		bcursor = &ub->ub_bcursor[slot];
	}
	return bcursor;
}

static const struct silofs_bcursor128b *
ub_bcursor_at2(const struct silofs_uber_block *ub, size_t slot)
{
	const struct silofs_bcursor128b *bcursor = nullptr;

	if (likely(slot < ARRAY_SIZE(ub->ub_bcursor))) {
		bcursor = &ub->ub_bcursor[slot];
	}
	return bcursor;
}

static struct silofs_bcursor128b *
ub_bcursor_of(struct silofs_uber_block *ub, enum silofs_mtype mtype)
{
	STATICASSERT_GT(ARRAY_SIZE(ub->ub_bcursor), SILOFS_MTYPE_LAST);
	silofs_assert_lt(mtype, ARRAY_SIZE(ub->ub_bcursor));

	return ub_bcursor_at(ub, (size_t)(mtype - 1));
}

static const struct silofs_bcursor128b *
ub_bcursor_of2(const struct silofs_uber_block *ub, enum silofs_mtype mtype)
{
	STATICASSERT_GT(ARRAY_SIZE(ub->ub_bcursor), SILOFS_MTYPE_LAST);
	silofs_assert_lt(mtype, ARRAY_SIZE(ub->ub_bcursor));

	return ub_bcursor_at2(ub, (size_t)(mtype - 1));
}

static void ub_reset_bcursor_at(struct silofs_uber_block *ub, size_t slot)
{
	struct silofs_bcursor128b *bcur = ub_bcursor_at(ub, slot);

	if (likely(bcur != nullptr)) {
		silofs_bcursor128b_reset(bcur);
	}
}

static void ub_reset_bcursors(struct silofs_uber_block *ub)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ub->ub_bcursor); ++slot) {
		ub_reset_bcursor_at(ub, slot);
	}
}

static inline const struct silofs_key *
ub_key_of(const struct silofs_uber_block *ub, size_t idx)
{
	return &ub->ub_key[idx % ARRAY_SIZE(ub->ub_key)];
}

static void ub_setup_keys(struct silofs_uber_block *ub)
{
	silofs_generate_keys(ub->ub_key, ARRAY_SIZE(ub->ub_key), true);
}

static void ub_setup(struct silofs_uber_block *ub, const struct timespec *ts)
{
	ub_set_generation(ub, 1);
	ub_set_btime(ub, ts);
	ub_set_ctime(ub, ts);
	ub_reset_bcursors(ub);
	ub_setup_keys(ub);
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

int silofs_ubi_bcursor_of(const struct silofs_uber_info *ubi,
                          enum silofs_mtype mtype,
                          struct silofs_bcursor *out_bcursor)
{
	const struct silofs_bcursor128b *bcur;

	bcur = ub_bcursor_of2(ubi->ub, mtype);
	if (unlikely(bcur == nullptr)) {
		return -SILOFS_ENOENT;
	}
	silofs_bcursor128b_xtoh(bcur, out_bcursor);
	return 0;
}

static void ubi_update_changed(struct silofs_uber_info *ubi)
{
	struct timespec now;

	silofs_clock_real_now(&now);
	ub_set_ctime(ubi->ub, &now);
	ub_inc_generation(ubi->ub);
	silofs_ubi_dirtify(ubi);
}

int silofs_ubi_update_bcursor(struct silofs_uber_info *ubi,
                              enum silofs_mtype mtype,
                              const struct silofs_bcursor *bcursor)
{
	struct silofs_bcursor128b *bcur;

	bcur = ub_bcursor_of(ubi->ub, mtype);
	if (unlikely(bcur == nullptr)) {
		return -SILOFS_ENOENT;
	}
	silofs_bcursor128b_htox(bcur, bcursor);
	ubi_update_changed(ubi);
	return 0;
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
                          const struct silofs_paddr *paddr, bool spawn)
{
	struct silofs_pnode_info *pni;
	struct silofs_uber_info *ubi;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_UBER);
	pni = silofs_pcache_create_pnode(pcache, paddr);
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
