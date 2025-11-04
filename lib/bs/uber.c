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

static void ub_setup_hdr(struct silofs_uber_block *ub)
{
	silofs_hdr_setup(&ub->ub_hdr, SILOFS_MTYPE_UBER, sizeof(*ub));
}

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

static void ub_init(struct silofs_uber_block *ub)
{
	ub_setup_hdr(ub);
	ub_set_generation(ub, 0);
	ub_reset_bcursors(ub);
}

static void ub_fini(struct silofs_uber_block *ub)
{
	ub_set_generation(ub, UINT64_MAX);
}

static struct silofs_uber_block *ub_malloc(struct silofs_alloc *alloc)
{
	struct silofs_uber_block *ub;

	ub = silofs_memalloc(alloc, sizeof(*ub), SILOFS_ALLOCF_BZERO);
	return ub;
}

static void ub_free(struct silofs_uber_block *ub, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ub, sizeof(*ub), SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_uber_block *ub_new(struct silofs_alloc *alloc)
{
	struct silofs_uber_block *ub;

	ub = ub_malloc(alloc);
	if (ub != nullptr) {
		ub_init(ub);
	}
	return ub;
}

static void ub_del(struct silofs_uber_block *ub, struct silofs_alloc *alloc)
{
	ub_fini(ub);
	ub_free(ub, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ub_info *ubi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ub_info *ubi = nullptr;

	ubi = silofs_memalloc(alloc, sizeof(*ubi), 0);
	return ubi;
}

static void ubi_free(struct silofs_ub_info *ubi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ubi, sizeof(*ubi), 0);
}

static void
ubi_init(struct silofs_ub_info *ubi, const struct silofs_baddr *baddr)
{
	silofs_bni_init(&ubi->ub_bni, baddr);
	ubi->ub = nullptr;
}

static void ubi_fini(struct silofs_ub_info *ubi)
{
	silofs_bni_fini(&ubi->ub_bni);
}

struct silofs_ub_info *
silofs_ubi_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc)
{
	struct silofs_uber_block *ub = nullptr;
	struct silofs_ub_info *ubi = nullptr;

	ub = ub_new(alloc);
	if (ub == nullptr) {
		return nullptr;
	}
	ubi = ubi_malloc(alloc);
	if (ubi == nullptr) {
		ub_del(ub, alloc);
		return nullptr;
	}
	ubi_init(ubi, baddr);
	ubi->ub = ub;
	return ubi;
}

void silofs_ubi_del(struct silofs_ub_info *ubi, struct silofs_alloc *alloc)
{
	struct silofs_uber_block *ub = ubi->ub;

	ubi_fini(ubi);
	ubi_free(ubi, alloc);
	ub_del(ub, alloc);
}

static struct silofs_ub_info *ubi_unconst(const struct silofs_ub_info *p)
{
	union {
		const struct silofs_ub_info *p;
		struct silofs_ub_info *q;
	} u = { .p = p };

	return u.q;
}

struct silofs_ub_info *silofs_ubi_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_ub_info *ubi = nullptr;

	if (bni != nullptr) {
		ubi = container_of2(bni, struct silofs_ub_info, ub_bni);
	}
	return ubi_unconst(ubi);
}

void silofs_ubi_set_dq(struct silofs_ub_info *ubi, struct silofs_dirtyq *dq)
{
	silofs_bni_set_dq(&ubi->ub_bni, dq);
}

void silofs_ubi_dirtify(struct silofs_ub_info *ubi)
{
	silofs_bni_dirtify(&ubi->ub_bni);
}

void silofs_ubi_undirtify(struct silofs_ub_info *ubi)
{
	silofs_bni_undirtify(&ubi->ub_bni);
}

void silofs_ubi_setup_spawned(struct silofs_ub_info *ubi)
{
	struct timespec now;

	silofs_clock_real_now(&now);
	ub_set_btime(ubi->ub, &now);
	ub_set_ctime(ubi->ub, &now);
	ub_inc_generation(ubi->ub);
	silofs_ubi_dirtify(ubi);
}

int silofs_ubi_bcursor_of(const struct silofs_ub_info *ubi,
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

static void ubi_update_changed(struct silofs_ub_info *ubi)
{
	struct timespec now;

	silofs_clock_real_now(&now);
	ub_set_ctime(ubi->ub, &now);
	ub_inc_generation(ubi->ub);
	silofs_ubi_dirtify(ubi);
}

int silofs_ubi_update_bcursor(struct silofs_ub_info *ubi,
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
