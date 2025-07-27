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

static void bdc_reset_paddr(struct silofs_bdcur128b *bdc)
{
	silofs_paddr64b_reset(&bdc->bdc_paddr);
}

static void bdc_set_blobsz(struct silofs_bdcur128b *bdc, size_t blobsz)
{
	bdc->bdc_blobsz = silofs_cpu_to_le64(blobsz);
}

static void bdc_reset(struct silofs_bdcur128b *bdc)
{
	silofs_memzero(bdc, sizeof(*bdc));
	bdc_reset_paddr(bdc);
	bdc_set_blobsz(bdc, 0);
}

static void
bdc_xtoh(const struct silofs_bdcur128b *bdc128, struct silofs_bdcur *bdc)
{
	silofs_paddr64b_xtoh(&bdc128->bdc_paddr, &bdc->paddr);
	bdc->blobsz = silofs_le64_to_cpu(bdc128->bdc_blobsz);
}

static void
bdc_htox(struct silofs_bdcur128b *bdc128, const struct silofs_bdcur *bdc)
{
	silofs_paddr64b_htox(&bdc128->bdc_paddr, &bdc->paddr);
	bdc128->bdc_blobsz = silofs_cpu_to_le64(bdc->blobsz);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static struct silofs_bdcur128b *
ub_bdcur_at(struct silofs_uber_block *ub, size_t slot)
{
	struct silofs_bdcur128b *bdcur = NULL;

	if (likely(slot < ARRAY_SIZE(ub->ub_bdcur))) {
		bdcur = &ub->ub_bdcur[slot];
	}
	return bdcur;
}

static const struct silofs_bdcur128b *
ub_bdcur_at2(const struct silofs_uber_block *ub, size_t slot)
{
	const struct silofs_bdcur128b *bdcur = NULL;

	if (likely(slot < ARRAY_SIZE(ub->ub_bdcur))) {
		bdcur = &ub->ub_bdcur[slot];
	}
	return bdcur;
}

static struct silofs_bdcur128b *
ub_bdcur_of(struct silofs_uber_block *ub, enum silofs_mtype mtype)
{
	STATICASSERT_GT(ARRAY_SIZE(ub->ub_bdcur), SILOFS_MTYPE_LAST);
	silofs_assert_lt(mtype, ARRAY_SIZE(ub->ub_bdcur));

	return ub_bdcur_at(ub, (size_t)(mtype - 1));
}

static const struct silofs_bdcur128b *
ub_bdcur_of2(const struct silofs_uber_block *ub, enum silofs_mtype mtype)
{
	STATICASSERT_GT(ARRAY_SIZE(ub->ub_bdcur), SILOFS_MTYPE_LAST);
	silofs_assert_lt(mtype, ARRAY_SIZE(ub->ub_bdcur));

	return ub_bdcur_at2(ub, (size_t)(mtype - 1));
}

static void ub_reset_bdcur_at(struct silofs_uber_block *ub, size_t slot)
{
	struct silofs_bdcur128b *bdcur = ub_bdcur_at(ub, slot);

	if (likely(bdcur != NULL)) {
		bdc_reset(bdcur);
	}
}

static void ub_reset_bdcurs(struct silofs_uber_block *ub)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ub->ub_bdcur); ++slot) {
		ub_reset_bdcur_at(ub, slot);
	}
}

static void ub_init(struct silofs_uber_block *ub)
{
	ub_setup_hdr(ub);
	ub_set_generation(ub, 0);
	ub_reset_bdcurs(ub);
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
	if (ub != NULL) {
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
	struct silofs_ub_info *ubi = NULL;

	ubi = silofs_memalloc(alloc, sizeof(*ubi), 0);
	return ubi;
}

static void ubi_free(struct silofs_ub_info *ubi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ubi, sizeof(*ubi), 0);
}

static void
ubi_init(struct silofs_ub_info *ubi, const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));
	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BTNODE);

	silofs_pni_init(&ubi->ub_pni, paddr);
	ubi->ub = NULL;
}

static void ubi_fini(struct silofs_ub_info *ubi)
{
	silofs_pni_fini(&ubi->ub_pni);
}

struct silofs_ub_info *
silofs_ubi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_uber_block *ub = NULL;
	struct silofs_ub_info *ubi = NULL;

	ub = ub_new(alloc);
	if (ub == NULL) {
		return NULL;
	}
	ubi = ubi_malloc(alloc);
	if (ubi == NULL) {
		ub_del(ub, alloc);
		return NULL;
	}
	ubi_init(ubi, paddr);
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

void silofs_ubi_set_dq(struct silofs_ub_info *ubi, struct silofs_dirtyq *dq)
{
	silofs_pni_set_dq(&ubi->ub_pni, dq);
}

void silofs_ubi_dirtify(struct silofs_ub_info *ubi)
{
	silofs_pni_dirtify(&ubi->ub_pni);
}

void silofs_ubi_undirtify(struct silofs_ub_info *ubi)
{
	silofs_pni_undirtify(&ubi->ub_pni);
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

int silofs_ubi_bdcur_of(const struct silofs_ub_info *ubi,
                        enum silofs_mtype mtype,
                        struct silofs_bdcur *out_bdcur)
{
	const struct silofs_bdcur128b *bdc;

	bdc = ub_bdcur_of2(ubi->ub, mtype);
	if (bdc == NULL) {
		return -SILOFS_ENOENT;
	}
	bdc_xtoh(bdc, out_bdcur);
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

int silofs_ubi_update_bdcur(struct silofs_ub_info *ubi,
                            enum silofs_mtype mtype,
                            const struct silofs_bdcur *bdcur)
{
	struct silofs_bdcur128b *bdc;

	bdc = ub_bdcur_of(ubi->ub, mtype);
	if (bdc == NULL) {
		return -SILOFS_ENOENT;
	}
	bdc_htox(bdc, bdcur);
	ubi_update_changed(ubi);
	return 0;
}
