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

static void ub_set_generation(struct silofs_uber_block *ub, uint64_t gn)
{
	ub->ub_generation = silofs_cpu_to_le64(gn);
}

static struct silofs_blobref64b *
ub_blobref_at(struct silofs_uber_block *ub, size_t slot)
{
	struct silofs_blobref64b *blobref = NULL;

	if (likely(slot < ARRAY_SIZE(ub->ub_blobref))) {
		blobref = &ub->ub_blobref[slot];
	}
	return blobref;
}

#if 0
static struct silofs_blobref64b *
ub_blobref_of(struct silofs_uber_block *ub, enum silofs_mtype mtype)
{
	STATICASSERT_GT(ARRAY_SIZE(ub->ub_blobref), SILOFS_MTYPE_LAST);
	silofs_assert_lt(mtype, ARRAY_SIZE(ub->ub_blobref));

	return ub_blobref_at(ub, (size_t)(mtype - 1));
}
#endif

static void ub_reset_blobref_at(struct silofs_uber_block *ub, size_t slot)
{
	struct silofs_blobref64b *blobref = ub_blobref_at(ub, slot);

	if (likely(blobref != NULL)) {
		blobref->blobsz = 0;
	}
}

static void ub_reset_blobrefs(struct silofs_uber_block *ub)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(ub->ub_blobref); ++slot) {
		ub_reset_blobref_at(ub, slot);
	}
}

static void ub_init(struct silofs_uber_block *ub)
{
	ub_setup_hdr(ub);
	ub_set_generation(ub, 0);
	ub_reset_blobrefs(ub);
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
