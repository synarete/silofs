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
#include <stdint.h>
#include "infra.h"
#include "addr.h"
#include "fs.h"
#include "index.h"

void silofs_ard_init(struct silofs_ar_desc *ard,
		     const struct silofs_laddr *laddr, size_t len)
{
	silofs_baddr_reset(&ard->baddr);
	silofs_laddr_assign(&ard->laddr, laddr);
	ard->len = len;
}

static void ard_reset(struct silofs_ar_desc *ard)
{
	silofs_baddr_reset(&ard->baddr);
	silofs_laddr_reset(&ard->laddr);
	ard->len = 0;
}

void silofs_ard_fini(struct silofs_ar_desc *ard)
{
	silofs_baddr_reset(&ard->baddr);
	silofs_laddr_reset(&ard->laddr);
	ard->len = 0;
}

static enum silofs_mtype ard_mtype(const struct silofs_ar_desc *ard)
{
	return ard->laddr.lsid.mtype;
}

void silofs_ard_update_baddr(struct silofs_ar_desc *ard,
			     const struct silofs_mdigest *md,
			     const struct silofs_rovec *rov)
{
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_baddr_of(md, ard_mtype(ard), &iov, 1, &ard->baddr);
}

void silofs_ard256b_htox(struct silofs_ar_desc256b *ard256,
			 const struct silofs_ar_desc *ard)
{
	silofs_memzero(ard256, sizeof(*ard256));
	silofs_baddr64b_htox(&ard256->ad_baddr, &ard->baddr);
	silofs_laddr64b_htox(&ard256->ad_laddr, &ard->laddr);
	ard256->ad_len = silofs_cpu_to_le64(ard->len);
}

void silofs_ard256b_xtoh(const struct silofs_ar_desc256b *ard256,
			 struct silofs_ar_desc *ard)
{
	silofs_baddr64b_xtoh(&ard256->ad_baddr, &ard->baddr);
	silofs_laddr64b_xtoh(&ard256->ad_laddr, &ard->laddr);
	ard->len = silofs_le64_to_cpu(ard256->ad_len);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ab_setup_hdr(struct silofs_arix_block *ab)
{
	silofs_hdr_setup(&ab->ab_hdr, SILOFS_MTYPE_ARIX, sizeof(*ab));
}

static void
ab_set_btime(struct silofs_arix_block *ab, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ab->ab_btime);
}

static void ab_reset_btime(struct silofs_arix_block *ab)
{
	const struct timespec ts = { 0, 0 };

	ab_set_btime(ab, &ts);
}

static void ab_set_flags(struct silofs_arix_block *ab, uint32_t flags)
{
	ab->ab_flags = silofs_cpu_to_le32(flags);
}

static void ab_set_ndescs(struct silofs_arix_block *ab, uint32_t n)
{
	ab->ab_ndescs = silofs_cpu_to_le32(n);
}

static void
ab_set_next(struct silofs_arix_block *ab, const struct silofs_baddr *baddr)
{
	silofs_baddr64b_htox(&ab->ab_next, baddr);
}

static void ab_reset_next(struct silofs_arix_block *ab)
{
	ab_set_next(ab, silofs_baddr_none());
}

static void ab_set_desc(struct silofs_arix_block *ab, size_t slot,
			const struct silofs_ar_desc *ard)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ab->ab_descs));

	silofs_ard256b_htox(&ab->ab_descs[slot], ard);
}

static void ab_reset_descs(struct silofs_arix_block *ab)
{
	struct silofs_ar_desc ard_none;

	ard_reset(&ard_none);
	for (size_t slot = 0; slot < ARRAY_SIZE(ab->ab_descs); ++slot) {
		ab_set_desc(ab, slot, &ard_none);
	}
}

static void ab_init(struct silofs_arix_block *ab)
{
	ab_setup_hdr(ab);
	ab_reset_btime(ab);
	ab_set_flags(ab, 0);
	ab_set_ndescs(ab, 0);
	ab_reset_next(ab);
	ab_reset_descs(ab);
}

static void ab_fini(struct silofs_arix_block *ab)
{
	ab_reset_btime(ab);
	ab_reset_next(ab);
	ab_reset_descs(ab);
}

static struct silofs_arix_block *ab_malloc(struct silofs_alloc *alloc)
{
	struct silofs_arix_block *ab;

	ab = silofs_memalloc(alloc, sizeof(*ab), SILOFS_ALLOCF_BZERO);
	return ab;
}

static void ab_free(struct silofs_arix_block *ab, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ab, sizeof(*ab), SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_arix_block *ab_new(struct silofs_alloc *alloc)
{
	struct silofs_arix_block *ab;

	ab = ab_malloc(alloc);
	if (ab != nullptr) {
		ab_init(ab);
	}
	return ab;
}

static void ab_del(struct silofs_arix_block *ab, struct silofs_alloc *alloc)
{
	ab_fini(ab);
	ab_free(ab, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ab_info *abi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ab_info *abi = nullptr;

	abi = silofs_memalloc(alloc, sizeof(*abi), 0);
	return abi;
}

static void abi_free(struct silofs_ab_info *abi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, abi, sizeof(*abi), 0);
}

static void
abi_init(struct silofs_ab_info *abi, const struct silofs_baddr *baddr)
{
	silofs_assert(!silofs_baddr_isnull(baddr));
	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_ARIX);

	silofs_baddr_assign(&abi->ab_baddr, baddr);
	silofs_list_head_init(&abi->ab_lh);
	abi->ab = nullptr;
}

static void abi_fini(struct silofs_ab_info *abi)
{
	silofs_baddr_reset(&abi->ab_baddr);
}

struct silofs_ab_info *
silofs_abi_new(struct silofs_alloc *alloc, const struct silofs_baddr *baddr)
{
	struct silofs_arix_block *ab = nullptr;
	struct silofs_ab_info *abi = nullptr;

	ab = ab_new(alloc);
	if (ab == nullptr) {
		return nullptr;
	}
	abi = abi_malloc(alloc);
	if (abi == nullptr) {
		ab_del(ab, alloc);
		return nullptr;
	}
	abi_init(abi, baddr);
	abi->ab = ab;
	return abi;
}

void silofs_abi_del(struct silofs_ab_info *abi, struct silofs_alloc *alloc)
{
	struct silofs_arix_block *ab = abi->ab;

	abi_fini(abi);
	abi_free(abi, alloc);
	ab_del(ab, alloc);
}
