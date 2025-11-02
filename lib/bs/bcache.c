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
#include "infra.h"
#include "addr.h"
#include "flags.h"
#include "bldesc.h"
#include "btnode.h"
#include "bcache.h"

enum {
	BCACHE_RETRY_MAX = 4,
};

/* local functions */
static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bnode_info *bni_unconst(const struct silofs_bnode_info *p)
{
	union {
		const struct silofs_bnode_info *p;
		struct silofs_bnode_info *q;
	} u = { .p = p };
	return u.q;
}

static struct silofs_bnode_info *
bni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_bnode_info *bni = nullptr;

	if (hmqe != nullptr) {
		bni = container_of2(hmqe, struct silofs_bnode_info, bn_hmqe);
	}
	return bni_unconst(bni);
}

static struct silofs_hmapq_elem *bni_to_hmqe(struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe;
}

static struct silofs_bnode_info *bni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmqe_from_dqe(dqe);
	return bni_from_hmqe(hmqe);
}

static bool bni_isevictable(const struct silofs_bnode_info *bni)
{
	return silofs_hmqe_is_evictable(&bni->bn_hmqe);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc)
{
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 1);
	int err;

	silofs_memzero(bcache, sizeof(*bcache));
	err = silofs_hmapq_init(&bcache->pc_hmapq, alloc, nslots);
	if (err) {
		return err;
	}
	silofs_dirtyq_init(&bcache->pc_dirtyq);
	bcache->pc_alloc = alloc;
	return 0;
}

void silofs_bcache_fini(struct silofs_bcache *bcache)
{
	silofs_hmapq_fini(&bcache->pc_hmapq, bcache->pc_alloc);
	silofs_dirtyq_fini(&bcache->pc_dirtyq);
	bcache->pc_alloc = nullptr;
}

static struct silofs_bnode_info *
bcache_search(const struct silofs_bcache *bcache,
              const struct silofs_baddr *baddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_baddr(&hkey, baddr);
	hmqe = silofs_hmapq_lookup(&bcache->pc_hmapq, &hkey);
	return bni_from_hmqe(hmqe);
}

static void
bcache_promote(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	silofs_hmapq_promote(&bcache->pc_hmapq, bni_to_hmqe(bni), false);
}

static struct silofs_bnode_info *
bcache_search_and_relru(struct silofs_bcache *bcache,
                        const struct silofs_baddr *baddr)
{
	struct silofs_bnode_info *bni;

	bni = bcache_search(bcache, baddr);
	if (bni != nullptr) {
		bcache_promote(bcache, bni);
	}
	return bni;
}

static struct silofs_bnode_info *
bcache_lookup(struct silofs_bcache *bcache, const struct silofs_baddr *baddr)
{
	return bcache_search_and_relru(bcache, baddr);
}

static void
bcache_store(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	silofs_hmapq_store(&bcache->pc_hmapq, bni_to_hmqe(bni));
}

static void
bcache_remove(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	silofs_hmapq_remove(&bcache->pc_hmapq, bni_to_hmqe(bni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bldesc_info *
bcache_new_bdi(const struct silofs_bcache *bcache,
               const struct silofs_baddr *baddr)
{
	return silofs_bdi_new(baddr, bcache->pc_alloc);
}

static void bcache_del_bdi(const struct silofs_bcache *bcache,
                           struct silofs_bldesc_info *bdi)
{
	silofs_bdi_del(bdi, bcache->pc_alloc);
}

struct silofs_bldesc_info *
silofs_bcache_lookup_bdi(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_bnode_info *bni;

	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_BDESC);

	bni = bcache_lookup(bcache, baddr);
	return silofs_bdi_from_bni(bni);
}

static struct silofs_bldesc_info *
bcache_require_bdi(struct silofs_bcache *bcache,
                   const struct silofs_baddr *baddr)
{
	struct silofs_bldesc_info *bdi = nullptr;

	for (size_t i = 0; i < BCACHE_RETRY_MAX; ++i) {
		bdi = bcache_new_bdi(bcache, baddr);
		if (bdi != nullptr) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return bdi;
}

static void bcache_bind_bdi_dq(struct silofs_bcache *bcache,
                               struct silofs_bldesc_info *bdi)
{
	silofs_bdi_set_dq(bdi, &bcache->pc_dirtyq);
}

static void
bcache_store_bdi(struct silofs_bcache *bcache, struct silofs_bldesc_info *bdi)
{
	bcache_store(bcache, &bdi->bd_bni);
}

struct silofs_bldesc_info *
silofs_bcache_create_bdi(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_bldesc_info *bdi;

	bdi = bcache_require_bdi(bcache, baddr);
	if (bdi != nullptr) {
		bcache_bind_bdi_dq(bcache, bdi);
		bcache_store_bdi(bcache, bdi);
	}
	return bdi;
}

static void
bcache_remove_bdi(struct silofs_bcache *bcache, struct silofs_bldesc_info *bdi)
{
	bcache_remove(bcache, &bdi->bd_bni);
}

static void
bcache_forget_bdi(struct silofs_bcache *bcache, struct silofs_bldesc_info *bdi)
{
	silofs_bdi_undirtify(bdi);
	bcache_remove_bdi(bcache, bdi);
}

void silofs_bcache_evict_bdi(struct silofs_bcache *bcache,
                             struct silofs_bldesc_info *bdi)
{
	bcache_forget_bdi(bcache, bdi);
	bcache_del_bdi(bcache, bdi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
bcache_new_bti(const struct silofs_bcache *bcache,
               const struct silofs_baddr *baddr)
{
	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_BTNODE);

	return silofs_bti_new(baddr, bcache->pc_alloc);
}

static void bcache_del_bti(const struct silofs_bcache *bcache,
                           struct silofs_btnode_info *bti)
{
	silofs_assert_eq(bti->btn_bni.bn_baddr.mtype, SILOFS_MTYPE_BTNODE);

	silofs_bti_del(bti, bcache->pc_alloc);
}

struct silofs_btnode_info *
silofs_bcache_lookup_bti(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_bnode_info *bni;

	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_BTNODE);

	bni = bcache_lookup(bcache, baddr);
	return silofs_bti_from_bni(bni);
}

static struct silofs_btnode_info *
bcache_require_bti(struct silofs_bcache *bcache,
                   const struct silofs_baddr *baddr)
{
	struct silofs_btnode_info *bti = nullptr;

	for (size_t i = 0; i < BCACHE_RETRY_MAX; ++i) {
		bti = bcache_new_bti(bcache, baddr);
		if (bti != nullptr) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return bti;
}

static void bcache_bind_bti_dq(struct silofs_bcache *bcache,
                               struct silofs_btnode_info *bti)
{
	silofs_bti_set_dq(bti, &bcache->pc_dirtyq);
}

static void
bcache_store_bti(struct silofs_bcache *bcache, struct silofs_btnode_info *bti)
{
	bcache_store(bcache, &bti->btn_bni);
}

struct silofs_btnode_info *
silofs_bcache_create_bti(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_btnode_info *bti;

	bti = bcache_require_bti(bcache, baddr);
	if (bti != nullptr) {
		bcache_bind_bti_dq(bcache, bti);
		bcache_store_bti(bcache, bti);
	}
	return bti;
}

static void
bcache_remove_bti(struct silofs_bcache *bcache, struct silofs_btnode_info *bti)
{
	bcache_remove(bcache, &bti->btn_bni);
}

static void
bcache_forget_bti(struct silofs_bcache *bcache, struct silofs_btnode_info *bti)
{
	silofs_bti_undirtify(bti);
	bcache_remove_bti(bcache, bti);
}

void silofs_bcache_evict_bti(struct silofs_bcache *bcache,
                             struct silofs_btnode_info *bti)
{
	bcache_forget_bti(bcache, bti);
	bcache_del_bti(bcache, bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
bcache_evict_by(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	const enum silofs_mtype mtype = silofs_bni_mtype(bni);

	switch (mtype) {
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
		/* XXX */
		silofs_assert_null(bni);
		break;
	case SILOFS_MTYPE_BDESC:
		silofs_bcache_evict_bdi(bcache, silofs_bdi_from_bni(bni));
		break;
	case SILOFS_MTYPE_BTNODE:
		silofs_bcache_evict_bti(bcache, silofs_bti_from_bni(bni));
		break;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_MBR:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("corrupted bcache: mtype=%d", (int)mtype);
		break;
	}
}

static int visit_evictable_bni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_bnode_info *bni = bni_from_hmqe(hmqe);
	struct silofs_bnode_info **out_bni;
	int ret = 0;

	if (bni_isevictable(bni)) {
		out_bni = (struct silofs_bnode_info **)arg;
		*out_bni = bni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static struct silofs_bnode_info *
bcache_find_evictable(struct silofs_bcache *bcache, bool iterall)
{
	struct silofs_bnode_info *bni = nullptr;
	struct silofs_bnode_info **p_bni = &bni;

	silofs_hmapq_riterate(&bcache->pc_hmapq,
	                      iterall ? SILOFS_HMAPQ_ITERALL : 10,
	                      visit_evictable_bni, (void *)p_bni);
	return bni;
}

static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall)
{
	struct silofs_bnode_info *bni;
	size_t cnt = 0;

	while (niter-- > 0) {
		bni = bcache_find_evictable(bcache, iterall);
		if (bni == nullptr) {
			break;
		}
		bcache_evict_by(bcache, bni);
		cnt++;
	}
	return cnt;
}

static size_t bcache_usage(const struct silofs_bcache *bcache)
{
	return silofs_hmapq_usage(&bcache->pc_hmapq);
}

bool silofs_bcache_isempty(const struct silofs_bcache *bcache)
{
	return (bcache_usage(bcache) == 0);
}

void silofs_bcache_drop(struct silofs_bcache *bcache)
{
	size_t cnt;

	cnt = bcache_evict_some(bcache, 1, true);
	while (cnt > 0) {
		cnt = bcache_evict_some(bcache, 1, true);
	}
}

static size_t bcache_memory_pressure(const struct silofs_bcache *bcache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 0;

	silofs_memstat(bcache->pc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres; /* percentage of total available memory */
}

static void bcache_relax_args(const struct silofs_bcache *bcache, int flags,
                              size_t *out_niter, bool *out_iterall)
{
	size_t mem_pres;

	*out_niter = 0;
	*out_iterall = false;
	if (flags & SILOFS_CTLF_NOW) {
		*out_niter += 2;
		*out_iterall = true;
	}
	if (flags & SILOFS_CTLF_IDLE) {
		*out_niter += 1;
		*out_iterall = false;
	}
	mem_pres = bcache_memory_pressure(bcache);
	if (mem_pres > 50) {
		*out_niter += mem_pres / 10;
		*out_iterall = true;
	}
}

void silofs_bcache_relax(struct silofs_bcache *bcache, int flags)
{
	size_t niter = 0;
	bool iterall = false;

	bcache_relax_args(bcache, flags, &niter, &iterall);
	bcache_evict_some(bcache, niter, iterall);
}

struct silofs_bnode_info *
silofs_bcache_dq_front(const struct silofs_bcache *bcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&bcache->pc_dirtyq);
	return bni_from_dqe(dqe);
}
