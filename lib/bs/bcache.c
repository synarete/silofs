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
#include "bdesc.h"
#include "btnode.h"
#include "bcache.h"

enum {
	BCACHE_RETRY_MAX = 4,
};

/* local functions */
static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pnode_info *pni_unconst(const struct silofs_pnode_info *p)
{
	union {
		const struct silofs_pnode_info *p;
		struct silofs_pnode_info *q;
	} u = { .p = p };
	return u.q;
}

static struct silofs_pnode_info *
pni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_pnode_info *pni = nullptr;

	if (hmqe != nullptr) {
		pni = container_of2(hmqe, struct silofs_pnode_info, pn_hmqe);
	}
	return pni_unconst(pni);
}

static struct silofs_hmapq_elem *pni_to_hmqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe;
}

static struct silofs_pnode_info *pni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmqe_from_dqe(dqe);
	return pni_from_hmqe(hmqe);
}

static bool pni_isevictable(const struct silofs_pnode_info *pni)
{
	return silofs_hmqe_is_evictable(&pni->pn_hmqe);
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

static struct silofs_pnode_info *
bcache_search(const struct silofs_bcache *bcache,
              const struct silofs_baddr *baddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_baddr(&hkey, baddr);
	hmqe = silofs_hmapq_lookup(&bcache->pc_hmapq, &hkey);
	return pni_from_hmqe(hmqe);
}

static void
bcache_promote(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_promote(&bcache->pc_hmapq, pni_to_hmqe(pni), false);
}

static struct silofs_pnode_info *
bcache_search_and_relru(struct silofs_bcache *bcache,
                        const struct silofs_baddr *baddr)
{
	struct silofs_pnode_info *pni;

	pni = bcache_search(bcache, baddr);
	if (pni != nullptr) {
		bcache_promote(bcache, pni);
	}
	return pni;
}

static struct silofs_pnode_info *
bcache_lookup(struct silofs_bcache *bcache, const struct silofs_baddr *baddr)
{
	return bcache_search_and_relru(bcache, baddr);
}

static void
bcache_store(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&bcache->pc_hmapq, pni_to_hmqe(pni));
}

static void
bcache_remove(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&bcache->pc_hmapq, pni_to_hmqe(pni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bdesc_info *
bcache_new_bdi(const struct silofs_bcache *bcache,
               const struct silofs_baddr *baddr)
{
	return silofs_bdi_new(baddr, bcache->pc_alloc);
}

static void bcache_del_bdi(const struct silofs_bcache *bcache,
                           struct silofs_bdesc_info *bdi)
{
	silofs_bdi_del(bdi, bcache->pc_alloc);
}

struct silofs_bdesc_info *
silofs_bcache_lookup_bdi(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_BDESC);

	pni = bcache_lookup(bcache, baddr);
	return silofs_bdi_from_pni(pni);
}

static struct silofs_bdesc_info *
bcache_require_bdi(struct silofs_bcache *bcache,
                   const struct silofs_baddr *baddr)
{
	struct silofs_bdesc_info *bdi = nullptr;

	for (size_t i = 0; i < BCACHE_RETRY_MAX; ++i) {
		bdi = bcache_new_bdi(bcache, baddr);
		if (bdi != nullptr) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return bdi;
}

static void
bcache_bind_bdi_dq(struct silofs_bcache *bcache, struct silofs_bdesc_info *bdi)
{
	silofs_bdi_set_dq(bdi, &bcache->pc_dirtyq);
}

static void
bcache_store_bdi(struct silofs_bcache *bcache, struct silofs_bdesc_info *bdi)
{
	bcache_store(bcache, &bdi->bd_pni);
}

struct silofs_bdesc_info *
silofs_bcache_create_bdi(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_bdesc_info *bdi;

	bdi = bcache_require_bdi(bcache, baddr);
	if (bdi != nullptr) {
		bcache_bind_bdi_dq(bcache, bdi);
		bcache_store_bdi(bcache, bdi);
	}
	return bdi;
}

static void
bcache_remove_bdi(struct silofs_bcache *bcache, struct silofs_bdesc_info *bdi)
{
	bcache_remove(bcache, &bdi->bd_pni);
}

static void
bcache_forget_bdi(struct silofs_bcache *bcache, struct silofs_bdesc_info *bdi)
{
	silofs_bdi_undirtify(bdi);
	bcache_remove_bdi(bcache, bdi);
}

void silofs_bcache_evict_bdi(struct silofs_bcache *bcache,
                             struct silofs_bdesc_info *bdi)
{
	bcache_forget_bdi(bcache, bdi);
	bcache_del_bdi(bcache, bdi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
bcache_new_bni(const struct silofs_bcache *bcache,
               const struct silofs_baddr *baddr)
{
	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_BTNODE);

	return silofs_bni_new(baddr, bcache->pc_alloc);
}

static void bcache_del_bni(const struct silofs_bcache *bcache,
                           struct silofs_btnode_info *bni)
{
	silofs_assert_eq(bni->bn_pni.pn_baddr.mtype, SILOFS_MTYPE_BTNODE);

	silofs_bni_del(bni, bcache->pc_alloc);
}

struct silofs_btnode_info *
silofs_bcache_lookup_bni(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_BTNODE);

	pni = bcache_lookup(bcache, baddr);
	return silofs_bni_from_pni(pni);
}

static struct silofs_btnode_info *
bcache_require_bni(struct silofs_bcache *bcache,
                   const struct silofs_baddr *baddr)
{
	struct silofs_btnode_info *bni = nullptr;

	for (size_t i = 0; i < BCACHE_RETRY_MAX; ++i) {
		bni = bcache_new_bni(bcache, baddr);
		if (bni != nullptr) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return bni;
}

static void bcache_bind_bni_dq(struct silofs_bcache *bcache,
                               struct silofs_btnode_info *bni)
{
	silofs_bni_set_dq(bni, &bcache->pc_dirtyq);
}

static void
bcache_store_bni(struct silofs_bcache *bcache, struct silofs_btnode_info *bni)
{
	bcache_store(bcache, &bni->bn_pni);
}

struct silofs_btnode_info *
silofs_bcache_create_bni(struct silofs_bcache *bcache,
                         const struct silofs_baddr *baddr)
{
	struct silofs_btnode_info *bni;

	bni = bcache_require_bni(bcache, baddr);
	if (bni != nullptr) {
		bcache_bind_bni_dq(bcache, bni);
		bcache_store_bni(bcache, bni);
	}
	return bni;
}

static void
bcache_remove_bni(struct silofs_bcache *bcache, struct silofs_btnode_info *bni)
{
	bcache_remove(bcache, &bni->bn_pni);
}

static void
bcache_forget_bni(struct silofs_bcache *bcache, struct silofs_btnode_info *bni)
{
	silofs_bni_undirtify(bni);
	bcache_remove_bni(bcache, bni);
}

void silofs_bcache_evict_bni(struct silofs_bcache *bcache,
                             struct silofs_btnode_info *bni)
{
	bcache_forget_bni(bcache, bni);
	bcache_del_bni(bcache, bni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
bcache_evict_by(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	const enum silofs_mtype mtype = silofs_pni_mtype(pni);

	switch (mtype) {
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
		/* XXX */
		silofs_assert_null(pni);
		break;
	case SILOFS_MTYPE_BDESC:
		silofs_bcache_evict_bdi(bcache, silofs_bdi_from_pni(pni));
		break;
	case SILOFS_MTYPE_BTNODE:
		silofs_bcache_evict_bni(bcache, silofs_bni_from_pni(pni));
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

static int visit_evictable_pni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_pnode_info *pni = pni_from_hmqe(hmqe);
	struct silofs_pnode_info **out_pni;
	int ret = 0;

	if (pni_isevictable(pni)) {
		out_pni = (struct silofs_pnode_info **)arg;
		*out_pni = pni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static struct silofs_pnode_info *
bcache_find_evictable(struct silofs_bcache *bcache, bool iterall)
{
	struct silofs_pnode_info *pni = nullptr;
	struct silofs_pnode_info **p_pni = &pni;

	silofs_hmapq_riterate(&bcache->pc_hmapq,
	                      iterall ? SILOFS_HMAPQ_ITERALL : 10,
	                      visit_evictable_pni, (void *)p_pni);
	return pni;
}

static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = bcache_find_evictable(bcache, iterall);
		if (pni == nullptr) {
			break;
		}
		bcache_evict_by(bcache, pni);
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

struct silofs_pnode_info *
silofs_bcache_dq_front(const struct silofs_bcache *bcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&bcache->pc_dirtyq);
	return pni_from_dqe(dqe);
}
