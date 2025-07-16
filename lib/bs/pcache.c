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
#include "pnodes.h"
#include "bdesc.h"
#include "pcache.h"

enum {
	PCACHE_RETRY_MAX = 4,
};

/* local functions */
static size_t
pcache_evict_some(struct silofs_pcache *pcache, size_t niter, bool iterall);

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
	const struct silofs_pnode_info *pni = NULL;

	if (hmqe != NULL) {
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

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc *alloc)
{
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 1);
	int err;

	silofs_memzero(pcache, sizeof(*pcache));
	err = silofs_hmapq_init(&pcache->pc_hmapq, alloc, nslots);
	if (err) {
		return err;
	}
	silofs_dirtyq_init(&pcache->pc_dirtyq);
	pcache->pc_alloc = alloc;
	return 0;
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	silofs_hmapq_fini(&pcache->pc_hmapq, pcache->pc_alloc);
	silofs_dirtyq_fini(&pcache->pc_dirtyq);
	pcache->pc_alloc = NULL;
}

static struct silofs_pnode_info *
pcache_search(const struct silofs_pcache *pcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_paddr(&hkey, paddr);
	hmqe = silofs_hmapq_lookup(&pcache->pc_hmapq, &hkey);
	return pni_from_hmqe(hmqe);
}

static void
pcache_promote(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_promote(&pcache->pc_hmapq, pni_to_hmqe(pni), false);
}

static struct silofs_pnode_info *
pcache_search_and_relru(struct silofs_pcache *pcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_search(pcache, paddr);
	if (pni != NULL) {
		pcache_promote(pcache, pni);
	}
	return pni;
}

static struct silofs_pnode_info *
pcache_lookup(struct silofs_pcache *pcache, const struct silofs_paddr *paddr)
{
	return pcache_search_and_relru(pcache, paddr);
}

static void
pcache_store(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&pcache->pc_hmapq, pni_to_hmqe(pni));
}

static void
pcache_remove(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&pcache->pc_hmapq, pni_to_hmqe(pni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bdesc_info *
pcache_new_bdi(const struct silofs_pcache *pcache,
               const struct silofs_paddr *paddr)
{
	return silofs_bdi_new(paddr, pcache->pc_alloc);
}

static void pcache_del_bdi(const struct silofs_pcache *pcache,
                           struct silofs_bdesc_info *bdi)
{
	silofs_bdi_del(bdi, pcache->pc_alloc);
}

struct silofs_bdesc_info *
silofs_pcache_lookup_bdi(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BLDESC);

	pni = pcache_lookup(pcache, paddr);
	return silofs_bdi_from_pni(pni);
}

static struct silofs_bdesc_info *
pcache_require_bdi(struct silofs_pcache *pcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_bdesc_info *bdi = NULL;

	for (size_t i = 0; i < PCACHE_RETRY_MAX; ++i) {
		bdi = pcache_new_bdi(pcache, paddr);
		if (bdi != NULL) {
			break;
		}
		pcache_evict_some(pcache, i + 1, false);
	}
	return bdi;
}

static void
pcache_bind_bdi_dq(struct silofs_pcache *pcache, struct silofs_bdesc_info *bdi)
{
	silofs_bdi_set_dq(bdi, &pcache->pc_dirtyq);
}

static void
pcache_store_bdi(struct silofs_pcache *pcache, struct silofs_bdesc_info *bdi)
{
	pcache_store(pcache, &bdi->bd_pni);
}

struct silofs_bdesc_info *
silofs_pcache_create_bdi(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_bdesc_info *bdi;

	bdi = pcache_require_bdi(pcache, paddr);
	if (bdi != NULL) {
		pcache_bind_bdi_dq(pcache, bdi);
		pcache_store_bdi(pcache, bdi);
	}
	return bdi;
}

static void
pcache_remove_bdi(struct silofs_pcache *pcache, struct silofs_bdesc_info *bdi)
{
	pcache_remove(pcache, &bdi->bd_pni);
}

static void
pcache_forget_bdi(struct silofs_pcache *pcache, struct silofs_bdesc_info *bdi)
{
	silofs_bdi_undirtify(bdi);
	pcache_remove_bdi(pcache, bdi);
}

void silofs_pcache_evict_bdi(struct silofs_pcache *pcache,
                             struct silofs_bdesc_info *bdi)
{
	pcache_forget_bdi(pcache, bdi);
	pcache_del_bdi(pcache, bdi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
pcache_new_bni(const struct silofs_pcache *pcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BTNODE);

	return silofs_bni_new(paddr, pcache->pc_alloc);
}

static void pcache_del_bni(const struct silofs_pcache *pcache,
                           struct silofs_btnode_info *bni)
{
	silofs_assert_eq(bni->bn_pni.pn_paddr.mtype, SILOFS_MTYPE_BTNODE);

	silofs_bni_del(bni, pcache->pc_alloc);
}

struct silofs_btnode_info *
silofs_pcache_lookup_bni(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BTNODE);

	pni = pcache_lookup(pcache, paddr);
	return silofs_bni_from_pni(pni);
}

static struct silofs_btnode_info *
pcache_require_bni(struct silofs_pcache *pcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bni = NULL;

	for (size_t i = 0; i < PCACHE_RETRY_MAX; ++i) {
		bni = pcache_new_bni(pcache, paddr);
		if (bni != NULL) {
			break;
		}
		pcache_evict_some(pcache, i + 1, false);
	}
	return bni;
}

static void pcache_bind_bni_dq(struct silofs_pcache *pcache,
                               struct silofs_btnode_info *bni)
{
	silofs_bni_set_dq(bni, &pcache->pc_dirtyq);
}

static void
pcache_store_bni(struct silofs_pcache *pcache, struct silofs_btnode_info *bni)
{
	pcache_store(pcache, &bni->bn_pni);
}

struct silofs_btnode_info *
silofs_pcache_create_bni(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bni;

	bni = pcache_require_bni(pcache, paddr);
	if (bni != NULL) {
		pcache_bind_bni_dq(pcache, bni);
		pcache_store_bni(pcache, bni);
	}
	return bni;
}

static void
pcache_remove_bni(struct silofs_pcache *pcache, struct silofs_btnode_info *bni)
{
	pcache_remove(pcache, &bni->bn_pni);
}

static void
pcache_forget_bni(struct silofs_pcache *pcache, struct silofs_btnode_info *bni)
{
	silofs_bni_undirtify(bni);
	pcache_remove_bni(pcache, bni);
}

void silofs_pcache_evict_bni(struct silofs_pcache *pcache,
                             struct silofs_btnode_info *bni)
{
	pcache_forget_bni(pcache, bni);
	pcache_del_bni(pcache, bni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
pcache_evict_by(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	const enum silofs_mtype mtype = silofs_pni_mtype(pni);

	switch (mtype) {
	case SILOFS_MTYPE_BLDESC:
		silofs_pcache_evict_bdi(pcache, silofs_bdi_from_pni(pni));
		break;
	case SILOFS_MTYPE_BTNODE:
		silofs_pcache_evict_bni(pcache, silofs_bni_from_pni(pni));
		break;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_BOOTREC:
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
		silofs_panic("corrupted pcache: mtype=%d", (int)mtype);
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
pcache_find_evictable(struct silofs_pcache *pcache, bool iterall)
{
	struct silofs_pnode_info *pni = NULL;
	struct silofs_pnode_info **p_pni = &pni;

	silofs_hmapq_riterate(&pcache->pc_hmapq,
	                      iterall ? SILOFS_HMAPQ_ITERALL : 10,
	                      visit_evictable_pni, (void *)p_pni);
	return pni;
}

static size_t
pcache_evict_some(struct silofs_pcache *pcache, size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = pcache_find_evictable(pcache, iterall);
		if (pni == NULL) {
			break;
		}
		pcache_evict_by(pcache, pni);
		cnt++;
	}
	return cnt;
}

static size_t pcache_usage(const struct silofs_pcache *pcache)
{
	return silofs_hmapq_usage(&pcache->pc_hmapq);
}

bool silofs_pcache_isempty(const struct silofs_pcache *pcache)
{
	return (pcache_usage(pcache) == 0);
}

void silofs_pcache_drop(struct silofs_pcache *pcache)
{
	size_t cnt;

	cnt = pcache_evict_some(pcache, 1, true);
	while (cnt > 0) {
		cnt = pcache_evict_some(pcache, 1, true);
	}
}

static size_t pcache_memory_pressure(const struct silofs_pcache *pcache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 0;

	silofs_memstat(pcache->pc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres; /* percentage of total available memory */
}

static void pcache_relax_args(const struct silofs_pcache *pcache, int flags,
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
	mem_pres = pcache_memory_pressure(pcache);
	if (mem_pres > 50) {
		*out_niter += mem_pres / 10;
		*out_iterall = true;
	}
}

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags)
{
	size_t niter = 0;
	bool iterall = false;

	pcache_relax_args(pcache, flags, &niter, &iterall);
	pcache_evict_some(pcache, niter, iterall);
}

struct silofs_pnode_info *
silofs_pcache_dq_front(const struct silofs_pcache *pcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&pcache->pc_dirtyq);
	return pni_from_dqe(dqe);
}
