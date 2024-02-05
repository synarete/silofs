/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/pv.h>


static struct silofs_pnode_info *
pni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_pnode_info *pni = NULL;

	if (hmqe != NULL) {
		pni = container_of2(hmqe, struct silofs_pnode_info, p_hmqe);
	}
	return unconst(pni);
}

static struct silofs_hmapq_elem *
pni_to_hmqe(const struct silofs_pnode_info *pni)
{
	const struct silofs_hmapq_elem *hmqe = &pni->p_hmqe;

	return unconst(hmqe);
}

static void pni_do_undirtify(struct silofs_pnode_info *pni)
{
	pni->p_hmqe.hme_dirty = false;
}

static bool pni_isevictable(const struct silofs_pnode_info *pni)
{
	return silofs_hmqe_is_evictable(&pni->p_hmqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	pcache->pc_alloc = alloc;
	return 0;
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	silofs_hmapq_fini(&pcache->pc_hmapq, pcache->pc_alloc);
	pcache->pc_alloc = NULL;
}

static struct silofs_pnode_info *
pcache_find_pni(const struct silofs_pcache *pcache,
                const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_paddr(&hkey, paddr);
	hmqe = silofs_hmapq_lookup(&pcache->pc_hmapq, &hkey);
	return pni_from_hmqe(hmqe);
}

static void pcache_promote_pni(struct silofs_pcache *pcache,
                               struct silofs_pnode_info *pni, bool now)
{
	silofs_hmapq_promote(&pcache->pc_hmapq, pni_to_hmqe(pni), now);
}


static struct silofs_pnode_info *
pcache_find_relru_pni(struct silofs_pcache *pcache,
                      const struct silofs_paddr *paddr, bool now)
{
	struct silofs_pnode_info *pni;

	pni = pcache_find_pni(pcache, paddr);
	if (pni != NULL) {
		pcache_promote_pni(pcache, pni, now);
	}
	return pni;
}

static struct silofs_pnode_info *
pcache_lookup_pni(struct silofs_pcache *pcache,
                  const struct silofs_paddr *paddr)
{
	return pcache_find_relru_pni(pcache, paddr, false);
}

struct silofs_btnode_info *
silofs_pcache_lookup_bti(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_lookup_pni(pcache, paddr);
	return silofs_bti_from_pni(pni);
}

struct silofs_btleaf_info *
silofs_pcache_lookup_bli(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_lookup_pni(pcache, paddr);
	return silofs_bli_from_pni(pni);
}

static struct silofs_pnode_info *
pcache_new_bti_as_pni(const struct silofs_pcache *pcache,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti;

	bti = silofs_bti_new(paddr, pcache->pc_alloc);
	return (bti != NULL) ? &bti->btn_pni : NULL;
}

static void pcache_del_bti_by_pni(const struct silofs_pcache *pcache,
                                  struct silofs_pnode_info *pni)
{
	struct silofs_btnode_info *bti = silofs_bti_from_pni(pni);

	silofs_bti_del(bti, pcache->pc_alloc);
}

static struct silofs_pnode_info *
pcache_new_bli_as_pni(const struct silofs_pcache *pcache,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli;

	bli = silofs_bli_new(paddr, pcache->pc_alloc);
	return (bli != NULL) ? &bli->btl_pni : NULL;
}

static void pcache_del_bli_by_pni(const struct silofs_pcache *pcache,
                                  struct silofs_pnode_info *pni)
{
	struct silofs_btleaf_info *bli = silofs_bli_from_pni(pni);

	silofs_bli_del(bli, pcache->pc_alloc);
}

static struct silofs_pnode_info *
pcache_new_pni(const struct silofs_pcache *pcache,
               const struct silofs_paddr *paddr, enum silofs_ptype ptype)
{
	struct silofs_pnode_info *pni = NULL;

	switch (ptype) {
	case SILOFS_PTYPE_BTNODE:
		pni = pcache_new_bti_as_pni(pcache, paddr);
		break;
	case SILOFS_PTYPE_BTLEAF:
		pni = pcache_new_bli_as_pni(pcache, paddr);
		break;
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		pni = NULL;
		break;
	}
	return pni;
}

static void pcache_del_pni(const struct silofs_pcache *pcache,
                           struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = pni->p_type;

	switch (ptype) {
	case SILOFS_PTYPE_BTNODE:
		pcache_del_bti_by_pni(pcache, pni);
		break;
	case SILOFS_PTYPE_BTLEAF:
		pcache_del_bli_by_pni(pcache, pni);
		break;
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		break;
	}
}

static int visit_evictable_pni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_pnode_info *pni = pni_from_hmqe(hmqe);
	struct silofs_pnode_info **out_pni = arg;
	int ret = 0;

	if (pni_isevictable(pni)) {
		*out_pni = pni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static void pcache_remove_pni(struct silofs_pcache *pcache,
                              struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&pcache->pc_hmapq, pni_to_hmqe(pni));
}

static void pcache_evict_pni(struct silofs_pcache *pcache,
                             struct silofs_pnode_info *pni)
{
	pni_do_undirtify(pni);
	pcache_remove_pni(pcache, pni);
	pcache_del_pni(pcache, pni);
}

static struct silofs_pnode_info *
pcache_find_evictable_pni(struct silofs_pcache *pcache, bool iterall)
{
	struct silofs_pnode_info *pni = NULL;
	const size_t limit = iterall ? SILOFS_HMAPQ_ITERALL : 10;

	silofs_hmapq_riterate(&pcache->pc_hmapq, limit,
	                      visit_evictable_pni, &pni);
	return pni;
}

static size_t pcache_evict_some(struct silofs_pcache *pcache,
                                size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = pcache_find_evictable_pni(pcache, iterall);
		if (pni == NULL) {
			break;
		}
		pcache_evict_pni(pcache, pni);
		cnt++;
	}
	return cnt;
}

static struct silofs_pnode_info *
pcache_require_pni(struct silofs_pcache *pcache,
                   const struct silofs_paddr *paddr, enum silofs_ptype ptype)
{
	struct silofs_pnode_info *pni = NULL;
	int retry = 3;

	while (retry-- > 0) {
		pni = pcache_new_pni(pcache, paddr, ptype);
		if (pni != NULL) {
			break;
		}
		pcache_evict_some(pcache, 2, false);
	}
	return pni;
}

static void pcache_store_pni(struct silofs_pcache *pcache,
                             struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&pcache->pc_hmapq, pni_to_hmqe(pni));
}

static struct silofs_pnode_info *
pcache_create_pni(struct silofs_pcache *pcache,
                  const struct silofs_paddr *paddr, enum silofs_ptype ptype)
{
	struct silofs_pnode_info *pni;

	pni = pcache_require_pni(pcache, paddr, ptype);
	if (pni != NULL) {
		pcache_store_pni(pcache, pni);
	}
	return pni;
}

struct silofs_btnode_info *
silofs_pcache_create_bti(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_create_pni(pcache, paddr, SILOFS_PTYPE_BTNODE);
	return silofs_bti_from_pni(pni);
}

struct silofs_btleaf_info *
silofs_pcache_create_bli(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_create_pni(pcache, paddr, SILOFS_PTYPE_BTLEAF);
	return silofs_bli_from_pni(pni);
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
	if (flags & SILOFS_F_NOW) {
		*out_niter += 2;
		*out_iterall = true;
	}
	if (flags & SILOFS_F_TIMEOUT) {
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

