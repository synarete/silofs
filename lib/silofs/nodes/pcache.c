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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/flags.h>
#include <silofs/nodes.h>

const struct silofs_pnode_info *
silofs_pni_from_ni(const struct silofs_node_info *ni)
{
	return container_of(ni, struct silofs_pnode_info, pn_base);
}

static struct silofs_pnode_info *pni_unconst(const struct silofs_pnode_info *p)
{
	return silofs_unconst(p);
}

static struct silofs_pnode_info *pni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_pnode_info *pni = nullptr;

	if (ni != nullptr) {
		pni = silofs_pni_from_ni(ni);
	}
	return pni_unconst(pni);
}

static struct silofs_pnode_info *
pni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	return pni_from_ni(silofs_ni_from_hmqe(hmqe));
}

static struct silofs_hmapq_elem *pni_to_mut_hmqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_base.hmqe;
}

struct silofs_pnode_info *silofs_pni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_node_info *ni;

	ni = silofs_ni_from_dqe(dqe);
	return pni_from_ni(ni);
}

struct silofs_pnode_info *silofs_pni_from_mut_ni(struct silofs_node_info *ni)
{
	return mut_container_of(ni, struct silofs_pnode_info, pn_base);
}

static bool pni_isevictable(const struct silofs_pnode_info *pni)
{
	return !silofs_ni_ispinned(&pni->pn_base);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pcache_init_hmapq(struct silofs_pcache *pcache)
{
	const size_t nslots = 1024; /* TODO: revisit */

	return silofs_hmapq_init(&pcache->pc_hmapq, pcache->pc_alloc, nslots);
}

static void pcache_fini_hmapq(struct silofs_pcache *pcache)
{
	silofs_hmapq_fini(&pcache->pc_hmapq, pcache->pc_alloc);
}

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc *alloc)
{
	silofs_memzero(pcache, sizeof(*pcache));
	pcache->pc_alloc = alloc;
	silofs_dirtyq_init(&pcache->pc_dirtyq);
	return pcache_init_hmapq(pcache);
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	pcache_fini_hmapq(pcache);
	silofs_dirtyq_fini(&pcache->pc_dirtyq);
	pcache->pc_alloc = nullptr;
}

static const struct silofs_hmapq *
pcache_hmapq_of(const struct silofs_pcache *pcache,
                const struct silofs_paddr *paddr)
{
	const struct silofs_hmapq *hmapq = nullptr;

	switch (paddr->ptype) {
	case SILOFS_PTYPE_UBER:
	case SILOFS_PTYPE_BLDESC:
	case SILOFS_PTYPE_BTNODE:
		hmapq = &pcache->pc_hmapq;
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_MBR:
	case SILOFS_PTYPE_LNODE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("bad pcache-elem: ptype=%d", (int)paddr->ptype);
		break;
	}
	return hmapq;
}

static struct silofs_hmapq *
pcache_hmapq_of2(const struct silofs_pcache *pcache,
                 const struct silofs_pnode_info *pni)
{
	const struct silofs_hmapq *hmapq;

	hmapq = pcache_hmapq_of(pcache, &pni->pn_self.paddr);
	return silofs_unconst(hmapq);
}

static struct silofs_pnode_info *
pcache_search(const struct silofs_pcache *pcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe   = nullptr;
	const struct silofs_hmapq *hmapq = nullptr;

	hmapq = pcache_hmapq_of(pcache, paddr);
	if (likely(hmapq != nullptr)) {
		silofs_hkey_by_paddr(&hkey, paddr);
		hmqe = silofs_hmapq_lookup(hmapq, &hkey);
	}
	return pni_from_hmqe(hmqe);
}

static void
pcache_promote(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_promote(hmapq, pni_to_mut_hmqe(pni), false);
	}
}

static struct silofs_pnode_info *
pcache_search_and_relru(struct silofs_pcache *pcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_search(pcache, paddr);
	if (pni != nullptr) {
		pcache_promote(pcache, pni);
	}
	return pni;
}

static void
pcache_map(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_store(hmapq, pni_to_mut_hmqe(pni));
	}
}

static void
pcache_unmap(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_remove(hmapq, pni_to_mut_hmqe(pni));
	}
}

static void
pcache_bind_dirtyq(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_pni_set_dq(pni, &pcache->pc_dirtyq);
}

static void pcache_unbind_dirtyq(struct silofs_pcache *pcache,
                                 struct silofs_pnode_info *pni)
{
	silofs_pni_cleardirty(pni);
	silofs_pni_set_dq(pni, nullptr);
	unused(pcache);
}

static struct silofs_pnode_info *
pcache_new_pnode(const struct silofs_pcache *pcache,
                 const struct silofs_pnptr *pnptr)
{
	return silofs_new_pnode(pnptr, pcache->pc_alloc);
}

static void pcache_del_pnode(const struct silofs_pcache *pcache,
                             struct silofs_pnode_info *pni)
{
	silofs_del_pnode(pni, pcache->pc_alloc);
}

static void pcache_insert_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	pcache_bind_dirtyq(pcache, pni);
	pcache_map(pcache, pni);
}

static void pcache_remove_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	pcache_unbind_dirtyq(pcache, pni);
	pcache_unmap(pcache, pni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache *pcache,
                           const struct silofs_paddr *paddr)
{
	return pcache_search_and_relru(pcache, paddr);
}

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache *pcache,
                           const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni = nullptr;

	pni = pcache_new_pnode(pcache, pnptr);
	if (pni != nullptr) {
		pcache_insert_pnode(pcache, pni);
	}
	return pni;
}

void silofs_pcache_delete_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	pcache_remove_pnode(pcache, pni);
	pcache_del_pnode(pcache, pni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
pcache_evict_by(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_pcache_delete_pnode(pcache, pni);
}

static int visit_evictable_pni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_pnode_info *pni = pni_from_hmqe(hmqe);

	if (unlikely(pni == nullptr)) {
		return 0;
	}
	if (!pni_isevictable(pni)) {
		return 0;
	}
	*(struct silofs_pnode_info **)arg = pni; /* candidate for eviction */
	return 1;
}

static struct silofs_pnode_info *
pcache_find_evictable(struct silofs_pcache *pcache, bool iterall)
{
	struct silofs_pnode_info *pni    = nullptr;
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
		if (pni == nullptr) {
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

	*out_niter   = 0;
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
	return silofs_pni_from_dqe(dqe);
}
