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
#include <silofs/nodes.h>

const struct silofs_pnode_info *
silofs_pni_from_ni(const struct silofs_node_info *ni)
{
	return container_of(ni, struct silofs_pnode_info, pn_ni);
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
	return &pni->pn_ni.hmqe;
}

struct silofs_pnode_info *silofs_pni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_node_info *ni;

	ni = silofs_ni_from_dqe(dqe);
	return pni_from_ni(ni);
}

struct silofs_pnode_info *silofs_pni_from_mut_ni(struct silofs_node_info *ni)
{
	return mut_container_of(ni, struct silofs_pnode_info, pn_ni);
}

static bool pni_isevictable(const struct silofs_pnode_info *pni)
{
	const struct silofs_node_info *ni = &pni->pn_ni;

	return ni->isevictable_fn(ni);
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

static struct silofs_pnode_info *
pcache_search_by(const struct silofs_pcache *pcache,
                 const struct silofs_hkey *hkey)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_lookup(&pcache->pc_hmapq, hkey);
	return pni_from_hmqe(hmqe);
}

static struct silofs_pnode_info *
pcache_search(const struct silofs_pcache *pcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;

	silofs_hkey_by_paddr(&hkey, paddr);
	return pcache_search_by(pcache, &hkey);
}

static void pcache_promote(struct silofs_pcache *pcache,
                           struct silofs_pnode_info *pni, bool now)
{
	silofs_hmapq_promote(&pcache->pc_hmapq, pni_to_mut_hmqe(pni), now);
}

static struct silofs_pnode_info *
pcache_search_and_relru(struct silofs_pcache *pcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_search(pcache, paddr);
	if (pni != nullptr) {
		pcache_promote(pcache, pni, false);
	}
	return pni;
}

static void
pcache_map(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&pcache->pc_hmapq, pni_to_mut_hmqe(pni));
}

static void
pcache_unmap(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&pcache->pc_hmapq, pni_to_mut_hmqe(pni));
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

static struct silofs_pnode_info *
pcache_get_lru(const struct silofs_pcache *pcache)
{
	struct silofs_hmapq_elem *hmqe;
	struct silofs_pnode_info *pni = nullptr;

	hmqe = silofs_hmapq_get_lru(&pcache->pc_hmapq);
	if (hmqe != nullptr) {
		pni = pni_from_hmqe(hmqe);
	}
	return pni;
}

static bool pcache_evict_or_promote(struct silofs_pcache *pcache)
{
	struct silofs_pnode_info *pni;

	pni = pcache_get_lru(pcache);
	if (pni == nullptr) {
		return true;
	}
	if (pni_isevictable(pni)) {
		pcache_evict_by(pcache, pni);
		return true;
	}
	pcache_promote(pcache, pni, true);
	return false;
}

static size_t pcache_lru_size(const struct silofs_pcache *pcache)
{
	return pcache->pc_hmapq.hmq_lru.sz;
}

static void pcache_evict_some(struct silofs_pcache *pcache, size_t nevict_max)
{
	const size_t sz = pcache_lru_size(pcache);
	size_t nevicted = 0;

	for (size_t i = 0; (i < sz) && (nevicted < nevict_max); ++i) {
		if (pcache_evict_or_promote(pcache)) {
			nevicted += 1;
		}
	}
}

struct silofs_pcache_evict_ctx {
	struct silofs_pcache *pcache;
	size_t evict_max;
	size_t evict_cnt;
};

static int try_evict_pni(struct silofs_pcache_evict_ctx *pcec,
                         struct silofs_pnode_info *pni)
{
	if ((pcec->evict_cnt < pcec->evict_max) && pni_isevictable(pni)) {
		pcache_evict_by(pcec->pcache, pni);
		pcec->evict_cnt += 1;
	}
	return (pcec->evict_cnt < pcec->evict_max) ? 0 : 1;
}

static int try_evict_pni_cb(struct silofs_hmapq_elem *hmqe, void *arg)
{
	return try_evict_pni(arg, pni_from_hmqe(hmqe));
}

static void pcache_evict_many(struct silofs_pcache *pcache, size_t nevict_max)
{
	struct silofs_pcache_evict_ctx pcec = {
		.pcache    = pcache,
		.evict_max = nevict_max,
		.evict_cnt = 0,
	};

	silofs_hmapq_riterate(&pcache->pc_hmapq, pcache_lru_size(pcache),
	                      try_evict_pni_cb, &pcec);
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
	pcache_evict_many(pcache, pcache_lru_size(pcache));
}

static size_t pcache_mempress(const struct silofs_pcache *pcache)
{
	return silofs_mempress(pcache->pc_alloc);
}

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags)
{
	const size_t lrusize = pcache_lru_size(pcache);
	const size_t mempres = pcache_mempress(pcache);
	size_t count;

	if (mempres > 40) {
		count = lrusize / 5;
		pcache_evict_many(pcache, count);
	} else if (mempres > 20) {
		pcache_evict_some(pcache, lrusize / 10);
	} else if (flags & SILOFS_CTLF_IDLE) {
		pcache_evict_some(pcache, 1);
	}
}
