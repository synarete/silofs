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
	return silofs_ni_isevictable(&pni->pn_base);
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

static void pcache_promote(struct silofs_pcache *pcache,
                           struct silofs_pnode_info *pni, bool now)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_promote(hmapq, pni_to_mut_hmqe(pni), now);
	}
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
	const size_t n = pcache_lru_size(pcache);

	pcache_evict_some(pcache, n);
}

static size_t pcache_mempress(const struct silofs_pcache *pcache)
{
	return silofs_mempress(pcache->pc_alloc);
}

static size_t pcache_relax_count(const struct silofs_pcache *pcache, int flags)
{
	const size_t lrusize = pcache_lru_size(pcache);
	const size_t mempres = pcache_mempress(pcache);
	size_t cnt;

	cnt = (lrusize * mempres) / 100;
	if (flags & SILOFS_CTLF_IDLE) {
		cnt += 1;
	}
	return cnt;
}

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags)
{
	const size_t cnt = pcache_relax_count(pcache, flags);

	pcache_evict_some(pcache, cnt);
}

struct silofs_pnode_info *
silofs_pcache_dq_front(const struct silofs_pcache *pcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&pcache->pc_dirtyq);
	return silofs_pni_from_dqe(dqe);
}
