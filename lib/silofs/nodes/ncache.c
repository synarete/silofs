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

static struct silofs_node_info *ni_unconst(const struct silofs_node_info *ni)
{
	return silofs_unconst(ni);
}

static struct silofs_node_info *
ni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_node_info *ni = nullptr;

	if (hmqe != nullptr) {
		ni = container_of(hmqe, struct silofs_node_info, hmqe);
	}
	return ni_unconst(ni);
}

static bool ni_isevictable(const struct silofs_node_info *ni)
{
	return ni->isevictable_fn(ni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int ncache_init_hmapq(struct silofs_ncache *ncache)
{
	const size_t nslots = 1024; /* TODO: revisit */

	return silofs_hmapq_init(&ncache->hmapq, ncache->nc_alloc, nslots);
}

static void ncache_fini_hmapq(struct silofs_ncache *ncache)
{
	silofs_hmapq_fini(&ncache->hmapq, ncache->nc_alloc);
}

static int
ncache_init(struct silofs_ncache *ncache, struct silofs_alloc *alloc)
{
	silofs_memzero(ncache, sizeof(*ncache));
	ncache->nc_alloc = alloc;
	silofs_dirtyq_init(&ncache->dirtyq);
	return ncache_init_hmapq(ncache);
}

static void ncache_fini(struct silofs_ncache *ncache)
{
	ncache_fini_hmapq(ncache);
	silofs_dirtyq_fini(&ncache->dirtyq);
	ncache->nc_alloc = nullptr;
}

static struct silofs_node_info *
ncache_search_by(const struct silofs_ncache *ncache,
                 const struct silofs_hkey *hkey)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_lookup(&ncache->hmapq, hkey);
	return ni_from_hmqe(hmqe);
}

static void ncache_promote(struct silofs_ncache *ncache,
                           struct silofs_node_info *ni, bool now)
{
	silofs_hmapq_promote(&ncache->hmapq, &ni->hmqe, now);
}

static struct silofs_node_info *
ncache_search_and_relru(struct silofs_ncache *ncache,
                        const struct silofs_hkey *hkey)
{
	struct silofs_node_info *ni;

	ni = ncache_search_by(ncache, hkey);
	if (ni != nullptr) {
		ncache_promote(ncache, ni, false);
	}
	return ni;
}

static void
ncache_map_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_hmapq_store(&ncache->hmapq, &ni->hmqe);
}

static void
ncache_unmap_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_hmapq_remove(&ncache->hmapq, &ni->hmqe);
}

static void
ncache_bind_dirtyq(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_ni_set_dq(ni, &ncache->dirtyq);
}

static void
ncache_unbind_dirtyq(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_ni_cleardirty(ni);
	silofs_ni_set_dq(ni, nullptr);
	unused(ncache);
}

static void
ncache_insert_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	ncache_bind_dirtyq(ncache, ni);
	ncache_map_node(ncache, ni);
}

static void
ncache_remove_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	ncache_unbind_dirtyq(ncache, ni);
	ncache_unmap_node(ncache, ni);
}

static void ncache_del_node(const struct silofs_ncache *ncache,
                            struct silofs_node_info *ni)
{
	ni->delete_fn(ni, ncache->nc_alloc);
}

static void
ncache_evict_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	ncache_remove_node(ncache, ni);
	ncache_del_node(ncache, ni);
}

static struct silofs_node_info *
ncache_get_lru(const struct silofs_ncache *ncache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&ncache->hmapq);
	return ni_from_hmqe(hmqe);
}

static bool ncache_evict_or_promote(struct silofs_ncache *ncache)
{
	struct silofs_node_info *ni;

	ni = ncache_get_lru(ncache);
	if (ni == nullptr) {
		return true;
	}
	if (!ni_isevictable(ni)) {
		ncache_promote(ncache, ni, true);
		return false;
	}
	ncache_evict_node(ncache, ni);
	return true;
}

static size_t ncache_lru_size(const struct silofs_ncache *ncache)
{
	return ncache->hmapq.hmq_lru.sz;
}

static void ncache_evict_some(struct silofs_ncache *ncache, size_t nevict_max)
{
	const size_t sz = ncache_lru_size(ncache);
	size_t nevicted = 0;

	for (size_t i = 0; (i < sz) && (nevicted < nevict_max); ++i) {
		if (ncache_evict_or_promote(ncache)) {
			nevicted += 1;
		}
	}
}

struct silofs_ncache_evict_ctx {
	struct silofs_ncache *ncache;
	size_t evict_max;
	size_t evict_cnt;
};

static int try_evict_node(struct silofs_ncache_evict_ctx *pcec,
                          struct silofs_node_info *ni)
{
	if ((pcec->evict_cnt < pcec->evict_max) && ni_isevictable(ni)) {
		ncache_evict_node(pcec->ncache, ni);
		pcec->evict_cnt += 1;
	}
	return (pcec->evict_cnt < pcec->evict_max) ? 0 : 1;
}

static int try_evict_node_cb(struct silofs_hmapq_elem *hmqe, void *arg)
{
	return try_evict_node(arg, ni_from_hmqe(hmqe));
}

static void ncache_evict_many(struct silofs_ncache *ncache, size_t nevict_max)
{
	struct silofs_ncache_evict_ctx pcec = {
		.ncache    = ncache,
		.evict_max = nevict_max,
		.evict_cnt = 0,
	};

	silofs_hmapq_riterate(&ncache->hmapq, ncache_lru_size(ncache),
	                      try_evict_node_cb, &pcec);
}

static void
ncache_forget_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_ni_cleardirty(ni);
	if (silofs_ni_refcnt(ni) > 0) {
		ncache_unmap_node(ncache, ni);
		ni->hmqe.hme_forgot = true;
	} else {
		ncache_evict_node(ncache, ni);
	}
}

static size_t ncache_usage(const struct silofs_ncache *ncache)
{
	return silofs_hmapq_usage(&ncache->hmapq);
}

static void ncache_drop(struct silofs_ncache *ncache)
{
	ncache_evict_many(ncache, ncache_lru_size(ncache));
}

static size_t ncache_mempress(const struct silofs_ncache *ncache)
{
	return silofs_mempress(ncache->nc_alloc);
}

static size_t ncache_overpop(const struct silofs_ncache *ncache)
{
	return silofs_hmapq_overpop(&ncache->hmapq);
}

static void ncache_relax(struct silofs_ncache *ncache, int flags)
{
	const size_t lrusize = ncache_lru_size(ncache);
	const size_t mempres = ncache_mempress(ncache);
	const size_t overpop = ncache_overpop(ncache);

	if (mempres > 40) {
		ncache_evict_many(ncache, lrusize / 5);
	} else if (mempres > 20) {
		ncache_evict_some(ncache, lrusize / 10);
	} else if (flags & SILOFS_CTLF_IDLE) {
		ncache_evict_some(ncache, 1 + overpop);
	}
}

static struct silofs_node_info *
ncache_lookup_node_by(struct silofs_ncache *ncache,
                      const struct silofs_hkey *hkey)
{
	return ncache_search_and_relru(ncache, hkey);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc *alloc)
{
	return ncache_init(&pcache->nc, alloc);
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	ncache_fini(&pcache->nc);
}

void silofs_pcache_drop(struct silofs_pcache *pcache)
{
	ncache_drop(&pcache->nc);
}

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags)
{
	ncache_relax(&pcache->nc, flags);
}

static struct silofs_pnode_info *pni_from_ni(struct silofs_node_info *ni)
{
	struct silofs_pnode_info *pni = nullptr;

	if (ni != nullptr) {
		pni = silofs_pni_from_ni(ni);
	}
	return pni;
}

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache *pcache,
                           const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_node_info *ni;

	silofs_hkey_by_paddr(&hkey, paddr);
	ni = ncache_lookup_node_by(&pcache->nc, &hkey);
	return pni_from_ni(ni);
}

static void
del_pnode_as(struct silofs_node_info *ni, struct silofs_alloc *alloc)
{
	struct silofs_pnode_info *pni = silofs_pni_from_ni(ni);

	silofs_del_pnode(pni, alloc);
}

static struct silofs_pnode_info *
pcache_new_pnode(const struct silofs_pcache *pcache,
                 const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni;

	pni = silofs_new_pnode(pnptr, pcache->nc.nc_alloc);
	if (pni != nullptr) {
		pni->pn_ni.delete_fn = del_pnode_as;
	}
	return pni;
}

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache *pcache,
                           const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni = nullptr;

	pni = pcache_new_pnode(pcache, pnptr);
	if (pni != nullptr) {
		ncache_insert_node(&pcache->nc, &pni->pn_ni);
	}
	return pni;
}

void silofs_pcache_delete_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	ncache_evict_node(&pcache->nc, &pni->pn_ni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc *alloc)
{
	return ncache_init(&lcache->nc, alloc);
}

void silofs_lcache_fini(struct silofs_lcache *lcache)
{
	ncache_fini(&lcache->nc);
}

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags)
{
	ncache_relax(&lcache->nc, flags);
}

void silofs_lcache_drop(struct silofs_lcache *lcache)
{
	ncache_drop(&lcache->nc);
}

static struct silofs_lnode_info *lni_from_ni(struct silofs_node_info *ni)
{
	struct silofs_lnode_info *lni = nullptr;

	if (ni != nullptr) {
		lni = silofs_lni_from_ni(ni);
	}
	return lni;
}

struct silofs_lnode_info *
silofs_lcache_lookup_lnode(struct silofs_lcache *lcache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_hkey hkey;
	struct silofs_node_info *ni;

	silofs_hkey_by_laddr(&hkey, laddr);
	ni = ncache_lookup_node_by(&lcache->nc, &hkey);
	return lni_from_ni(ni);
}

static void
del_lnode_as(struct silofs_node_info *ni, struct silofs_alloc *alloc)
{
	struct silofs_lnode_info *lni = silofs_lni_from_ni(ni);

	silofs_del_lnode(lni, alloc);
}

static struct silofs_lnode_info *
lcache_new_lnode(const struct silofs_lcache *lcache,
                 const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = silofs_new_lnode(lcache->nc.nc_alloc, laddr);
	if (lni != nullptr) {
		lni->ln_ni.delete_fn = del_lnode_as;
	}
	return lni;
}

struct silofs_lnode_info *
silofs_lcache_create_lnode(struct silofs_lcache *lcache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;

	lni = lcache_new_lnode(lcache, laddr);
	if (lni != nullptr) {
		ncache_insert_node(&lcache->nc, &lni->ln_ni);
	}
	return lni;
}

void silofs_lcache_forget_lnode(struct silofs_lcache *lcache,
                                struct silofs_lnode_info *lni)
{
	ncache_forget_node(&lcache->nc, &lni->ln_ni);
}

size_t silofs_lcache_usage(const struct silofs_lcache *lcache)
{
	return ncache_usage(&lcache->nc);
}
