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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pnode_info *
pni_unconst(const struct silofs_pnode_info *pni)
{
	return silofs_unconst(pni);
}

static struct silofs_pnode_info *pni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_pnode_info *pni = nullptr;

	if (ni != nullptr) {
		pni = container_of(ni, struct silofs_pnode_info, pn_ni);
	}
	return pni_unconst(pni);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *
lni_unconst(const struct silofs_lnode_info *lni)
{
	return silofs_unconst(lni);
}

static struct silofs_lnode_info *lni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_lnode_info *lni = nullptr;

	if (ni != nullptr) {
		lni = container_of(ni, struct silofs_lnode_info, ln_ni);
	}
	return lni_unconst(lni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int ncache_init_hmapq(struct silofs_ncache *ncache)
{
	const size_t nslots = 1024; /* TODO: revisit */

	return silofs_hmapq_init(&ncache->nc_hmapq, ncache->nc_alloc, nslots);
}

static void ncache_fini_hmapq(struct silofs_ncache *ncache)
{
	silofs_hmapq_fini(&ncache->nc_hmapq, ncache->nc_alloc);
}

int silofs_ncache_init(struct silofs_ncache *ncache,
                       struct silofs_alloc *alloc)
{
	silofs_memzero(ncache, sizeof(*ncache));
	ncache->nc_alloc = alloc;
	silofs_dirtyq_init(&ncache->nc_dirtyq);
	return ncache_init_hmapq(ncache);
}

void silofs_ncache_fini(struct silofs_ncache *ncache)
{
	ncache_fini_hmapq(ncache);
	silofs_dirtyq_fini(&ncache->nc_dirtyq);
	ncache->nc_alloc = nullptr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_node_info *
ncache_search_by(const struct silofs_ncache *ncache,
                 const struct silofs_hkey *hkey)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_lookup(&ncache->nc_hmapq, hkey);
	return ni_from_hmqe(hmqe);
}

static void ncache_promote(struct silofs_ncache *ncache,
                           struct silofs_node_info *ni, bool now)
{
	silofs_hmapq_promote(&ncache->nc_hmapq, &ni->hmqe, now);
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
	silofs_hmapq_store(&ncache->nc_hmapq, &ni->hmqe);
}

static void
ncache_unmap_node(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_hmapq_remove(&ncache->nc_hmapq, &ni->hmqe);
}

static void
ncache_bind_dirtyq(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_ni_set_dq(ni, &ncache->nc_dirtyq);
}

static void
ncache_unbind_dirtyq(struct silofs_ncache *ncache, struct silofs_node_info *ni)
{
	silofs_ni_cleardirty(ni);
	silofs_ni_set_dq(ni, nullptr);
	unused(ncache);
}

void silofs_ncache_insert_node(struct silofs_ncache *ncache,
                               struct silofs_node_info *ni)
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
del_pnode_as(struct silofs_node_info *ni, struct silofs_alloc *alloc)
{
	struct silofs_pnode_info *pni = pni_from_ni(ni);

	silofs_del_pnode(pni, alloc);
}

static struct silofs_pnode_info *
ncache_new_pnode(const struct silofs_ncache *ncache,
                 const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni;

	pni = silofs_new_pnode(pnptr, ncache->nc_alloc);
	if (pni != nullptr) {
		pni->pn_ni.delete_fn = del_pnode_as;
	}
	return pni;
}

static void
del_lnode_as(struct silofs_node_info *ni, struct silofs_alloc *alloc)
{
	struct silofs_lnode_info *lni = silofs_lni_from_ni(ni);

	silofs_del_lnode(lni, alloc);
}

static struct silofs_lnode_info *
ncache_new_lnode(const struct silofs_ncache *ncache,
                 const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = silofs_new_lnode(ncache->nc_alloc, laddr);
	if (lni != nullptr) {
		lni->ln_ni.delete_fn = del_lnode_as;
	}
	return lni;
}

static void ncache_del_node(const struct silofs_ncache *ncache,
                            struct silofs_node_info *ni)
{
	void (*del_hook)(struct silofs_node_info *, struct silofs_alloc *);

	del_hook = ni->delete_fn;
	silofs_assert(del_hook != nullptr);
	del_hook(ni, ncache->nc_alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ncache_evict_node(struct silofs_ncache *ncache,
                              struct silofs_node_info *ni)
{
	ncache_remove_node(ncache, ni);
	ncache_del_node(ncache, ni);
}

static struct silofs_node_info *
ncache_get_lru(const struct silofs_ncache *ncache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&ncache->nc_hmapq);
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
	silofs_ncache_evict_node(ncache, ni);
	return true;
}

static size_t ncache_lru_size(const struct silofs_ncache *ncache)
{
	return ncache->nc_hmapq.hmq_lru.sz;
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
		silofs_ncache_evict_node(pcec->ncache, ni);
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

	silofs_hmapq_riterate(&ncache->nc_hmapq, ncache_lru_size(ncache),
	                      try_evict_node_cb, &pcec);
}

void silofs_ncache_forget_node(struct silofs_ncache *ncache,
                               struct silofs_node_info *ni)
{
	silofs_ni_cleardirty(ni);
	if (silofs_ni_refcnt(ni) > 0) {
		ncache_unmap_node(ncache, ni);
		ni->hmqe.hme_forgot = true;
	} else {
		silofs_ncache_evict_node(ncache, ni);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t ncache_usage(const struct silofs_ncache *ncache)
{
	return silofs_hmapq_usage(&ncache->nc_hmapq);
}

bool silofs_ncache_isempty(const struct silofs_ncache *ncache)
{
	return (ncache_usage(ncache) == 0);
}

void silofs_ncache_drop(struct silofs_ncache *ncache)
{
	ncache_evict_many(ncache, ncache_lru_size(ncache));
}

static size_t ncache_mempress(const struct silofs_ncache *ncache)
{
	return silofs_mempress(ncache->nc_alloc);
}

void silofs_ncache_relax(struct silofs_ncache *ncache, int flags)
{
	const size_t lrusize = ncache_lru_size(ncache);
	const size_t mempres = ncache_mempress(ncache);
	size_t count;

	if (mempres > 40) {
		count = lrusize / 5;
		ncache_evict_many(ncache, count);
	} else if (mempres > 20) {
		ncache_evict_some(ncache, lrusize / 10);
	} else if (flags & SILOFS_CTLF_IDLE) {
		ncache_evict_some(ncache, 1);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_node_info *
silofs_ncache_lookup_node_by(struct silofs_ncache *ncache,
                             const struct silofs_hkey *hkey)
{
	return ncache_search_and_relru(ncache, hkey);
}

struct silofs_pnode_info *
silofs_ncache_lookup_pnode(struct silofs_ncache *ncache,
                           const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_node_info *ni;

	silofs_hkey_by_paddr(&hkey, paddr);
	ni = ncache_search_and_relru(ncache, &hkey);
	return pni_from_ni(ni);
}

struct silofs_pnode_info *
silofs_ncache_create_pnode(struct silofs_ncache *ncache,
                           const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni = nullptr;

	pni = ncache_new_pnode(ncache, pnptr);
	if (pni != nullptr) {
		silofs_ncache_insert_node(ncache, &pni->pn_ni);
	}
	return pni;
}

void silofs_ncache_delete_pnode(struct silofs_ncache *ncache,
                                struct silofs_pnode_info *pni)
{
	silofs_ncache_evict_node(ncache, &pni->pn_ni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_lnode_info *
silofs_ncache_lookup_lnode(struct silofs_ncache *ncache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_hkey hkey;
	struct silofs_node_info *ni;

	silofs_hkey_by_laddr(&hkey, laddr);
	ni = ncache_search_and_relru(ncache, &hkey);
	return lni_from_ni(ni);
}

struct silofs_lnode_info *
silofs_ncache_create_lnode(struct silofs_ncache *ncache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;

	lni = ncache_new_lnode(ncache, laddr);
	if (lni != nullptr) {
		silofs_ncache_insert_node(ncache, &lni->ln_ni);
	}
	return lni;
}

void silofs_ncache_forget_lnode(struct silofs_ncache *ncache,
                                struct silofs_lnode_info *lni)
{
	silofs_ncache_forget_node(ncache, &lni->ln_ni);
}
