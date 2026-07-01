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

static void lcache_evict_some(struct silofs_lcache *lcache);

static struct silofs_hmapq_elem *lni_to_hmqe(struct silofs_lnode_info *lni)
{
	return &lni->vn_ni.hmqe;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lcache_init_dq(struct silofs_lcache *lcache)
{
	silofs_dirtyq_init(&lcache->vc_dirtyq);
}

static void lcache_fini_dq(struct silofs_lcache *lcache)
{
	silofs_dirtyq_fini(&lcache->vc_dirtyq);
}

static struct silofs_dirtyq *
lcache_resolve_dq(struct silofs_lcache *lcache,
                  const struct silofs_lnode_info *lni)
{
	silofs_unused(lni);
	return &lcache->vc_dirtyq;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lcache_init_lni_hmapq(struct silofs_lcache *lcache)
{
	struct silofs_alloc *alloc = lcache->vc_alloc;
	const size_t nslots        = silofs_hmapq_nslots_by(alloc, 3);

	return silofs_hmapq_init(&lcache->vc_hmapq, alloc, nslots);
}

static void lcache_fini_lni_hmapq(struct silofs_lcache *lcache)
{
	silofs_hmapq_fini(&lcache->vc_hmapq, lcache->vc_alloc);
}

static bool test_evictable_lni(const struct silofs_lnode_info *lni)
{
	bool ret = true;

	if (lni->isevictable_fn != nullptr) {
		ret = lni->isevictable_fn(lni);
	}
	return ret;
}

static int visit_evictable_lni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_lnode_info *lni = silofs_lni_from_hmqe(hmqe);

	if (unlikely(lni == nullptr) || !test_evictable_lni(lni)) {
		return 0;
	}
	*(struct silofs_lnode_info **)arg = lni;
	return 1;
}

static struct silofs_lnode_info *
lcache_find_evictable_lni(struct silofs_lcache *lcache)
{
	struct silofs_hmapq *hmapq      = &lcache->vc_hmapq;
	struct silofs_lnode_info *lni   = nullptr;
	struct silofs_lnode_info **plni = &lni;

	silofs_hmapq_riterate(hmapq, 10, visit_evictable_lni, (void *)plni);
	return lni;
}

static struct silofs_lnode_info *
lcache_find_lni(struct silofs_lcache *lcache, const struct silofs_laddr *laddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_laddr(&hkey, laddr);
	hmqe = silofs_hmapq_lookup(&lcache->vc_hmapq, &hkey);
	return (hmqe != nullptr) ? silofs_lni_from_hmqe(hmqe) : nullptr;
}

static void lcache_promote_lni(struct silofs_lcache *lcache,
                               struct silofs_lnode_info *lni, bool now)
{
	silofs_hmapq_promote(&lcache->vc_hmapq, lni_to_hmqe(lni), now);
}

static struct silofs_lnode_info *
lcache_search_relru_lni(struct silofs_lcache *lcache,
                        const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = lcache_find_lni(lcache, laddr);
	if (lni != nullptr) {
		lcache_promote_lni(lcache, lni, false);
	}
	return lni;
}

static void
lcache_remove_lni(struct silofs_lcache *lcache, struct silofs_lnode_info *lni)
{
	silofs_lni_remove_from(lni, &lcache->vc_hmapq);
	lni->vn_ni.hmqe.hme_forgot = false;
}

static void
lcache_evict_lni(struct silofs_lcache *lcache, struct silofs_lnode_info *lni)
{
	lcache_remove_lni(lcache, lni);
	silofs_del_lnode(lni, lcache->vc_alloc);
}

static void lcache_store_lni_hmapq(struct silofs_lcache *lcache,
                                   struct silofs_lnode_info *lni)
{
	silofs_hmapq_store(&lcache->vc_hmapq, lni_to_hmqe(lni));
}

static void
lcache_store_lni(struct silofs_lcache *lcache, struct silofs_lnode_info *lni)
{
	silofs_hkey_by_laddr(&lni->vn_ni.hmqe.hme_key, &lni->vn_laddr);
	lcache_store_lni_hmapq(lcache, lni);
}

static struct silofs_lnode_info *
lcache_get_lru_lni(struct silofs_lcache *lcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&lcache->vc_hmapq);
	return (hmqe != nullptr) ? silofs_lni_from_hmqe(hmqe) : nullptr;
}

static bool lcache_evict_or_relru_lni(struct silofs_lcache *lcache,
                                      struct silofs_lnode_info *lni)
{
	bool evicted;

	if (test_evictable_lni(lni)) {
		lcache_evict_lni(lcache, lni);
		evicted = true;
	} else {
		lcache_promote_lni(lcache, lni, true);
		evicted = false;
	}
	return evicted;
}

static size_t lcache_shrink_or_relru_lnis(struct silofs_lcache *lcache,
                                          size_t cnt, int flags)
{
	struct silofs_lnode_info *lni = nullptr;
	const size_t n = silofs_min(cnt, lcache->vc_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_CTLF_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		lni = lcache_get_lru_lni(lcache);
		if (lni == nullptr) {
			break;
		}
		ok = lcache_evict_or_relru_lni(lcache, lni);
		if (ok) {
			evicted++;
		} else if (!now && (i || evicted)) {
			break;
		}
	}
	return evicted;
}

static int try_evict_lni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_lcache *lcache  = arg;
	struct silofs_lnode_info *lni = silofs_lni_from_hmqe(hmqe);

	lcache_evict_or_relru_lni(lcache, lni);
	return 0;
}

static void lcache_drop_evictable_lnis(struct silofs_lcache *lcache)
{
	silofs_hmapq_riterate(&lcache->vc_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_lni, lcache);
}

struct silofs_lnode_info *
silofs_lcache_dq_front(const struct silofs_lcache *lcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&lcache->vc_dirtyq);
	return silofs_lni_from_dqe(dqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *
lcache_new_lni(const struct silofs_lcache *lcache,
               const struct silofs_laddr *laddr)
{
	return silofs_new_lnode(lcache->vc_alloc, laddr);
}

struct silofs_lnode_info *
silofs_lcache_lookup_lnode(struct silofs_lcache *lcache,
                           const struct silofs_laddr *laddr)
{
	return lcache_search_relru_lni(lcache, laddr);
}

static struct silofs_lnode_info *
lcache_require_lni(struct silofs_lcache *lcache,
                   const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;

	for (int i = 0; i < 4; ++i) {
		lni = lcache_new_lni(lcache, laddr);
		if (lni != nullptr) {
			break;
		}
		lcache_evict_some(lcache);
	}
	return lni;
}

static void
lcache_unmap_lni(struct silofs_lcache *lcache, struct silofs_lnode_info *lni)
{
	silofs_hmapq_unmap(&lcache->vc_hmapq, lni_to_hmqe(lni));
}

void silofs_lcache_forget_lnode(struct silofs_lcache *lcache,
                                struct silofs_lnode_info *lni)
{
	silofs_lni_cleardirty(lni);
	if (silofs_lni_refcnt(lni) > 0) {
		lcache_unmap_lni(lcache, lni);
		lni->vn_ni.hmqe.hme_forgot = true;
	} else {
		lcache_evict_lni(lcache, lni);
	}
}

static void lcache_set_dq_of_lni(struct silofs_lcache *lcache,
                                 struct silofs_lnode_info *lni)
{
	struct silofs_dirtyq *dq;

	dq = lcache_resolve_dq(lcache, lni);
	silofs_lni_set_dq(lni, dq);
}

struct silofs_lnode_info *
silofs_lcache_create_lnode(struct silofs_lcache *lcache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = lcache_require_lni(lcache, laddr);
	if (likely(lni != nullptr)) {
		lcache_set_dq_of_lni(lcache, lni);
		lcache_store_lni(lcache, lni);
	}
	return lni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
lcache_shrink_some_lnis(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_or_relru_lnis(lcache, count, flags);
}

static size_t
lcache_shrink_some(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_some_lnis(lcache, count, flags);
}

static void lcache_evict_some(struct silofs_lcache *lcache)
{
	struct silofs_lnode_info *lni = nullptr;

	lni = lcache_find_evictable_lni(lcache);
	if ((lni != nullptr) && test_evictable_lni(lni)) {
		lcache_evict_lni(lcache, lni);
	} else {
		lcache_shrink_some(lcache, 1, 0);
	}
}

/* returns memory-pressure as ratio of total available memory, normalized to
 * a value within the range [0,1000] */
static size_t lcache_memory_pressure(const struct silofs_lcache *lcache)
{
	struct silofs_alloc_stat st;
	size_t mem_press = 0;

	silofs_memstat(lcache->vc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_press = ((1000UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_press;
}

static size_t lcache_calc_niter(const struct silofs_lcache *lcache, int flags)
{
	const size_t mempress            = lcache_memory_pressure(lcache);
	const size_t mempress_percentage = mempress / 10;
	size_t niter                     = 0;

	if (mempress_percentage > 60) {
		niter += 10;
	} else if (mempress_percentage > 20) {
		if (flags & SILOFS_CTLF_INTERN) {
			niter += 5;
		}
		if (flags & SILOFS_CTLF_OPSTART) {
			niter += 1;
		}
	}
	if (flags & SILOFS_CTLF_NOW) {
		niter += 2 + silofs_min(mempress_percentage, 5);
	}
	if (!niter && (flags & SILOFS_CTLF_IDLE)) {
		niter += 2 + silofs_min(mempress_percentage, 3);
	}
	return niter;
}

static size_t
lcache_relax_by_niter(struct silofs_lcache *lcache, size_t niter, int flags)
{
	size_t total = 0;
	size_t nvis;

	for (size_t i = 0; i < niter; ++i) {
		nvis = lcache_shrink_some_lnis(lcache, i + 1, flags);
		if (!nvis) {
			break;
		}
		total += nvis;
	}
	return total;
}

static size_t lcache_overpop_lnis(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_overpop(&lcache->vc_hmapq);
}

static size_t lcache_relax_by_overpop(struct silofs_lcache *lcache)
{
	size_t opop;
	size_t total = 0;

	opop = lcache_overpop_lnis(lcache);
	if (opop > 0) {
		const size_t want = silofs_min(opop, 8);
		const int flags   = SILOFS_CTLF_NOW;
		total += lcache_shrink_some_lnis(lcache, want, flags);
	}
	return total;
}

size_t silofs_lcache_relax(struct silofs_lcache *lcache, int flags)
{
	size_t niter;
	size_t drop1;
	size_t drop2;

	niter = lcache_calc_niter(lcache, flags);
	drop1 = lcache_relax_by_niter(lcache, niter, flags);
	drop2 = lcache_relax_by_overpop(lcache);
	return drop1 + drop2;
}

static size_t lcache_hmapq_usage_sum(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_usage(&lcache->vc_hmapq);
}

static void lcache_drop_evictables_once(struct silofs_lcache *lcache)
{
	lcache_drop_evictable_lnis(lcache);
}

static void lcache_drop_evictables(struct silofs_lcache *lcache)
{
	size_t usage_now;
	size_t usage_pre  = 0;
	size_t iter_count = 0;

	usage_now = lcache_hmapq_usage_sum(lcache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
		lcache_drop_evictables_once(lcache);
		usage_now = lcache_hmapq_usage_sum(lcache);
	}
}

void silofs_lcache_drop(struct silofs_lcache *lcache)
{
	lcache_drop_evictables(lcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lcache_fini_hmapqs(struct silofs_lcache *lcache)
{
	lcache_fini_lni_hmapq(lcache);
}

static int lcache_init_hmapqs(struct silofs_lcache *lcache)
{
	return lcache_init_lni_hmapq(lcache);
}

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc *alloc)
{
	lcache->vc_alloc = alloc;
	lcache_init_dq(lcache);

	return lcache_init_hmapqs(lcache);
}

void silofs_lcache_fini(struct silofs_lcache *lcache)
{
	lcache_fini_dq(lcache);
	lcache_fini_hmapqs(lcache);
	lcache->vc_alloc = nullptr;
}

static size_t lcache_alloc_bytes(const struct silofs_lcache *lcache)
{
	struct silofs_alloc_stat as = { .nbytes_use = 0 };

	silofs_memstat(lcache->vc_alloc, &as);
	return as.nbytes_use;
}

static size_t lcache_sum_nodes(const struct silofs_lcache *lcache)
{
	return lcache->vc_hmapq.hmq_htbl_size;
}

void silofs_lcache_collect_stats(const struct silofs_lcache *lcache,
                                 struct silofs_cache_stats *out_cstats)
{
	out_cstats->nalloc_bytes = lcache_alloc_bytes(lcache);
	out_cstats->ncache_nodes = lcache_sum_nodes(lcache);
}
