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

static void vcache_evict_some(struct silofs_vcache *vcache);

static struct silofs_hmapq_elem *lni_to_hmqe(struct silofs_lnode_info *lni)
{
	return &lni->vn_ni.hmqe;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vcache_init_dq(struct silofs_vcache *vcache)
{
	silofs_dirtyq_init(&vcache->vc_dirtyq);
}

static void vcache_fini_dq(struct silofs_vcache *vcache)
{
	silofs_dirtyq_fini(&vcache->vc_dirtyq);
}

static struct silofs_dirtyq *
vcache_resolve_dq(struct silofs_vcache *vcache,
                  const struct silofs_lnode_info *lni)
{
	silofs_unused(lni);
	return &vcache->vc_dirtyq;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vcache_init_lni_hmapq(struct silofs_vcache *vcache)
{
	struct silofs_alloc *alloc = vcache->vc_alloc;
	const size_t nslots        = silofs_hmapq_nslots_by(alloc, 3);

	return silofs_hmapq_init(&vcache->vc_hmapq, alloc, nslots);
}

static void vcache_fini_lni_hmapq(struct silofs_vcache *vcache)
{
	silofs_hmapq_fini(&vcache->vc_hmapq, vcache->vc_alloc);
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
vcache_find_evictable_lni(struct silofs_vcache *vcache)
{
	struct silofs_hmapq *hmapq      = &vcache->vc_hmapq;
	struct silofs_lnode_info *lni   = nullptr;
	struct silofs_lnode_info **plni = &lni;

	silofs_hmapq_riterate(hmapq, 10, visit_evictable_lni, (void *)plni);
	return lni;
}

static struct silofs_lnode_info *
vcache_find_lni(struct silofs_vcache *vcache, const struct silofs_laddr *laddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_laddr(&hkey, laddr);
	hmqe = silofs_hmapq_lookup(&vcache->vc_hmapq, &hkey);
	return (hmqe != nullptr) ? silofs_lni_from_hmqe(hmqe) : nullptr;
}

static void vcache_promote_lni(struct silofs_vcache *vcache,
                               struct silofs_lnode_info *lni, bool now)
{
	silofs_hmapq_promote(&vcache->vc_hmapq, lni_to_hmqe(lni), now);
}

static struct silofs_lnode_info *
vcache_search_relru_lni(struct silofs_vcache *vcache,
                        const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = vcache_find_lni(vcache, laddr);
	if (lni != nullptr) {
		vcache_promote_lni(vcache, lni, false);
	}
	return lni;
}

static void
vcache_remove_lni(struct silofs_vcache *vcache, struct silofs_lnode_info *lni)
{
	silofs_lni_remove_from(lni, &vcache->vc_hmapq);
	lni->vn_ni.hmqe.hme_forgot = false;
}

static void
vcache_evict_lni(struct silofs_vcache *vcache, struct silofs_lnode_info *lni)
{
	vcache_remove_lni(vcache, lni);
	silofs_del_lnode(lni, vcache->vc_alloc);
}

static void vcache_store_lni_hmapq(struct silofs_vcache *vcache,
                                   struct silofs_lnode_info *lni)
{
	silofs_hmapq_store(&vcache->vc_hmapq, lni_to_hmqe(lni));
}

static void
vcache_store_lni(struct silofs_vcache *vcache, struct silofs_lnode_info *lni)
{
	silofs_hkey_by_laddr(&lni->vn_ni.hmqe.hme_key, &lni->vn_laddr);
	vcache_store_lni_hmapq(vcache, lni);
}

static struct silofs_lnode_info *
vcache_get_lru_lni(struct silofs_vcache *vcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&vcache->vc_hmapq);
	return (hmqe != nullptr) ? silofs_lni_from_hmqe(hmqe) : nullptr;
}

static bool vcache_evict_or_relru_lni(struct silofs_vcache *vcache,
                                      struct silofs_lnode_info *lni)
{
	bool evicted;

	if (test_evictable_lni(lni)) {
		vcache_evict_lni(vcache, lni);
		evicted = true;
	} else {
		vcache_promote_lni(vcache, lni, true);
		evicted = false;
	}
	return evicted;
}

static size_t vcache_shrink_or_relru_lnis(struct silofs_vcache *vcache,
                                          size_t cnt, int flags)
{
	struct silofs_lnode_info *lni = nullptr;
	const size_t n = silofs_min(cnt, vcache->vc_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_CTLF_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		lni = vcache_get_lru_lni(vcache);
		if (lni == nullptr) {
			break;
		}
		ok = vcache_evict_or_relru_lni(vcache, lni);
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
	struct silofs_vcache *vcache  = arg;
	struct silofs_lnode_info *lni = silofs_lni_from_hmqe(hmqe);

	vcache_evict_or_relru_lni(vcache, lni);
	return 0;
}

static void vcache_drop_evictable_lnis(struct silofs_vcache *vcache)
{
	silofs_hmapq_riterate(&vcache->vc_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_lni, vcache);
}

struct silofs_lnode_info *
silofs_vcache_dq_front(const struct silofs_vcache *vcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&vcache->vc_dirtyq);
	return silofs_lni_from_dqe(dqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *
vcache_new_lni(const struct silofs_vcache *vcache,
               const struct silofs_laddr *laddr)
{
	return silofs_new_lnode(vcache->vc_alloc, laddr);
}

struct silofs_lnode_info *
silofs_vcache_lookup_lnode(struct silofs_vcache *vcache,
                           const struct silofs_laddr *laddr)
{
	return vcache_search_relru_lni(vcache, laddr);
}

static struct silofs_lnode_info *
vcache_require_lni(struct silofs_vcache *vcache,
                   const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;

	for (int i = 0; i < 4; ++i) {
		lni = vcache_new_lni(vcache, laddr);
		if (lni != nullptr) {
			break;
		}
		vcache_evict_some(vcache);
	}
	return lni;
}

static void
vcache_unmap_lni(struct silofs_vcache *vcache, struct silofs_lnode_info *lni)
{
	silofs_hmapq_unmap(&vcache->vc_hmapq, lni_to_hmqe(lni));
}

void silofs_vcache_forget_lnode(struct silofs_vcache *vcache,
                                struct silofs_lnode_info *lni)
{
	silofs_lni_cleardirty(lni);
	if (silofs_lni_refcnt(lni) > 0) {
		vcache_unmap_lni(vcache, lni);
		lni->vn_ni.hmqe.hme_forgot = true;
	} else {
		vcache_evict_lni(vcache, lni);
	}
}

static void vcache_set_dq_of_lni(struct silofs_vcache *vcache,
                                 struct silofs_lnode_info *lni)
{
	struct silofs_dirtyq *dq;

	dq = vcache_resolve_dq(vcache, lni);
	silofs_lni_set_dq(lni, dq);
}

struct silofs_lnode_info *
silofs_vcache_create_lnode(struct silofs_vcache *vcache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = vcache_require_lni(vcache, laddr);
	if (likely(lni != nullptr)) {
		vcache_set_dq_of_lni(vcache, lni);
		vcache_store_lni(vcache, lni);
	}
	return lni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
vcache_shrink_some_lnis(struct silofs_vcache *vcache, size_t count, int flags)
{
	return vcache_shrink_or_relru_lnis(vcache, count, flags);
}

static size_t
vcache_shrink_some(struct silofs_vcache *vcache, size_t count, int flags)
{
	return vcache_shrink_some_lnis(vcache, count, flags);
}

static void vcache_evict_some(struct silofs_vcache *vcache)
{
	struct silofs_lnode_info *lni = nullptr;

	lni = vcache_find_evictable_lni(vcache);
	if ((lni != nullptr) && test_evictable_lni(lni)) {
		vcache_evict_lni(vcache, lni);
	} else {
		vcache_shrink_some(vcache, 1, 0);
	}
}

/* returns memory-pressure as ratio of total available memory, normalized to
 * a value within the range [0,1000] */
static size_t vcache_memory_pressure(const struct silofs_vcache *vcache)
{
	struct silofs_alloc_stat st;
	size_t mem_press = 0;

	silofs_memstat(vcache->vc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_press = ((1000UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_press;
}

static size_t vcache_calc_niter(const struct silofs_vcache *vcache, int flags)
{
	const size_t mempress            = vcache_memory_pressure(vcache);
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
vcache_relax_by_niter(struct silofs_vcache *vcache, size_t niter, int flags)
{
	size_t total = 0;
	size_t nvis;

	for (size_t i = 0; i < niter; ++i) {
		nvis = vcache_shrink_some_lnis(vcache, i + 1, flags);
		if (!nvis) {
			break;
		}
		total += nvis;
	}
	return total;
}

static size_t vcache_overpop_lnis(const struct silofs_vcache *vcache)
{
	return silofs_hmapq_overpop(&vcache->vc_hmapq);
}

static size_t vcache_relax_by_overpop(struct silofs_vcache *vcache)
{
	size_t opop;
	size_t total = 0;

	opop = vcache_overpop_lnis(vcache);
	if (opop > 0) {
		const size_t want = silofs_min(opop, 8);
		const int flags   = SILOFS_CTLF_NOW;
		total += vcache_shrink_some_lnis(vcache, want, flags);
	}
	return total;
}

size_t silofs_vcache_relax(struct silofs_vcache *vcache, int flags)
{
	size_t niter;
	size_t drop1;
	size_t drop2;

	niter = vcache_calc_niter(vcache, flags);
	drop1 = vcache_relax_by_niter(vcache, niter, flags);
	drop2 = vcache_relax_by_overpop(vcache);
	return drop1 + drop2;
}

static size_t vcache_hmapq_usage_sum(const struct silofs_vcache *vcache)
{
	return silofs_hmapq_usage(&vcache->vc_hmapq);
}

static void vcache_drop_evictables_once(struct silofs_vcache *vcache)
{
	vcache_drop_evictable_lnis(vcache);
}

static void vcache_drop_evictables(struct silofs_vcache *vcache)
{
	size_t usage_now;
	size_t usage_pre  = 0;
	size_t iter_count = 0;

	usage_now = vcache_hmapq_usage_sum(vcache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
		vcache_drop_evictables_once(vcache);
		usage_now = vcache_hmapq_usage_sum(vcache);
	}
}

void silofs_vcache_drop(struct silofs_vcache *vcache)
{
	vcache_drop_evictables(vcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vcache_fini_hmapqs(struct silofs_vcache *vcache)
{
	vcache_fini_lni_hmapq(vcache);
}

static int vcache_init_hmapqs(struct silofs_vcache *vcache)
{
	return vcache_init_lni_hmapq(vcache);
}

int silofs_vcache_init(struct silofs_vcache *vcache,
                       struct silofs_alloc *alloc)
{
	vcache->vc_alloc = alloc;
	vcache_init_dq(vcache);

	return vcache_init_hmapqs(vcache);
}

void silofs_vcache_fini(struct silofs_vcache *vcache)
{
	vcache_fini_dq(vcache);
	vcache_fini_hmapqs(vcache);
	vcache->vc_alloc = nullptr;
}

static size_t vcache_alloc_bytes(const struct silofs_vcache *vcache)
{
	struct silofs_alloc_stat as = { .nbytes_use = 0 };

	silofs_memstat(vcache->vc_alloc, &as);
	return as.nbytes_use;
}

static size_t vcache_sum_nodes(const struct silofs_vcache *vcache)
{
	return vcache->vc_hmapq.hmq_htbl_size;
}

void silofs_vcache_collect_stats(const struct silofs_vcache *vcache,
                                 struct silofs_cache_stats *out_cstats)
{
	out_cstats->nalloc_bytes = vcache_alloc_bytes(vcache);
	out_cstats->ncache_nodes = vcache_sum_nodes(vcache);
}
