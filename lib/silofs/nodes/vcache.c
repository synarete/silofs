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

static struct silofs_hmapq_elem *vni_to_hmqe(struct silofs_vnode_info *vni)
{
	return &vni->vn_ni.hmqe;
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
                  const struct silofs_vnode_info *vni)
{
	silofs_unused(vni);
	return &vcache->vc_dirtyq;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vcache_init_vni_hmapq(struct silofs_vcache *vcache)
{
	struct silofs_alloc *alloc = vcache->vc_alloc;
	const size_t nslots        = silofs_hmapq_nslots_by(alloc, 3);

	return silofs_hmapq_init(&vcache->vc_hmapq, alloc, nslots);
}

static void vcache_fini_vni_hmapq(struct silofs_vcache *vcache)
{
	silofs_hmapq_fini(&vcache->vc_hmapq, vcache->vc_alloc);
}

static bool test_evictable_vni(const struct silofs_vnode_info *vni)
{
	bool ret = true;

	if (vni->isevictable_fn != nullptr) {
		ret = vni->isevictable_fn(vni);
	}
	return ret;
}

static int visit_evictable_vni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_vnode_info *vni = silofs_vni_from_hmqe(hmqe);

	if (unlikely(vni == nullptr) || !test_evictable_vni(vni)) {
		return 0;
	}
	*(struct silofs_vnode_info **)arg = vni;
	return 1;
}

static struct silofs_vnode_info *
vcache_find_evictable_vni(struct silofs_vcache *vcache)
{
	struct silofs_hmapq *hmapq      = &vcache->vc_hmapq;
	struct silofs_vnode_info *vni   = nullptr;
	struct silofs_vnode_info **pvni = &vni;

	silofs_hmapq_riterate(hmapq, 10, visit_evictable_vni, (void *)pvni);
	return vni;
}

static struct silofs_vnode_info *
vcache_find_vni(struct silofs_vcache *vcache, const struct silofs_vaddr *vaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_vaddr(&hkey, vaddr);
	hmqe = silofs_hmapq_lookup(&vcache->vc_hmapq, &hkey);
	return (hmqe != nullptr) ? silofs_vni_from_hmqe(hmqe) : nullptr;
}

static void vcache_promote_vni(struct silofs_vcache *vcache,
                               struct silofs_vnode_info *vni, bool now)
{
	silofs_hmapq_promote(&vcache->vc_hmapq, vni_to_hmqe(vni), now);
}

static struct silofs_vnode_info *
vcache_search_relru_vni(struct silofs_vcache *vcache,
                        const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;

	vni = vcache_find_vni(vcache, vaddr);
	if (vni != nullptr) {
		vcache_promote_vni(vcache, vni, false);
	}
	return vni;
}

static void
vcache_remove_vni(struct silofs_vcache *vcache, struct silofs_vnode_info *vni)
{
	silofs_vni_remove_from(vni, &vcache->vc_hmapq);
	vni->vn_ni.hmqe.hme_forgot = false;
}

static void
vcache_evict_vni(struct silofs_vcache *vcache, struct silofs_vnode_info *vni)
{
	vcache_remove_vni(vcache, vni);
	silofs_del_vnode(vni, vcache->vc_alloc);
}

static void vcache_store_vni_hmapq(struct silofs_vcache *vcache,
                                   struct silofs_vnode_info *vni)
{
	silofs_hmapq_store(&vcache->vc_hmapq, vni_to_hmqe(vni));
}

static void
vcache_store_vni(struct silofs_vcache *vcache, struct silofs_vnode_info *vni)
{
	silofs_hkey_by_vaddr(&vni->vn_ni.hmqe.hme_key, &vni->vn_vaddr);
	vcache_store_vni_hmapq(vcache, vni);
}

static struct silofs_vnode_info *
vcache_get_lru_vni(struct silofs_vcache *vcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&vcache->vc_hmapq);
	return (hmqe != nullptr) ? silofs_vni_from_hmqe(hmqe) : nullptr;
}

static bool vcache_evict_or_relru_vni(struct silofs_vcache *vcache,
                                      struct silofs_vnode_info *vni)
{
	bool evicted;

	if (test_evictable_vni(vni)) {
		vcache_evict_vni(vcache, vni);
		evicted = true;
	} else {
		vcache_promote_vni(vcache, vni, true);
		evicted = false;
	}
	return evicted;
}

static size_t vcache_shrink_or_relru_vnis(struct silofs_vcache *vcache,
                                          size_t cnt, int flags)
{
	struct silofs_vnode_info *vni = nullptr;
	const size_t n = silofs_min(cnt, vcache->vc_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_CTLF_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		vni = vcache_get_lru_vni(vcache);
		if (vni == nullptr) {
			break;
		}
		ok = vcache_evict_or_relru_vni(vcache, vni);
		if (ok) {
			evicted++;
		} else if (!now && (i || evicted)) {
			break;
		}
	}
	return evicted;
}

static int try_evict_vni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_vcache *vcache  = arg;
	struct silofs_vnode_info *vni = silofs_vni_from_hmqe(hmqe);

	vcache_evict_or_relru_vni(vcache, vni);
	return 0;
}

static void vcache_drop_evictable_vnis(struct silofs_vcache *vcache)
{
	silofs_hmapq_riterate(&vcache->vc_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_vni, vcache);
}

struct silofs_vnode_info *
silofs_vcache_dq_front(const struct silofs_vcache *vcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&vcache->vc_dirtyq);
	return silofs_vni_from_dqe(dqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
vcache_new_vni(const struct silofs_vcache *vcache,
               const struct silofs_vaddr *vaddr)
{
	return silofs_new_vnode(vcache->vc_alloc, vaddr);
}

struct silofs_vnode_info *
silofs_vcache_lookup_vnode(struct silofs_vcache *vcache,
                           const struct silofs_vaddr *vaddr)
{
	return vcache_search_relru_vni(vcache, vaddr);
}

static struct silofs_vnode_info *
vcache_require_vni(struct silofs_vcache *vcache,
                   const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = nullptr;

	for (int i = 0; i < 4; ++i) {
		vni = vcache_new_vni(vcache, vaddr);
		if (vni != nullptr) {
			break;
		}
		vcache_evict_some(vcache);
	}
	return vni;
}

static void
vcache_unmap_vni(struct silofs_vcache *vcache, struct silofs_vnode_info *vni)
{
	silofs_hmapq_unmap(&vcache->vc_hmapq, vni_to_hmqe(vni));
}

void silofs_vcache_forget_vnode(struct silofs_vcache *vcache,
                                struct silofs_vnode_info *vni)
{
	silofs_vni_cleardirty(vni);
	if (silofs_vni_refcnt(vni) > 0) {
		vcache_unmap_vni(vcache, vni);
		vni->vn_ni.hmqe.hme_forgot = true;
	} else {
		vcache_evict_vni(vcache, vni);
	}
}

static void vcache_set_dq_of_vni(struct silofs_vcache *vcache,
                                 struct silofs_vnode_info *vni)
{
	struct silofs_dirtyq *dq;

	dq = vcache_resolve_dq(vcache, vni);
	silofs_vni_set_dq(vni, dq);
}

struct silofs_vnode_info *
silofs_vcache_create_vnode(struct silofs_vcache *vcache,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;

	vni = vcache_require_vni(vcache, vaddr);
	if (likely(vni != nullptr)) {
		vcache_set_dq_of_vni(vcache, vni);
		vcache_store_vni(vcache, vni);
	}
	return vni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
vcache_shrink_some_vnis(struct silofs_vcache *vcache, size_t count, int flags)
{
	return vcache_shrink_or_relru_vnis(vcache, count, flags);
}

static size_t
vcache_shrink_some(struct silofs_vcache *vcache, size_t count, int flags)
{
	return vcache_shrink_some_vnis(vcache, count, flags);
}

static void vcache_evict_some(struct silofs_vcache *vcache)
{
	struct silofs_vnode_info *vni = nullptr;

	vni = vcache_find_evictable_vni(vcache);
	if ((vni != nullptr) && test_evictable_vni(vni)) {
		vcache_evict_vni(vcache, vni);
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
		nvis = vcache_shrink_some_vnis(vcache, i + 1, flags);
		if (!nvis) {
			break;
		}
		total += nvis;
	}
	return total;
}

static size_t vcache_overpop_vnis(const struct silofs_vcache *vcache)
{
	return silofs_hmapq_overpop(&vcache->vc_hmapq);
}

static size_t vcache_relax_by_overpop(struct silofs_vcache *vcache)
{
	size_t opop;
	size_t total = 0;

	opop = vcache_overpop_vnis(vcache);
	if (opop > 0) {
		const size_t want = silofs_min(opop, 8);
		const int flags   = SILOFS_CTLF_NOW;
		total += vcache_shrink_some_vnis(vcache, want, flags);
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
	vcache_drop_evictable_vnis(vcache);
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
	vcache_fini_vni_hmapq(vcache);
}

static int vcache_init_hmapqs(struct silofs_vcache *vcache)
{
	return vcache_init_vni_hmapq(vcache);
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
