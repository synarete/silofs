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
#include <silofs/fs.h>
#include <silofs/exec.h>

static void lcache_drop_uamap(struct silofs_lcache *lcache);
static void lcache_evict_some(struct silofs_lcache *lcache);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dirtyqs_init(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_init(&dqs->dq_unis);
	silofs_dirtyq_init(&dqs->dq_iis);
	silofs_dirtyq_init(&dqs->dq_vnis);
}

static void dirtyqs_fini(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_fini(&dqs->dq_unis);
	silofs_dirtyq_fini(&dqs->dq_iis);
	silofs_dirtyq_fini(&dqs->dq_vnis);
}

static struct silofs_dirtyq *
dirtyqs_get(struct silofs_dirtyqs *dqs, enum silofs_vtype vtype)
{
	struct silofs_dirtyq *dq;

	if (silofs_vtype_isinode(vtype)) {
		dq = &dqs->dq_iis;
	} else if (silofs_vtype_isvnode(vtype)) {
		dq = &dqs->dq_vnis;
	} else {
		silofs_assert(silofs_vtype_isunode(vtype));
		dq = &dqs->dq_unis;
	}
	return dq;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *uni_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	struct silofs_unode_info *uni = nullptr;

	if (hmqe != nullptr) {
		uni = silofs_uni_from_lni(silofs_lni_from_hmqe(hmqe));
	}
	return uni;
}

static struct silofs_hmapq_elem *uni_to_hmqe(struct silofs_unode_info *uni)
{
	return silofs_lni_to_hmqe(&uni->un_lni);
}

static const struct silofs_uaddr *
uni_uaddr(const struct silofs_unode_info *uni)
{
	return silofs_uni_uaddr(uni);
}

static enum silofs_vtype uni_vtype(const struct silofs_unode_info *uni)
{
	return silofs_uni_vtype(uni);
}

static struct silofs_vnode_info *vni_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	return silofs_vni_from_lni(silofs_lni_from_hmqe(hmqe));
}

static struct silofs_hmapq_elem *vni_to_hmqe(struct silofs_vnode_info *vni)
{
	return &vni->vn_lni.ln_hmqe;
}

static enum silofs_vtype vni_vtype(const struct silofs_vnode_info *vni)
{
	return silofs_vni_vtype(vni);
}

static bool vni_isinode(const struct silofs_vnode_info *vni)
{
	return silofs_vtype_isinode(vni_vtype(vni));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_dirtyq *
lcache_dirtyq_by(struct silofs_lcache *lcache, enum silofs_vtype vtype)
{
	return dirtyqs_get(&lcache->lc_dirtyqs, vtype);
}

static int lcache_init_uni_hmapq(struct silofs_lcache *lcache)
{
	struct silofs_alloc *alloc = lcache->lc_alloc;
	const size_t nslots        = silofs_hmapq_nslots_by(alloc, 1);

	return silofs_hmapq_init(&lcache->lc_uni_hmapq, alloc, nslots);
}

static void lcache_fini_uni_hmapq(struct silofs_lcache *lcache)
{
	silofs_hmapq_fini(&lcache->lc_uni_hmapq, lcache->lc_alloc);
}

static int visit_evictable_uni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_unode_info *uni = uni_from_hmqe(hmqe);

	if (!silofs_uni_isevictable(uni)) {
		return 0;
	}
	*(struct silofs_unode_info **)arg = uni;
	return 1;
}

static struct silofs_unode_info *
lcache_find_evictable_uni(struct silofs_lcache *lcache)
{
	struct silofs_hmapq *hmapq      = &lcache->lc_uni_hmapq;
	struct silofs_unode_info *uni   = nullptr;
	struct silofs_unode_info **puni = &uni;

	silofs_hmapq_riterate(hmapq, 10, visit_evictable_uni, (void *)puni);
	return uni;
}

static struct silofs_unode_info *
lcache_find_uni(const struct silofs_lcache *lcache,
                const struct silofs_uaddr *uaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_uaddr(&hkey, uaddr);
	hmqe = silofs_hmapq_lookup(&lcache->lc_uni_hmapq, &hkey);
	return uni_from_hmqe(hmqe);
}

static void lcache_promote_uni(struct silofs_lcache *lcache,
                               struct silofs_unode_info *uni, bool now)
{
	silofs_hmapq_promote(&lcache->lc_uni_hmapq, uni_to_hmqe(uni), now);
}

static struct silofs_unode_info *
lcache_find_relru_uni(struct silofs_lcache *lcache,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni;

	uni = lcache_find_uni(lcache, uaddr);
	if (uni != nullptr) {
		lcache_promote_uni(lcache, uni, false);
	}
	return uni;
}

static void
lcache_remove_uni(struct silofs_lcache *lcache, struct silofs_unode_info *uni)
{
	silofs_lni_remove_from(&uni->un_lni, &lcache->lc_uni_hmapq);
}

static void
lcache_evict_uni(struct silofs_lcache *lcache, struct silofs_unode_info *uni,
                 enum silofs_allocf flags)
{
	silofs_uni_undirtify(uni);
	lcache_remove_uni(lcache, uni);
	silofs_del_unode(uni, lcache->lc_alloc, (int)flags);
}

static void lcache_store_uni_hmapq(struct silofs_lcache *lcache,
                                   struct silofs_unode_info *uni)
{
	silofs_hmapq_store(&lcache->lc_uni_hmapq, uni_to_hmqe(uni));
}

static struct silofs_unode_info *
lcache_get_lru_uni(struct silofs_lcache *lcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&lcache->lc_uni_hmapq);
	return (hmqe != nullptr) ? uni_from_hmqe(hmqe) : nullptr;
}

static enum silofs_allocf flags_to_allocf(int flags)
{
	return (flags & SILOFS_CTLF_IDLE) ? SILOFS_ALLOCF_TRYPUNCH :
	                                    SILOFS_ALLOCF_NONE;
}

static bool lcache_evict_or_relru_uni(struct silofs_lcache *lcache,
                                      struct silofs_unode_info *uni, int flags)
{
	bool evicted;

	if (silofs_uni_isevictable(uni)) {
		lcache_evict_uni(lcache, uni, flags_to_allocf(flags));
		evicted = true;
	} else {
		lcache_promote_uni(lcache, uni, true);
		evicted = false;
	}
	return evicted;
}

static size_t lcache_shrink_or_relru_unis(struct silofs_lcache *lcache,
                                          size_t cnt, int flags)
{
	struct silofs_unode_info *uni;
	const size_t n = silofs_min(cnt, lcache->lc_uni_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_CTLF_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		uni = lcache_get_lru_uni(lcache);
		if (uni == nullptr) {
			break;
		}
		ok = lcache_evict_or_relru_uni(lcache, uni, flags);
		if (ok) {
			evicted++;
		} else if (!now) {
			break;
		}
	}
	return evicted;
}

static int try_evict_uni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_lcache *lcache = arg;

	lcache_evict_or_relru_uni(lcache, uni_from_hmqe(hmqe), 0);
	return 0;
}

static void lcache_drop_evictable_unis(struct silofs_lcache *lcache)
{
	silofs_hmapq_riterate(&lcache->lc_uni_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_uni, lcache);
}

static struct silofs_unode_info *
lcache_new_uni(const struct silofs_lcache *lcache,
               const struct silofs_uaddr *uaddr)
{
	return silofs_new_unode(lcache->lc_alloc, uaddr);
}

static void lcache_track_uaddr(struct silofs_lcache *lcache,
                               const struct silofs_uaddr *uaddr)
{
	silofs_uamap_insert(&lcache->lc_uamap, uaddr);
}

static void lcache_forget_uaddr(struct silofs_lcache *lcache,
                                const struct silofs_uaddr *uaddr)
{
	struct silofs_uakey uakey;

	silofs_uakey_setup_by(&uakey, uaddr);
	silofs_uamap_remove(&lcache->lc_uamap, &uakey);
}

static const struct silofs_uaddr *
lcache_lookup_uaddr_by(struct silofs_lcache *lcache,
                       const struct silofs_uakey *uakey)
{
	return silofs_uamap_lookup(&lcache->lc_uamap, uakey);
}

static void lcache_track_uaddr_of(struct silofs_lcache *lcache,
                                  const struct silofs_unode_info *uni)
{
	struct silofs_uakey uakey;
	const struct silofs_uaddr *uaddr = uni_uaddr(uni);

	silofs_uakey_setup_by(&uakey, uaddr);
	if (!lcache_lookup_uaddr_by(lcache, &uakey)) {
		lcache_track_uaddr(lcache, uaddr);
	}
}

static struct silofs_unode_info *
lcache_lookup_uni(struct silofs_lcache *lcache,
                  const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni;

	uni = lcache_find_relru_uni(lcache, uaddr);
	if (uni != nullptr) {
		lcache_track_uaddr_of(lcache, uni);
	}
	return uni;
}

struct silofs_unode_info *
silofs_lcache_lookup_uni(struct silofs_lcache *lcache,
                         const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni;

	uni = lcache_lookup_uni(lcache, uaddr);
	return uni;
}

static struct silofs_unode_info *
lcache_require_uni(struct silofs_lcache *lcache,
                   const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni = nullptr;
	int retry                     = 4;

	while (retry-- > 0) {
		uni = lcache_new_uni(lcache, uaddr);
		if (uni != nullptr) {
			break;
		}
		lcache_evict_some(lcache);
	}
	return uni;
}

static void
lcache_store_uni(struct silofs_lcache *lcache, struct silofs_unode_info *uni)
{
	silofs_hkey_by_uaddr(&uni->un_lni.ln_hmqe.hme_key, uni_uaddr(uni));
	lcache_store_uni_hmapq(lcache, uni);
}

static void lcache_set_dq_of_uni(struct silofs_lcache *lcache,
                                 struct silofs_unode_info *uni)
{
	struct silofs_dirtyq *dq = lcache_dirtyq_by(lcache, uni_vtype(uni));

	silofs_uni_set_dq(uni, dq);
}

static struct silofs_unode_info *
lcache_create_uni(struct silofs_lcache *lcache,
                  const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni;

	uni = lcache_require_uni(lcache, uaddr);
	if (uni != nullptr) {
		lcache_set_dq_of_uni(lcache, uni);
		lcache_store_uni(lcache, uni);
		lcache_track_uaddr(lcache, silofs_uni_uaddr(uni));
	}
	return uni;
}

struct silofs_unode_info *
silofs_lcache_create_uni(struct silofs_lcache *lcache,
                         const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni;

	uni = lcache_create_uni(lcache, uaddr);
	return uni;
}

static void
lcache_forget_uni(struct silofs_lcache *lcache, struct silofs_unode_info *uni)
{
	lcache_forget_uaddr(lcache, uni_uaddr(uni));
	lcache_evict_uni(lcache, uni, SILOFS_ALLOCF_NONE);
}

void silofs_lcache_forget_uni(struct silofs_lcache *lcache,
                              struct silofs_unode_info *uni)
{
	lcache_forget_uni(lcache, uni);
}

static struct silofs_unode_info *
lcache_find_uni_by(struct silofs_lcache *lcache,
                   const struct silofs_uakey *uakey)
{
	const struct silofs_uaddr *uaddr;
	struct silofs_unode_info *uni = nullptr;

	uaddr = lcache_lookup_uaddr_by(lcache, uakey);
	if (uaddr != nullptr) {
		uni = lcache_lookup_uni(lcache, uaddr);
	}
	return uni;
}

struct silofs_unode_info *
silofs_lcache_find_uni_by(struct silofs_lcache *lcache,
                          const struct silofs_uakey *uakey)
{
	struct silofs_unode_info *uni;

	uni = lcache_find_uni_by(lcache, uakey);
	return uni;
}

void silofs_lcache_drop_uamap(struct silofs_lcache *lcache)
{
	lcache_drop_uamap(lcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lcache_init_vni_hmapq(struct silofs_lcache *lcache)
{
	struct silofs_alloc *alloc = lcache->lc_alloc;
	const size_t nslots        = silofs_hmapq_nslots_by(alloc, 3);

	return silofs_hmapq_init(&lcache->lc_vni_hmapq, alloc, nslots);
}

static void lcache_fini_vni_hmapq(struct silofs_lcache *lcache)
{
	silofs_hmapq_fini(&lcache->lc_vni_hmapq, lcache->lc_alloc);
}

static bool test_evictable_vni(const struct silofs_vnode_info *vni)
{
	const struct silofs_inode_info *ii = nullptr;
	bool ret                           = false;

	if (vni_isinode(vni)) {
		ii  = silofs_ii_from_vni(vni);
		ret = silofs_ii_isevictable(ii);
	} else {
		ret = silofs_vni_isevictable(vni);
	}
	return ret;
}

static int visit_evictable_vni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_vnode_info *vni = vni_from_hmqe(hmqe);

	if (!test_evictable_vni(vni)) {
		return 0;
	}
	*(struct silofs_vnode_info **)arg = vni;
	return 1;
}

static struct silofs_vnode_info *
lcache_find_evictable_vni(struct silofs_lcache *lcache)
{
	struct silofs_hmapq *hmapq      = &lcache->lc_vni_hmapq;
	struct silofs_vnode_info *vni   = nullptr;
	struct silofs_vnode_info **pvni = &vni;

	silofs_hmapq_riterate(hmapq, 10, visit_evictable_vni, (void *)pvni);
	return vni;
}

static struct silofs_vnode_info *
lcache_find_vni(struct silofs_lcache *lcache, const struct silofs_vaddr *vaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_vaddr(&hkey, vaddr);
	hmqe = silofs_hmapq_lookup(&lcache->lc_vni_hmapq, &hkey);
	return (hmqe != nullptr) ? vni_from_hmqe(hmqe) : nullptr;
}

static void lcache_promote_vni(struct silofs_lcache *lcache,
                               struct silofs_vnode_info *vni, bool now)
{
	silofs_hmapq_promote(&lcache->lc_vni_hmapq, vni_to_hmqe(vni), now);
}

static struct silofs_vnode_info *
lcache_find_relru_vni(struct silofs_lcache *lcache,
                      const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;

	vni = lcache_find_vni(lcache, vaddr);
	if (vni != nullptr) {
		lcache_promote_vni(lcache, vni, false);
	}
	return vni;
}

static void
lcache_remove_vni(struct silofs_lcache *lcache, struct silofs_vnode_info *vni)
{
	silofs_lni_remove_from(&vni->vn_lni, &lcache->lc_vni_hmapq);
	vni->vn_lni.ln_hmqe.hme_forgot = false;
}

static void
lcache_evict_vni(struct silofs_lcache *lcache, struct silofs_vnode_info *vni,
                 enum silofs_allocf flags)
{
	lcache_remove_vni(lcache, vni);
	silofs_del_vnode(vni, lcache->lc_alloc, (int)flags);
}

static void lcache_store_vni_hmapq(struct silofs_lcache *lcache,
                                   struct silofs_vnode_info *vni)
{
	silofs_hmapq_store(&lcache->lc_vni_hmapq, vni_to_hmqe(vni));
}

static void
lcache_store_vni(struct silofs_lcache *lcache, struct silofs_vnode_info *vni)
{
	silofs_hkey_by_vaddr(&vni->vn_lni.ln_hmqe.hme_key, &vni->vn_vaddr);
	lcache_store_vni_hmapq(lcache, vni);
}

static struct silofs_vnode_info *
lcache_get_lru_vni(struct silofs_lcache *lcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&lcache->lc_vni_hmapq);
	return (hmqe != nullptr) ? vni_from_hmqe(hmqe) : nullptr;
}

static bool lcache_evict_or_relru_vni(struct silofs_lcache *lcache,
                                      struct silofs_vnode_info *vni, int flags)
{
	bool evicted;

	if (test_evictable_vni(vni)) {
		lcache_evict_vni(lcache, vni, flags_to_allocf(flags));
		evicted = true;
	} else {
		lcache_promote_vni(lcache, vni, true);
		evicted = false;
	}
	return evicted;
}

static size_t lcache_shrink_or_relru_vnis(struct silofs_lcache *lcache,
                                          size_t cnt, int flags)
{
	struct silofs_vnode_info *vni = nullptr;
	const size_t n = silofs_min(cnt, lcache->lc_vni_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_CTLF_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		vni = lcache_get_lru_vni(lcache);
		if (vni == nullptr) {
			break;
		}
		ok = lcache_evict_or_relru_vni(lcache, vni, flags);
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
	struct silofs_lcache *lcache  = arg;
	struct silofs_vnode_info *vni = vni_from_hmqe(hmqe);

	lcache_evict_or_relru_vni(lcache, vni, 0);
	return 0;
}

static void lcache_drop_evictable_vnis(struct silofs_lcache *lcache)
{
	silofs_hmapq_riterate(&lcache->lc_vni_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_vni, lcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
lcache_new_vni(const struct silofs_lcache *lcache,
               const struct silofs_vaddr *vaddr)
{
	return silofs_new_vnode(lcache->lc_alloc, vaddr);
}

struct silofs_vnode_info *
silofs_lcache_lookup_vnode(struct silofs_lcache *lcache,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;

	vni = lcache_find_relru_vni(lcache, vaddr);
	return vni;
}

static struct silofs_vnode_info *
lcache_require_vni(struct silofs_lcache *lcache,
                   const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = nullptr;
	int retry                     = 4;

	while (retry-- > 0) {
		vni = lcache_new_vni(lcache, vaddr);
		if (vni != nullptr) {
			break;
		}
		lcache_evict_some(lcache);
	}
	return vni;
}

static void
lcache_unmap_vni(struct silofs_lcache *lcache, struct silofs_vnode_info *vni)
{
	silofs_hmapq_unmap(&lcache->lc_vni_hmapq, vni_to_hmqe(vni));
}

static void
lcache_forget_vni(struct silofs_lcache *lcache, struct silofs_vnode_info *vni)
{
	silofs_vni_undirtify(vni);
	if (silofs_vni_refcnt(vni) > 0) {
		lcache_unmap_vni(lcache, vni);
		vni->vn_lni.ln_hmqe.hme_forgot = true;
	} else {
		lcache_evict_vni(lcache, vni, SILOFS_ALLOCF_NONE);
	}
}

void silofs_lcache_forget_vnode(struct silofs_lcache *lcache,
                                struct silofs_vnode_info *vni)
{
	lcache_forget_vni(lcache, vni);
}

static void lcache_set_dq_of_vni(struct silofs_lcache *lcache,
                                 struct silofs_vnode_info *vni)
{
	struct silofs_dirtyq *dq = lcache_dirtyq_by(lcache, vni_vtype(vni));

	silofs_vni_set_dq(vni, dq);
}

static struct silofs_vnode_info *
lcache_create_vni(struct silofs_lcache *lcache,
                  const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;

	vni = lcache_require_vni(lcache, vaddr);
	if (vni != nullptr) {
		lcache_set_dq_of_vni(lcache, vni);
		lcache_store_vni(lcache, vni);
	}
	return vni;
}

struct silofs_vnode_info *
silofs_lcache_create_vnode(struct silofs_lcache *lcache,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni;

	vni = lcache_create_vni(lcache, vaddr);
	return vni;
}

void silofs_lcache_redirtify_vnode(struct silofs_lcache *lcache,
                                   struct silofs_vnode_info *vni)
{
	silofs_vni_undirtify(vni);
	lcache_set_dq_of_vni(lcache, vni);
	silofs_vni_dirtify(vni, nullptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
lcache_shrink_some_vnis(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_or_relru_vnis(lcache, count, flags);
}

static size_t
lcache_shrink_some_unis(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_or_relru_unis(lcache, count, flags);
}

static size_t
lcache_shrink_some(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_some_vnis(lcache, count, flags) +
	       lcache_shrink_some_unis(lcache, count, flags);
}

static void lcache_evict_some(struct silofs_lcache *lcache)
{
	struct silofs_vnode_info *vni = nullptr;
	struct silofs_unode_info *uni = nullptr;
	bool evicted                  = false;

	vni = lcache_find_evictable_vni(lcache);
	if ((vni != nullptr) && test_evictable_vni(vni)) {
		lcache_evict_vni(lcache, vni, SILOFS_ALLOCF_NONE);
		evicted = true;
	}
	uni = lcache_find_evictable_uni(lcache);
	if ((uni != nullptr) && silofs_uni_isevictable(uni)) {
		lcache_evict_uni(lcache, uni, SILOFS_ALLOCF_NONE);
		evicted = true;
	}
	if (!evicted) {
		lcache_shrink_some(lcache, 1, 0);
	}
}

/* returns memory-pressure as ratio of total available memory, normalized to
 * a value within the range [0,1000] */
static size_t lcache_memory_pressure(const struct silofs_lcache *lcache)
{
	struct silofs_alloc_stat st;
	size_t mem_press = 0;

	silofs_memstat(lcache->lc_alloc, &st);
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

static size_t lcache_nmapped_unis(const struct silofs_lcache *lcache)
{
	return lcache->lc_uni_hmapq.hmq_htbl_size;
}

static size_t
lcache_relax_by_niter(struct silofs_lcache *lcache, size_t niter, int flags)
{
	size_t total = 0;
	size_t nvis;
	size_t nuis;
	size_t cnt;
	bool now;

	now = (flags & SILOFS_CTLF_NOW) > 0;
	cnt = (now || (niter > 1)) ? 2 : 1;
	for (size_t i = 0; i < niter; ++i) {
		nvis = lcache_shrink_some_vnis(lcache, i + 1, flags);
		if (!nvis || now || (lcache_nmapped_unis(lcache) > 128)) {
			nuis = lcache_shrink_some_unis(lcache, cnt, flags);
		} else {
			nuis = 0;
		}
		if (!nvis && !nuis) {
			break;
		}
		total += nvis + nuis;
	}
	return total;
}

static size_t lcache_overpop_vnis(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_overpop(&lcache->lc_vni_hmapq);
}

static size_t lcache_overpop_unis(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_overpop(&lcache->lc_uni_hmapq);
}

static size_t lcache_relax_by_overpop(struct silofs_lcache *lcache)
{
	size_t opop;
	size_t want;
	size_t total = 0;

	opop = lcache_overpop_vnis(lcache);
	if (opop > 0) {
		want = silofs_min(opop, 8);
		total +=
			lcache_shrink_some_vnis(lcache, want, SILOFS_CTLF_NOW);
	}
	opop = lcache_overpop_unis(lcache);
	if (opop > 0) {
		want = silofs_min(opop, 2);
		total +=
			lcache_shrink_some_unis(lcache, want, SILOFS_CTLF_NOW);
	}
	return total;
}

static void lcache_try_relax_uamap(struct silofs_lcache *lcache, int flags)
{
	if (flags & SILOFS_CTLF_IDLE) {
		silofs_uamap_drop_lru(&lcache->lc_uamap);
	}
}

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags)
{
	size_t niter;
	size_t drop1;
	size_t drop2;

	niter = lcache_calc_niter(lcache, flags);
	drop1 = lcache_relax_by_niter(lcache, niter, flags);
	drop2 = lcache_relax_by_overpop(lcache);
	if (!drop1 && !drop2) {
		lcache_try_relax_uamap(lcache, flags);
	}
}

static size_t lcache_hmapq_usage_sum(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_usage(&lcache->lc_vni_hmapq) +
	       silofs_hmapq_usage(&lcache->lc_uni_hmapq);
}

static void lcache_drop_evictables_once(struct silofs_lcache *lcache)
{
	lcache_drop_evictable_vnis(lcache);
	lcache_drop_evictable_unis(lcache);
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

static void lcache_drop_uamap(struct silofs_lcache *lcache)
{
	silofs_uamap_drop_all(&lcache->lc_uamap);
}

void silofs_lcache_drop(struct silofs_lcache *lcache)
{
	lcache_drop_evictables(lcache);
	lcache_drop_uamap(lcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lcache_fini_hmapqs(struct silofs_lcache *lcache)
{
	lcache_fini_vni_hmapq(lcache);
	lcache_fini_uni_hmapq(lcache);
}

static int lcache_init_hmapqs(struct silofs_lcache *lcache)
{
	int err;

	err = lcache_init_uni_hmapq(lcache);
	if (err) {
		goto out_err;
	}
	err = lcache_init_vni_hmapq(lcache);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	lcache_fini_hmapqs(lcache);
	return err;
}

static int lcache_init_uamap(struct silofs_lcache *lcache)
{
	return silofs_uamap_init(&lcache->lc_uamap, lcache->lc_alloc);
}

static void lcache_fini_uamap(struct silofs_lcache *lcache)
{
	silofs_uamap_fini(&lcache->lc_uamap);
}

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc *alloc)
{
	int err;

	lcache->lc_alloc = alloc;
	dirtyqs_init(&lcache->lc_dirtyqs);

	err = lcache_init_uamap(lcache);
	if (err) {
		goto out_err;
	}
	err = lcache_init_hmapqs(lcache);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_lcache_fini(lcache);
	return err;
}

void silofs_lcache_fini(struct silofs_lcache *lcache)
{
	dirtyqs_fini(&lcache->lc_dirtyqs);
	lcache_fini_hmapqs(lcache);
	lcache_fini_uamap(lcache);
	lcache->lc_alloc = nullptr;
}

static size_t lcache_alloc_bytes(const struct silofs_lcache *lcache)
{
	struct silofs_alloc_stat as = { .nbytes_use = 0 };

	silofs_memstat(lcache->lc_alloc, &as);
	return as.nbytes_use;
}

static size_t lcache_sum_nodes(const struct silofs_lcache *lcache)
{
	return lcache->lc_uni_hmapq.hmq_htbl_size +
	       lcache->lc_vni_hmapq.hmq_htbl_size;
}

void silofs_lcache_collect_stats(const struct silofs_lcache *lcache,
                                 struct silofs_cache_stats *out_cstats)
{
	out_cstats->nalloc_bytes = lcache_alloc_bytes(lcache);
	out_cstats->ncache_nodes = lcache_sum_nodes(lcache);
}
