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
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>

static void lcache_drop_uamap(struct silofs_lcache *lcache);
static void lcache_evict_some(struct silofs_lcache *lcache);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lblock *lbk_malloc(struct silofs_alloc *alloc, int flags)
{
	struct silofs_lblock *lbk;

	lbk = silofs_memalloc(alloc, sizeof(*lbk), flags);
	return lbk;
}

static void lbk_free(struct silofs_lblock *lbk,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, lbk, sizeof(*lbk), flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dirtyqs_init(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_init(&dqs->dq_unis);
	silofs_dirtyq_init(&dqs->dq_iis);
	silofs_dirtyq_init(&dqs->dq_vis);
}

static void dirtyqs_fini(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_fini(&dqs->dq_unis);
	silofs_dirtyq_fini(&dqs->dq_iis);
	silofs_dirtyq_fini(&dqs->dq_vis);
}

static struct silofs_dirtyq *
dirtyqs_get(struct silofs_dirtyqs *dqs, enum silofs_ltype ltype)
{
	struct silofs_dirtyq *dq;

	if (ltype_isinode(ltype)) {
		dq = &dqs->dq_iis;
	} else if (ltype_isvnode(ltype)) {
		dq = &dqs->dq_vis;
	} else {
		silofs_assert(ltype_isunode(ltype));
		dq = &dqs->dq_unis;
	}
	return dq;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *uni_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	struct silofs_unode_info *uni = NULL;

	if (hmqe != NULL) {
		uni = silofs_uni_from_lni(silofs_lni_from_hmqe(hmqe));
	}
	return uni;
}

static struct silofs_hmapq_elem *uni_to_hmqe(struct silofs_unode_info *uni)
{
	return silofs_lni_to_hmqe(&uni->un_lni);
}

static struct silofs_vnode_info *vi_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	return silofs_vi_from_lni(silofs_lni_from_hmqe(hmqe));
}

static struct silofs_hmapq_elem *vi_to_hmqe(struct silofs_vnode_info *vi)
{
	return &vi->v_lni.ln_hmqe;
}

static bool vi_isinode(const struct silofs_vnode_info *vi)
{
	const enum silofs_ltype ltype = vi_ltype(vi);

	return ltype_isinode(ltype);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_dirtyq *
lcache_dirtyq_by(struct silofs_lcache *lcache, enum silofs_ltype ltype)
{
	return dirtyqs_get(&lcache->lc_dirtyqs, ltype);
}

static int lcache_init_uni_hmapq(struct silofs_lcache *lcache)
{
	struct silofs_alloc *alloc = lcache->lc_alloc;
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 1);

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
	struct silofs_unode_info *uni = NULL;

	silofs_hmapq_riterate(&lcache->lc_uni_hmapq, 10,
	                      visit_evictable_uni, &uni);
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
	if (uni != NULL) {
		lcache_promote_uni(lcache, uni, false);
	}
	return uni;
}

static void lcache_remove_uni(struct silofs_lcache *lcache,
                              struct silofs_unode_info *uni)
{
	silofs_lni_remove_from(&uni->un_lni, &lcache->lc_uni_hmapq);
}

static void lcache_evict_uni(struct silofs_lcache *lcache,
                             struct silofs_unode_info *uni, int flags)
{
	silofs_uni_undirtify(uni);
	lcache_remove_uni(lcache, uni);
	silofs_del_unode(uni, lcache->lc_alloc, flags);
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
	return (hmqe != NULL) ? uni_from_hmqe(hmqe) : NULL;
}

static bool lcache_evict_or_relru_uni(struct silofs_lcache *lcache,
                                      struct silofs_unode_info *uni, int flags)
{
	const int alf = (flags & SILOFS_F_IDLE) ? SILOFS_ALLOCF_TRYPUNCH : 0;
	bool evicted;

	if (silofs_uni_isevictable(uni)) {
		lcache_evict_uni(lcache, uni, alf);
		evicted = true;
	} else {
		lcache_promote_uni(lcache, uni, true);
		evicted = false;
	}
	return evicted;
}

static size_t
lcache_shrink_or_relru_unis(struct silofs_lcache *lcache, size_t cnt,
                            int flags)
{
	struct silofs_unode_info *uni;
	const size_t n = min(cnt, lcache->lc_uni_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_F_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		uni = lcache_get_lru_uni(lcache);
		if (uni == NULL) {
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
	silofs_hmapq_riterate(&lcache->lc_uni_hmapq,
	                      SILOFS_HMAPQ_ITERALL,
	                      try_evict_uni, lcache);
}

static struct silofs_unode_info *
lcache_new_uni(const struct silofs_lcache *lcache,
               const struct silofs_ulink *ulink)
{
	return silofs_new_unode(lcache->lc_alloc, ulink);
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
	if (uni != NULL) {
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
                   const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *uni = NULL;
	int retry = 4;

	while (retry-- > 0) {
		uni = lcache_new_uni(lcache, ulink);
		if (uni != NULL) {
			break;
		}
		lcache_evict_some(lcache);
	}
	return uni;
}

static void lcache_store_uni(struct silofs_lcache *lcache,
                             struct silofs_unode_info *uni)
{
	silofs_hkey_by_uaddr(&uni->un_lni.ln_hmqe.hme_key, uni_uaddr(uni));
	lcache_store_uni_hmapq(lcache, uni);
}

static void lcache_set_dq_of_uni(struct silofs_lcache *lcache,
                                 struct silofs_unode_info *uni)
{
	struct silofs_dirtyq *dq = lcache_dirtyq_by(lcache, uni_ltype(uni));

	silofs_uni_set_dq(uni, dq);
}

static struct silofs_unode_info *
lcache_create_uni(struct silofs_lcache *lcache,
                  const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *uni;

	uni = lcache_require_uni(lcache, ulink);
	if (uni != NULL) {
		lcache_set_dq_of_uni(lcache, uni);
		lcache_store_uni(lcache, uni);
		lcache_track_uaddr(lcache, uni_uaddr(uni));
	}
	return uni;
}

struct silofs_unode_info *
silofs_lcache_create_uni(struct silofs_lcache *lcache,
                         const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *uni;

	uni = lcache_create_uni(lcache, ulink);
	return uni;
}

static void lcache_forget_uni(struct silofs_lcache *lcache,
                              struct silofs_unode_info *uni)
{
	lcache_forget_uaddr(lcache, uni_uaddr(uni));
	lcache_evict_uni(lcache, uni, 0);
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
	struct silofs_unode_info *uni = NULL;

	uaddr = lcache_lookup_uaddr_by(lcache, uakey);
	if (uaddr != NULL) {
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

static int lcache_init_vi_hmapq(struct silofs_lcache *lcache)
{
	struct silofs_alloc *alloc = lcache->lc_alloc;
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 7);

	return silofs_hmapq_init(&lcache->lc_vi_hmapq, alloc, nslots);
}

static void lcache_fini_vi_hmapq(struct silofs_lcache *lcache)
{
	silofs_hmapq_fini(&lcache->lc_vi_hmapq, lcache->lc_alloc);
}

static bool test_evictable_vi(const struct silofs_vnode_info *vi)
{
	const struct silofs_inode_info *ii = NULL;
	bool ret = false;

	if (vi_isinode(vi)) {
		ii = silofs_ii_from_vi(vi);
		ret = silofs_ii_isevictable(ii);
	} else {
		ret = silofs_vi_isevictable(vi);
	}
	return ret;
}

static int visit_evictable_vi(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_vnode_info *vi = vi_from_hmqe(hmqe);

	if (!test_evictable_vi(vi)) {
		return 0;
	}
	*(struct silofs_vnode_info **)arg = vi;
	return 1;
}

static struct silofs_vnode_info *
lcache_find_evictable_vi(struct silofs_lcache *lcache)
{
	struct silofs_vnode_info *vi = NULL;

	silofs_hmapq_riterate(&lcache->lc_vi_hmapq, 10,
	                      visit_evictable_vi, &vi);
	return vi;
}

static struct silofs_vnode_info *
lcache_find_vi(struct silofs_lcache *lcache, const struct silofs_vaddr *vaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_vaddr(&hkey, vaddr);
	hmqe = silofs_hmapq_lookup(&lcache->lc_vi_hmapq, &hkey);
	return (hmqe != NULL) ? vi_from_hmqe(hmqe) : NULL;
}

static void lcache_promote_vi(struct silofs_lcache *lcache,
                              struct silofs_vnode_info *vi, bool now)
{
	silofs_hmapq_promote(&lcache->lc_vi_hmapq, vi_to_hmqe(vi), now);
}

static struct silofs_vnode_info *
lcache_find_relru_vi(struct silofs_lcache *lcache,
                     const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = lcache_find_vi(lcache, vaddr);
	if (vi != NULL) {
		lcache_promote_vi(lcache, vi, false);
	}
	return vi;
}

static void lcache_remove_vi(struct silofs_lcache *lcache,
                             struct silofs_vnode_info *vi)
{
	silofs_lni_remove_from(&vi->v_lni, &lcache->lc_vi_hmapq);
	vi->v_lni.ln_hmqe.hme_forgot = false;
}

static void lcache_evict_vi(struct silofs_lcache *lcache,
                            struct silofs_vnode_info *vi, int flags)
{
	lcache_remove_vi(lcache, vi);
	silofs_del_vnode(vi, lcache->lc_alloc, flags);
}

static void lcache_store_vi_hmapq(struct silofs_lcache *lcache,
                                  struct silofs_vnode_info *vi)
{
	silofs_hmapq_store(&lcache->lc_vi_hmapq, vi_to_hmqe(vi));
}

static void lcache_store_vi(struct silofs_lcache *lcache,
                            struct silofs_vnode_info *vi)
{
	silofs_hkey_by_vaddr(&vi->v_lni.ln_hmqe.hme_key, &vi->v_vaddr);
	lcache_store_vi_hmapq(lcache, vi);
}

static struct silofs_vnode_info *
lcache_get_lru_vi(struct silofs_lcache *lcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&lcache->lc_vi_hmapq);
	return (hmqe != NULL) ? vi_from_hmqe(hmqe) : NULL;
}

static bool lcache_evict_or_relru_vi(struct silofs_lcache *lcache,
                                     struct silofs_vnode_info *vi, int flags)
{
	int allocf;
	bool evicted;

	if (test_evictable_vi(vi)) {
		allocf = (flags & SILOFS_F_IDLE) ? SILOFS_ALLOCF_TRYPUNCH : 0;
		lcache_evict_vi(lcache, vi, allocf);
		evicted = true;
	} else {
		lcache_promote_vi(lcache, vi, true);
		evicted = false;
	}
	return evicted;
}

static size_t
lcache_shrink_or_relru_vis(struct silofs_lcache *lcache, size_t cnt, int flags)
{
	struct silofs_vnode_info *vi = NULL;
	const size_t n = min(cnt, lcache->lc_vi_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool now;
	bool ok;

	now = (flags & SILOFS_F_NOW) > 0;
	for (size_t i = 0; i < n; ++i) {
		vi = lcache_get_lru_vi(lcache);
		if (vi == NULL) {
			break;
		}
		ok = lcache_evict_or_relru_vi(lcache, vi, flags);
		if (ok) {
			evicted++;
		} else if (!now && (i || evicted)) {
			break;
		}
	}
	return evicted;
}

static int try_evict_vi(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_lcache *lcache = arg;
	struct silofs_vnode_info *vi = vi_from_hmqe(hmqe);

	lcache_evict_or_relru_vi(lcache, vi, 0);
	return 0;
}

static void lcache_drop_evictable_vis(struct silofs_lcache *lcache)
{
	silofs_hmapq_riterate(&lcache->lc_vi_hmapq,
	                      SILOFS_HMAPQ_ITERALL,
	                      try_evict_vi, lcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
lcache_new_vi(const struct silofs_lcache *lcache,
              const struct silofs_vaddr *vaddr)
{
	return silofs_new_vnode(lcache->lc_alloc, vaddr);
}

struct silofs_vnode_info *
silofs_lcache_lookup_vi(struct silofs_lcache *lcache,
                        const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = lcache_find_relru_vi(lcache, vaddr);
	return vi;
}

static struct silofs_vnode_info *
lcache_require_vi(struct silofs_lcache *lcache,
                  const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi = NULL;
	int retry = 4;

	while (retry-- > 0) {
		vi = lcache_new_vi(lcache, vaddr);
		if (vi != NULL) {
			break;
		}
		lcache_evict_some(lcache);
	}
	return vi;
}

static void lcache_unmap_vi(struct silofs_lcache *lcache,
                            struct silofs_vnode_info *vi)
{
	silofs_hmapq_unmap(&lcache->lc_vi_hmapq, vi_to_hmqe(vi));
}

static void lcache_forget_vi(struct silofs_lcache *lcache,
                             struct silofs_vnode_info *vi)
{
	silofs_vi_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		lcache_unmap_vi(lcache, vi);
		vi->v_lni.ln_hmqe.hme_forgot = true;
	} else {
		lcache_evict_vi(lcache, vi, 0);
	}
}

void silofs_lcache_forget_vi(struct silofs_lcache *lcache,
                             struct silofs_vnode_info *vi)
{
	lcache_forget_vi(lcache, vi);
}

static void lcache_set_dq_of_vi(struct silofs_lcache *lcache,
                                struct silofs_vnode_info *vi)
{
	struct silofs_dirtyq *dq = lcache_dirtyq_by(lcache, vi_ltype(vi));

	silofs_vi_set_dq(vi, dq);
}

static struct silofs_vnode_info *
lcache_create_vi(struct silofs_lcache *lcache,
                 const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = lcache_require_vi(lcache, vaddr);
	if (vi != NULL) {
		lcache_set_dq_of_vi(lcache, vi);
		lcache_store_vi(lcache, vi);
	}
	return vi;
}

struct silofs_vnode_info *
silofs_lcache_create_vi(struct silofs_lcache *lcache,
                        const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = lcache_create_vi(lcache, vaddr);
	return vi;
}

void silofs_lcache_reditify_vi(struct silofs_lcache *lcache,
                               struct silofs_vnode_info *vi)
{
	silofs_vi_undirtify(vi);
	lcache_set_dq_of_vi(lcache, vi);
	silofs_vi_dirtify(vi, NULL);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
lcache_shrink_some_vis(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_or_relru_vis(lcache, count, flags);
}

static size_t
lcache_shrink_some_unis(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_or_relru_unis(lcache, count, flags);
}

static size_t
lcache_shrink_some(struct silofs_lcache *lcache, size_t count, int flags)
{
	return lcache_shrink_some_vis(lcache, count, flags) +
	       lcache_shrink_some_unis(lcache, count, flags);
}

static void lcache_evict_some(struct silofs_lcache *lcache)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_unode_info *uni = NULL;
	bool evicted = false;

	vi = lcache_find_evictable_vi(lcache);
	if ((vi != NULL) && test_evictable_vi(vi)) {
		lcache_evict_vi(lcache, vi, 0);
		evicted = true;
	}
	uni = lcache_find_evictable_uni(lcache);
	if ((uni != NULL) && silofs_uni_isevictable(uni)) {
		lcache_evict_uni(lcache, uni, 0);
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
	const size_t mempress = lcache_memory_pressure(lcache);
	const size_t mempress_percentage = mempress / 10;
	size_t niter = 0;

	if (mempress_percentage > 60) {
		niter += mempress_percentage / 10;
	} else if (mempress_percentage > 20) {
		if (flags & SILOFS_F_OPSTART) {
			niter += mempress_percentage / 40;
		}
		if (flags & SILOFS_F_INTERN) {
			niter += mempress_percentage / 20;
		}
	}
	if (!niter && (mempress > 0) && (flags & SILOFS_F_IDLE)) {
		niter += 2 + mempress_percentage / 10;
	}
	if (flags & SILOFS_F_NOW) {
		niter += 2;
	}
	return niter;
}

static size_t lcache_nmapped_unis(const struct silofs_lcache *lcache)
{
	return lcache->lc_uni_hmapq.hmq_htbl_size;
}

static size_t lcache_relax_by_niter(struct silofs_lcache *lcache,
                                    size_t niter, int flags)
{
	size_t total = 0;
	size_t nvis;
	size_t nuis;
	size_t cnt;
	bool now;

	now = (flags & SILOFS_F_NOW) > 0;
	cnt = (now || (niter > 1)) ? 2 : 1;
	for (size_t i = 0; i < niter; ++i) {
		nvis = lcache_shrink_some_vis(lcache, i + 1, flags);
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

static size_t lcache_overpop_vis(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_overpop(&lcache->lc_vi_hmapq);
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

	opop = lcache_overpop_vis(lcache);
	if (opop > 0) {
		want = min(opop, 8);
		total += lcache_shrink_some_vis(lcache, want, SILOFS_F_NOW);
	}
	opop = lcache_overpop_unis(lcache);
	if (opop > 0) {
		want = min(opop, 2);
		total += lcache_shrink_some_unis(lcache, want, SILOFS_F_NOW);
	}
	return total;
}

static void lcache_try_relax_uamap(struct silofs_lcache *lcache, int flags)
{
	if (flags & SILOFS_F_IDLE) {
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
	return silofs_hmapq_usage(&lcache->lc_vi_hmapq) +
	       silofs_hmapq_usage(&lcache->lc_uni_hmapq);
}

static void lcache_drop_evictables_once(struct silofs_lcache *lcache)
{
	lcache_drop_evictable_vis(lcache);
	lcache_drop_evictable_unis(lcache);
}

static void lcache_drop_evictables(struct silofs_lcache *lcache)
{
	size_t usage_now;
	size_t usage_pre = 0;
	size_t iter_count = 0;

	usage_now = lcache_hmapq_usage_sum(lcache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
		lcache_drop_evictables_once(lcache);
		usage_now = lcache_hmapq_usage_sum(lcache);
	}
}

static void lcache_drop_spcmaps(struct silofs_lcache *lcache)
{
	silofs_spamaps_drop(&lcache->lc_spamaps);
}

static void lcache_drop_uamap(struct silofs_lcache *lcache)
{
	silofs_uamap_drop_all(&lcache->lc_uamap);
}

void silofs_lcache_drop(struct silofs_lcache *lcache)
{
	lcache_drop_evictables(lcache);
	lcache_drop_spcmaps(lcache);
	lcache_drop_uamap(lcache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lcache_init_nil_bk(struct silofs_lcache *lcache)
{
	struct silofs_lblock *lbk;

	lbk = lbk_malloc(lcache->lc_alloc, SILOFS_ALLOCF_BZERO);
	if (lbk == NULL) {
		return -SILOFS_ENOMEM;
	}
	lcache->lc_nil_lbk = lbk;
	return 0;
}

static void lcache_fini_nil_bk(struct silofs_lcache *lcache)
{
	struct silofs_lblock *lbk = lcache->lc_nil_lbk;

	if (lbk != NULL) {
		lbk_free(lbk, lcache->lc_alloc, 0);
		lcache->lc_nil_lbk = NULL;
	}
}

static void lcache_fini_hmapqs(struct silofs_lcache *lcache)
{
	lcache_fini_vi_hmapq(lcache);
	lcache_fini_uni_hmapq(lcache);
}

static int lcache_init_hmapqs(struct silofs_lcache *lcache)
{
	int err;

	err = lcache_init_uni_hmapq(lcache);
	if (err) {
		goto out_err;
	}
	err = lcache_init_vi_hmapq(lcache);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	lcache_fini_hmapqs(lcache);
	return err;
}

static int lcache_init_spamaps(struct silofs_lcache *lcache)
{
	return silofs_spamaps_init(&lcache->lc_spamaps, lcache->lc_alloc);
}

static void lcache_fini_spamaps(struct silofs_lcache *lcache)
{
	silofs_spamaps_fini(&lcache->lc_spamaps);
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
	lcache->lc_nil_lbk = NULL;

	dirtyqs_init(&lcache->lc_dirtyqs);
	err = lcache_init_spamaps(lcache);
	if (err) {
		goto out_err;
	}
	err = lcache_init_uamap(lcache);
	if (err) {
		goto out_err;
	}
	err = lcache_init_nil_bk(lcache);
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
	lcache_fini_nil_bk(lcache);
	lcache_fini_uamap(lcache);
	lcache_fini_spamaps(lcache);
	lcache->lc_alloc = NULL;
}
