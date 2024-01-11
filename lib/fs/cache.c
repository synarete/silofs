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
#include <limits.h>

static void vi_do_undirtify(struct silofs_vnode_info *vi);
static void cache_post_op(struct silofs_cache *cache);
static void cache_drop_uamap(struct silofs_cache *cache);
static void cache_evict_some(struct silofs_cache *cache);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lblock *lbk_malloc(struct silofs_alloc *alloc, int flags)
{
	struct silofs_lblock *lbk;

	lbk = silofs_allocate(alloc, sizeof(*lbk), flags);
	return lbk;
}

static void lbk_free(struct silofs_lblock *lbk,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, lbk, sizeof(*lbk), flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *dq)
{
	listq_init(&dq->dq);
	dq->dq_accum = 0;
}

void silofs_dirtyq_fini(struct silofs_dirtyq *dq)
{
	listq_fini(&dq->dq);
	dq->dq_accum = 0;
}

void silofs_dirtyq_append(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len)
{
	listq_push_back(&dq->dq, lh);
	dq->dq_accum += len;
}

void silofs_dirtyq_remove(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len)
{
	silofs_assert_ge(dq->dq_accum, len);

	listq_remove(&dq->dq, lh);
	dq->dq_accum -= len;
}

struct silofs_list_head *silofs_dirtyq_front(const struct silofs_dirtyq *dq)
{
	return listq_front(&dq->dq);
}

struct silofs_list_head *
silofs_dirtyq_next_of(const struct silofs_dirtyq *dq,
                      const struct silofs_list_head *lh)
{
	return listq_next(&dq->dq, lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dirtyqs_init(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_init(&dqs->dq_uis);
	silofs_dirtyq_init(&dqs->dq_iis);
	silofs_dirtyq_init(&dqs->dq_vis);
}

static void dirtyqs_fini(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_fini(&dqs->dq_uis);
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
		dq = &dqs->dq_uis;
	}
	return dq;
}

static struct silofs_dirtyq *
dirtyqs_get_by(struct silofs_dirtyqs *dqs, const struct silofs_vaddr *vaddr)
{
	return dirtyqs_get(dqs, vaddr->ltype);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_lnode_info *
lni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_lnode_info *lni = NULL;

	if (likely(hmqe != NULL)) {
		lni = container_of2(hmqe, struct silofs_lnode_info, l_hmqe);
	}
	return unconst(lni);
}

static struct silofs_hmapq_elem *
lni_to_hmqe(const struct silofs_lnode_info *lni)
{
	const struct silofs_hmapq_elem *hmqe = &lni->l_hmqe;

	return unconst(hmqe);
}

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni)
{
	bool ret = false;

	if (!(lni->l_flags & SILOFS_LNF_PINNED)) {
		ret = silofs_hmqe_is_evictable(lni_to_hmqe(lni));
	}
	return ret;
}

static size_t lni_view_len(const struct silofs_lnode_info *lni)
{
	return silofs_ltype_size(lni->l_ltype);
}

static void lni_incref(struct silofs_lnode_info *lni)
{
	silofs_hmqe_incref(&lni->l_hmqe);
}

static void lni_decref(struct silofs_lnode_info *lni)
{
	silofs_hmqe_decref(&lni->l_hmqe);
}

void silofs_lni_incref(struct silofs_lnode_info *lni)
{
	if (likely(lni != NULL)) {
		lni_incref(lni);
	}
}

void silofs_lni_decref(struct silofs_lnode_info *lni)
{
	if (likely(lni != NULL)) {
		lni_decref(lni);
	}
}

static void lni_remove_from_hmapq(struct silofs_lnode_info *lni,
                                  struct silofs_hmapq *hmapq)
{
	silofs_hmapq_remove(hmapq, lni_to_hmqe(lni));
}

static void lni_delete(struct silofs_lnode_info *lni,
                       struct silofs_alloc *alloc, int flags)
{
	silofs_lnode_del_fn del = lni->l_del_cb;

	del(lni, alloc, flags);
}

static int visit_evictable_lni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_lnode_info *lni = lni_from_hmqe(hmqe);
	struct silofs_lnode_info **out_lni = arg;
	int ret = 0;

	if (silofs_test_evictable(lni)) {
		*out_lni = lni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ui_set_dq(struct silofs_unode_info *ui, struct silofs_dirtyq *dq)
{
	silofs_assert_null(ui->u_dq);
	ui->u_dq = dq;
}

static bool ui_isdirty(const struct silofs_unode_info *ui)
{
	return ui->u_lni.l_hmqe.hme_dirty;
}

static void ui_do_dirtify(struct silofs_unode_info *ui)
{
	if (!ui_isdirty(ui)) {
		silofs_dirtyq_append(ui->u_dq, &ui->u_dq_lh,
		                     lni_view_len(&ui->u_lni));
		ui->u_lni.l_hmqe.hme_dirty = true;
	}
}

static void ui_do_undirtify(struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui->u_dq);

	if (ui_isdirty(ui)) {
		silofs_dirtyq_remove(ui->u_dq, &ui->u_dq_lh,
		                     lni_view_len(&ui->u_lni));
		ui->u_lni.l_hmqe.hme_dirty = false;
	}
}

void silofs_ui_dirtify(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ui_do_dirtify(ui);
	}
}

void silofs_ui_undirtify(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ui_do_undirtify(ui);
	}
}

void silofs_ui_incref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		lni_incref(&ui->u_lni);
	}
}

void silofs_ui_decref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		lni_decref(&ui->u_lni);
	}
}

static struct silofs_unode_info *ui_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	struct silofs_unode_info *ui = NULL;

	if (hmqe != NULL) {
		ui = silofs_ui_from_lni(lni_from_hmqe(hmqe));
	}
	return ui;
}

static struct silofs_hmapq_elem *ui_to_hmqe(struct silofs_unode_info *ui)
{
	return lni_to_hmqe(&ui->u_lni);
}

static int visit_evictable_ui(struct silofs_hmapq_elem *hmqe, void *arg)
{
	return visit_evictable_lni(hmqe, arg);
}

static bool ui_is_evictable(const struct silofs_unode_info *ui)
{
	return silofs_test_evictable(&ui->u_lni);
}


static void ui_delete(struct silofs_unode_info *ui,
                      struct silofs_alloc *alloc, int flags)
{
	lni_delete(&ui->u_lni, alloc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dirtyqs *vi_dirtyqs(const struct silofs_vnode_info *vi)
{
	const struct silofs_fsenv *fsenv = vi_fsenv(vi);

	return &fsenv->fse.cache->c_dqs;
}

static void vi_set_dq(struct silofs_vnode_info *vi, struct silofs_dirtyq *dq)
{
	vi->v_dq = dq;
}

static void vi_update_dq_by(struct silofs_vnode_info *vi,
                            struct silofs_inode_info *ii)
{
	struct silofs_dirtyq *dq;

	if (ii != NULL) {
		dq = &ii->i_dq_vis;
	} else {
		dq = dirtyqs_get_by(vi_dirtyqs(vi), vi_vaddr(vi));
	}
	vi_set_dq(vi, dq);
}

static struct silofs_vnode_info *vi_from_lme(struct silofs_hmapq_elem *lme)
{
	struct silofs_vnode_info *vi = NULL;

	if (lme != NULL) {
		vi = silofs_vi_from_lni(lni_from_hmqe(lme));
	}
	return vi;
}

static struct silofs_hmapq_elem *vi_to_lme(const struct silofs_vnode_info *vi)
{
	const struct silofs_hmapq_elem *lme = &vi->v_lni.l_hmqe;

	return unconst(lme);
}

static int visit_evictable_vi(struct silofs_hmapq_elem *lme, void *arg)
{
	return visit_evictable_lni(lme, arg);
}

int silofs_vi_refcnt(const struct silofs_vnode_info *vi)
{
	return likely(vi != NULL) ? silofs_hmqe_refcnt(vi_to_lme(vi)) : 0;
}

void silofs_vi_incref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		lni_incref(&vi->v_lni);
	}
}

void silofs_vi_decref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		lni_decref(&vi->v_lni);
	}
}

static bool vi_is_evictable(const struct silofs_vnode_info *vi)
{
	return silofs_test_evictable(&vi->v_lni);
}

static void vi_delete(struct silofs_vnode_info *vi,
                      struct silofs_alloc *alloc, int flags)
{
	lni_delete(&vi->v_lni, alloc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dirtyq *
cache_dirtyq_by(struct silofs_cache *cache, enum silofs_ltype ltype)
{
	return dirtyqs_get(&cache->c_dqs, ltype);
}

static int cache_init_ui_hmapq(struct silofs_cache *cache)
{
	return silofs_hmapq_init(&cache->c_ui_hmapq, cache->c_alloc);
}

static void cache_fini_ui_hmapq(struct silofs_cache *cache)
{
	silofs_hmapq_fini(&cache->c_ui_hmapq, cache->c_alloc);
}

static struct silofs_unode_info *
cache_find_evictable_ui(struct silofs_cache *cache)
{
	struct silofs_lnode_info *lni = NULL;

	silofs_hmapq_riterate(&cache->c_ui_hmapq, 10,
	                      visit_evictable_ui, &lni);
	return silofs_ui_from_lni(lni);
}

static struct silofs_unode_info *
cache_find_ui(const struct silofs_cache *cache,
              const struct silofs_uaddr *uaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_uaddr(&hkey, uaddr);
	hmqe = silofs_hmapq_lookup(&cache->c_ui_hmapq, &hkey);
	return ui_from_hmqe(hmqe);
}

static void cache_promote_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui, bool now)
{
	silofs_hmapq_promote(&cache->c_ui_hmapq, ui_to_hmqe(ui), now);
}

static struct silofs_unode_info *
cache_find_relru_ui(struct silofs_cache *cache,
                    const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_ui(cache, uaddr);
	if (ui != NULL) {
		cache_promote_ui(cache, ui, false);
	}
	return ui;
}

static void cache_remove_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui)
{
	lni_remove_from_hmapq(&ui->u_lni, &cache->c_ui_hmapq);
}

static void cache_evict_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui, int flags)
{
	ui_do_undirtify(ui);
	cache_remove_ui(cache, ui);
	ui_delete(ui, cache->c_alloc, flags);
}

static void cache_store_ui_hmapq(struct silofs_cache *cache,
                                 struct silofs_unode_info *ui)
{
	silofs_hmapq_store(&cache->c_ui_hmapq, ui_to_hmqe(ui));
}

static struct silofs_unode_info *cache_get_lru_ui(struct silofs_cache *cache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&cache->c_ui_hmapq);
	return (hmqe != NULL) ? ui_from_hmqe(hmqe) : NULL;
}

static bool cache_evict_or_relru_ui(struct silofs_cache *cache,
                                    struct silofs_unode_info *ui)
{
	bool evicted;

	if (ui_is_evictable(ui)) {
		cache_evict_ui(cache, ui, 0);
		evicted = true;
	} else {
		cache_promote_ui(cache, ui, true);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_uis(struct silofs_cache *cache, size_t cnt, bool force)
{
	struct silofs_unode_info *ui;
	const size_t n = min(cnt, cache->c_ui_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		ui = cache_get_lru_ui(cache);
		if (ui == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ui(cache, ui);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
	}
	return evicted;
}

static int try_evict_ui(struct silofs_hmapq_elem *lme, void *arg)
{
	struct silofs_cache *cache = arg;
	struct silofs_unode_info *ui = ui_from_hmqe(lme);

	cache_evict_or_relru_ui(cache, ui);
	return 0;
}

static void cache_drop_evictable_uis(struct silofs_cache *cache)
{
	silofs_hmapq_riterate(&cache->c_ui_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_ui, cache);
}

static struct silofs_unode_info *
cache_new_ui(const struct silofs_cache *cache,
             const struct silofs_ulink *ulink)
{
	return silofs_new_ui(cache->c_alloc, ulink);
}

static void cache_track_uaddr(struct silofs_cache *cache,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uamap_insert(&cache->c_uamap, uaddr);
}

static void cache_forget_uaddr(struct silofs_cache *cache,
                               const struct silofs_uaddr *uaddr)
{
	struct silofs_uakey uakey;

	silofs_uakey_setup_by(&uakey, uaddr);
	silofs_uamap_remove(&cache->c_uamap, &uakey);
}

static const struct silofs_uaddr *
cache_lookup_uaddr_by(struct silofs_cache *cache,
                      const struct silofs_uakey *uakey)
{
	return silofs_uamap_lookup(&cache->c_uamap, uakey);
}

static void cache_track_uaddr_of(struct silofs_cache *cache,
                                 const struct silofs_unode_info *ui)
{
	struct silofs_uakey uakey;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	silofs_uakey_setup_by(&uakey, uaddr);
	if (!cache_lookup_uaddr_by(cache, &uakey)) {
		cache_track_uaddr(cache, uaddr);
	}
}

static struct silofs_unode_info *
cache_lookup_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_relru_ui(cache, uaddr);
	if (ui != NULL) {
		cache_track_uaddr_of(cache, ui);
	}
	return ui;
}

struct silofs_unode_info *
silofs_cache_lookup_ui(struct silofs_cache *cache,
                       const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_lookup_ui(cache, uaddr);
	cache_post_op(cache);
	return ui;
}

static struct silofs_unode_info *
cache_require_ui(struct silofs_cache *cache, const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui = NULL;
	int retry = 4;

	while (retry-- > 0) {
		ui = cache_new_ui(cache, ulink);
		if (ui != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return ui;
}

static void cache_store_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui)
{
	silofs_hkey_by_uaddr(&ui->u_lni.l_hmqe.hme_key, ui_uaddr(ui));
	cache_store_ui_hmapq(cache, ui);
}

static void cache_set_dq_of_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	struct silofs_dirtyq *dq;

	dq = cache_dirtyq_by(cache, uaddr->ltype);
	ui_set_dq(ui, dq);
}

static struct silofs_unode_info *
cache_create_ui(struct silofs_cache *cache, const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	ui = cache_require_ui(cache, ulink);
	if (ui != NULL) {
		cache_set_dq_of_ui(cache, ui);
		cache_store_ui(cache, ui);
		cache_track_uaddr(cache, ui_uaddr(ui));
	}
	return ui;
}

struct silofs_unode_info *
silofs_cache_create_ui(struct silofs_cache *cache,
                       const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	ui = cache_create_ui(cache, ulink);
	cache_post_op(cache);
	return ui;
}

static void
cache_forget_ui(struct silofs_cache *cache, struct silofs_unode_info *ui)
{
	cache_forget_uaddr(cache, ui_uaddr(ui));
	cache_evict_ui(cache, ui, 0);
}

void silofs_cache_forget_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui)
{
	cache_forget_ui(cache, ui);
	cache_post_op(cache);
}

static struct silofs_unode_info *
cache_find_ui_by(struct silofs_cache *cache, const struct silofs_uakey *uakey)
{
	const struct silofs_uaddr *uaddr;
	struct silofs_unode_info *ui = NULL;

	uaddr = cache_lookup_uaddr_by(cache, uakey);
	if (uaddr != NULL) {
		ui = cache_lookup_ui(cache, uaddr);
	}
	return ui;
}

struct silofs_unode_info *
silofs_cache_find_ui_by(struct silofs_cache *cache,
                        const struct silofs_uakey *uakey)
{
	struct silofs_unode_info *ui;

	ui = cache_find_ui_by(cache, uakey);
	cache_post_op(cache);
	return ui;
}

void silofs_cache_drop_uamap(struct silofs_cache *cache)
{
	cache_drop_uamap(cache);
	cache_post_op(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_vi_hmapq(struct silofs_cache *cache)
{
	return silofs_hmapq_init(&cache->c_vi_hmapq, cache->c_alloc);
}

static void cache_fini_vi_hmapq(struct silofs_cache *cache)
{
	silofs_hmapq_fini(&cache->c_vi_hmapq, cache->c_alloc);
}

static struct silofs_vnode_info *
cache_find_evictable_vi(struct silofs_cache *cache)
{
	struct silofs_lnode_info *lni = NULL;

	silofs_hmapq_riterate(&cache->c_vi_hmapq, 10,
	                      visit_evictable_vi, &lni);
	return silofs_vi_from_lni(lni);
}

static struct silofs_vnode_info *
cache_find_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_vaddr(&hkey, vaddr);
	hmqe = silofs_hmapq_lookup(&cache->c_vi_hmapq, &hkey);
	return vi_from_lme(hmqe);
}

static void cache_promote_vi(struct silofs_cache *cache,
                             struct silofs_vnode_info *vi, bool now)
{
	silofs_hmapq_promote(&cache->c_vi_hmapq, vi_to_lme(vi), now);
}

static struct silofs_vnode_info *
cache_find_relru_vi(struct silofs_cache *cache,
                    const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_find_vi(cache, vaddr);
	if (vi != NULL) {
		cache_promote_vi(cache, vi, false);
	}
	return vi;
}

static void cache_remove_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	lni_remove_from_hmapq(&vi->v_lni, &cache->c_vi_hmapq);
	vi->v_lni.l_hmqe.hme_forgot = false;
}

static void cache_evict_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi, int flags)
{
	cache_remove_vi(cache, vi);
	vi_delete(vi, cache->c_alloc, flags);
}

static void cache_store_vi_hmapq(struct silofs_cache *cache,
                                 struct silofs_vnode_info *vi)
{
	silofs_hmapq_store(&cache->c_vi_hmapq, vi_to_lme(vi));
}

static void cache_store_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	silofs_hkey_by_vaddr(&vi->v_lni.l_hmqe.hme_key, &vi->v_vaddr);
	cache_store_vi_hmapq(cache, vi);
}

static struct silofs_vnode_info *cache_get_lru_vi(struct silofs_cache *cache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&cache->c_vi_hmapq);
	return (hmqe != NULL) ? vi_from_lme(hmqe) : NULL;
}

static bool cache_evict_or_relru_vi(struct silofs_cache *cache,
                                    struct silofs_vnode_info *vi)
{
	bool evicted;

	if (vi_is_evictable(vi)) {
		cache_evict_vi(cache, vi, 0);
		evicted = true;
	} else {
		cache_promote_vi(cache, vi, true);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_vis(struct silofs_cache *cache, size_t cnt, bool now)
{
	struct silofs_vnode_info *vi = NULL;
	const size_t n = min(cnt, cache->c_vi_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		vi = cache_get_lru_vi(cache);
		if (vi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vi(cache, vi);
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
	struct silofs_cache *cache = arg;
	struct silofs_vnode_info *vi = vi_from_lme(hmqe);

	cache_evict_or_relru_vi(cache, vi);
	return 0;
}

static void cache_drop_evictable_vis(struct silofs_cache *cache)
{
	silofs_hmapq_riterate(&cache->c_vi_hmapq, SILOFS_HMAPQ_ITERALL,
	                      try_evict_vi, cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
cache_new_vi(const struct silofs_cache *cache,
             const struct silofs_vaddr *vaddr)
{
	return silofs_new_vi(cache->c_alloc, vaddr);
}

struct silofs_vnode_info *
silofs_cache_lookup_vi(struct silofs_cache *cache,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_find_relru_vi(cache, vaddr);
	cache_post_op(cache);
	return vi;
}

static struct silofs_vnode_info *
cache_require_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi = NULL;
	int retry = 4;

	while (retry-- > 0) {
		vi = cache_new_vi(cache, vaddr);
		if (vi != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return vi;
}

static void cache_unmap_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	silofs_hmapq_unmap(&cache->c_vi_hmapq, vi_to_lme(vi));
}

static void cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	vi_do_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		cache_unmap_vi(cache, vi);
		vi->v_lni.l_hmqe.hme_forgot = true;
	} else {
		cache_evict_vi(cache, vi, 0);
	}
}

void silofs_cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	cache_forget_vi(cache, vi);
	cache_post_op(cache);
}

static struct silofs_vnode_info *
cache_create_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_require_vi(cache, vaddr);
	if (vi != NULL) {
		cache_store_vi(cache, vi);
	}
	return vi;
}

struct silofs_vnode_info *
silofs_cache_create_vi(struct silofs_cache *cache,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_create_vi(cache, vaddr);
	cache_post_op(cache);
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
cache_shrink_some_vis(struct silofs_cache *cache, size_t count, bool now)
{
	return cache_shrink_or_relru_vis(cache, count, now);
}

static size_t
cache_shrink_some_uis(struct silofs_cache *cache, size_t count, bool now)
{
	return cache_shrink_or_relru_uis(cache, count, now);
}

static size_t
cache_shrink_some(struct silofs_cache *cache, size_t count, bool now)
{
	return cache_shrink_some_vis(cache, count, now) +
	       cache_shrink_some_uis(cache, count, now);
}

static void cache_evict_some(struct silofs_cache *cache)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_unode_info *ui = NULL;
	bool evicted = false;

	vi = cache_find_evictable_vi(cache);
	if ((vi != NULL) && vi_is_evictable(vi)) {
		cache_evict_vi(cache, vi, 0);
		evicted = true;
	}
	ui = cache_find_evictable_ui(cache);
	if ((ui != NULL) && ui_is_evictable(ui)) {
		cache_evict_ui(cache, ui, 0);
		evicted = true;
	}
	if (!evicted) {
		cache_shrink_some(cache, 1, false);
	}
}

/* returns memory-pressure as percentage of total available memory */
static size_t cache_memory_pressure(const struct silofs_cache *cache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 0;

	silofs_allocstat(cache->c_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres;
}

static size_t cache_calc_niter(const struct silofs_cache *cache, int flags)
{
	const size_t mem_pres = cache_memory_pressure(cache);
	const size_t niter_base = (flags & SILOFS_F_NOW) ? 2 : 0;
	size_t niter = 0;

	if (mem_pres > 60) {
		niter += mem_pres / 10;
	} else if (mem_pres > 20) {
		if (flags & SILOFS_F_OPSTART) {
			niter += mem_pres / 40;
		} else if (flags & SILOFS_F_OPFINISH) {
			niter += mem_pres / 25;
		} else if (flags & SILOFS_F_TIMEOUT) {
			niter += mem_pres / 10;
		}
	} else if (mem_pres > 0) {
		if (flags & SILOFS_F_TIMEOUT) {
			niter += mem_pres / 10;
		}
		if (flags & SILOFS_F_IDLE) {
			niter += 1;
		}
	}
	return niter + niter_base;
}

static size_t cache_nmapped_uis(const struct silofs_cache *cache)
{
	return cache->c_ui_hmapq.hmq_htbl_size;
}

static size_t cache_relax_by_niter(struct silofs_cache *cache,
                                   size_t niter, int flags)
{
	const size_t nmapped = cache_nmapped_uis(cache);
	size_t total = 0;
	size_t nvis;
	size_t nuis;
	size_t cnt;
	bool now;

	now = (flags & SILOFS_F_NOW) > 0;
	cnt = (now || (niter > 1)) ? 2 : 1;
	for (size_t i = 0; i < niter; ++i) {
		nvis = cache_shrink_some_vis(cache, i + 1, now);
		if (!nvis || now || (nmapped > 256)) {
			nuis = cache_shrink_some_uis(cache, cnt, now);
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

static size_t cache_overpop_vis(const struct silofs_cache *cache)
{
	return silofs_hmapq_overpop(&cache->c_vi_hmapq);
}

static size_t cache_overpop_uis(const struct silofs_cache *cache)
{
	return silofs_hmapq_overpop(&cache->c_ui_hmapq);
}

static size_t cache_relax_by_overpop(struct silofs_cache *cache)
{
	size_t opop;
	size_t cnt = 0;

	opop = cache_overpop_vis(cache);
	if (opop > 0) {
		cnt += cache_shrink_some_vis(cache, min(opop, 8), true);
	}
	opop = cache_overpop_uis(cache);
	if (opop > 0) {
		cnt += cache_shrink_some_uis(cache, min(opop, 2), true);
	}
	return cnt;
}

static void cache_relax_uamap(struct silofs_cache *cache, int flags)
{
	if (flags & SILOFS_F_IDLE) {
		silofs_uamap_drop_lru(&cache->c_uamap);
	}
}

void silofs_cache_relax(struct silofs_cache *cache, int flags)
{
	size_t niter;
	size_t drop1;
	size_t drop2;

	niter = cache_calc_niter(cache, flags);
	drop1 = cache_relax_by_niter(cache, niter, flags);
	drop2 = cache_relax_by_overpop(cache);
	if (niter && !drop1 && !drop2 && (flags & SILOFS_F_IDLE)) {
		cache_relax_uamap(cache, flags);
	}
}

static size_t cache_hmapq_usage_sum(const struct silofs_cache *cache)
{
	return silofs_hmapq_usage(&cache->c_vi_hmapq) +
	       silofs_hmapq_usage(&cache->c_ui_hmapq);
}

static void cache_drop_evictables_once(struct silofs_cache *cache)
{
	cache_drop_evictable_vis(cache);
	cache_drop_evictable_uis(cache);
}

static void cache_drop_evictables(struct silofs_cache *cache)
{
	size_t usage_now;
	size_t usage_pre = 0;
	size_t iter_count = 0;

	usage_now = cache_hmapq_usage_sum(cache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
		cache_drop_evictables_once(cache);
		usage_now = cache_hmapq_usage_sum(cache);
	}
}

static void cache_drop_spcmaps(struct silofs_cache *cache)
{
	silofs_spamaps_drop(&cache->c_spams);
}

static void cache_drop_uamap(struct silofs_cache *cache)
{
	silofs_uamap_drop_all(&cache->c_uamap);
}

void silofs_cache_drop(struct silofs_cache *cache)
{
	cache_drop_evictables(cache);
	cache_drop_spcmaps(cache);
	cache_drop_uamap(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_nil_bk(struct silofs_cache *cache)
{
	struct silofs_lblock *lbk;

	lbk = lbk_malloc(cache->c_alloc, SILOFS_ALLOCF_BZERO);
	if (lbk == NULL) {
		return -SILOFS_ENOMEM;
	}
	cache->c_nil_lbk = lbk;
	return 0;
}

static void cache_fini_nil_bk(struct silofs_cache *cache)
{
	struct silofs_lblock *lbk = cache->c_nil_lbk;

	if (lbk != NULL) {
		lbk_free(lbk, cache->c_alloc, 0);
		cache->c_nil_lbk = NULL;
	}
}

static void cache_fini_hmapqs(struct silofs_cache *cache)
{
	cache_fini_vi_hmapq(cache);
	cache_fini_ui_hmapq(cache);
}

static int cache_init_hmapqs(struct silofs_cache *cache)
{
	int err;

	err = cache_init_ui_hmapq(cache);
	if (err) {
		goto out_err;
	}
	err = cache_init_vi_hmapq(cache);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	cache_fini_hmapqs(cache);
	return err;
}

static int cache_init_spamaps(struct silofs_cache *cache)
{
	return silofs_spamaps_init(&cache->c_spams, cache->c_alloc);
}

static void cache_fini_spamaps(struct silofs_cache *cache)
{
	silofs_spamaps_fini(&cache->c_spams);
}

static int cache_init_uamap(struct silofs_cache *cache)
{
	return silofs_uamap_init(&cache->c_uamap, cache->c_alloc);
}

static void cache_fini_uamap(struct silofs_cache *cache)
{
	silofs_uamap_fini(&cache->c_uamap);
}

int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_alloc *alloc)
{
	struct silofs_alloc_stat st;
	int err;

	silofs_allocstat(alloc, &st);

	cache->c_alloc = alloc;
	cache->c_nil_lbk = NULL;
	cache->c_mem_size_hint = st.nbytes_max;
	dirtyqs_init(&cache->c_dqs);
	err = cache_init_spamaps(cache);
	if (err) {
		goto out_err;
	}
	err = cache_init_uamap(cache);
	if (err) {
		goto out_err;
	}
	err = cache_init_nil_bk(cache);
	if (err) {
		goto out_err;
	}
	err = cache_init_hmapqs(cache);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_cache_fini(cache);
	return err;
}

void silofs_cache_fini(struct silofs_cache *cache)
{
	dirtyqs_fini(&cache->c_dqs);
	cache_fini_hmapqs(cache);
	cache_fini_nil_bk(cache);
	cache_fini_uamap(cache);
	cache_fini_spamaps(cache);
	cache->c_alloc = NULL;
}

static void cache_post_op(struct silofs_cache *cache)
{
	silofs_unused(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_isdirty(const struct silofs_vnode_info *vi)
{
	return vi->v_lni.l_hmqe.hme_dirty;
}

static void vi_set_dirty(struct silofs_vnode_info *vi, bool dirty)
{
	vi->v_lni.l_hmqe.hme_dirty = dirty;
}

static void vi_do_dirtify(struct silofs_vnode_info *vi,
                          struct silofs_inode_info *ii)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);

	if (!vi_isdirty(vi)) {
		vi_update_dq_by(vi, ii);
		silofs_dirtyq_append(vi->v_dq, &vi->v_dq_lh, vaddr->len);
		vi_set_dirty(vi, true);
	}
}

static void vi_do_undirtify(struct silofs_vnode_info *vi)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);

	if (vi_isdirty(vi)) {
		silofs_dirtyq_remove(vi->v_dq, &vi->v_dq_lh, vaddr->len);
		vi_update_dq_by(vi, NULL);
		vi_set_dirty(vi, false);
	}
}

void silofs_vi_dirtify(struct silofs_vnode_info *vi,
                       struct silofs_inode_info *ii)
{
	if (likely(vi != NULL)) {
		vi_do_dirtify(vi, ii);
	}
}

void silofs_vi_undirtify(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		vi_do_undirtify(vi);
	}
}

static void ii_do_dirtify(struct silofs_inode_info *ii)
{
	vi_do_dirtify(&ii->i_vi, NULL);
}

static void ii_do_undirtify(struct silofs_inode_info *ii)
{
	vi_do_undirtify(&ii->i_vi);
}

void silofs_ii_dirtify(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL) && !ii_isloose(ii)) {
		ii_do_dirtify(ii);
	}
}

void silofs_ii_undirtify(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		ii_do_undirtify(ii);
	}
}

bool silofs_ii_isdirty(const struct silofs_inode_info *ii)
{
	bool ret = false;

	if (likely(ii != NULL)) {
		ret = vi_isdirty(&ii->i_vi);
	}
	return ret;
}

void silofs_ii_incref(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		silofs_vi_incref(ii_to_vi(ii));
	}
}

void silofs_ii_decref(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		silofs_vi_decref(ii_to_vi(ii));
	}
}

void silofs_ii_set_loose(struct silofs_inode_info *ii)
{
	ii->i_vi.v_lni.l_flags |= SILOFS_LNF_LOOSE;
}

bool silofs_ii_is_loose(const struct silofs_inode_info *ii)
{
	return (ii->i_vi.v_lni.l_flags & SILOFS_LNF_LOOSE) > 0;
}

