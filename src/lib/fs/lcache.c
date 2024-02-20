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

	return &fsenv->fse.lcache->lc_dirtyqs;
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

static struct silofs_vnode_info *vi_from_hmqe(struct silofs_hmapq_elem *lme)
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
lcache_dirtyq_by(struct silofs_lcache *lcache, enum silofs_ltype ltype)
{
	return dirtyqs_get(&lcache->lc_dirtyqs, ltype);
}

static int lcache_init_ui_hmapq(struct silofs_lcache *lcache)
{
	struct silofs_alloc *alloc = lcache->lc_alloc;
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 1);

	return silofs_hmapq_init(&lcache->lc_ui_hmapq, alloc, nslots);
}

static void lcache_fini_ui_hmapq(struct silofs_lcache *lcache)
{
	silofs_hmapq_fini(&lcache->lc_ui_hmapq, lcache->lc_alloc);
}

static struct silofs_unode_info *
lcache_find_evictable_ui(struct silofs_lcache *lcache)
{
	struct silofs_lnode_info *lni = NULL;

	silofs_hmapq_riterate(&lcache->lc_ui_hmapq, 10,
	                      visit_evictable_ui, &lni);
	return silofs_ui_from_lni(lni);
}

static struct silofs_unode_info *
lcache_find_ui(const struct silofs_lcache *lcache,
               const struct silofs_uaddr *uaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_uaddr(&hkey, uaddr);
	hmqe = silofs_hmapq_lookup(&lcache->lc_ui_hmapq, &hkey);
	return ui_from_hmqe(hmqe);
}

static void lcache_promote_ui(struct silofs_lcache *lcache,
                              struct silofs_unode_info *ui, bool now)
{
	silofs_hmapq_promote(&lcache->lc_ui_hmapq, ui_to_hmqe(ui), now);
}

static struct silofs_unode_info *
lcache_find_relru_ui(struct silofs_lcache *lcache,
                     const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = lcache_find_ui(lcache, uaddr);
	if (ui != NULL) {
		lcache_promote_ui(lcache, ui, false);
	}
	return ui;
}

static void lcache_remove_ui(struct silofs_lcache *lcache,
                             struct silofs_unode_info *ui)
{
	lni_remove_from_hmapq(&ui->u_lni, &lcache->lc_ui_hmapq);
}

static void lcache_evict_ui(struct silofs_lcache *lcache,
                            struct silofs_unode_info *ui, int flags)
{
	ui_do_undirtify(ui);
	lcache_remove_ui(lcache, ui);
	ui_delete(ui, lcache->lc_alloc, flags);
}

static void lcache_store_ui_hmapq(struct silofs_lcache *lcache,
                                  struct silofs_unode_info *ui)
{
	silofs_hmapq_store(&lcache->lc_ui_hmapq, ui_to_hmqe(ui));
}

static struct silofs_unode_info *
lcache_get_lru_ui(struct silofs_lcache *lcache)
{
	struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmapq_get_lru(&lcache->lc_ui_hmapq);
	return (hmqe != NULL) ? ui_from_hmqe(hmqe) : NULL;
}

static bool lcache_evict_or_relru_ui(struct silofs_lcache *lcache,
                                     struct silofs_unode_info *ui)
{
	bool evicted;

	if (ui_is_evictable(ui)) {
		lcache_evict_ui(lcache, ui, 0);
		evicted = true;
	} else {
		lcache_promote_ui(lcache, ui, true);
		evicted = false;
	}
	return evicted;
}

static size_t lcache_shrink_or_relru_uis(struct silofs_lcache *lcache,
                size_t cnt, bool force)
{
	struct silofs_unode_info *ui;
	const size_t n = min(cnt, lcache->lc_ui_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		ui = lcache_get_lru_ui(lcache);
		if (ui == NULL) {
			break;
		}
		ok = lcache_evict_or_relru_ui(lcache, ui);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
	}
	return evicted;
}

static int try_evict_ui(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_lcache *lcache = arg;
	struct silofs_unode_info *ui = ui_from_hmqe(hmqe);

	lcache_evict_or_relru_ui(lcache, ui);
	return 0;
}

static void lcache_drop_evictable_uis(struct silofs_lcache *lcache)
{
	silofs_hmapq_riterate(&lcache->lc_ui_hmapq,
	                      SILOFS_HMAPQ_ITERALL,
	                      try_evict_ui, lcache);
}

static struct silofs_unode_info *
lcache_new_ui(const struct silofs_lcache *lcache,
              const struct silofs_ulink *ulink)
{
	return silofs_new_ui(lcache->lc_alloc, ulink);
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
                                  const struct silofs_unode_info *ui)
{
	struct silofs_uakey uakey;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	silofs_uakey_setup_by(&uakey, uaddr);
	if (!lcache_lookup_uaddr_by(lcache, &uakey)) {
		lcache_track_uaddr(lcache, uaddr);
	}
}

static struct silofs_unode_info *
lcache_lookup_ui(struct silofs_lcache *lcache,
                 const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = lcache_find_relru_ui(lcache, uaddr);
	if (ui != NULL) {
		lcache_track_uaddr_of(lcache, ui);
	}
	return ui;
}

struct silofs_unode_info *
silofs_lcache_lookup_ui(struct silofs_lcache *lcache,
                        const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = lcache_lookup_ui(lcache, uaddr);
	return ui;
}

static struct silofs_unode_info *
lcache_require_ui(struct silofs_lcache *lcache,
                  const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui = NULL;
	int retry = 4;

	while (retry-- > 0) {
		ui = lcache_new_ui(lcache, ulink);
		if (ui != NULL) {
			break;
		}
		lcache_evict_some(lcache);
	}
	return ui;
}

static void lcache_store_ui(struct silofs_lcache *lcache,
                            struct silofs_unode_info *ui)
{
	silofs_hkey_by_uaddr(&ui->u_lni.l_hmqe.hme_key, ui_uaddr(ui));
	lcache_store_ui_hmapq(lcache, ui);
}

static void lcache_set_dq_of_ui(struct silofs_lcache *lcache,
                                struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	struct silofs_dirtyq *dq;

	dq = lcache_dirtyq_by(lcache, uaddr->laddr.ltype);
	ui_set_dq(ui, dq);
}

static struct silofs_unode_info *
lcache_create_ui(struct silofs_lcache *lcache,
                 const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	ui = lcache_require_ui(lcache, ulink);
	if (ui != NULL) {
		lcache_set_dq_of_ui(lcache, ui);
		lcache_store_ui(lcache, ui);
		lcache_track_uaddr(lcache, ui_uaddr(ui));
	}
	return ui;
}

struct silofs_unode_info *
silofs_lcache_create_ui(struct silofs_lcache *lcache,
                        const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	ui = lcache_create_ui(lcache, ulink);
	return ui;
}

static void
lcache_forget_ui(struct silofs_lcache *lcache, struct silofs_unode_info *ui)
{
	lcache_forget_uaddr(lcache, ui_uaddr(ui));
	lcache_evict_ui(lcache, ui, 0);
}

void silofs_lcache_forget_ui(struct silofs_lcache *lcache,
                             struct silofs_unode_info *ui)
{
	lcache_forget_ui(lcache, ui);
}

static struct silofs_unode_info *
lcache_find_ui_by(struct silofs_lcache *lcache,
                  const struct silofs_uakey *uakey)
{
	const struct silofs_uaddr *uaddr;
	struct silofs_unode_info *ui = NULL;

	uaddr = lcache_lookup_uaddr_by(lcache, uakey);
	if (uaddr != NULL) {
		ui = lcache_lookup_ui(lcache, uaddr);
	}
	return ui;
}

struct silofs_unode_info *
silofs_lcache_find_ui_by(struct silofs_lcache *lcache,
                         const struct silofs_uakey *uakey)
{
	struct silofs_unode_info *ui;

	ui = lcache_find_ui_by(lcache, uakey);
	return ui;
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

static struct silofs_vnode_info *
lcache_find_evictable_vi(struct silofs_lcache *lcache)
{
	struct silofs_lnode_info *lni = NULL;

	silofs_hmapq_riterate(&lcache->lc_vi_hmapq, 10,
	                      visit_evictable_vi, &lni);
	return silofs_vi_from_lni(lni);
}

static struct silofs_vnode_info *
lcache_find_vi(struct silofs_lcache *lcache, const struct silofs_vaddr *vaddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_vaddr(&hkey, vaddr);
	hmqe = silofs_hmapq_lookup(&lcache->lc_vi_hmapq, &hkey);
	return vi_from_hmqe(hmqe);
}

static void lcache_promote_vi(struct silofs_lcache *lcache,
                              struct silofs_vnode_info *vi, bool now)
{
	silofs_hmapq_promote(&lcache->lc_vi_hmapq, vi_to_lme(vi), now);
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
	lni_remove_from_hmapq(&vi->v_lni, &lcache->lc_vi_hmapq);
	vi->v_lni.l_hmqe.hme_forgot = false;
}

static void lcache_evict_vi(struct silofs_lcache *lcache,
                            struct silofs_vnode_info *vi, int flags)
{
	lcache_remove_vi(lcache, vi);
	vi_delete(vi, lcache->lc_alloc, flags);
}

static void lcache_store_vi_hmapq(struct silofs_lcache *lcache,
                                  struct silofs_vnode_info *vi)
{
	silofs_hmapq_store(&lcache->lc_vi_hmapq, vi_to_lme(vi));
}

static void lcache_store_vi(struct silofs_lcache *lcache,
                            struct silofs_vnode_info *vi)
{
	silofs_hkey_by_vaddr(&vi->v_lni.l_hmqe.hme_key, &vi->v_vaddr);
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
                                     struct silofs_vnode_info *vi)
{
	bool evicted;

	if (vi_is_evictable(vi)) {
		lcache_evict_vi(lcache, vi, 0);
		evicted = true;
	} else {
		lcache_promote_vi(lcache, vi, true);
		evicted = false;
	}
	return evicted;
}

static size_t
lcache_shrink_or_relru_vis(struct silofs_lcache *lcache, size_t cnt, bool now)
{
	struct silofs_vnode_info *vi = NULL;
	const size_t n = min(cnt, lcache->lc_vi_hmapq.hmq_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		vi = lcache_get_lru_vi(lcache);
		if (vi == NULL) {
			break;
		}
		ok = lcache_evict_or_relru_vi(lcache, vi);
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

	lcache_evict_or_relru_vi(lcache, vi);
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
	return silofs_new_vi(lcache->lc_alloc, vaddr);
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
	silofs_hmapq_unmap(&lcache->lc_vi_hmapq, vi_to_lme(vi));
}

static void lcache_forget_vi(struct silofs_lcache *lcache,
                             struct silofs_vnode_info *vi)
{
	vi_do_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		lcache_unmap_vi(lcache, vi);
		vi->v_lni.l_hmqe.hme_forgot = true;
	} else {
		lcache_evict_vi(lcache, vi, 0);
	}
}

void silofs_lcache_forget_vi(struct silofs_lcache *lcache,
                             struct silofs_vnode_info *vi)
{
	lcache_forget_vi(lcache, vi);
}

static struct silofs_vnode_info *
lcache_create_vi(struct silofs_lcache *lcache,
                 const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = lcache_require_vi(lcache, vaddr);
	if (vi != NULL) {
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
lcache_shrink_some_vis(struct silofs_lcache *lcache, size_t count, bool now)
{
	return lcache_shrink_or_relru_vis(lcache, count, now);
}

static size_t
lcache_shrink_some_uis(struct silofs_lcache *lcache, size_t count, bool now)
{
	return lcache_shrink_or_relru_uis(lcache, count, now);
}

static size_t
lcache_shrink_some(struct silofs_lcache *lcache, size_t count, bool now)
{
	return lcache_shrink_some_vis(lcache, count, now) +
	       lcache_shrink_some_uis(lcache, count, now);
}

static void lcache_evict_some(struct silofs_lcache *lcache)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_unode_info *ui = NULL;
	bool evicted = false;

	vi = lcache_find_evictable_vi(lcache);
	if ((vi != NULL) && vi_is_evictable(vi)) {
		lcache_evict_vi(lcache, vi, 0);
		evicted = true;
	}
	ui = lcache_find_evictable_ui(lcache);
	if ((ui != NULL) && ui_is_evictable(ui)) {
		lcache_evict_ui(lcache, ui, 0);
		evicted = true;
	}
	if (!evicted) {
		lcache_shrink_some(lcache, 1, false);
	}
}

/* returns memory-pressure as percentage of total available memory */
static size_t lcache_memory_pressure(const struct silofs_lcache *lcache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 0;

	silofs_memstat(lcache->lc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres;
}

static size_t lcache_calc_niter(const struct silofs_lcache *lcache, int flags)
{
	const size_t mem_pres = lcache_memory_pressure(lcache);
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

static size_t lcache_nmapped_uis(const struct silofs_lcache *lcache)
{
	return lcache->lc_ui_hmapq.hmq_htbl_size;
}

static size_t lcache_relax_by_niter(struct silofs_lcache *lcache,
                                    size_t niter, int flags)
{
	const size_t nmapped = lcache_nmapped_uis(lcache);
	size_t total = 0;
	size_t nvis;
	size_t nuis;
	size_t cnt;
	bool now;

	now = (flags & SILOFS_F_NOW) > 0;
	cnt = (now || (niter > 1)) ? 2 : 1;
	for (size_t i = 0; i < niter; ++i) {
		nvis = lcache_shrink_some_vis(lcache, i + 1, now);
		if (!nvis || now || (nmapped > 256)) {
			nuis = lcache_shrink_some_uis(lcache, cnt, now);
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

static size_t lcache_overpop_uis(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_overpop(&lcache->lc_ui_hmapq);
}

static size_t lcache_relax_by_overpop(struct silofs_lcache *lcache)
{
	size_t opop;
	size_t cnt = 0;

	opop = lcache_overpop_vis(lcache);
	if (opop > 0) {
		cnt += lcache_shrink_some_vis(lcache, min(opop, 8), true);
	}
	opop = lcache_overpop_uis(lcache);
	if (opop > 0) {
		cnt += lcache_shrink_some_uis(lcache, min(opop, 2), true);
	}
	return cnt;
}

static void lcache_relax_uamap(struct silofs_lcache *lcache, int flags)
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
	if (niter && !drop1 && !drop2 && (flags & SILOFS_F_IDLE)) {
		lcache_relax_uamap(lcache, flags);
	}
}

static size_t lcache_hmapq_usage_sum(const struct silofs_lcache *lcache)
{
	return silofs_hmapq_usage(&lcache->lc_vi_hmapq) +
	       silofs_hmapq_usage(&lcache->lc_ui_hmapq);
}

static void lcache_drop_evictables_once(struct silofs_lcache *lcache)
{
	lcache_drop_evictable_vis(lcache);
	lcache_drop_evictable_uis(lcache);
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
	lcache_fini_ui_hmapq(lcache);
}

static int lcache_init_hmapqs(struct silofs_lcache *lcache)
{
	int err;

	err = lcache_init_ui_hmapq(lcache);
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

