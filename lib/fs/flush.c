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
#include <silofs/fs/flush.h>
#include <silofs/run.h>

static bool lni_isunode(const struct silofs_lnode_info *lni)
{
	return silofs_vtype_isunode(lni->ln_vtype);
}

static bool lni_isvnode(const struct silofs_lnode_info *lni)
{
	return silofs_vtype_isvnode(lni->ln_vtype);
}

static bool lni_isdata(const struct silofs_lnode_info *lni)
{
	return silofs_vtype_isdata(lni->ln_vtype);
}

static bool uni_issuper(const struct silofs_unode_info *uni)
{
	return silofs_vtype_issuper(silofs_uni_vtype(uni));
}

static struct silofs_unode_info *
uni_from_lni(const struct silofs_lnode_info *lni)
{
	return silofs_uni_from_lni(lni);
}

static struct silofs_unode_info *uni_from_dqe(struct silofs_dq_elem *dqe)
{
	return uni_from_lni(silofs_lni_from_dqe(dqe));
}

static struct silofs_vnode_info *
vni_from_lni(const struct silofs_lnode_info *lni)
{
	return silofs_vni_from_lni(lni);
}

static bool vni_may_flush(const struct silofs_vnode_info *vni)
{
	const int asyncwr = silofs_atomic_sqc_get(&vni->vn_asyncwr);

	return (asyncwr == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long hkey_compare(const void *x, const void *y)
{
	const struct silofs_hkey *hkey_x = x;
	const struct silofs_hkey *hkey_y = y;

	return silofs_hkey_compare(hkey_x, hkey_y);
}

static struct silofs_lnode_info *
avl_node_to_lni(const struct silofs_avl_node *an)
{
	const struct silofs_lnode_info *lni;

	lni = container_of2(an, struct silofs_lnode_info, ln_ds_avl_node);
	return unconst(lni);
}

static const void *lni_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_lnode_info *lni = avl_node_to_lni(an);

	return &lni->ln_hmqe.hme_key;
}

static void lni_visit_reinit(struct silofs_avl_node *an, void *p)
{
	struct silofs_lnode_info *lni = avl_node_to_lni(an);

	silofs_avl_node_init(&lni->ln_ds_avl_node);
	unused(p);
}

static void lni_seal_meta(struct silofs_lnode_info *lni)
{
	if (lni_isunode(lni)) {
		silofs_uni_seal_view(uni_from_lni(lni));
	} else if (lni_isvnode(lni) && !lni_isdata(lni)) {
		silofs_seal_vnode(vni_from_lni(lni));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void undirtify_lnode(struct silofs_lnode_info *lni)
{
	struct silofs_vnode_info *vni = nullptr;
	struct silofs_unode_info *uni = nullptr;

	if (lni_isvnode(lni)) {
		vni = vni_from_lni(lni);
		silofs_vni_undirtify(vni);
	} else if (lni_isunode(lni)) {
		uni = uni_from_lni(lni);
		silofs_uni_undirtify(uni);
	} else {
		silofs_panic("bad lnode: vtype=%d", (int)(lni->ln_vtype));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dset_clear_map(struct silofs_dset *dset)
{
	const struct silofs_avl_node_functor fn = {
		.fn  = lni_visit_reinit,
		.ctx = nullptr,
	};

	silofs_avl_clear(&dset->ds_avl, &fn);
}

static void
dset_add_dirty(struct silofs_dset *dset, struct silofs_lnode_info *lni)
{
	silofs_avl_insert(&dset->ds_avl, &lni->ln_ds_avl_node);
}

static void dset_init(struct silofs_dset *dset)
{
	silofs_avl_init(&dset->ds_avl, lni_getkey, hkey_compare, dset);
	dset->ds_preq  = nullptr;
	dset->ds_postq = nullptr;
}

static void dset_fini(struct silofs_dset *dset)
{
	silofs_avl_fini(&dset->ds_avl);
	dset->ds_preq  = nullptr;
	dset->ds_postq = nullptr;
}

static void
dset_push_preq(struct silofs_dset *dset, struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->ln_ds_next);

	lni->ln_ds_next = dset->ds_preq;
	dset->ds_preq   = lni;
}

static void
dset_push_postq(struct silofs_dset *dset, struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->ln_ds_next);

	lni->ln_ds_next = dset->ds_postq;
	dset->ds_postq  = lni;
}

static struct silofs_lnode_info *dset_pop_preq(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = nullptr;

	if (dset->ds_preq != nullptr) {
		lni             = dset->ds_preq;
		dset->ds_preq   = lni->ln_ds_next;
		lni->ln_ds_next = nullptr;
	}
	return lni;
}

static void dset_moveq(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni;

	lni = dset_pop_preq(dset);
	if (lni != nullptr) {
		dset_push_postq(dset, lni);
	}
}

static struct silofs_lnode_info *
dset_preq_front(const struct silofs_dset *dset)
{
	return dset->ds_preq;
}

static void dset_seal_all(const struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_preq;

	while (lni != nullptr) {
		lni_seal_meta(lni);
		lni = lni->ln_ds_next;
	}
}

static void dset_mkfifo(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni;
	const struct silofs_avl_node *end;
	const struct silofs_avl_node *itr;
	const struct silofs_avl *avl = &dset->ds_avl;

	silofs_assert_null(dset->ds_preq);

	itr = silofs_avl_begin(avl);
	end = silofs_avl_end(avl);
	while (itr != end) {
		lni = avl_node_to_lni(itr);
		dset_push_preq(dset, lni);
		itr = silofs_avl_next(avl, itr);
	}
}

static void dset_undirtify_all(const struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_postq;

	while (lni != nullptr) {
		undirtify_lnode(lni);
		lni = lni->ln_ds_next;
	}
}

static void dset_unlink_queues(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni_next = nullptr;
	struct silofs_lnode_info *lni      = nullptr;

	lni = dset->ds_preq;
	while (lni != nullptr) {
		lni_next        = lni->ln_ds_next;
		lni->ln_ds_next = nullptr;
		lni             = lni_next;
	}
	dset->ds_preq = nullptr;

	lni = dset->ds_postq;
	while (lni != nullptr) {
		lni_next        = lni->ln_ds_next;
		lni->ln_ds_next = nullptr;
		lni             = lni_next;
	}
	dset->ds_postq = nullptr;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flusher_dset_slot_of(const struct silofs_flusher *flusher,
                                   enum silofs_vtype vtype)
{
	size_t slot;

	STATICASSERT_EQ(ARRAY_SIZE(flusher->dset), 3);

	if (silofs_vtype_isdata(vtype)) {
		slot = 0;
	} else if (silofs_vtype_isvnode(vtype)) {
		slot = 1;
	} else {
		slot = 2;
	}
	return slot;
}

static void flusher_init_dsets(struct silofs_flusher *flusher)
{
	for (size_t i = 0; i < ARRAY_SIZE(flusher->dset); ++i) {
		dset_init(&flusher->dset[i]);
	}
}

static void flusher_reinit_dsets(struct silofs_flusher *flusher)
{
	for (size_t i = 0; i < ARRAY_SIZE(flusher->dset); ++i) {
		dset_clear_map(&flusher->dset[i]);
		dset_init(&flusher->dset[i]);
	}
}

static void flusher_fini_dsets(struct silofs_flusher *flusher)
{
	for (size_t i = 0; i < ARRAY_SIZE(flusher->dset); ++i) {
		dset_fini(&flusher->dset[i]);
	}
}

static struct silofs_dset *
flusher_dset_at(struct silofs_flusher *flusher, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(flusher->dset));

	return &flusher->dset[slot];
}

static struct silofs_dset *
flusher_dset_of(struct silofs_flusher *flusher, enum silofs_vtype vtype)
{
	const size_t slot = flusher_dset_slot_of(flusher, vtype);

	return flusher_dset_at(flusher, slot);
}

static const struct silofs_dset *
flusher_dset_at2(const struct silofs_flusher *flusher, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(flusher->dset));

	return &flusher->dset[slot];
}

static struct silofs_dset *
flusher_dset_of_vni(struct silofs_flusher *flusher,
                    const struct silofs_vnode_info *vni)
{
	return flusher_dset_of(flusher, silofs_vni_vtype(vni));
}

static struct silofs_dset *
flusher_dset_of_uni(struct silofs_flusher *flusher,
                    const struct silofs_unode_info *uni)
{
	return flusher_dset_of(flusher, silofs_uni_vtype(uni));
}

static void flusher_add_dirty_vni(struct silofs_flusher *flusher,
                                  struct silofs_vnode_info *vni)
{
	struct silofs_dset *dset = flusher_dset_of_vni(flusher, vni);

	dset_add_dirty(dset, &vni->vn_lni);
}

static void flusher_add_dirty_uni(struct silofs_flusher *flusher,
                                  struct silofs_unode_info *uni)
{
	struct silofs_dset *dset = flusher_dset_of_uni(flusher, uni);

	dset_add_dirty(dset, &uni->un_lni);
}

static void flusher_add_dirty_vnis_of(struct silofs_flusher *flusher,
                                      struct silofs_dirtyq *dq)
{
	struct silofs_dq_elem *dqe    = nullptr;
	struct silofs_vnode_info *vni = nullptr;

	dqe = silofs_dirtyq_front(dq);
	while (dqe != nullptr) {
		vni = silofs_vni_from_dqe(dqe);
		if (vni_may_flush(vni)) {
			flusher_add_dirty_vni(flusher, vni);
		}
		dqe = silofs_dirtyq_next_of(dq, dqe);
	}
}

static void flusher_add_dirty_ii(struct silofs_flusher *flusher,
                                 struct silofs_inode_info *ii)
{
	flusher_add_dirty_vnis_of(flusher, &ii->i_dq_vnis);
	flusher_add_dirty_vni(flusher, &ii->i_vni);
}

static void flusher_add_dirty_iis_of(struct silofs_flusher *flusher,
                                     struct silofs_dirtyq *dq)
{
	struct silofs_dq_elem *dqe   = nullptr;
	struct silofs_inode_info *ii = nullptr;

	dqe = silofs_dirtyq_front(dq);
	while (dqe != nullptr) {
		ii = silofs_ii_from_dqe(dqe);
		flusher_add_dirty_ii(flusher, ii);
		dqe = silofs_dirtyq_next_of(dq, dqe);
	}
}

static void flusher_add_dirty_unis_of(struct silofs_flusher *flusher,
                                      struct silofs_dirtyq *dq)
{
	struct silofs_dq_elem *dqe    = nullptr;
	struct silofs_unode_info *uni = nullptr;

	dqe = silofs_dirtyq_front(dq);
	while (dqe != nullptr) {
		uni = uni_from_dqe(dqe);
		flusher_add_dirty_uni(flusher, uni);
		dqe = silofs_dirtyq_next_of(dq, dqe);
	}
}

static struct silofs_lcache *
flusher_lcache(const struct silofs_flusher *flusher)
{
	silofs_assert_not_null(flusher->task);
	silofs_assert_not_null(flusher->task->lcache);

	return flusher->task->lcache;
}

static void flusher_add_dirty_alt_of(struct silofs_flusher *flusher)
{
	struct silofs_lcache *lcache = flusher_lcache(flusher);

	flusher_add_dirty_vnis_of(flusher, &lcache->lc_vc.vc_vnis_dq);
	flusher_add_dirty_unis_of(flusher, &lcache->lc_unis_dq);
}

static void flusher_add_dirty_any_of(struct silofs_flusher *flusher)
{
	struct silofs_lcache *lcache = flusher_lcache(flusher);

	flusher_add_dirty_iis_of(flusher, &lcache->lc_vc.vc_iis_dq);
	flusher_add_dirty_vnis_of(flusher, &lcache->lc_vc.vc_vnis_dq);
	flusher_add_dirty_unis_of(flusher, &lcache->lc_unis_dq);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_submitq_ent *sqe_from_qlh(struct silofs_list_head *qlh)
{
	return silofs_sqe_from_qlh(qlh);
}

static void flusher_init_txq(struct silofs_flusher *flusher)
{
	listq_init(&flusher->txq);
}

static void flusher_fini_txq(struct silofs_flusher *flusher)
{
	listq_fini(&flusher->txq);
}

static void flusher_enqueue_sqe(struct silofs_flusher *flusher,
                                struct silofs_submitq_ent *sqe)
{
	listq_push_back(&flusher->txq, &sqe->qlh);
	flusher->tx_count++;
}

static struct silofs_submitq_ent *
flusher_dequeue_sqe(struct silofs_flusher *flusher)
{
	struct silofs_list_head *qlh;
	struct silofs_submitq_ent *sqe = nullptr;

	qlh = listq_pop_front(&flusher->txq);
	if (qlh != nullptr) {
		sqe = sqe_from_qlh(qlh);
	}
	return sqe;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_env *flusher_env(const struct silofs_flusher *flusher)
{
	silofs_assert_not_null(flusher->task);

	return flusher->task->env;
}

static int flusher_require_mutable_llink(const struct silofs_flusher *flusher,
                                         const struct silofs_llink *llink)
{
	const struct silofs_env *env = flusher_env(flusher);
	bool mut;

	mut = silofs_sbi_ismutable_laddr(env->sbi, &llink->laddr);
	silofs_assert(mut);

	return mut ? 0 : -SILOFS_EROFS;
}

static void flusher_unode_nmeta(const struct silofs_flusher *flusher,
                                struct silofs_nmeta *out_nmeta)
{
	silofs_resolve_unode_nmeta(flusher->task->env, out_nmeta);
}

static int flusher_resolve_llink_of_uni(const struct silofs_flusher *flusher,
                                        const struct silofs_unode_info *uni,
                                        struct silofs_llink *out_llink)
{
	struct silofs_nmeta nmeta;
	int ret = 0;

	flusher_unode_nmeta(flusher, &nmeta);
	silofs_llink_of_uni(uni, &nmeta, out_llink);
	if (!uni_issuper(uni)) {
		ret = flusher_require_mutable_llink(flusher, out_llink);
	}
	return ret;
}

static int flusher_resolve_llink_of_vni(const struct silofs_flusher *flusher,
                                        const struct silofs_vnode_info *vni,
                                        struct silofs_llink *out_llink)
{
	silofs_llink_of_vni(vni, out_llink);
	return flusher_require_mutable_llink(flusher, out_llink);
}

static int flusher_pre_resolve_llink_of(const struct silofs_flusher *flusher,
                                        struct silofs_lnode_info *lni)
{
	struct silofs_vnode_info *vni = nullptr;
	int ret                       = 0;

	if (lni_isvnode(lni)) {
		vni = vni_from_lni(lni);
		ret = silofs_refresh_llink(flusher->task, vni);
	}
	return ret;
}

static int flusher_resolve_llink_of(const struct silofs_flusher *flusher,
                                    const struct silofs_lnode_info *lni,
                                    struct silofs_llink *out_llink)
{
	const struct silofs_unode_info *uni = nullptr;
	const struct silofs_vnode_info *vni = nullptr;
	int ret;

	if (lni_isunode(lni)) {
		uni = uni_from_lni(lni);
		ret = flusher_resolve_llink_of_uni(flusher, uni, out_llink);
	} else if (lni_isvnode(lni)) {
		vni = vni_from_lni(lni);
		ret = flusher_resolve_llink_of_vni(flusher, vni, out_llink);
	} else {
		silofs_panic("corrupted lnode: vtype=%d", (int)lni->ln_vtype);
		ret = -SILOFS_EFSCORRUPTED; /* makes clang-scan happy */
	}
	return ret;
}

static void flusher_relax_cache_now(const struct silofs_flusher *flusher)
{
	struct silofs_env *env = flusher_env(flusher);

	silofs_lcache_relax(env->base.lcache, SILOFS_CTLF_NOW);
}

static int flusher_do_make_sqe(struct silofs_flusher *flusher,
                               struct silofs_submitq_ent **out_sqe)
{
	struct silofs_submitq *smq = flusher->submitq;
	int retry                  = 4;
	int err;

	err = silofs_submitq_new_sqe(smq, out_sqe);
	while ((err == -SILOFS_ENOMEM) && (retry-- > 0)) {
		flusher_relax_cache_now(flusher);
		err = silofs_submitq_new_sqe(smq, out_sqe);
	}
	return err;
}

static int flusher_make_sqe(struct silofs_flusher *flusher,
                            struct silofs_submitq_ent **out_sqe)
{
	int err;

	err = flusher_do_make_sqe(flusher, out_sqe);
	if (err) {
		return err;
	}
	(*out_sqe)->env = flusher_env(flusher);
	return 0;
}

static void flusher_append_at(struct silofs_flusher *flusher, size_t pos,
                              const struct silofs_llink *llink,
                              const struct silofs_lnode_info *lni)
{
	struct silofs_submit_ref *ref = &flusher->sref[pos];

	silofs_assert_lt(pos, ARRAY_SIZE(flusher->sref));
	silofs_llink_assign(&ref->llink, llink);
	ref->view  = lni->ln_view;
	ref->vtype = lni->ln_vtype;
}

static bool flusher_append_next_ref(struct silofs_flusher *flusher,
                                    struct silofs_submitq_ent *sqe,
                                    const struct silofs_llink *llink,
                                    struct silofs_lnode_info *lni)
{
	const size_t cur = sqe->cnt;
	bool ok;

	if (cur >= ARRAY_SIZE(flusher->sref)) {
		return false;
	}
	ok = silofs_sqe_append_ref(sqe, &llink->laddr, lni);
	if (!ok) {
		return false;
	}
	flusher_append_at(flusher, cur, llink, lni);
	return true;
}

static int flusher_populate_sqe_refs(struct silofs_flusher *flusher,
                                     struct silofs_dset *dset,
                                     struct silofs_submitq_ent *sqe)
{
	struct silofs_llink llink;
	struct silofs_lnode_info *lni;
	int err;

	lni = dset_preq_front(dset);
	while (lni != nullptr) {
		err = flusher_pre_resolve_llink_of(flusher, lni);
		if (err) {
			return err;
		}
		err = flusher_resolve_llink_of(flusher, lni, &llink);
		if (err) {
			return err;
		}
		if (!flusher_append_next_ref(flusher, sqe, &llink, lni)) {
			break;
		}
		dset_moveq(dset);
		lni = dset_preq_front(dset);
	}
	return 0;
}

static void
flusher_del_sqe(struct silofs_flusher *flusher, struct silofs_submitq_ent *sqe)
{
	silofs_submitq_del_sqe(flusher->submitq, sqe);
}

static int flusher_setup_sqe_by_refs(struct silofs_flusher *flusher,
                                     struct silofs_submitq_ent *sqe)
{
	int retry = 4;
	int err;

	err = silofs_sqe_assign_iovs(sqe, flusher->sref);
	while ((err == -SILOFS_ENOMEM) && (retry-- > 0)) {
		flusher_relax_cache_now(flusher);
		err = silofs_sqe_assign_iovs(sqe, flusher->sref);
	}
	return err;
}

static int flusher_populate_sqe_by(struct silofs_flusher *flusher,
                                   struct silofs_dset *dset,
                                   struct silofs_submitq_ent *sqe)
{
	int err;

	err = flusher_populate_sqe_refs(flusher, dset, sqe);
	if (!err) {
		silofs_sqe_increfs(sqe);
		err = flusher_setup_sqe_by_refs(flusher, sqe);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool flusher_has_dirty_dset(struct silofs_flusher *flusher, size_t slot)
{
	const struct silofs_dset *dset = flusher_dset_at2(flusher, slot);

	return dset->ds_avl.size > 0;
}

static void flusher_make_fifo_dset(struct silofs_flusher *flusher, size_t slot)
{
	dset_mkfifo(flusher_dset_at(flusher, slot));
}

static void flusher_seal_dset(struct silofs_flusher *flusher, size_t slot)
{
	dset_seal_all(flusher_dset_at(flusher, slot));
}

static void flusher_undirtify_dset(struct silofs_flusher *flusher, size_t slot)
{
	dset_undirtify_all(flusher_dset_at(flusher, slot));
}

static void flusher_cleanup_dset(struct silofs_flusher *flusher, size_t slot)
{
	struct silofs_dset *dset = flusher_dset_at(flusher, slot);

	dset_unlink_queues(dset);
	dset_clear_map(dset);
}

static int flusher_prep_sqe(const struct silofs_flusher *flusher,
                            struct silofs_submitq_ent *sqe)
{
	struct silofs_env *env = flusher_env(flusher);

	return silofs_stage_lseg(env, &sqe->laddr_base.lsid);
}

static void flusher_submit_sqe(struct silofs_flusher *flusher,
                               struct silofs_submitq_ent *sqe)
{
	silofs_submitq_enqueue(flusher->submitq, sqe);
	silofs_task_update_id(flusher->task, sqe);
}

static void flusher_submit_txq(struct silofs_flusher *flusher)
{
	struct silofs_submitq_ent *sqe;
	uint32_t tx_index = 0;

	sqe = flusher_dequeue_sqe(flusher);
	while (sqe != nullptr) {
		sqe->tx_count = flusher->tx_count;
		sqe->tx_index = ++tx_index;
		flusher_submit_sqe(flusher, sqe);
		sqe = flusher_dequeue_sqe(flusher);
	}
}

static void flusher_discard_txq(struct silofs_flusher *flusher)
{
	struct silofs_submitq_ent *sqe;

	sqe = flusher_dequeue_sqe(flusher);
	while (sqe != nullptr) {
		flusher_del_sqe(flusher, sqe);
		sqe = flusher_dequeue_sqe(flusher);
	}
}

static int flusher_enqueue_dset_into(struct silofs_flusher *flusher,
                                     struct silofs_dset *dset,
                                     struct silofs_submitq_ent *sqe)
{
	int err;

	err = flusher_populate_sqe_by(flusher, dset, sqe);
	if (err) {
		return err;
	}
	err = flusher_prep_sqe(flusher, sqe);
	if (err) {
		return err;
	}
	return 0;
}

static int flusher_enqueue_dset(struct silofs_flusher *flusher, size_t slot)
{
	struct silofs_dset *dset;
	struct silofs_submitq_ent *sqe;
	int err;

	dset = flusher_dset_at(flusher, slot);
	while (dset->ds_preq != nullptr) {
		sqe = nullptr;
		err = flusher_make_sqe(flusher, &sqe);
		if (err) {
			return err;
		}
		err = flusher_enqueue_dset_into(flusher, dset, sqe);
		if (err) {
			flusher_del_sqe(flusher, sqe);
			return err;
		}
		flusher_enqueue_sqe(flusher, sqe);
	}
	return 0;
}

static int flusher_process_dset_at(struct silofs_flusher *flusher, size_t slot)
{
	int err;

	if (!flusher_has_dirty_dset(flusher, slot)) {
		return 0; /* no-op */
	}
	flusher_make_fifo_dset(flusher, slot);
	flusher_seal_dset(flusher, slot);
	err = flusher_enqueue_dset(flusher, slot);
	if (!err) {
		flusher_undirtify_dset(flusher, slot);
	}
	flusher_cleanup_dset(flusher, slot);
	return err;
}

static void flusher_fill_dsets(struct silofs_flusher *flusher)
{
	if ((flusher->ii == nullptr) || (flusher->flags & SILOFS_CTLF_NOW)) {
		flusher_add_dirty_any_of(flusher);
	} else {
		flusher_add_dirty_ii(flusher, flusher->ii);
		flusher_add_dirty_alt_of(flusher);
	}
}

static int flusher_process_dsets(struct silofs_flusher *flusher)
{
	int err;

	for (size_t slot = 0; slot < ARRAY_SIZE(flusher->dset); ++slot) {
		err = flusher_process_dset_at(flusher, slot);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int flusher_collect_flush_dirty(struct silofs_flusher *flusher)
{
	int err;

	flusher_fill_dsets(flusher);
	err = flusher_process_dsets(flusher);
	if (!err) {
		flusher_submit_txq(flusher);
	} else {
		flusher_discard_txq(flusher);
	}
	return err;
}

/*
 * TODO-0034: Issue flush sync to dirty lsegs
 *
 * Implement fsync at lsegs level and ensure that all of kernel's in-cache
 * data is flushed all the way to stable storage.
 */
static int flusher_complete_commits(const struct silofs_flusher *flusher)
{
	int ret = 0;

	if (flusher->flags & SILOFS_CTLF_NOW) {
		ret = silofs_task_submit(flusher->task, true);
	}
	return ret;
}

static int flusher_do_flush_dirty(struct silofs_flusher *flusher)
{
	int err;

	err = flusher_collect_flush_dirty(flusher);
	if (err) {
		log_warn("flush execute failure: err=%d", err);
		return err;
	}
	err = flusher_complete_commits(flusher);
	if (err) {
		log_warn("flush complete failure: err=%d", err);
		return err;
	}
	return 0;
}

static int flusher_flush_dirty(struct silofs_flusher *flusher)
{
	int err;

	silofs_ii_incref(flusher->ii);
	err = flusher_do_flush_dirty(flusher);
	silofs_ii_decref(flusher->ii);
	return err;
}

static void flusher_pre_flush_dirty(struct silofs_flusher *flusher)
{
	if (flusher->sbi != nullptr) {
		silofs_sbst_force_into_sb(flusher->sbi);
	}
}

static void
flusher_rebind(struct silofs_flusher *flusher, struct silofs_task_ctx *task,
               struct silofs_inode_info *ii, int flags)
{
	flusher_reinit_dsets(flusher);
	flusher->task     = task;
	flusher->sbi      = silofs_get_sbi(task);
	flusher->ii       = ii;
	flusher->tx_count = 0;
	flusher->flags    = flags;
}

static void flusher_unbind(struct silofs_flusher *flusher)
{
	flusher->task     = nullptr;
	flusher->sbi      = nullptr;
	flusher->ii       = nullptr;
	flusher->tx_count = 0;
	flusher->flags    = 0;
}

int silofs_flusher_init(struct silofs_flusher *flusher,
                        struct silofs_submitq *submitq)
{
	silofs_memzero(flusher, sizeof(*flusher));
	flusher_init_dsets(flusher);
	flusher_init_txq(flusher);
	flusher->submitq  = submitq;
	flusher->task     = nullptr;
	flusher->sbi      = nullptr;
	flusher->ii       = nullptr;
	flusher->tx_count = 0;
	flusher->flags    = 0;
	return 0;
}

void silofs_flusher_fini(struct silofs_flusher *flusher)
{
	if (flusher->submitq != nullptr) {
		flusher_fini_dsets(flusher);
		flusher_fini_txq(flusher);
		flusher->submitq = nullptr;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flush_threshold_of(int flags)
{
	size_t threshold;

	if (flags & (SILOFS_CTLF_NOW | SILOFS_CTLF_IDLE | SILOFS_CTLF_FSYNC)) {
		threshold = 0;
	} else if (flags & SILOFS_CTLF_RELEASE) {
		threshold = SILOFS_LSEG_SIZE_MAX / 2;
	} else if (flags & SILOFS_CTLF_INTERN) {
		threshold = SILOFS_LSEG_SIZE_MAX;
	} else if (flags & SILOFS_CTLF_OPSTART) {
		threshold = 2 * SILOFS_LSEG_SIZE_MAX;
	} else {
		threshold = 4 * SILOFS_LSEG_SIZE_MAX;
	}
	return threshold;
}

static bool need_flush_now(const struct silofs_task_ctx *task, int flags)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0, .nbytes_max = 0 };

	if (flags & SILOFS_CTLF_NOW) {
		return true;
	}
	silofs_memstat(task->env->alloc, &alst);
	if (alst.nbytes_use > (alst.nbytes_max / 2)) {
		return true;
	}
	return false;
}

static bool need_flush_by_ii(const struct silofs_inode_info *ii, int flags)
{
	size_t ndirty;
	size_t thresh;

	thresh = flush_threshold_of(flags);
	ndirty = ii->i_dq_vnis.dq_accum;
	return (ndirty > thresh);
}

static bool need_flush_by_env(const struct silofs_env *env, int flags)
{
	const struct silofs_lcache *lcache = env->base.lcache;
	size_t ndirty;
	size_t thresh;

	thresh = flush_threshold_of(flags);
	ndirty = lcache->lc_unis_dq.dq_accum +      //
	         lcache->lc_vc.vc_iis_dq.dq_accum + //
	         lcache->lc_vc.vc_vnis_dq.dq_accum;
	return (ndirty > thresh);
}

static bool need_flush_by(const struct silofs_task_ctx *task,
                          const struct silofs_inode_info *ii, int flags)
{
	bool ret = false;

	if (need_flush_now(task, flags)) {
		ret = true;
	} else if (ii != nullptr) {
		ret = need_flush_by_ii(ii, flags);
	} else {
		ret = need_flush_by_env(task->env, flags);
	}
	return ret;
}

static int do_flush_dirty(struct silofs_task_ctx *task,
                          struct silofs_inode_info *ii, int flags)
{
	struct silofs_flusher *flusher = task->env->base.flusher;
	int err;

	flusher_rebind(flusher, task, ii, flags);
	flusher_pre_flush_dirty(flusher);
	err = flusher_flush_dirty(flusher);
	if (err) {
		log_dbg("failed to flush: err=%d", err);
	}
	flusher_unbind(flusher);
	return err;
}

int silofs_flush_dirty(struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii, int flags)
{
	int err = 0;

	if (need_flush_by(task, ii, flags)) {
		silofs_ii_incref(ii);
		err = do_flush_dirty(task, ii, flags);
		silofs_ii_decref(ii);
	}
	return err;
}

int silofs_flush_dirty_now(struct silofs_task_ctx *task)
{
	return silofs_flush_dirty(task, nullptr, SILOFS_CTLF_NOW);
}

int silofs_destage_dirty_by(struct silofs_task_ctx *task)
{
	struct silofs_pexec_ctx pexec;

	silofs_make_pexec(task, &pexec);
	return silofs_destage_dirty(&pexec);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
sqe_setup_iov_at(struct silofs_submitq_ent *sqe, size_t idx, size_t len)
{
	STATICASSERT_LE(ARRAY_SIZE(sqe->iov), SILOFS_IOV_MAX);

	silofs_assert_lt(idx, ARRAY_SIZE(sqe->iov));
	silofs_assert_null(sqe->iov[idx].iov_base);

	sqe->iov[idx].iov_base = silofs_memalloc(sqe->alloc, len, 0);
	if (sqe->iov[idx].iov_base == nullptr) {
		return -SILOFS_ENOMEM;
	}
	sqe->iov[idx].iov_len = len;
	return 0;
}

static void sqe_reset_iovs(struct silofs_submitq_ent *sqe)
{
	for (size_t idx = 0; idx < sqe->cnt; ++idx) {
		silofs_memfree(sqe->alloc, sqe->iov[idx].iov_base,
		               sqe->iov[idx].iov_len, SILOFS_ALLOCF_NOPUNCH);
		sqe->iov[idx].iov_base = nullptr;
		sqe->iov[idx].iov_len  = 0;
	}
}

static bool sqe_isappendable(const struct silofs_submitq_ent *sqe,
                             const struct silofs_laddr *laddr)
{
	const struct silofs_laddr *sqe_laddr = &sqe->laddr_base;
	const ssize_t len_max                = SILOFS_COMMIT_LEN_MAX;
	size_t len;
	off_t end;
	off_t nxt;

	STATICASSERT_EQ(ARRAY_SIZE(sqe->iov), ARRAY_SIZE(sqe->lni));

	if (sqe->cnt == 0) {
		return true;
	}
	if (sqe->cnt == ARRAY_SIZE(sqe->iov)) {
		return false;
	}
	if (!silofs_lsid_isequal(&sqe_laddr->lsid, &laddr->lsid)) {
		return false;
	}
	end = silofs_off_end(sqe_laddr->pos, sqe->len);
	if (laddr->pos != end) {
		return false;
	}
	len = sqe->len + silofs_laddr_len(laddr);
	if (len > (size_t)len_max) {
		return false;
	}
	if (!silofs_vtype_isinode(sqe->vtype)) {
		return true;
	}
	/* for inodes require alignment on commit-len boundaries */
	nxt = silofs_off_next(sqe_laddr->pos, len_max);
	end = silofs_off_end(sqe_laddr->pos, len);
	if (end > nxt) {
		return false;
	}
	return true;
}

bool silofs_sqe_append_ref(struct silofs_submitq_ent *sqe,
                           const struct silofs_laddr *laddr,
                           struct silofs_lnode_info *lni)
{
	if (!sqe_isappendable(sqe, laddr)) {
		return false;
	}
	if (sqe->cnt == 0) {
		silofs_laddr_assign(&sqe->laddr_base, laddr);
		sqe->vtype = lni->ln_vtype;
	}
	sqe->len += silofs_laddr_len(laddr);
	sqe->lni[sqe->cnt++] = lni;
	return true;
}

static int sqe_setup_iovs(struct silofs_submitq_ent *sqe,
                          const struct silofs_submit_ref *refs_arr)
{
	const struct silofs_submit_ref *ref;
	size_t len;
	int err;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &refs_arr[i];
		len = silofs_laddr_len(&ref->llink.laddr);
		err = sqe_setup_iov_at(sqe, i, len);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int sqe_encrypted_iovs(struct silofs_submitq_ent *sqe,
                              const struct silofs_submit_ref *refs_arr)
{
	const struct silofs_submit_ref *ref = nullptr;
	int err;

	for (size_t i = 0; i < sqe->cnt; ++i) {
		ref = &refs_arr[i];
		err = silofs_encrypt_view(sqe->env, &ref->llink, ref->view,
		                          sqe->iov[i].iov_base);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_sqe_assign_iovs(struct silofs_submitq_ent *sqe,
                           const struct silofs_submit_ref *refs_arr)
{
	int err;

	err = sqe_setup_iovs(sqe, refs_arr);
	if (err) {
		goto out_err;
	}
	err = sqe_encrypted_iovs(sqe, refs_arr);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	sqe_reset_iovs(sqe);
	return err;
}

static int sqe_do_write(const struct silofs_submitq_ent *sqe)
{
	return silofs_repo_writev_at(sqe->env->base.repo, &sqe->laddr_base,
	                             sqe->iov, sqe->cnt);
}

void silofs_sqe_increfs(struct silofs_submitq_ent *sqe)
{
	if (!sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			silofs_lni_incref(sqe->lni[i]);
		}
		sqe->hold_refs = 1;
	}
}

static void sqe_decrefs(struct silofs_submitq_ent *sqe)
{
	if (sqe->hold_refs) {
		for (size_t i = 0; i < sqe->cnt; ++i) {
			silofs_lni_decref(sqe->lni[i]);
		}
		sqe->hold_refs = 0;
	}
}

static void sqe_init(struct silofs_submitq_ent *sqe,
                     struct silofs_alloc *alloc, uint64_t uniq_id)
{
	memset(sqe, 0, sizeof(*sqe));
	silofs_list_head_init(&sqe->qlh);
	silofs_laddr_reset(&sqe->laddr_base);
	sqe->alloc     = alloc;
	sqe->env       = nullptr;
	sqe->uniq_id   = uniq_id;
	sqe->len       = 0;
	sqe->cnt       = 0;
	sqe->hold_refs = 0;
	sqe->status    = 0;
}

static void sqe_fini(struct silofs_submitq_ent *sqe)
{
	silofs_list_head_fini(&sqe->qlh);
	silofs_laddr_reset(&sqe->laddr_base);
	sqe_reset_iovs(sqe);
	sqe->len    = 0;
	sqe->cnt    = 0;
	sqe->alloc  = nullptr;
	sqe->status = -1;
}

static struct silofs_submitq_ent *
sqe_new(struct silofs_alloc *alloc, uint64_t uniq_id)
{
	struct silofs_submitq_ent *sqe;

	STATICASSERT_LE(sizeof(*sqe), 1024);

	sqe = silofs_memalloc(alloc, sizeof(*sqe), 0);
	if (likely(sqe != nullptr)) {
		sqe_init(sqe, alloc, uniq_id);
	}
	return sqe;
}

static void sqe_del(struct silofs_submitq_ent *sqe, struct silofs_alloc *alloc)
{
	sqe_fini(sqe);
	silofs_memfree(alloc, sqe, sizeof(*sqe), SILOFS_ALLOCF_NOPUNCH);
}

struct silofs_submitq_ent *silofs_sqe_from_qlh(struct silofs_list_head *qlh)
{
	struct silofs_submitq_ent *sqe = nullptr;

	if (qlh != nullptr) {
		sqe = container_of(qlh, struct silofs_submitq_ent, qlh);
	}
	return sqe;
}

static int sqe_apply(struct silofs_submitq_ent *sqe)
{
	sqe->status = sqe_do_write(sqe);
	return sqe->status;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_submitq_init(struct silofs_submitq *smq, struct silofs_alloc *alloc)
{
	memset(smq, 0, sizeof(*smq));
	silofs_listq_init(&smq->smq_listq);
	smq->smq_alloc    = alloc;
	smq->smq_upper_id = 1;
	return silofs_mutex_init(&smq->smq_mutex);
}

void silofs_submitq_fini(struct silofs_submitq *smq)
{
	silofs_mutex_fini(&smq->smq_mutex);
	silofs_listq_fini(&smq->smq_listq);
	smq->smq_upper_id = 0;
}

static struct silofs_submitq_ent *submitq_front_sqe(struct silofs_submitq *smq)
{
	struct silofs_list_head *lh;

	lh = listq_front(&smq->smq_listq);
	return silofs_sqe_from_qlh(lh);
}

static void
submitq_unlink_sqe(struct silofs_submitq *smq, struct silofs_submitq_ent *sqe)
{
	listq_remove(&smq->smq_listq, &sqe->qlh);
}

static void
submitq_push_sqe(struct silofs_submitq *smq, struct silofs_submitq_ent *sqe)
{
	listq_push_back(&smq->smq_listq, &sqe->qlh);
}

void silofs_submitq_enqueue(struct silofs_submitq *smq,
                            struct silofs_submitq_ent *sqe)
{
	silofs_mutex_lock(&smq->smq_mutex);
	submitq_push_sqe(smq, sqe);
	silofs_mutex_unlock(&smq->smq_mutex);
}

static struct silofs_submitq_ent *
submitq_get_sqe(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_ent *sqe;

	sqe = submitq_front_sqe(smq);
	if (sqe == nullptr) {
		return nullptr;
	}
	if (sqe->uniq_id > id) {
		return nullptr;
	}
	return sqe;
}

static int submitq_apply_one(struct silofs_submitq *smq, uint64_t id,
                             struct silofs_submitq_ent **out_sqe)
{
	struct silofs_submitq_ent *sqe;
	int ret = 0;

	silofs_mutex_lock(&smq->smq_mutex);
	sqe = submitq_get_sqe(smq, id);
	if (sqe != nullptr) {
		submitq_unlink_sqe(smq, sqe);
		ret = sqe_apply(sqe);
	}
	silofs_mutex_unlock(&smq->smq_mutex);
	*out_sqe = sqe;
	return ret;
}

int silofs_submitq_apply(struct silofs_submitq *smq, uint64_t id)
{
	struct silofs_submitq_ent *sqe = nullptr;
	int ret                        = 0;

	while (ret == 0) {
		sqe = nullptr;
		ret = submitq_apply_one(smq, id, &sqe);
		if (sqe == nullptr) {
			break;
		}
		silofs_submitq_del_sqe(smq, sqe);
	}
	return ret;
}

int silofs_submitq_new_sqe(struct silofs_submitq *smq,
                           struct silofs_submitq_ent **out_sqe)
{
	*out_sqe = sqe_new(smq->smq_alloc, smq->smq_upper_id++);
	return likely(*out_sqe != nullptr) ? 0 : -SILOFS_ENOMEM;
}

void silofs_submitq_del_sqe(struct silofs_submitq *smq,
                            struct silofs_submitq_ent *sqe)
{
	sqe_decrefs(sqe);
	sqe_reset_iovs(sqe);
	sqe_del(sqe, smq->smq_alloc);
}
