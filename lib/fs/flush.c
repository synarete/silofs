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
#include <silofs/fs.h>


static bool lni_isunode(const struct silofs_lnode_info *lni)
{
	return ltype_isunode(lni->ln_ltype);
}

static bool lni_isvnode(const struct silofs_lnode_info *lni)
{
	return ltype_isvnode(lni->ln_ltype);
}

static bool lni_isdata(const struct silofs_lnode_info *lni)
{
	return ltype_isdata(lni->ln_ltype);
}

static bool uni_issuper(const struct silofs_unode_info *uni)
{
	return ltype_issuper(uni_ltype(uni));
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
	const int asyncwr = silofs_atomic_get(&vni->vn_asyncwr);

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
		silofs_vni_seal_view(vni_from_lni(lni));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void undirtify_lnode(struct silofs_lnode_info *lni)
{
	struct silofs_vnode_info *vni = NULL;
	struct silofs_unode_info *uni = NULL;

	if (lni_isvnode(lni)) {
		vni = vni_from_lni(lni);
		silofs_vni_undirtify(vni);
	} else if (lni_isunode(lni)) {
		uni = uni_from_lni(lni);
		silofs_uni_undirtify(uni);
	} else {
		silofs_panic("bad lnode: ltype=%d", (int)(lni->ln_ltype));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dset_clear_map(struct silofs_dset *dset)
{
	const struct silofs_avl_node_functor fn = { .fn = lni_visit_reinit,
						    .ctx = NULL };

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
	dset->ds_preq = NULL;
	dset->ds_postq = NULL;
}

static void dset_fini(struct silofs_dset *dset)
{
	silofs_avl_fini(&dset->ds_avl);
	dset->ds_preq = NULL;
	dset->ds_postq = NULL;
}

static void
dset_push_preq(struct silofs_dset *dset, struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->ln_ds_next);

	lni->ln_ds_next = dset->ds_preq;
	dset->ds_preq = lni;
}

static void
dset_push_postq(struct silofs_dset *dset, struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->ln_ds_next);

	lni->ln_ds_next = dset->ds_postq;
	dset->ds_postq = lni;
}

static struct silofs_lnode_info *dset_pop_preq(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = NULL;

	if (dset->ds_preq != NULL) {
		lni = dset->ds_preq;
		dset->ds_preq = lni->ln_ds_next;
		lni->ln_ds_next = NULL;
	}
	return lni;
}

static void dset_moveq(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni;

	lni = dset_pop_preq(dset);
	if (lni != NULL) {
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

	while (lni != NULL) {
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

	while (lni != NULL) {
		undirtify_lnode(lni);
		lni = lni->ln_ds_next;
	}
}

static void dset_unlink_queues(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni_next = NULL;
	struct silofs_lnode_info *lni = NULL;

	lni = dset->ds_preq;
	while (lni != NULL) {
		lni_next = lni->ln_ds_next;
		lni->ln_ds_next = NULL;
		lni = lni_next;
	}
	dset->ds_preq = NULL;

	lni = dset->ds_postq;
	while (lni != NULL) {
		lni_next = lni->ln_ds_next;
		lni->ln_ds_next = NULL;
		lni = lni_next;
	}
	dset->ds_postq = NULL;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flusher_dset_slot_of(const struct silofs_flusher *flusher,
				   enum silofs_ltype ltype)
{
	size_t slot;

	STATICASSERT_EQ(ARRAY_SIZE(flusher->dset), 3);

	if (ltype_isdata(ltype)) {
		slot = 0;
	} else if (ltype_isvnode(ltype)) {
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
flusher_dset_of(struct silofs_flusher *flusher, const enum silofs_ltype ltype)
{
	const size_t slot = flusher_dset_slot_of(flusher, ltype);

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
	return flusher_dset_of(flusher, vni_ltype(vni));
}

static struct silofs_dset *
flusher_dset_of_uni(struct silofs_flusher *flusher,
		    const struct silofs_unode_info *uni)
{
	return flusher_dset_of(flusher, uni_ltype(uni));
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
	struct silofs_dq_elem *dqe = NULL;
	struct silofs_vnode_info *vni = NULL;

	dqe = silofs_dirtyq_front(dq);
	while (dqe != NULL) {
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
	struct silofs_dq_elem *dqe = NULL;
	struct silofs_inode_info *ii = NULL;

	dqe = silofs_dirtyq_front(dq);
	while (dqe != NULL) {
		ii = silofs_ii_from_dqe(dqe);
		flusher_add_dirty_ii(flusher, ii);
		dqe = silofs_dirtyq_next_of(dq, dqe);
	}
}

static void flusher_add_dirty_unis_of(struct silofs_flusher *flusher,
				      struct silofs_dirtyq *dq)
{
	struct silofs_dq_elem *dqe = NULL;
	struct silofs_unode_info *uni = NULL;

	dqe = silofs_dirtyq_front(dq);
	while (dqe != NULL) {
		uni = uni_from_dqe(dqe);
		flusher_add_dirty_uni(flusher, uni);
		dqe = silofs_dirtyq_next_of(dq, dqe);
	}
}

static void flusher_add_dirty_alt_of(struct silofs_flusher *flusher,
				     struct silofs_dirtyqs *dqs)
{
	flusher_add_dirty_vnis_of(flusher, &dqs->dq_vnis);
	flusher_add_dirty_unis_of(flusher, &dqs->dq_unis);
}

static void flusher_add_dirty_any_of(struct silofs_flusher *flusher,
				     struct silofs_dirtyqs *dqs)
{
	flusher_add_dirty_iis_of(flusher, &dqs->dq_iis);
	flusher_add_dirty_alt_of(flusher, dqs);
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
	struct silofs_submitq_ent *sqe = NULL;

	qlh = listq_pop_front(&flusher->txq);
	if (qlh != NULL) {
		sqe = sqe_from_qlh(qlh);
	}
	return sqe;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_fsenv *
flusher_fsenv_from_task(const struct silofs_flusher *flusher)
{
	silofs_assert_not_null(flusher->task);

	return flusher->task->t_fsenv;
}

static struct silofs_dirtyqs *
flusher_dirtyqs_from_task(const struct silofs_flusher *flusher)
{
	const struct silofs_fsenv *fsenv = flusher_fsenv_from_task(flusher);

	return &fsenv->fse.lcache->lc_dirtyqs;
}

static int flusher_require_mutable_llink(const struct silofs_flusher *flusher,
					 const struct silofs_llink *llink)
{
	const struct silofs_fsenv *fsenv = flusher_fsenv_from_task(flusher);
	int err = 0;
	bool mut;

	mut = silofs_sbi_ismutable_laddr(fsenv->fse_sbi, &llink->laddr);
	err = mut ? 0 : -SILOFS_EROFS;
	silofs_assert_ok(err);
	return err;
}

static int flusher_resolve_llink_of_uni(const struct silofs_flusher *flusher,
					const struct silofs_unode_info *uni,
					struct silofs_llink *out_llink)
{
	int ret = 0;

	silofs_ulink_as_llink(uni_ulink(uni), out_llink);
	if (!uni_issuper(uni)) {
		ret = flusher_require_mutable_llink(flusher, out_llink);
	}
	return ret;
}

static int flusher_resolve_llink_of_vni(const struct silofs_flusher *flusher,
					const struct silofs_vnode_info *vni,
					struct silofs_llink *out_llink)
{
	silofs_llink_assign(out_llink, &vni->vn_llink);
	return flusher_require_mutable_llink(flusher, out_llink);
}

static int flusher_pre_resolve_llink_of(const struct silofs_flusher *flusher,
					struct silofs_lnode_info *lni)
{
	struct silofs_vnode_info *vni = NULL;
	int ret = 0;

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
	const struct silofs_unode_info *uni = NULL;
	const struct silofs_vnode_info *vni = NULL;
	int ret;

	if (lni_isunode(lni)) {
		uni = uni_from_lni(lni);
		ret = flusher_resolve_llink_of_uni(flusher, uni, out_llink);
	} else if (lni_isvnode(lni)) {
		vni = vni_from_lni(lni);
		ret = flusher_resolve_llink_of_vni(flusher, vni, out_llink);
	} else {
		silofs_panic("corrupted lnode: ltype=%d", (int)lni->ln_ltype);
		ret = -SILOFS_EFSCORRUPTED; /* makes clang-scan happy */
	}
	return ret;
}

static void flusher_relax_cache_now(const struct silofs_flusher *flusher)
{
	struct silofs_fsenv *fsenv = flusher_fsenv_from_task(flusher);

	silofs_lcache_relax(fsenv->fse.lcache, SILOFS_F_NOW);
}

static int flusher_do_make_sqe(struct silofs_flusher *flusher,
			       struct silofs_submitq_ent **out_sqe)
{
	struct silofs_submitq *smq = flusher->submitq;
	int retry = 4;
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
	(*out_sqe)->fsenv = flusher_fsenv_from_task(flusher);
	return 0;
}

static void flusher_append_at(struct silofs_flusher *flusher, size_t pos,
			      const struct silofs_llink *llink,
			      const struct silofs_lnode_info *lni)
{
	struct silofs_submit_ref *ref = &flusher->sref[pos];

	silofs_assert_lt(pos, ARRAY_SIZE(flusher->sref));
	silofs_llink_assign(&ref->llink, llink);
	ref->view = lni->ln_view;
	ref->ltype = lni->ln_ltype;
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
	while (lni != NULL) {
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
	struct silofs_fsenv *fsenv = flusher_fsenv_from_task(flusher);

	return silofs_stage_lseg(fsenv, &sqe->laddr.lsid);
}

static void flusher_submit_sqe(struct silofs_flusher *flusher,
			       struct silofs_submitq_ent *sqe)
{
	silofs_submitq_enqueue(flusher->submitq, sqe);
	silofs_task_update_by(flusher->task, sqe);
}

static void flusher_submit_txq(struct silofs_flusher *flusher)
{
	struct silofs_submitq_ent *sqe;
	uint32_t tx_index = 0;

	sqe = flusher_dequeue_sqe(flusher);
	while (sqe != NULL) {
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
	while (sqe != NULL) {
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
	while (dset->ds_preq != NULL) {
		sqe = NULL;
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
	struct silofs_dirtyqs *dirtyqs = flusher_dirtyqs_from_task(flusher);

	if ((flusher->ii == NULL) || (flusher->flags & SILOFS_F_NOW)) {
		flusher_add_dirty_any_of(flusher, dirtyqs);
	} else {
		flusher_add_dirty_ii(flusher, flusher->ii);
		flusher_add_dirty_alt_of(flusher, dirtyqs);
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

	if (flusher->flags & SILOFS_F_NOW) {
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

	ii_incref(flusher->ii);
	err = flusher_do_flush_dirty(flusher);
	ii_decref(flusher->ii);
	return err;
}

static void
flusher_rebind(struct silofs_flusher *flusher, struct silofs_task *task,
	       struct silofs_inode_info *ii, int flags)
{
	flusher_reinit_dsets(flusher);
	flusher->task = task;
	flusher->ii = ii;
	flusher->tx_count = 0;
	flusher->flags = flags;
}

static void flusher_unbind(struct silofs_flusher *flusher)
{
	flusher->task = NULL;
	flusher->ii = NULL;
	flusher->tx_count = 0;
	flusher->flags = 0;
}

int silofs_flusher_init(struct silofs_flusher *flusher,
			struct silofs_submitq *submitq)
{
	silofs_memzero(flusher, sizeof(*flusher));
	flusher_init_dsets(flusher);
	flusher_init_txq(flusher);
	flusher->submitq = submitq;
	flusher->task = NULL;
	flusher->ii = NULL;
	flusher->tx_count = 0;
	flusher->flags = 0;
	return 0;
}

void silofs_flusher_fini(struct silofs_flusher *flusher)
{
	if (flusher->submitq != NULL) {
		flusher_fini_dsets(flusher);
		flusher_fini_txq(flusher);
		flusher->submitq = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flush_threshold_of(int flags)
{
	size_t threshold;

	if (flags & (SILOFS_F_NOW | SILOFS_F_IDLE | SILOFS_F_FSYNC)) {
		threshold = 0;
	} else if (flags & SILOFS_F_RELEASE) {
		threshold = SILOFS_LSEG_SIZE_MAX / 2;
	} else if (flags & SILOFS_F_INTERN) {
		threshold = SILOFS_LSEG_SIZE_MAX;
	} else if (flags & SILOFS_F_OPSTART) {
		threshold = 2 * SILOFS_LSEG_SIZE_MAX;
	} else {
		threshold = 4 * SILOFS_LSEG_SIZE_MAX;
	}
	return threshold;
}

static bool need_flush_now(const struct silofs_task *task, int flags)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0, .nbytes_max = 0 };

	if (flags & SILOFS_F_NOW) {
		return true;
	}
	silofs_memstat(task->t_fsenv->fse.alloc, &alst);
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

static bool need_flush_by_fsenv(const struct silofs_fsenv *fsenv, int flags)
{
	const struct silofs_lcache *lcache = fsenv->fse.lcache;
	const struct silofs_dirtyqs *dqs = &lcache->lc_dirtyqs;
	size_t ndirty;
	size_t thresh;

	thresh = flush_threshold_of(flags);
	ndirty = dqs->dq_unis.dq_accum + dqs->dq_iis.dq_accum +
		 dqs->dq_vnis.dq_accum;
	return (ndirty > thresh);
}

static bool need_flush_by(const struct silofs_task *task,
			  const struct silofs_inode_info *ii, int flags)
{
	bool ret = false;

	if (need_flush_now(task, flags)) {
		ret = true;
	} else if (ii != NULL) {
		ret = need_flush_by_ii(ii, flags);
	} else {
		ret = need_flush_by_fsenv(task->t_fsenv, flags);
	}
	return ret;
}

int silofs_flush_dirty(struct silofs_task *task, struct silofs_inode_info *ii,
		       int flags)
{
	struct silofs_flusher *flusher = task->t_fsenv->fse.flusher;
	int err;

	if (!need_flush_by(task, ii, flags)) {
		return 0;
	}
	flusher_rebind(flusher, task, ii, flags);
	err = flusher_flush_dirty(flusher);
	if (err) {
		log_dbg("failed to flush: err=%d", err);
	}
	flusher_unbind(flusher);
	return err;
}

int silofs_flush_dirty_now(struct silofs_task *task)
{
	return silofs_flush_dirty(task, NULL, SILOFS_F_NOW);
}
