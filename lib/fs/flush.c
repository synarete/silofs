/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/fs-private.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ui_issuper(const struct silofs_unode_info *ui)
{
	return stype_issuper(ui_stype(ui));
}

static const struct silofs_unode_info *
ui_from(const struct silofs_lnode_info *lni)
{
	return silofs_ui_from_lni(lni);
}

static struct silofs_vnode_info *
vi_from(struct silofs_lnode_info *lni)
{
	return silofs_vi_from_lni(lni);
}

static bool vi_may_flush(const struct silofs_vnode_info *vi)
{
	const int asyncwr = silofs_atomic_get(&vi->v_asyncwr);

	return (asyncwr == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long ckey_compare(const void *x, const void *y)
{
	const struct silofs_ckey *ckey_x = x;
	const struct silofs_ckey *ckey_y = y;

	return silofs_ckey_compare(ckey_x, ckey_y);
}

static struct silofs_lnode_info *
avl_node_to_lni(const struct silofs_avl_node *an)
{
	const struct silofs_lnode_info *lni;

	lni = container_of2(an, struct silofs_lnode_info, l_ds_avl_node);
	return unconst(lni);
}

static const void *lni_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_lnode_info *lni = avl_node_to_lni(an);

	return &lni->l_ce.ce_ckey;
}

static void lni_visit_reinit(struct silofs_avl_node *an, void *p)
{
	struct silofs_lnode_info *lni = avl_node_to_lni(an);

	silofs_avl_node_init(&lni->l_ds_avl_node);
	unused(p);
}

static void lni_seal_meta(struct silofs_lnode_info *lni)
{
	const enum silofs_stype stype = lni->l_stype;

	if (stype_isunode(stype)) {
		silofs_seal_unode(silofs_ui_from_lni(lni));
	} else if (stype_isvnode(stype) && !stype_isdata(stype)) {
		silofs_seal_vnode(silofs_vi_from_lni(lni));
	}
}

static void dset_clear_map(struct silofs_dset *dset)
{
	const struct silofs_avl_node_functor fn = {
		.fn = lni_visit_reinit,
		.ctx = NULL
	};

	silofs_avl_clear(&dset->ds_avl, &fn);
}

static void dset_add_dirty(struct silofs_dset *dset,
                           struct silofs_lnode_info *lni)
{
	silofs_avl_insert(&dset->ds_avl, &lni->l_ds_avl_node);
}

static void dset_init(struct silofs_dset *dset)
{
	silofs_avl_init(&dset->ds_avl, lni_getkey, ckey_compare, dset);
	dset->ds_preq = NULL;
	dset->ds_postq = NULL;
}

static void dset_fini(struct silofs_dset *dset)
{
	silofs_avl_fini(&dset->ds_avl);
	dset->ds_preq = NULL;
	dset->ds_postq = NULL;
}

static void dset_push_preq(struct silofs_dset *dset,
                           struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->l_ds_next);

	lni->l_ds_next = dset->ds_preq;
	dset->ds_preq = lni;
}

static void dset_push_postq(struct silofs_dset *dset,
                            struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->l_ds_next);

	lni->l_ds_next = dset->ds_postq;
	dset->ds_postq = lni;
}

static void dset_moveq(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_preq;

	if (lni != NULL) {
		dset->ds_preq = dset->ds_preq->l_ds_next;
		lni->l_ds_next = NULL;
		dset_push_postq(dset, lni);
	}
}

static void dset_seal_all(const struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_preq;

	while (lni != NULL) {
		lni_seal_meta(lni);
		lni = lni->l_ds_next;
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

static void lni_undirtify(struct silofs_lnode_info *lni)
{
	struct silofs_unode_info *ui = NULL;
	struct silofs_vnode_info *vi = NULL;

	if (stype_isvnode(lni->l_stype)) {
		vi = silofs_vi_from_lni(lni);
		silofs_vi_undirtify(vi);
	} else {
		silofs_assert(stype_isunode(lni->l_stype));
		ui = silofs_ui_from_lni(lni);
		silofs_ui_undirtify(ui);
	}
}

static void dset_undirtify_all(const struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_postq;

	while (lni != NULL) {
		lni_undirtify(lni);
		lni = lni->l_ds_next;
	}
}

static void dset_unlink_queues(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni_next = NULL;
	struct silofs_lnode_info *lni = NULL;

	lni = dset->ds_preq;
	while (lni != NULL) {
		lni_next = lni->l_ds_next;
		lni->l_ds_next = NULL;
		lni = lni_next;
	}
	dset->ds_preq = NULL;

	lni = dset->ds_postq;
	while (lni != NULL) {
		lni_next = lni->l_ds_next;
		lni->l_ds_next = NULL;
		lni = lni_next;
	}
	dset->ds_postq = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dsets_init(struct silofs_dsets *dsets)
{
	for (size_t i = 0; i < ARRAY_SIZE(dsets->dset); ++i) {
		dset_init(&dsets->dset[i]);
	}
}

static void dsets_reinit(struct silofs_dsets *dsets)
{
	for (size_t i = 0; i < ARRAY_SIZE(dsets->dset); ++i) {
		dset_clear_map(&dsets->dset[i]);
		dset_init(&dsets->dset[i]);
	}
}

static void dsets_fini(struct silofs_dsets *dsets)
{
	for (size_t i = 0; i < ARRAY_SIZE(dsets->dset); ++i) {
		dset_fini(&dsets->dset[i]);
	}
}

static struct silofs_dset *
dsets_get_by(struct silofs_dsets *dsets, const enum silofs_stype stype)
{
	const size_t idx = min((size_t)stype, (ARRAY_SIZE(dsets->dset) - 1));

	return &dsets->dset[idx];
}

static struct silofs_dset *
dsets_get_by_vi(struct silofs_dsets *dsets, const struct silofs_vnode_info *vi)
{
	return dsets_get_by(dsets, vi_stype(vi));
}

static struct silofs_dset *
dsets_get_by_ui(struct silofs_dsets *dsets, const struct silofs_unode_info *ui)
{
	return dsets_get_by(dsets, ui_stype(ui));
}

static void dsets_add_by_vi(struct silofs_dsets *dsets,
                            struct silofs_vnode_info *vi)
{
	struct silofs_dset *dset = dsets_get_by_vi(dsets, vi);

	dset_add_dirty(dset, &vi->v_lni);
}

static void dsets_add_by_ui(struct silofs_dsets *dsets,
                            struct silofs_unode_info *ui)
{
	struct silofs_dset *dset = dsets_get_by_ui(dsets, ui);

	dset_add_dirty(dset, &ui->u_lni);
}

static void dsets_fill_vis_of(struct silofs_dsets *dsets,
                              struct silofs_dirtyq *dq)
{
	struct silofs_list_head *lh = NULL;
	struct silofs_vnode_info *vi = NULL;

	lh = silofs_dirtyq_front(dq);
	while (lh != NULL) {
		vi = silofs_vi_from_dirty_lh(lh);
		silofs_assert_eq(vi->v_dq, dq);
		if (vi_may_flush(vi)) {
			dsets_add_by_vi(dsets, vi);
		}
		lh = silofs_dirtyq_next_of(dq, lh);
	}
}

static void dsets_fill_by_ii(struct silofs_dsets *dsets,
                             struct silofs_inode_info *ii)
{
	dsets_fill_vis_of(dsets, &ii->i_dq_vis);
	dsets_add_by_vi(dsets, &ii->i_vi);
}

static void dsets_fill_iis_of(struct silofs_dsets *dsets,
                              struct silofs_dirtyq *dq)
{
	struct silofs_list_head *lh = NULL;
	struct silofs_inode_info *ii = NULL;

	lh = silofs_dirtyq_front(dq);
	while (lh != NULL) {
		ii = silofs_ii_from_dirty_lh(lh);
		dsets_fill_by_ii(dsets, ii);
		lh = silofs_dirtyq_next_of(dq, lh);
	}
}

static void dsets_fill_uis_of(struct silofs_dsets *dsets,
                              struct silofs_dirtyq *dq)
{
	struct silofs_list_head *lh = NULL;
	struct silofs_unode_info *ui = NULL;

	lh = silofs_dirtyq_front(dq);
	while (lh != NULL) {
		ui = silofs_ui_from_dirty_lh(lh);
		dsets_add_by_ui(dsets, ui);
		lh = silofs_dirtyq_next_of(dq, lh);
	}
}

static void dsets_fill_alt(struct silofs_dsets *dsets,
                           struct silofs_dirtyqs *dqs)
{
	dsets_fill_vis_of(dsets, &dqs->dq_vis);
	dsets_fill_uis_of(dsets, &dqs->dq_uis);
}

static void dsets_fill_all(struct silofs_dsets *dsets,
                           struct silofs_dirtyqs *dqs)
{
	dsets_fill_iis_of(dsets, &dqs->dq_iis);
	dsets_fill_alt(dsets, dqs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_submitq_ent *sqe_from_qlh(struct silofs_list_head *qlh)
{
	return silofs_sqe_from_qlh(qlh);
}

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

	return &fsenv->fse.cache->c_dqs;
}

static int
flusher_require_mutable_llink(const struct silofs_flusher *flusher,
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

static int flusher_resolve_llink_of_ui(const struct silofs_flusher *flusher,
                                       const struct silofs_unode_info *ui,
                                       struct silofs_llink *out_llink)
{
	int ret = 0;

	silofs_ulink_as_llink(ui_ulink(ui), out_llink);
	if (!ui_issuper(ui)) {
		ret = flusher_require_mutable_llink(flusher, out_llink);
	}
	return ret;
}

static int flusher_resolve_llink_of_vi(const struct silofs_flusher *flusher,
                                       struct silofs_vnode_info *vi,
                                       struct silofs_llink *out_llink)
{
	int err;

	err = silofs_refresh_llink_of(flusher->task, vi);
	if (err) {
		return err;
	}
	silofs_llink_assign(out_llink, &vi->v_llink);
	return flusher_require_mutable_llink(flusher, out_llink);
}

static int flusher_resolve_llink_of(const struct silofs_flusher *flusher,
                                    struct silofs_lnode_info *lni,
                                    struct silofs_llink *out_llink)
{
	int ret;

	if (stype_isunode(lni->l_stype)) {
		ret = flusher_resolve_llink_of_ui(flusher,
		                                  ui_from(lni),
		                                  out_llink);
	} else if (stype_isvnode(lni->l_stype)) {
		ret = flusher_resolve_llink_of_vi(flusher,
		                                  vi_from(lni),
		                                  out_llink);
	} else {
		silofs_panic("corrupted lnode: stype=%d", lni->l_stype);
		ret = -SILOFS_EFSCORRUPTED; /* makes clang-scan happy */
	}
	return ret;
}

static void flusher_relax_cache_now(const struct silofs_flusher *flusher)
{
	struct silofs_fsenv *fsenv = flusher_fsenv_from_task(flusher);

	silofs_cache_relax(fsenv->fse.cache, SILOFS_F_NOW);
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

static bool flusher_append_next_ref(struct silofs_flusher *flusher,
                                    struct silofs_submitq_ent *sqe,
                                    const struct silofs_llink *llink,
                                    struct silofs_lnode_info *lni)
{
	struct silofs_submit_ref *ref = &flusher->sqrefs.sr[sqe->cnt];
	bool ok;

	ok = silofs_sqe_append_ref(sqe, &llink->laddr, lni);
	if (ok) {
		silofs_assert_not_null(lni->l_view);
		silofs_llink_assign(&ref->llink, llink);
		ref->view = lni->l_view;
		ref->stype = lni->l_stype;
	}
	return ok;
}

static int flusher_populate_sqe_refs(struct silofs_flusher *flusher,
                                     struct silofs_dset *dset,
                                     struct silofs_submitq_ent *sqe)
{
	struct silofs_llink llink;
	struct silofs_lnode_info *lni = dset->ds_preq;
	int err;

	while (lni != NULL) {
		err = flusher_resolve_llink_of(flusher, lni, &llink);
		if (err) {
			return err;
		}
		if (!flusher_append_next_ref(flusher, sqe, &llink, lni)) {
			break;
		}
		dset_moveq(dset);
		lni = dset->ds_preq;
	}
	return 0;
}

static void flusher_del_sqe(struct silofs_flusher *flusher,
                            struct silofs_submitq_ent *sqe)
{
	silofs_submitq_del_sqe(flusher->submitq, sqe);
}

static int flusher_setup_sqe_by_refs(struct silofs_flusher *flusher,
                                     struct silofs_submitq_ent *sqe)
{
	int retry = 4;
	int err;

	err = silofs_sqe_assign_iovs(sqe, flusher->sqrefs.sr);
	while ((err == -SILOFS_ENOMEM) && (retry-- > 0)) {
		flusher_relax_cache_now(flusher);
		err = silofs_sqe_assign_iovs(sqe, flusher->sqrefs.sr);
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

static void flusher_reinit_dsets(struct silofs_flusher *flusher)
{
	dsets_reinit(&flusher->dsets);
}

static struct silofs_dset *
flusher_dset_of(struct silofs_flusher *flusher, enum silofs_stype stype)
{
	struct silofs_dsets *dsets = &flusher->dsets;
	const size_t idx = (size_t)stype;

	return likely(idx < ARRAY_SIZE(dsets->dset)) ?
	       &dsets->dset[idx] : &dsets->dset[0];
}

static bool flusher_has_dirty_dset(struct silofs_flusher *flusher,
                                   enum silofs_stype stype)
{
	const struct silofs_dset *dset;

	dset = flusher_dset_of(flusher, stype);
	return dset->ds_avl.size > 0;
}

static void flusher_make_fifo_dset(struct silofs_flusher *flusher,
                                   enum silofs_stype stype)
{
	dset_mkfifo(flusher_dset_of(flusher, stype));
}

static void flusher_seal_dset(struct silofs_flusher *flusher,
                              enum silofs_stype stype)
{
	dset_seal_all(flusher_dset_of(flusher, stype));
}

static void flusher_undirtify_dset(struct silofs_flusher *flusher,
                                   enum silofs_stype stype)
{
	dset_undirtify_all(flusher_dset_of(flusher, stype));
}

static void flusher_cleanup_dset(struct silofs_flusher *flusher,
                                 enum silofs_stype stype)
{
	struct silofs_dset *dset = flusher_dset_of(flusher, stype);

	dset_unlink_queues(dset);
	dset_clear_map(dset);
}

static int flusher_prep_sqe(const struct silofs_flusher *flusher,
                            struct silofs_submitq_ent *sqe)
{
	struct silofs_fsenv *fsenv = flusher_fsenv_from_task(flusher);

	return silofs_stage_lseg_at(fsenv, &sqe->laddr.lsegid);
}

static void flusher_submit_sqe(struct silofs_flusher *flusher,
                               struct silofs_submitq_ent *sqe)
{
	silofs_submitq_enqueue(flusher->submitq, sqe);
	silofs_task_update_by(flusher->task, sqe);
}

static void flusher_submit_txq(struct silofs_flusher *flusher)
{
	struct silofs_listq *txq;
	struct silofs_list_head *qlh;
	struct silofs_submitq_ent *sqe;
	uint32_t tx_index = 0;

	for (size_t i = 0; i < ARRAY_SIZE(flusher->txq); ++i) {
		txq = &flusher->txq[i];
		qlh = listq_pop_front(txq);
		while (qlh != NULL) {
			sqe = sqe_from_qlh(qlh);
			sqe->tx_count = flusher->tx_count;
			sqe->tx_index = ++tx_index;
			flusher_submit_sqe(flusher, sqe);
			qlh = listq_pop_front(txq);
		}
	}
}

static void flusher_discard_txq(struct silofs_flusher *flusher)
{
	struct silofs_listq *txq;
	struct silofs_list_head *qlh;
	struct silofs_submitq_ent *sqe;

	for (size_t i = 0; i < ARRAY_SIZE(flusher->txq); ++i) {
		txq = &flusher->txq[i];
		qlh = listq_pop_front(txq);
		while (qlh != NULL) {
			sqe = sqe_from_qlh(qlh);
			flusher_del_sqe(flusher, sqe);
			qlh = listq_pop_front(txq);
		}
	}
}

static struct silofs_listq *
flusher_txq_of(struct silofs_flusher *flusher, enum silofs_stype stype)
{
	return stype_isdata(stype) ? &flusher->txq[0] : &flusher->txq[1];
}

static void flusher_enqueue_in_txq(struct silofs_flusher *flusher,
                                   struct silofs_submitq_ent *sqe)
{
	listq_push_back(flusher_txq_of(flusher, sqe->stype), &sqe->qlh);
	flusher->tx_count++;
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

static int flusher_enqueue_dset_of(struct silofs_flusher *flusher,
                                   enum silofs_stype stype)
{
	struct silofs_dset *dset;
	struct silofs_submitq_ent *sqe;
	int err;

	dset = flusher_dset_of(flusher, stype);
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
		flusher_enqueue_in_txq(flusher, sqe);
	}
	return 0;
}

static int flusher_process_dset_of(struct silofs_flusher *flusher,
                                   enum silofs_stype stype)
{
	int err;

	if (!flusher_has_dirty_dset(flusher, stype)) {
		return 0; /* no-op */
	}
	flusher_make_fifo_dset(flusher, stype);
	flusher_seal_dset(flusher, stype);
	err = flusher_enqueue_dset_of(flusher, stype);
	if (!err) {
		flusher_undirtify_dset(flusher, stype);
	}
	flusher_cleanup_dset(flusher, stype);
	return err;
}

static void flusher_fill_dsets(struct silofs_flusher *flusher)
{
	struct silofs_dsets *dsets = &flusher->dsets;
	struct silofs_dirtyqs *dirtyqs = flusher_dirtyqs_from_task(flusher);

	if ((flusher->ii == NULL) || (flusher->flags & SILOFS_F_NOW)) {
		dsets_fill_all(dsets, dirtyqs);
	} else {
		dsets_fill_by_ii(dsets, flusher->ii);
		dsets_fill_alt(dsets, dirtyqs);
	}
}

static int flusher_process_dsets(struct silofs_flusher *flusher)
{
	enum silofs_stype stype = SILOFS_STYPE_NONE;
	int ret = 0;

	while ((ret == 0) && (++stype < SILOFS_STYPE_LAST)) {
		ret = flusher_process_dset_of(flusher, stype);
	}
	return ret;
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

static void flusher_rebind(struct silofs_flusher *flusher,
                           struct silofs_task *task,
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
	dsets_init(&flusher->dsets);
	listq_init(&flusher->txq[0]);
	listq_init(&flusher->txq[1]);
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
		dsets_fini(&flusher->dsets);
		listq_fini(&flusher->txq[0]);
		listq_fini(&flusher->txq[1]);
		flusher->submitq = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flush_threshold_of(int flags)
{
	size_t threshold;

	if (flags & (SILOFS_F_NOW | SILOFS_F_IDLE)) {
		threshold = 0;
	} else if (flags & SILOFS_F_FSYNC) {
		threshold = 0;
	} else if (flags & SILOFS_F_TIMEOUT) {
		threshold = SILOFS_LSEG_SIZE_MAX / 4;
	} else if (flags & SILOFS_F_RELEASE) {
		threshold = SILOFS_LSEG_SIZE_MAX / 2;
	} else if (flags & (SILOFS_F_OPSTART | SILOFS_F_OPFINISH)) {
		threshold = 2 * SILOFS_LSEG_SIZE_MAX;
	} else {
		threshold = 4 * SILOFS_LSEG_SIZE_MAX;
	}
	return threshold;
}

static size_t total_ndirty_by(const struct silofs_task *task,
                              const struct silofs_inode_info *ii)
{
	const struct silofs_dirtyqs *dqs = NULL;
	size_t ret;

	if (ii != NULL) {
		ret = ii->i_dq_vis.dq_accum;
	} else {
		dqs = &task->t_fsenv->fse.cache->c_dqs;
		ret = dqs->dq_uis.dq_accum +
		      dqs->dq_iis.dq_accum + dqs->dq_vis.dq_accum;
	}
	return ret;
}

static bool need_flush_by(const struct silofs_task *task,
                          const struct silofs_inode_info *ii, int flags)
{
	struct silofs_alloc_stat alst = { .nbytes_use = 0, .nbytes_max = 0 };
	size_t ndirtysum;
	size_t threshold;

	if (flags & SILOFS_F_NOW) {
		return true;
	}
	silofs_allocstat(task->t_fsenv->fse.alloc, &alst);
	if (alst.nbytes_use > (alst.nbytes_max / 2)) {
		return true;
	}
	threshold = flush_threshold_of(flags);
	ndirtysum = total_ndirty_by(task, ii);
	return (ndirtysum > threshold);
}

int silofs_flush_dirty(struct silofs_task *task,
                       struct silofs_inode_info *ii, int flags)
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
	int err;

	err = silofs_flush_dirty(task, NULL, SILOFS_F_NOW);
	if (err) {
		return err;
	}
	return 0;
}
