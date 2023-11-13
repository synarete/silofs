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


struct silofs_dset {
	struct silofs_lnode_info       *ds_preq;
	struct silofs_lnode_info       *ds_postq;
	struct silofs_avl               ds_avl;
};

struct silofs_dsets {
	struct silofs_dset dset[SILOFS_STYPE_LAST];
};

struct silofs_submit_ctx {
	struct silofs_submit_ref        refs[SILOFS_SUBENT_NREFS_MAX];
	struct silofs_dsets             dsets;
	struct silofs_listq             txq[2];
	struct silofs_task             *task;
	struct silofs_inode_info       *ii;
	struct silofs_fsenv             *fsenv;
	struct silofs_repo             *repo;
	struct silofs_alloc            *alloc;
	struct silofs_cache            *cache;
	struct silofs_dirtyqs          *dirtyqs;
	struct silofs_submitq          *submitq;
	uint32_t tx_count;
	int flags;
};

static void dset_moveq(struct silofs_dset *dset);


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

static struct silofs_submitq_ent *sqe_from_qlh(struct silofs_list_head *qlh)
{
	return silofs_sqe_from_qlh(qlh);
}

static void lni_seal_meta(struct silofs_lnode_info *lni)
{
	const enum silofs_stype stype = lni->stype;

	if (stype_isunode(stype)) {
		silofs_seal_unode(silofs_ui_from_lni(lni));
	} else if (stype_isvnode(stype) && !stype_isdata(stype)) {
		silofs_seal_vnode(silofs_vi_from_lni(lni));
	}
}

static int smc_require_mutable_llink(const struct silofs_submit_ctx *sm_ctx,
                                     const struct silofs_llink *llink)
{
	const struct silofs_sb_info *sbi = sm_ctx->fsenv->fse_sbi;
	int err = 0;
	bool mut;

	mut = silofs_sbi_ismutable_laddr(sbi, &llink->laddr);
	err = mut ? 0 : -SILOFS_EROFS;
	silofs_assert_ok(err);
	return err;
}

static int smc_resolve_llink_of_ui(const struct silofs_submit_ctx *sm_ctx,
                                   const struct silofs_unode_info *ui,
                                   struct silofs_llink *out_llink)
{
	int ret = 0;

	silofs_ulink_as_llink(ui_ulink(ui), out_llink);
	if (!ui_issuper(ui)) {
		ret = smc_require_mutable_llink(sm_ctx, out_llink);
	}
	return ret;
}

static int smc_resolve_llink_of_vi(const struct silofs_submit_ctx *sm_ctx,
                                   struct silofs_vnode_info *vi,
                                   struct silofs_llink *out_llink)
{
	int err;

	err = silofs_refresh_llink_of(sm_ctx->task, vi);
	if (err) {
		return err;
	}
	silofs_llink_assign(out_llink, &vi->v_llink);
	return smc_require_mutable_llink(sm_ctx, out_llink);
}

static int smc_resolve_llink_of(const struct silofs_submit_ctx *sm_ctx,
                                struct silofs_lnode_info *lni,
                                struct silofs_llink *out_llink)
{
	int ret;

	if (stype_isunode(lni->stype)) {
		ret = smc_resolve_llink_of_ui(sm_ctx, ui_from(lni), out_llink);
	} else if (stype_isvnode(lni->stype)) {
		ret = smc_resolve_llink_of_vi(sm_ctx, vi_from(lni), out_llink);
	} else {
		silofs_panic("corrupted lnode: stype=%d", lni->stype);
		ret = -SILOFS_EFSCORRUPTED; /* makes clang-scan happy */
	}
	return ret;
}

static void smc_relax_cache_now(const struct silofs_submit_ctx *sm_ctx)
{
	silofs_cache_relax(sm_ctx->cache, SILOFS_F_NOW);
}

static int smc_do_make_sqe(struct silofs_submit_ctx *sm_ctx,
                           struct silofs_submitq_ent **out_sqe)
{
	int retry = 4;
	int err;

	err = silofs_submitq_new_sqe(sm_ctx->submitq, out_sqe);
	while ((err == -SILOFS_ENOMEM) && (retry-- > 0)) {
		smc_relax_cache_now(sm_ctx);
		err = silofs_submitq_new_sqe(sm_ctx->submitq, out_sqe);
	}
	return err;
}

static int smc_make_sqe(struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_ent **out_sqe)
{
	int err;

	err = smc_do_make_sqe(sm_ctx, out_sqe);
	if (err) {
		return err;
	}
	(*out_sqe)->fsenv = sm_ctx->fsenv;
	return 0;
}

static bool smc_append_next_ref(struct silofs_submit_ctx *sm_ctx,
                                struct silofs_submitq_ent *sqe,
                                const struct silofs_llink *llink,
                                struct silofs_lnode_info *lni)
{
	struct silofs_submit_ref *ref = &sm_ctx->refs[sqe->cnt];
	bool ret;

	ret = silofs_sqe_append_ref(sqe, &llink->laddr, lni);
	if (ret) {
		silofs_llink_assign(&ref->llink, llink);
		ref->view = lni->view;
		ref->stype = lni->stype;
	}
	return ret;
}

static int smc_populate_sqe_refs(struct silofs_submit_ctx *sm_ctx,
                                 struct silofs_dset *dset,
                                 struct silofs_submitq_ent *sqe)
{
	struct silofs_llink llink;
	struct silofs_lnode_info *lni = dset->ds_preq;
	int err;

	while (lni != NULL) {
		err = smc_resolve_llink_of(sm_ctx, lni, &llink);
		if (err) {
			return err;
		}
		if (!smc_append_next_ref(sm_ctx, sqe, &llink, lni)) {
			break;
		}
		dset_moveq(dset);
		lni = dset->ds_preq;
	}
	return 0;
}

static void smc_del_sqe(struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_ent *sqe)
{
	silofs_submitq_del_sqe(sm_ctx->submitq, sqe);
}

static int smc_setup_sqe_by_refs(struct silofs_submit_ctx *sm_ctx,
                                 struct silofs_submitq_ent *sqe)
{
	int retry = 4;
	int err;

	err = silofs_sqe_assign_iovs(sqe, sm_ctx->refs);
	while ((err == -SILOFS_ENOMEM) && (retry-- > 0)) {
		smc_relax_cache_now(sm_ctx);
		err = silofs_sqe_assign_iovs(sqe, sm_ctx->refs);
	}
	return err;
}

static int smc_populate_sqe_by(struct silofs_submit_ctx *sm_ctx,
                               struct silofs_dset *dset,
                               struct silofs_submitq_ent *sqe)
{
	int err;

	err = smc_populate_sqe_refs(sm_ctx, dset, sqe);
	if (!err) {
		silofs_sqe_increfs(sqe);
		err = smc_setup_sqe_by_refs(sm_ctx, sqe);
	}
	return err;
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

	lni = container_of2(an, struct silofs_lnode_info, ds_an);
	return unconst(lni);
}

static const void *lni_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_lnode_info *lni = avl_node_to_lni(an);

	return &lni->ce.ce_ckey;
}

static void lni_visit_reinit(struct silofs_avl_node *an, void *p)
{
	struct silofs_lnode_info *lni = avl_node_to_lni(an);

	silofs_avl_node_init(&lni->ds_an);
	unused(p);
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
	silofs_avl_insert(&dset->ds_avl, &lni->ds_an);
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
	silofs_assert_null(lni->ds_next);

	lni->ds_next = dset->ds_preq;
	dset->ds_preq = lni;
}

static void dset_push_postq(struct silofs_dset *dset,
                            struct silofs_lnode_info *lni)
{
	silofs_assert_null(lni->ds_next);

	lni->ds_next = dset->ds_postq;
	dset->ds_postq = lni;
}

static void dset_moveq(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_preq;

	if (lni != NULL) {
		dset->ds_preq = dset->ds_preq->ds_next;
		lni->ds_next = NULL;
		dset_push_postq(dset, lni);
	}
}

static void dset_seal_all(const struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_preq;

	while (lni != NULL) {
		lni_seal_meta(lni);
		lni = lni->ds_next;
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

	if (stype_isvnode(lni->stype)) {
		vi = silofs_vi_from_lni(lni);
		silofs_vi_undirtify(vi);
	} else {
		silofs_assert(stype_isunode(lni->stype));
		ui = silofs_ui_from_lni(lni);
		silofs_ui_undirtify(ui);
	}
}

static void dset_undirtify_all(const struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni = dset->ds_postq;

	while (lni != NULL) {
		lni_undirtify(lni);
		lni = lni->ds_next;
	}
}

static void dset_unlink_queues(struct silofs_dset *dset)
{
	struct silofs_lnode_info *lni_next = NULL;
	struct silofs_lnode_info *lni = NULL;

	lni = dset->ds_preq;
	while (lni != NULL) {
		lni_next = lni->ds_next;
		lni->ds_next = NULL;
		lni = lni_next;
	}
	dset->ds_preq = NULL;

	lni = dset->ds_postq;
	while (lni != NULL) {
		lni_next = lni->ds_next;
		lni->ds_next = NULL;
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

	dset_add_dirty(dset, &vi->v);
}

static void dsets_add_by_ui(struct silofs_dsets *dsets,
                            struct silofs_unode_info *ui)
{
	struct silofs_dset *dset = dsets_get_by_ui(dsets, ui);

	dset_add_dirty(dset, &ui->u);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void smc_init_dsets(struct silofs_submit_ctx *sm_ctx)
{
	dsets_init(&sm_ctx->dsets);
}

static void smc_fini_dsets(struct silofs_submit_ctx *sm_ctx)
{
	dsets_fini(&sm_ctx->dsets);
}

static struct silofs_dset *
smc_dset_of(struct silofs_submit_ctx *sm_ctx, enum silofs_stype stype)
{
	struct silofs_dsets *dsets = &sm_ctx->dsets;
	const size_t idx = (size_t)stype;

	return likely(idx < ARRAY_SIZE(dsets->dset)) ?
	       &dsets->dset[idx] : &dsets->dset[0];
}

static bool smc_has_dirty_dset(struct silofs_submit_ctx *sm_ctx,
                               enum silofs_stype stype)
{
	const struct silofs_dset *dset;

	dset = smc_dset_of(sm_ctx, stype);
	return dset->ds_avl.size > 0;
}

static void smc_make_fifo_dset(struct silofs_submit_ctx *sm_ctx,
                               enum silofs_stype stype)
{
	dset_mkfifo(smc_dset_of(sm_ctx, stype));
}

static void smc_seal_dset(struct silofs_submit_ctx *sm_ctx,
                          enum silofs_stype stype)
{
	dset_seal_all(smc_dset_of(sm_ctx, stype));
}

static void smc_undirtify_dset(struct silofs_submit_ctx *sm_ctx,
                               enum silofs_stype stype)
{
	dset_undirtify_all(smc_dset_of(sm_ctx, stype));
}

static void smc_cleanup_dset(struct silofs_submit_ctx *sm_ctx,
                             enum silofs_stype stype)
{
	struct silofs_dset *dset = smc_dset_of(sm_ctx, stype);

	dset_unlink_queues(dset);
	dset_clear_map(dset);
}

static int smc_prep_sqe(const struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_ent *sqe)
{
	return silofs_stage_lseg_at(sm_ctx->fsenv, &sqe->laddr.lsegid);
}

static void smc_submit_sqe(const struct silofs_submit_ctx *sm_ctx,
                           struct silofs_submitq_ent *sqe)
{
	silofs_submitq_enqueue(sm_ctx->submitq, sqe);
	silofs_task_update_by(sm_ctx->task, sqe);
}

static void smc_submit_txq(struct silofs_submit_ctx *sm_ctx)
{
	struct silofs_listq *txq;
	struct silofs_list_head *qlh;
	struct silofs_submitq_ent *sqe;
	uint32_t tx_index = 0;

	for (size_t i = 0; i < ARRAY_SIZE(sm_ctx->txq); ++i) {
		txq = &sm_ctx->txq[i];
		qlh = listq_pop_front(txq);
		while (qlh != NULL) {
			sqe = sqe_from_qlh(qlh);
			sqe->tx_count = sm_ctx->tx_count;
			sqe->tx_index = ++tx_index;
			smc_submit_sqe(sm_ctx, sqe);
			qlh = listq_pop_front(txq);
		}
	}
}

static void smc_discard_txq(struct silofs_submit_ctx *sm_ctx)
{
	struct silofs_listq *txq;
	struct silofs_list_head *qlh;
	struct silofs_submitq_ent *sqe;

	for (size_t i = 0; i < ARRAY_SIZE(sm_ctx->txq); ++i) {
		txq = &sm_ctx->txq[i];
		qlh = listq_pop_front(txq);
		while (qlh != NULL) {
			sqe = sqe_from_qlh(qlh);
			smc_del_sqe(sm_ctx, sqe);
			qlh = listq_pop_front(txq);
		}
	}
}

static struct silofs_listq *
smc_txq_of(struct silofs_submit_ctx *sm_ctx, enum silofs_stype stype)
{
	return stype_isdata(stype) ? &sm_ctx->txq[0] : &sm_ctx->txq[1];
}

static void smc_enqueue_in_txq(struct silofs_submit_ctx *sm_ctx,
                               struct silofs_submitq_ent *sqe)
{
	listq_push_back(smc_txq_of(sm_ctx, sqe->stype), &sqe->qlh);
	sm_ctx->tx_count++;
}

static int smc_enqueue_dset_into(struct silofs_submit_ctx *sm_ctx,
                                 struct silofs_dset *dset,
                                 struct silofs_submitq_ent *sqe)
{
	int err;

	err = smc_populate_sqe_by(sm_ctx, dset, sqe);
	if (err) {
		return err;
	}
	err = smc_prep_sqe(sm_ctx, sqe);
	if (err) {
		return err;
	}
	return 0;
}

static int smc_enqueue_dset_of(struct silofs_submit_ctx *sm_ctx,
                               enum silofs_stype stype)
{
	struct silofs_dset *dset;
	struct silofs_submitq_ent *sqe;
	int err;

	dset = smc_dset_of(sm_ctx, stype);
	while (dset->ds_preq != NULL) {
		sqe = NULL;
		err = smc_make_sqe(sm_ctx, &sqe);
		if (err) {
			return err;
		}
		err = smc_enqueue_dset_into(sm_ctx, dset, sqe);
		if (err) {
			smc_del_sqe(sm_ctx, sqe);
			return err;
		}
		smc_enqueue_in_txq(sm_ctx, sqe);
	}
	return 0;
}

static int smc_process_dset_of(struct silofs_submit_ctx *sm_ctx,
                               enum silofs_stype stype)
{
	int err;

	if (!smc_has_dirty_dset(sm_ctx, stype)) {
		return 0; /* no-op */
	}
	smc_make_fifo_dset(sm_ctx, stype);
	smc_seal_dset(sm_ctx, stype);
	err = smc_enqueue_dset_of(sm_ctx, stype);
	if (!err) {
		smc_undirtify_dset(sm_ctx, stype);
	}
	smc_cleanup_dset(sm_ctx, stype);
	return err;
}

static void smc_fill_dsets(struct silofs_submit_ctx *sm_ctx)
{
	struct silofs_dsets *dsets = &sm_ctx->dsets;

	if ((sm_ctx->ii == NULL) || (sm_ctx->flags & SILOFS_F_NOW)) {
		dsets_fill_all(dsets, sm_ctx->dirtyqs);
	} else {
		dsets_fill_by_ii(dsets, sm_ctx->ii);
		dsets_fill_alt(dsets, sm_ctx->dirtyqs);
	}
}

static int smc_process_dsets(struct silofs_submit_ctx *sm_ctx)
{
	enum silofs_stype stype = SILOFS_STYPE_NONE;
	int ret = 0;

	while ((ret == 0) && (++stype < SILOFS_STYPE_LAST)) {
		ret = smc_process_dset_of(sm_ctx, stype);
	}
	return ret;
}

static int smc_collect_flush_dirty(struct silofs_submit_ctx *sm_ctx)
{
	int err;

	smc_init_dsets(sm_ctx);
	smc_fill_dsets(sm_ctx);
	err = smc_process_dsets(sm_ctx);
	if (!err) {
		smc_submit_txq(sm_ctx);
	} else {
		smc_discard_txq(sm_ctx);
	}
	smc_fini_dsets(sm_ctx);
	return err;
}

/*
 * TODO-0034: Issue flush sync to dirty lsegs
 *
 * Implement fsync at lsegs level and ensure that all of kernel's in-cache
 * data is flushed all the way to stable storage.
 */
static int smc_complete_commits(const struct silofs_submit_ctx *sm_ctx)
{
	int ret = 0;

	if (sm_ctx->flags & SILOFS_F_NOW) {
		ret = silofs_task_submit(sm_ctx->task, true);
	}
	return ret;
}

static int smc_do_flush_dirty(struct silofs_submit_ctx *sm_ctx)
{
	int err;

	err = smc_collect_flush_dirty(sm_ctx);
	if (err) {
		log_warn("flush execute failure: err=%d", err);
		return err;
	}
	err = smc_complete_commits(sm_ctx);
	if (err) {
		log_warn("flush complete failure: err=%d", err);
		return err;
	}
	return 0;
}

static int smc_flush_dirty(struct silofs_submit_ctx *sm_ctx)
{
	int err;

	ii_incref(sm_ctx->ii);
	err = smc_do_flush_dirty(sm_ctx);
	ii_decref(sm_ctx->ii);
	return err;
}

static bool smc_need_flush1(const struct silofs_submit_ctx *sm_ctx)
{
	struct silofs_alloc_stat st;

	if (sm_ctx->flags & SILOFS_F_NOW) {
		return true;
	}
	silofs_allocstat(sm_ctx->alloc, &st);
	if (st.nbytes_use > (st.nbytes_max / 4)) {
		return true;
	}
	return false;
}

static bool smc_need_flush2(const struct silofs_submit_ctx *sm_ctx)
{
	const struct silofs_dirtyqs *dqs = sm_ctx->dirtyqs;
	size_t accum_ndirty;
	size_t threshold;

	threshold = flush_threshold_of(sm_ctx->flags);
	if (sm_ctx->ii != NULL) {
		accum_ndirty = sm_ctx->ii->i_dq_vis.dq_accum;
	} else {
		accum_ndirty = dqs->dq_uis.dq_accum +
		               dqs->dq_iis.dq_accum + dqs->dq_vis.dq_accum;
	}
	return (accum_ndirty > threshold);
}

static bool smc_need_flush(const struct silofs_submit_ctx *sm_ctx)
{
	return smc_need_flush1(sm_ctx) || smc_need_flush2(sm_ctx);
}

static int smc_setup(struct silofs_submit_ctx *sm_ctx,
                     struct silofs_task *task,
                     struct silofs_inode_info *ii, int flags)
{
	struct silofs_fsenv *fsenv = task->t_fsenv;
	struct silofs_repo *repo = fsenv->fse.repo;

	listq_init(&sm_ctx->txq[0]);
	listq_init(&sm_ctx->txq[1]);
	sm_ctx->task = task;
	sm_ctx->ii = ii;
	sm_ctx->fsenv = fsenv;
	sm_ctx->tx_count = 0;
	sm_ctx->flags = flags;
	sm_ctx->repo = repo;
	sm_ctx->cache = fsenv->fse.cache;
	sm_ctx->dirtyqs = &fsenv->fse.cache->c_dqs;
	sm_ctx->submitq = fsenv->fse.submitq;
	sm_ctx->alloc = sm_ctx->cache->c_alloc;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_flush_dirty(struct silofs_task *task,
                       struct silofs_inode_info *ii, int flags)
{
	struct silofs_submit_ctx sm_ctx = { .flags = -1 };
	int err;

	err = smc_setup(&sm_ctx, task, ii, flags);
	if (err) {
		return err;
	}
	if (!smc_need_flush(&sm_ctx)) {
		return 0;
	}
	err = smc_flush_dirty(&sm_ctx);
	if (err) {
		log_dbg("failed to flush: err=%d", err);
	}
	return err;
}

int silofs_flush_dirty_now(struct silofs_task *task)
{
	return silofs_flush_dirty(task, NULL, SILOFS_F_NOW);
}
