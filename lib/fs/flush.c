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


/*
 * TODO-0051: Journal
 *
 * Implement a journal.
 */


struct silofs_submit_ctx {
	struct silofs_dsets     dsets;
	struct silofs_task     *task;
	struct silofs_alloc    *alloc;
	struct silofs_uber     *uber;
	struct silofs_repo     *repo;
	struct silofs_cache    *cache;
	struct silofs_submitq  *submitq;
	silofs_dqid_t           dqid;
	int flags;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void si_seal_meta(struct silofs_snode_info *si)
{
	const enum silofs_stype stype = si->s_stype;

	if (stype_isunode(stype)) {
		silofs_seal_unode(silofs_ui_from_si(si));
	} else if (stype_isvnode(stype) && !stype_isdata(stype)) {
		silofs_seal_vnode(silofs_vi_from_si(si));
	}
}

static bool ismutable_oaddr(const struct silofs_task *task,
                            const struct silofs_oaddr *oaddr)
{
	if (oaddr_isnull(oaddr)) {
		return false;
	}
	if (!silofs_sbi_ismutable_oaddr(task_sbi(task), oaddr)) {
		return false;
	}
	return true;
}

static int refresh_cur_oaddr(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_oaddr *oaddr)
{
	enum silofs_stage_mode stg_mode = SILOFS_STAGE_CUR;
	int err = 0;

	if (!ismutable_oaddr(task, oaddr)) {
		err = silofs_resolve_oaddr_of(task, vaddr, stg_mode, oaddr);
		if (err) {
			log_warn("failed to resolve vaddr: stype=%d off=%ld "
			         "err=%d", vaddr->stype, vaddr->off, err);
		}
	}
	return err;
}

static int refresh_vi_oaddr(struct silofs_task *task,
                            struct silofs_vnode_info *vi)
{
	return refresh_cur_oaddr(task, vi_vaddr(vi), &vi->v_oaddr);
}

static int resolve_oaddr_of(struct silofs_task *task,
                            struct silofs_snode_info *si,
                            struct silofs_oaddr *out_oaddr)
{
	const struct silofs_unode_info *ui = NULL;
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_oaddr *oaddr = NULL;
	int err;

	if (stype_isunode(si->s_stype)) {
		ui = silofs_ui_from_si(si);
		oaddr = &ui->u_uaddr.oaddr;
	} else if (stype_isvnode(si->s_stype)) {
		vi = silofs_vi_from_si(si);
		oaddr = &vi->v_oaddr;
		err = refresh_vi_oaddr(task, vi);
		if (err) {
			return err;
		}
	} else {
		silofs_panic("corrupted snode: stype=%d", si->s_stype);
	}
	oaddr_assign(out_oaddr, oaddr);
	return 0;
}

static int smc_check_resolved_oaddr(const struct silofs_submit_ctx *sm_ctx,
                                    const struct silofs_snode_info *si,
                                    const struct silofs_oaddr *oaddr)
{
	const struct silofs_sb_info *sbi = sm_ctx->uber->ub_sbi;
	const struct silofs_blobid *blobid = &oaddr->bka.blobid;
	int err = 0;
	bool mut;

	if (stype_isvnode(si->s_stype)) {
		mut = silofs_sbi_ismutable_blobid(sbi, blobid);
		err = mut ? 0 : -EROFS;
	}
	silofs_assert_ok(err);
	return err;
}

static void smc_relax_cache_now(const struct silofs_submit_ctx *sm_ctx)
{
	silofs_cache_relax(sm_ctx->cache, SILOFS_F_NOW | SILOFS_F_URGENT);
}

static int smc_do_make_sqe(struct silofs_submit_ctx *sm_ctx,
                           struct silofs_submitq_entry **out_sqe)
{
	int retry = 4;
	int err;

	err = silofs_submitq_new_sqe(sm_ctx->submitq, out_sqe);
	while ((err == -ENOMEM) && (retry-- > 0)) {
		smc_relax_cache_now(sm_ctx);
		err = silofs_submitq_new_sqe(sm_ctx->submitq, out_sqe);
	}
	return err;
}

static int smc_make_sqe(struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_entry **out_sqe)
{
	struct silofs_submitq_entry *sqe = NULL;
	int err;

	err = smc_do_make_sqe(sm_ctx, &sqe);
	if (!err) {
		sqe->uber = sm_ctx->uber;
	}
	*out_sqe = sqe;
	return err;
}

static void smc_del_sqe(struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_entry *sqe)
{
	silofs_submitq_del_sqe(sm_ctx->submitq, sqe);
}

static int smc_setup_sqe_buf(struct silofs_submit_ctx *sm_ctx,
                             struct silofs_submitq_entry *sqe)
{
	int retry = 4;
	int err;

	err = silofs_sqe_assign_buf(sqe);
	while ((err == -ENOMEM) && (retry-- > 0)) {
		smc_relax_cache_now(sm_ctx);
		err = silofs_sqe_assign_buf(sqe);
	}
	return err;
}

static int smc_populate_sqe_refs(struct silofs_submit_ctx *sm_ctx,
                                 struct silofs_snode_info **siq,
                                 struct silofs_submitq_entry *sqe)
{
	struct silofs_oaddr oaddr;
	struct silofs_snode_info *si;
	int err;

	while (*siq != NULL) {
		si = *siq;
		err = resolve_oaddr_of(sm_ctx->task, si, &oaddr);
		if (err) {
			return err;
		}
		err = smc_check_resolved_oaddr(sm_ctx, si, &oaddr);
		if (err) {
			return err;
		}
		if (!silofs_sqe_append_ref(sqe, &oaddr, si)) {
			break;
		}
		*siq = si->s_ds_next;
	}
	return 0;
}

static int smc_populate_sqe(struct silofs_submit_ctx *sm_ctx,
                            struct silofs_snode_info **siq,
                            struct silofs_submitq_entry *sqe)
{
	int err;

	err = smc_populate_sqe_refs(sm_ctx, siq, sqe);
	if (!err) {
		silofs_sqe_increfs(sqe);
		err = smc_setup_sqe_buf(sm_ctx, sqe);
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

static struct silofs_snode_info *
avl_node_to_si(const struct silofs_avl_node *an)
{
	const struct silofs_snode_info *si;

	si = container_of2(an, struct silofs_snode_info, s_ds_an);
	return unconst(si);
}

static const void *si_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_snode_info *si = avl_node_to_si(an);

	return &si->s_ce.ce_ckey;
}

static void si_visit_reinit(struct silofs_avl_node *an, void *p)
{
	struct silofs_snode_info *si = avl_node_to_si(an);

	silofs_avl_node_init(&si->s_ds_an);
	unused(p);
}

static void dset_clear_map(struct silofs_dset *dset)
{
	const struct silofs_avl_node_functor fn = {
		.fn = si_visit_reinit,
		.ctx = NULL
	};

	silofs_avl_clear(&dset->ds_avl, &fn);
}

static void dset_add_dirty(struct silofs_dset *dset,
                           struct silofs_snode_info *si)
{
	silofs_avl_insert(&dset->ds_avl, &si->s_ds_an);
}

static void dset_init(struct silofs_dset *dset)
{
	silofs_avl_init(&dset->ds_avl, si_getkey, ckey_compare, dset);
	dset->ds_siq = NULL;
	dset->ds_add_fn = dset_add_dirty;
}

static void dset_fini(struct silofs_dset *dset)
{
	silofs_avl_fini(&dset->ds_avl);
	dset->ds_siq = NULL;
	dset->ds_add_fn = NULL;
}

static void dset_push_front_siq(struct silofs_dset *dset,
                                struct silofs_snode_info *si)
{
	si->s_ds_next = dset->ds_siq;
	dset->ds_siq = si;
}

static void dset_seal_all(const struct silofs_dset *dset)
{
	struct silofs_snode_info *si = dset->ds_siq;

	while (si != NULL) {
		si_seal_meta(si);
		si = si->s_ds_next;
	}
}

static void dset_mkfifo(struct silofs_dset *dset)
{
	struct silofs_snode_info *si;
	const struct silofs_avl_node *end;
	const struct silofs_avl_node *itr;
	const struct silofs_avl *avl = &dset->ds_avl;

	dset->ds_siq = NULL;
	itr = silofs_avl_begin(avl);
	end = silofs_avl_end(avl);
	while (itr != end) {
		si = avl_node_to_si(itr);
		dset_push_front_siq(dset, si);
		itr = silofs_avl_next(avl, itr);
	}
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
	silofs_cache_undirtify_by_dset(sm_ctx->cache,
	                               smc_dset_of(sm_ctx, stype));
}

static void smc_cleanup_dset(struct silofs_submit_ctx *sm_ctx,
                             enum silofs_stype stype)
{
	dset_clear_map(smc_dset_of(sm_ctx, stype));
}

static int smc_prep_sqe(const struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_entry *sqe)
{
	const struct silofs_blobid *blobid = &sqe->blobid;
	struct silofs_blobf *blobf = NULL;
	int err;

	err = silofs_stage_blob_at(sm_ctx->uber, blobid, &blobf);
	if (err) {
		return err;
	}
	silofs_sqe_bind_blobf(sqe, blobf);
	return 0;
}

static void smc_enqueue_sqe(const struct silofs_submit_ctx *sm_ctx,
                            struct silofs_submitq_entry *sqe)
{
	silofs_submitq_enqueue(sm_ctx->submitq, sqe);
	silofs_task_update_by(sm_ctx->task, sqe);
}

static int smc_pend_sqe(const struct silofs_submit_ctx *sm_ctx,
                        struct silofs_submitq_entry *sqe)
{
	int err;

	err = smc_prep_sqe(sm_ctx, sqe);
	if (!err) {
		smc_enqueue_sqe(sm_ctx, sqe);
	}
	return err;
}

static int smc_flush_siq(struct silofs_submit_ctx *sm_ctx,
                         struct silofs_snode_info **siq,
                         struct silofs_submitq_entry *sqe)
{
	int err;

	err = smc_populate_sqe(sm_ctx, siq, sqe);
	if (err) {
		return err;
	}
	err = smc_pend_sqe(sm_ctx, sqe);
	if (err) {
		return err;
	}
	return 0;
}

static int smc_flush_dset(struct silofs_submit_ctx *sm_ctx,
                          enum silofs_stype stype)
{
	struct silofs_submitq_entry *sqe = NULL;
	struct silofs_dset *dset = smc_dset_of(sm_ctx, stype);
	struct silofs_snode_info *siq = dset->ds_siq;
	int err;

	while (siq != NULL) {
		err = smc_make_sqe(sm_ctx, &sqe);
		if (err) {
			return err;
		}
		err = smc_flush_siq(sm_ctx, &siq, sqe);
		if (err) {
			smc_del_sqe(sm_ctx, sqe);
			return err;
		}
	}
	return 0;
}

static int smc_process_dset_of(struct silofs_submit_ctx *sm_ctx,
                               enum silofs_stype stype)
{
	int ret = 0;

	if (smc_has_dirty_dset(sm_ctx, stype)) {
		smc_make_fifo_dset(sm_ctx, stype);
		smc_seal_dset(sm_ctx, stype);
		ret = smc_flush_dset(sm_ctx, stype);
		if (!ret) {
			smc_undirtify_dset(sm_ctx, stype);
		}
		smc_cleanup_dset(sm_ctx, stype);
	}
	return ret;
}

static void smc_fill_dsets(struct silofs_submit_ctx *sm_ctx)
{
	silofs_cache_fill_dsets(sm_ctx->cache, &sm_ctx->dsets, sm_ctx->dqid);
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
	smc_fini_dsets(sm_ctx);
	return err;
}

/*
 * TODO-0034: Issue flush sync to dirty blobs
 *
 * Implement fsync at blobs level and ensure that all of kernel's in-cache
 * data is flushed all the way to stable storage.
 */
static int smc_complete_commits(const struct silofs_submit_ctx *sm_ctx)
{
	int ret = 0;

	if ((sm_ctx->flags & SILOFS_F_NOW) &&
	    (sm_ctx->dqid == SILOFS_DQID_ALL)) {
		ret = silofs_task_submit(sm_ctx->task, true);
	}
	return ret;
}

static int smc_flush_dirty_of(struct silofs_submit_ctx *sm_ctx)
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

static bool smc_need_flush(const struct silofs_submit_ctx *sm_ctx)
{
	return silofs_cache_need_flush(sm_ctx->cache, sm_ctx->dqid,
	                               sm_ctx->flags);
}

static int smc_setup(struct silofs_submit_ctx *sm_ctx,
                     struct silofs_task *task, silofs_dqid_t dqid, int flags)
{
	struct silofs_uber *uber = task->t_uber;
	struct silofs_repo *repo = uber->ub.repo;

	sm_ctx->task = task;
	sm_ctx->uber = uber;
	sm_ctx->dqid = dqid;
	sm_ctx->flags = flags;
	sm_ctx->repo = repo;
	sm_ctx->cache = &repo->re_cache;
	sm_ctx->submitq = uber->ub.submitq;
	sm_ctx->alloc = sm_ctx->cache->c_alloc;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static silofs_dqid_t ii_dqid(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v_si.s_dqid;
}

bool silofs_need_flush_dirty(struct silofs_task *task,
                             silofs_dqid_t dqid, int flags)
{
	struct silofs_submit_ctx sm_ctx = { .flags = -1 };
	int err;
	bool ret = false;

	err = smc_setup(&sm_ctx, task, dqid, flags);
	if (!err) {
		ret = smc_need_flush(&sm_ctx);
	}
	return ret;
}

int silofs_flush_dirty(struct silofs_task *task,
                       silofs_dqid_t dqid, int flags)
{
	struct silofs_submit_ctx sm_ctx = { .flags = -1 };
	int err;

	err = smc_setup(&sm_ctx, task, dqid, flags);
	if (err) {
		return err;
	}
	if (!smc_need_flush(&sm_ctx)) {
		return 0;
	}
	err = smc_flush_dirty_of(&sm_ctx);
	if (err) {
		log_dbg("failed to flush: err=%d", err);
	}
	return err;
}

int silofs_flush_dirty_of(struct silofs_task *task,
                          const struct silofs_inode_info *ii, int flags)
{
	return silofs_flush_dirty(task, ii_dqid(ii), flags);
}

int silofs_flush_dirty_now(struct silofs_task *task)
{
	return silofs_flush_dirty(task, SILOFS_DQID_ALL, SILOFS_F_NOW);
}
