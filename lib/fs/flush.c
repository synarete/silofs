/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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


struct silofs_flush_ctx {
	struct silofs_dsets     dsets;
	struct silofs_task     *task;
	struct silofs_alloc    *alloc;
	struct silofs_uber     *uber;
	struct silofs_repo     *repo;
	struct silofs_cache    *cache;
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

static int resolve_oaddr_of_vnode(struct silofs_task *task,
                                  const struct silofs_vnode_info *vi,
                                  struct silofs_oaddr *out_oaddr)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);
	int err;

	err = silofs_resolve_oaddr_of(task, vaddr, SILOFS_STAGE_RO, out_oaddr);
	if (err) {
		log_warn("failed to resolve voaddr: stype=%d off=%ld err=%d",
		         vaddr->stype, vaddr->off, err);
	}
	return err;
}

static void resolve_oaddr_of_unode(const struct silofs_unode_info *ui,
                                   struct silofs_oaddr *out_oaddr)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	oaddr_assign(out_oaddr, &uaddr->oaddr);
}

static int resolve_oaddr_of(struct silofs_task *task,
                            const struct silofs_snode_info *si,
                            struct silofs_oaddr *out_oaddr)
{
	const struct silofs_unode_info *ui = NULL;
	const struct silofs_vnode_info *vi = NULL;
	int ret = 0;

	if (stype_isunode(si->s_stype)) {
		ui = silofs_ui_from_si(si);
		resolve_oaddr_of_unode(ui, out_oaddr);
	} else if (stype_isvnode(si->s_stype)) {
		vi = silofs_vi_from_si(si);
		ret = resolve_oaddr_of_vnode(task, vi, out_oaddr);
	} else {
		silofs_panic("corrupted snode: stype=%d", si->s_stype);
	}
	silofs_assert_ok(ret);
	return ret;
}

static int flc_check_resolved_oaddr(const struct silofs_flush_ctx *fl_ctx,
                                    const struct silofs_snode_info *si,
                                    const struct silofs_oaddr *oaddr)
{
	const struct silofs_sb_info *sbi = fl_ctx->uber->ub_sbi;
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

static int flc_populate_sqe(struct silofs_flush_ctx *fl_ctx,
                            struct silofs_snode_info **siq,
                            struct silofs_submitq_entry *sqe)
{
	struct silofs_oaddr oaddr;
	struct silofs_snode_info *si;
	int err;

	while (*siq != NULL) {
		si = *siq;
		err = resolve_oaddr_of(fl_ctx->task, si, &oaddr);
		if (err) {
			return err;
		}
		err = flc_check_resolved_oaddr(fl_ctx, si, &oaddr);
		if (err) {
			return err;
		}
		if (!silofs_sqe_append_ref(sqe, &oaddr, si)) {
			break;
		}
		*siq = si->s_ds_next;
	}
	return silofs_sqe_assign_buf(sqe);
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

static void flc_init_dsets(struct silofs_flush_ctx *fl_ctx)
{
	dsets_init(&fl_ctx->dsets);
}

static void flc_fini_dsets(struct silofs_flush_ctx *fl_ctx)
{
	dsets_fini(&fl_ctx->dsets);
}

static struct silofs_dset *
flc_dset_of(struct silofs_flush_ctx *fl_ctx, enum silofs_stype stype)
{
	struct silofs_dsets *dsets = &fl_ctx->dsets;
	const size_t idx = (size_t)stype;

	return likely(idx < ARRAY_SIZE(dsets->dset)) ?
	       &dsets->dset[idx] : &dsets->dset[0];
}

static bool flc_has_dirty_dset(struct silofs_flush_ctx *fl_ctx,
                               enum silofs_stype stype)
{
	const struct silofs_dset *dset;

	dset = flc_dset_of(fl_ctx, stype);
	return dset->ds_avl.size > 0;
}

static void flc_make_fifo_dset(struct silofs_flush_ctx *fl_ctx,
                               enum silofs_stype stype)
{
	dset_mkfifo(flc_dset_of(fl_ctx, stype));
}

static void flc_seal_dset(struct silofs_flush_ctx *fl_ctx,
                          enum silofs_stype stype)
{
	dset_seal_all(flc_dset_of(fl_ctx, stype));
}

static void flc_undirtify_dset(struct silofs_flush_ctx *fl_ctx,
                               enum silofs_stype stype)
{
	silofs_cache_undirtify_by_dset(fl_ctx->cache,
	                               flc_dset_of(fl_ctx, stype));
}

static void flc_cleanup_dset(struct silofs_flush_ctx *fl_ctx,
                             enum silofs_stype stype)
{
	dset_clear_map(flc_dset_of(fl_ctx, stype));
}

static int flc_prep_sqe(const struct silofs_flush_ctx *fl_ctx,
                        struct silofs_submitq_entry *sqe)
{
	const struct silofs_blobid *blobid = &sqe->blobid;
	struct silofs_blobref_info *bri = NULL;
	int err;

	silofs_sqe_increfs(sqe);
	err = silofs_stage_blob_at(fl_ctx->uber, true, blobid, &bri);
	if (err) {
		return err;
	}
	silofs_sqe_bind_bri(sqe, bri);
	return 0;
}

static void flc_enqueue_sqe(const struct silofs_flush_ctx *fl_ctx,
                            struct silofs_submitq_entry *sqe)
{
	silofs_task_enq_sqe(fl_ctx->task, sqe);
}

static int flc_pend_sqe(const struct silofs_flush_ctx *fl_ctx,
                        struct silofs_submitq_entry *sqe)
{
	int err;

	err = flc_prep_sqe(fl_ctx, sqe);
	if (!err) {
		flc_enqueue_sqe(fl_ctx, sqe);
	}
	return err;
}

static int flc_flush_siq(struct silofs_flush_ctx *fl_ctx,
                         struct silofs_snode_info **siq,
                         struct silofs_submitq_entry *sqe)
{
	int err;

	err = flc_populate_sqe(fl_ctx, siq, sqe);
	if (err) {
		return err;
	}
	err = flc_pend_sqe(fl_ctx, sqe);
	if (err) {
		return err;
	}
	return 0;
}

static int flc_flush_dset(struct silofs_flush_ctx *fl_ctx,
                          enum silofs_stype stype)
{
	struct silofs_submitq_entry *sqe = NULL;
	struct silofs_dset *dset = flc_dset_of(fl_ctx, stype);
	struct silofs_snode_info *siq = dset->ds_siq;
	int err;

	while (siq != NULL) {
		err = silofs_task_mk_sqe(fl_ctx->task, &sqe);
		if (err) {
			return err;
		}
		err = flc_flush_siq(fl_ctx, &siq, sqe);
		if (err) {
			silofs_task_rm_sqe(fl_ctx->task, sqe);
			return err;
		}
	}
	return 0;
}

static int flc_process_dset_of(struct silofs_flush_ctx *fl_ctx,
                               enum silofs_stype stype)
{
	int ret = 0;

	if (flc_has_dirty_dset(fl_ctx, stype)) {
		flc_make_fifo_dset(fl_ctx, stype);
		flc_seal_dset(fl_ctx, stype);
		ret = flc_flush_dset(fl_ctx, stype);
		if (!ret) {
			flc_undirtify_dset(fl_ctx, stype);
		}
		flc_cleanup_dset(fl_ctx, stype);
	}
	return ret;
}

static void flc_fill_dsets(struct silofs_flush_ctx *fl_ctx)
{
	silofs_cache_fill_dsets(fl_ctx->cache, &fl_ctx->dsets, fl_ctx->dqid);
}

static int flc_process_dsets(struct silofs_flush_ctx *fl_ctx)
{
	enum silofs_stype stype = SILOFS_STYPE_NONE;
	int ret = 0;

	while ((ret == 0) && (++stype < SILOFS_STYPE_LAST)) {
		ret = flc_process_dset_of(fl_ctx, stype);
	}
	return ret;
}

static int flc_collect_flush_dirty(struct silofs_flush_ctx *fl_ctx)
{
	int err;

	flc_init_dsets(fl_ctx);
	flc_fill_dsets(fl_ctx);
	err = flc_process_dsets(fl_ctx);
	flc_fini_dsets(fl_ctx);
	return err;
}

/*
 * TODO-0034: Issue flush sync to dirty blobs
 *
 * Implement fsync at blobs level and ensure that all of kernel's in-cache
 * data is flushed all the way to stable storage.
 */
static int flc_complete_commits(const struct silofs_flush_ctx *fl_ctx)
{
	int ret = 0;

	if ((fl_ctx->flags & SILOFS_F_NOW) &&
	    (fl_ctx->dqid == SILOFS_DQID_ALL)) {
		ret = silofs_task_submit(fl_ctx->task, true);
	}
	return ret;
}

static int flc_flush_dirty_of(struct silofs_flush_ctx *fl_ctx)
{
	int err;

	err = flc_collect_flush_dirty(fl_ctx);
	if (err) {
		log_warn("flush execute failure: err=%d", err);
		return err;
	}
	err = flc_complete_commits(fl_ctx);
	if (err) {
		log_warn("flush complete failure: err=%d", err);
		return err;
	}
	return 0;
}

static bool flc_need_flush(const struct silofs_flush_ctx *fl_ctx)
{
	return silofs_cache_need_flush(fl_ctx->cache, fl_ctx->dqid,
	                               fl_ctx->flags);
}

static int flc_setup(struct silofs_flush_ctx *fl_ctx,
                     struct silofs_task *task, silofs_dqid_t dqid, int flags)
{
	struct silofs_repo *repo = NULL;
	struct silofs_uber *uber = task->t_uber;

	repo = silofs_repos_get(uber->ub_repos, SILOFS_REPO_LOCAL);
	if (unlikely(repo == NULL)) {
		return -SILOFS_ENOREPO;
	}
	fl_ctx->task = task;
	fl_ctx->uber = uber;
	fl_ctx->dqid = dqid;
	fl_ctx->flags = flags;
	fl_ctx->repo = repo;
	fl_ctx->cache = &repo->re_cache;
	fl_ctx->alloc = fl_ctx->cache->c_alloc;
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
	struct silofs_flush_ctx fl_ctx = { .flags = -1 };
	int err;
	bool ret = false;

	err = flc_setup(&fl_ctx, task, dqid, flags);
	if (!err) {
		ret = flc_need_flush(&fl_ctx);
	}
	return ret;
}

int silofs_flush_dirty(struct silofs_task *task,
                       silofs_dqid_t dqid, int flags)
{
	struct silofs_flush_ctx fl_ctx = { .flags = -1 };
	int err;

	err = flc_setup(&fl_ctx, task, dqid, flags);
	if (err) {
		return err;
	}
	if (!flc_need_flush(&fl_ctx)) {
		return 0;
	}
	err = flc_flush_dirty_of(&fl_ctx);
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
