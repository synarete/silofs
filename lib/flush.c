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
	struct silofs_dset      dset;
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
	struct silofs_voaddr voa;
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);
	int err;

	err = silofs_resolve_voaddr_of(task, vaddr, SILOFS_STAGE_RO, &voa);
	if (err) {
		log_warn("failed to resolve voaddr: stype=%d off=%ld err=%d",
		         vaddr->stype, vaddr->off, err);
		return err;
	}
	oaddr_assign(out_oaddr, &voa.oaddr);
	return 0;
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
	return ret;
}

static int populate_commit(struct silofs_snode_info **siq,
                           struct silofs_commit_info *cmi)
{
	struct silofs_oaddr oaddr;
	struct silofs_snode_info *si;
	int err;

	while (*siq != NULL) {
		si = *siq;
		err = resolve_oaddr_of(cmi->task, si, &oaddr);
		if (err) {
			return err;
		}
		if (!silofs_cmi_append_ref(cmi, &oaddr, si)) {
			break;
		}
		*siq = si->s_ds_next;
	}
	return silofs_cmi_assign_buf(cmi);
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

static void dsek_mkfifo(struct silofs_dset *dset)
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

static void flc_init_dset(struct silofs_flush_ctx *fl_ctx)
{
	dset_init(&fl_ctx->dset);
}

static void flc_fini_dset(struct silofs_flush_ctx *fl_ctx)
{
	dset_fini(&fl_ctx->dset);
}

static void flc_make_fifo_dset(struct silofs_flush_ctx *fl_ctx)
{
	dsek_mkfifo(&fl_ctx->dset);
}

static void flc_seal_dset(const struct silofs_flush_ctx *fl_ctx)
{
	dset_seal_all(&fl_ctx->dset);
}

static void flc_fill_dset(struct silofs_flush_ctx *fl_ctx)
{
	silofs_cache_fill_into_dset(fl_ctx->cache,
	                            &fl_ctx->dset, fl_ctx->dqid);
}

static void flc_populate_dset(struct silofs_flush_ctx *fl_ctx)
{
	flc_fill_dset(fl_ctx);
	flc_make_fifo_dset(fl_ctx);
	flc_seal_dset(fl_ctx);
}

static void flc_undirtify_dset(struct silofs_flush_ctx *fl_ctx)
{
	silofs_cache_undirtify_by_dset(fl_ctx->cache, &fl_ctx->dset);
}

static void flc_cleanup_dset(struct silofs_flush_ctx *fl_ctx)
{
	dset_clear_map(&fl_ctx->dset);
}

static int flc_commit_one(const struct silofs_flush_ctx *fl_ctx,
                          struct silofs_commit_info *cmi)
{
	const struct silofs_blobid *blobid = &cmi->bid;
	struct silofs_blobref_info *bri = NULL;
	int err;

	silofs_cmi_increfs(cmi);
	err = silofs_stage_blob_at(fl_ctx->uber, true, blobid, &bri);
	if (err) {
		goto out;
	}
	silofs_cmi_bind_bri(cmi, bri);
	err = silofs_cmi_write_buf(cmi);
	if (err) {
		goto out;
	}
out:
	silofs_cmi_decrefs(cmi);
	cmi->status = err;
	cmi->done = true;
	return err;
}

static int flc_flush_siq(struct silofs_flush_ctx *fl_ctx,
                         struct silofs_snode_info **siq,
                         struct silofs_commit_info *cmi)
{
	int err;

	err = populate_commit(siq, cmi);
	if (err) {
		return err;
	}
	err = flc_commit_one(fl_ctx, cmi);
	if (err) {
		return err;
	}
	return 0;
}

static int flc_flush_dset(struct silofs_flush_ctx *fl_ctx)
{
	struct silofs_commit_info *cmi = NULL;
	struct silofs_dset *dset = &fl_ctx->dset;
	struct silofs_snode_info *siq = dset->ds_siq;
	int err = 0;

	while (!err && (siq != NULL)) {
		cmi = NULL;
		err = silofs_task_make_commit(fl_ctx->task, &cmi);
		if (!err) {
			err = flc_flush_siq(fl_ctx, &siq, cmi);
		}
	}
	return err;
}

static int flc_collect_flush_dset(struct silofs_flush_ctx *fl_ctx)
{
	int err;

	flc_populate_dset(fl_ctx);
	err = flc_flush_dset(fl_ctx);
	if (!err) {
		flc_undirtify_dset(fl_ctx);
	}
	flc_cleanup_dset(fl_ctx);
	return err;
}

static int flc_collect_flush_dirty(struct silofs_flush_ctx *fl_ctx)
{
	int err;

	flc_init_dset(fl_ctx);
	err = flc_collect_flush_dset(fl_ctx);
	flc_fini_dset(fl_ctx);
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
		ret = silofs_task_let_complete(fl_ctx->task);
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
