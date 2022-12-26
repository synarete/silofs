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
	struct silofs_dset        dset;
	const struct silofs_task *task;
	struct silofs_alloc      *alloc;
	struct silofs_uber       *uber;
	struct silofs_repo       *repo;
	struct silofs_cache      *cache;
	struct silofs_flushbuf   *flush_buf;
	silofs_dqid_t             dqid;
	int flags;
	bool warm;
	bool use_buf;
};


struct silofs_sgvec {
	struct iovec              iov[SILOFS_NKB_IN_BK];
	struct silofs_snode_info *si[SILOFS_NKB_IN_BK];
	struct silofs_blobid      blobid;
	const struct silofs_task *task;
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int resolve_oaddr_of_vnode(const struct silofs_task *task,
                                  const struct silofs_vnode_info *vi,
                                  struct silofs_oaddr *out_oaddr)
{
	struct silofs_voaddr voa;
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);
	int err;

	err = silofs_resolve_voaddr_of(task, vaddr, SILOFS_STAGE_RO, &voa);
	if (err) {
		log_warn("failed to resolve voaddr: stype=%d off=%ld err=%d",
		         vaddr->stype, vaddr->voff, err);
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

static int resolve_oaddr_of(const struct silofs_task *task,
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

static void si_seal_meta(struct silofs_snode_info *si)
{
	const enum silofs_stype stype = si->s_stype;

	if (stype_isunode(stype)) {
		silofs_seal_unode(silofs_ui_from_si(si));
	} else if (stype_isvnode(stype) && !stype_isdata(stype)) {
		silofs_seal_vnode(silofs_vi_from_si(si));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sgvec_setup(struct silofs_sgvec *sgv,
                        const struct silofs_task *task, size_t lim)
{
	sgv->task = task;
	sgv->blobid.size = 0;
	sgv->off = -1;
	sgv->lim = lim;
	sgv->cnt = 0;
	sgv->len = 0;
}

static bool sgvec_isappendable(const struct silofs_sgvec *sgv,
                               const struct silofs_oaddr *oaddr)
{
	if (sgv->cnt == 0) {
		return true;
	}
	if (sgv->cnt == ARRAY_SIZE(sgv->iov)) {
		return false;
	}
	if (oaddr->pos != off_end(sgv->off, sgv->len)) {
		return false;
	}
	if ((sgv->len + oaddr->len) > sgv->lim) {
		return false;
	}
	if (!blobid_isequal(&oaddr->bka.blobid, &sgv->blobid)) {
		return false;
	}
	return true;
}

static int sgvec_append(struct silofs_sgvec *sgv,
                        const struct silofs_oaddr *oaddr,
                        struct silofs_snode_info *si)
{
	const void *dat = si->s_view;
	const size_t idx = sgv->cnt;

	if (idx == 0) {
		blobid_assign(&sgv->blobid, &oaddr->bka.blobid);
		sgv->off = oaddr->pos;
	}
	sgv->iov[idx].iov_base = unconst(dat);
	sgv->iov[idx].iov_len = oaddr->len;
	sgv->si[idx] = si;
	sgv->len += oaddr->len;
	sgv->cnt += 1;
	return 0;
}

static int sgvec_populate(struct silofs_sgvec *sgv,
                          struct silofs_snode_info **siq)
{
	struct silofs_oaddr oaddr;
	struct silofs_snode_info *si;
	int err;

	while (*siq != NULL) {
		si = *siq;
		err = resolve_oaddr_of(sgv->task, si, &oaddr);
		if (err) {
			return err;
		}
		if (!sgvec_isappendable(sgv, &oaddr)) {
			break;
		}
		err = sgvec_append(sgv, &oaddr, si);
		if (err) {
			return err;
		}
		*siq = si->s_ds_next;
	}
	return 0;
}

static void sgvec_copyto(const struct silofs_sgvec *sgv, void *buf)
{
	uint8_t *dat = buf;
	void *src;
	size_t len;

	for (size_t i = 0; i < sgv->cnt; ++i) {
		src = sgv->iov[i].iov_base;
		len = sgv->iov[i].iov_len;
		memcpy(dat, src, len);
		dat += len;
	}
}

static void sgvec_increfs(struct silofs_sgvec *sgv)
{
	for (size_t i = 0; i < sgv->cnt; ++i) {
		silofs_si_incref(sgv->si[i]);
	}
}

static void sgvec_decrefs(struct silofs_sgvec *sgv)
{
	for (size_t i = 0; i < sgv->cnt; ++i) {
		silofs_si_decref(sgv->si[i]);
	}
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

static int flc_allocate(const struct silofs_flush_ctx *fl_ctx,
                        size_t len, void **out_dat)
{
	*out_dat = silofs_allocate(fl_ctx->alloc, len);
	return unlikely(*out_dat == NULL) ? -ENOMEM : 0;
}

static void flc_deallocate(const struct silofs_flush_ctx *fl_ctx,
                           void *dat, size_t len)
{
	silofs_deallocate(fl_ctx->alloc, dat, len);
}

static int flc_store_sgv_buf(const struct silofs_flush_ctx *fl_ctx,
                             struct silofs_blobref_info *bri,
                             const struct silofs_oaddr *oaddr,
                             const struct silofs_sgvec *sgv)
{
	struct silofs_flushbuf *flush_buf = fl_ctx->flush_buf;
	void *buf = flush_buf->b;
	size_t len;
	int err;

	len = sgv->len;
	if (len > sizeof(flush_buf->b)) {
		err = flc_allocate(fl_ctx, len, &buf);
		if (err) {
			return err;
		}
	}
	sgvec_copyto(sgv, buf);
	err = silofs_bri_pwriten(bri, oaddr->pos, buf, len);
	if (len > sizeof(flush_buf->b)) {
		flc_deallocate(fl_ctx, buf, len);
	}
	return err;
}

static int flc_store_sgv_iov(const struct silofs_flush_ctx *fl_ctx,
                             struct silofs_blobref_info *bri,
                             const struct silofs_oaddr *oaddr,
                             const struct silofs_sgvec *sgv)
{
	unused(fl_ctx);
	return silofs_bri_pwritevn(bri, oaddr, sgv->iov, sgv->cnt);
}

static int flc_store_sgv_at(const struct silofs_flush_ctx *fl_ctx,
                            struct silofs_blobref_info *bri,
                            const struct silofs_oaddr *oaddr,
                            const struct silofs_sgvec *sgv)
{
	int ret;

	bri_incref(bri);
	if (fl_ctx->use_buf) {
		ret = flc_store_sgv_buf(fl_ctx, bri, oaddr, sgv);
	} else {
		ret = flc_store_sgv_iov(fl_ctx, bri, oaddr, sgv);
	}
	bri_decref(bri);
	return ret;
}

static int flc_do_store_sgv(const struct silofs_flush_ctx *fl_ctx,
                            const struct silofs_sgvec *sgv)
{
	struct silofs_oaddr oaddr = { .pos = -1 };
	const struct silofs_blobid *blobid = &sgv->blobid;
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = silofs_stage_blob_at(fl_ctx->uber, fl_ctx->warm, blobid, &bri);
	if (err) {
		return err;
	}
	silofs_assert(!bri->br_rdonly);
	oaddr_setup(&oaddr, blobid, sgv->off, sgv->len);
	err = flc_store_sgv_at(fl_ctx, bri, &oaddr, sgv);
	if (err) {
		return err;
	}
	return 0;
}

static int flc_store_sgv(const struct silofs_flush_ctx *fl_ctx,
                         struct silofs_sgvec *sgv)
{
	int ret;

	sgvec_increfs(sgv);
	ret = flc_do_store_sgv(fl_ctx, sgv);
	sgvec_decrefs(sgv);
	return ret;
}

static int flc_flush_dset(struct silofs_flush_ctx *fl_ctx)
{
	struct silofs_sgvec sgv;
	struct silofs_dset *dset = &fl_ctx->dset;
	struct silofs_snode_info *siq = dset->ds_siq;
	const size_t lim = sizeof(fl_ctx->flush_buf->b);
	int err;

	while (siq != NULL) {
		sgvec_setup(&sgv, fl_ctx->task, lim);
		err = sgvec_populate(&sgv, &siq);
		if (err) {
			return err;
		}
		err = flc_store_sgv(fl_ctx, &sgv);
		if (err) {
			return err;
		}
	}
	return 0;
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

static int flc_commit_last(const struct silofs_flush_ctx *fl_ctx)
{
	int ret = 0;

	if (fl_ctx->flags & SILOFS_F_NOW) {
		/*
		 * TODO-0034: Issue flush sync to dirty blobs
		 *
		 * Implement fsync at blobs level and ensure that all of
		 * kernel's in-cache data is flushed all the way to stable
		 * storage.
		 */
		ret = 0;
	}

	return ret;
}

static int flc_flush_dirty_of(struct silofs_flush_ctx *fl_ctx)
{
	int err;

	err = flc_collect_flush_dirty(fl_ctx);
	if (err) {
		log_warn("flush failure: err=%d", err);
		return err;
	}
	err = flc_commit_last(fl_ctx);
	if (err) {
		log_warn("commit-last failure: err=%d", err);
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
                     const struct silofs_task *task,
                     silofs_dqid_t dqid, int flags)
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
	fl_ctx->warm = true;
	fl_ctx->use_buf = true;
	fl_ctx->repo = repo;
	fl_ctx->cache = &repo->re_cache;
	fl_ctx->alloc = fl_ctx->cache->c_alloc;
	fl_ctx->flush_buf = fl_ctx->cache->c_flush_buf;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static silofs_dqid_t ii_dqid(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v_si.s_dqid;
}

int silofs_flush_dirty(const struct silofs_task *task,
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

int silofs_flush_dirty_of(const struct silofs_task *task,
                          const struct silofs_inode_info *ii, int flags)
{
	return silofs_flush_dirty(task, ii_dqid(ii), flags);
}

int silofs_flush_dirty_now(const struct silofs_task *task)
{
	return silofs_flush_dirty(task, SILOFS_DQID_ALL, SILOFS_F_NOW);
}
