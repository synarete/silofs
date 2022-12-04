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
	struct silofs_fs_uber  *uber;
	struct silofs_repo     *repo;
	struct silofs_cache    *cache;
	silofs_dqid_t           dqid;
	int flags;
	bool warm;
};


struct silofs_sgvec {
	struct iovec iov[SILOFS_NKB_IN_BK];
	struct silofs_snode_info *si[SILOFS_NKB_IN_BK];
	struct silofs_blobid blobid;
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

static void sgvec_setup(struct silofs_sgvec *sgv)
{
	sgv->blobid.size = 0;
	sgv->off = -1;
	sgv->lim = 2 * SILOFS_MEGA;
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
	silofs_assert_lt(oaddr->len, sgv->lim);
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

static int si_resolve_oaddr(const struct silofs_snode_info *si,
                            struct silofs_oaddr *out_oaddr)
{
	int err;

	err = si->s_vtbl->resolve(si, out_oaddr);
	if (err) {
		log_warn("failed to resolve oaddr: stype=%d err=%d",
		         si->s_stype, err);
	}
	return err;
}

static int sgvec_populate(struct silofs_sgvec *sgv,
                          struct silofs_snode_info **siq)
{
	struct silofs_oaddr oaddr;
	struct silofs_snode_info *si;
	int err;

	while (*siq != NULL) {
		si = *siq;
		err = si_resolve_oaddr(si, &oaddr);
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
		si->s_vtbl->seal(si);
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

static int flc_store_sgv_at(const struct silofs_flush_ctx *fl_ctx,
                            struct silofs_blobref_info *bri,
                            const struct silofs_oaddr *oaddr,
                            const struct silofs_sgvec *sgv)
{
	int ret;

	bri_incref(bri);
	ret = silofs_bri_pwritevn(bri, oaddr, sgv->iov, sgv->cnt);
	bri_decref(bri);
	unused(fl_ctx);
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
	int err;

	while (siq != NULL) {
		sgvec_setup(&sgv);
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
                     struct silofs_fs_uber *uber,
                     silofs_dqid_t dqid, int flags)
{
	struct silofs_repo *repo;

	repo = silofs_repos_get(uber->ub_repos, SILOFS_REPO_LOCAL);
	if (unlikely(repo == NULL)) {
		return -SILOFS_ENOREPO;
	}
	fl_ctx->uber = uber;
	fl_ctx->dqid = dqid;
	fl_ctx->flags = flags;
	fl_ctx->warm = true;
	fl_ctx->repo = repo;
	fl_ctx->cache = &repo->re_cache;
	return 0;
}

int silofs_uber_flush_dirty(struct silofs_fs_uber *uber,
                            silofs_dqid_t dqid, int flags)
{
	struct silofs_flush_ctx fl_ctx = { .flags = -1 };
	int err;

	err = flc_setup(&fl_ctx, uber, dqid, flags);
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
