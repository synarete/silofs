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
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>


struct silofs_stage_ctx {
	struct silofs_task             *task;
	struct silofs_uber             *uber;
	struct silofs_sb_info          *sbi;
	struct silofs_spnode_info      *sni5;
	struct silofs_spnode_info      *sni4;
	struct silofs_spnode_info      *sni3;
	struct silofs_spnode_info      *sni2;
	struct silofs_spnode_info      *sni1;
	struct silofs_spleaf_info      *sli;
	const struct silofs_vaddr      *vaddr;
	silofs_lba_t                    bk_lba;
	loff_t                          bk_voff;
	loff_t                          voff;
	enum silofs_stg_mode            stg_mode;
	enum silofs_stype               vspace;
	unsigned int                    retry;
};

struct silofs_vis {
	struct silofs_vaddrs vas;
	struct silofs_vnode_info *vis[SILOFS_NKB_IN_BK];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool is_low_resource_error(int err)
{
	return (err == -ENOMEM) || (err == -EMFILE) || (err == -ENFILE);
}

static bool stage_normal(enum silofs_stg_mode stg_mode)
{
	return (stg_mode & SILOFS_STG_CUR) > 0;
}

static bool stage_cow(enum silofs_stg_mode stg_mode)
{
	return (stg_mode & SILOFS_STG_COW) > 0;
}

static loff_t vaddr_bk_voff(const struct silofs_vaddr *vaddr)
{
	return off_align_to_bk(vaddr->off);
}

static ino_t vaddr_to_ino(const struct silofs_vaddr *vaddr)
{
	return silofs_off_to_ino(vaddr->off);
}

static void voaddr_by(struct silofs_voaddr *voa,
                      const struct silofs_blobid *blobid,
                      const struct silofs_vaddr *vaddr)
{
	silofs_voaddr_setup_by(voa, blobid, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_uber *uber, struct silofs_vbk_info *vbki)
{
	silofs_vi_attach_to(vi, vbki);
	vi->v_si.s_uber = uber;
}

static void vi_update_oaddr(struct silofs_vnode_info *vi,
                            const struct silofs_oaddr *oaddr)
{
	oaddr_assign(&vi->v_oaddr, oaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_cache *stgc_cache(const struct silofs_stage_ctx *stg_ctx)
{
	return stg_ctx->uber->ub.cache;
}

static void stgc_log_cache_stat(const struct silofs_stage_ctx *stg_ctx)
{
	const struct silofs_cache *cache = stgc_cache(stg_ctx);
	const struct silofs_dirtyqs *dqs = &cache->c_dqs;

	log_dbg("cache-stat: accum_unodes=%lu accum_inodes=%lu "\
	        "accum_vnodes=%lu ubki=%lu ui=%lu vbki=%lu vi=%lu blobf=%lu",
	        dqs->dq_uis.dq_accum, dqs->dq_iis.dq_accum,
	        dqs->dq_vis.dq_accum, cache->c_ubki_lm.lm_lru.sz,
	        cache->c_ui_lm.lm_lru.sz, cache->c_vbki_lm.lm_lru.sz,
	        cache->c_vi_lm.lm_lru.sz, cache->c_blobf_lm.lm_lru.sz);
}

static int stgc_lookup_cached_vbki(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_vbk_info **out_vbki)
{
	struct silofs_cache *cache = stgc_cache(stg_ctx);

	*out_vbki = silofs_cache_lookup_vbk(cache, vaddr->off, vaddr->stype);
	return (*out_vbki != NULL) ? 0 : -ENOENT;
}

static void stgc_forget_cached_vbki(const struct silofs_stage_ctx *stg_ctx,
                                    struct silofs_vbk_info *vbki)
{
	silofs_cache_forget_vbk(stgc_cache(stg_ctx), vbki);
}

static int stgc_spawn_cached_vbki(const struct silofs_stage_ctx *stg_ctx,
                                  loff_t voff, enum silofs_stype vspace,
                                  struct silofs_vbk_info **out_vbki)
{
	*out_vbki = silofs_cache_spawn_vbk(stgc_cache(stg_ctx), voff, vspace);
	return (*out_vbki != NULL) ? 0 : -ENOMEM;
}

static int stgc_spawn_cached_vi(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_vnode_info **out_vi)
{
	struct silofs_cache *cache = stgc_cache(stg_ctx);

	*out_vi = silofs_cache_spawn_vi(cache, vaddr);
	return (*out_vi == NULL) ? -ENOMEM : 0;
}

static void stgc_forget_cached_vi(const struct silofs_stage_ctx *stg_ctx,
                                  struct silofs_vnode_info *vi)
{
	if (vi != NULL) {
		silofs_cache_forget_vi(stgc_cache(stg_ctx), vi);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_flush_dirty_now(const struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = silofs_flush_dirty_now(stg_ctx->task);
	if (err) {
		log_dbg("flush dirty failed: err=%d", err);
	}
	return err;
}

static void stgc_relax_caches_now(const struct silofs_stage_ctx *stg_ctx)
{
	silofs_relax_cache_by(stg_ctx->task, SILOFS_F_NOW);
}

static int
stgc_try_evict_some(const struct silofs_stage_ctx *stg_ctx, bool flush_dirty)
{
	int err;

	if (flush_dirty) {
		err = stgc_flush_dirty_now(stg_ctx);
		if (err) {
			stgc_log_cache_stat(stg_ctx);
			return err;
		}
	}
	stgc_relax_caches_now(stg_ctx);
	return 0;
}

static int stgc_do_spawn_vbki(const struct silofs_stage_ctx *stg_ctx,
                              loff_t voff, enum silofs_stype vspace,
                              struct silofs_vbk_info **out_vbki)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = stgc_spawn_cached_vbki(stg_ctx, voff, vspace, out_vbki);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_do_spawn_vi(const struct silofs_stage_ctx *stg_ctx,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_vnode_info **out_vi)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = stgc_spawn_cached_vi(stg_ctx, vaddr, out_vi);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_do_stage_blob(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_blobid *blobid,
                              struct silofs_blobf **out_blobf)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_stage_blob_at(stg_ctx->uber, blobid, out_blobf);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_spawn_bind_vi(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_voaddr *voaddr,
                              struct silofs_vbk_info *vbki,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	silofs_vbki_incref(vbki);
	err = stgc_do_spawn_vi(stg_ctx, &voaddr->vaddr, &vi);
	if (!err) {
		vi_bind_to(vi, stg_ctx->uber, vbki);
		vi_update_oaddr(vi, &voaddr->oaddr);
	}
	silofs_vbki_decref(vbki);
	*out_vi = vi;
	return err;
}

static int stgc_restore_view_of(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_vnode_info *vi)
{
	int err;
	bool raw;

	raw = (stg_ctx->stg_mode & SILOFS_STG_RAW) > 0;
	err = silofs_restore_vi_view(stg_ctx->uber, vi, raw);
	if (!err && !raw) {
		err = silofs_vi_verify_view(vi);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool sbi_ismutable_bkaddr(const struct silofs_sb_info *sbi,
                                 const struct silofs_bkaddr *bkaddr)
{
	return silofs_sbi_ismutable_blobid(sbi, &bkaddr->blobid);
}

static int sbi_inspect_bkaddr(const struct silofs_sb_info *sbi,
                              const struct silofs_bkaddr *bkaddr,
                              enum silofs_stg_mode stg_mode)
{
	if (!stage_cow(stg_mode)) {
		return 0;
	}
	if (sbi_ismutable_bkaddr(sbi, bkaddr)) {
		return 0;
	}
	return -SILOFS_EPERM;
}

static int sbi_inspect_cached_ui(const struct silofs_sb_info *sbi,
                                 const struct silofs_unode_info *ui,
                                 enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_bkaddr(sbi, ui_bkaddr(ui), stg_mode);
}

static int sbi_inspect_cached_sni(const struct silofs_sb_info *sbi,
                                  const struct silofs_spnode_info *sni,
                                  enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_cached_ui(sbi, &sni->sn_ui, stg_mode);
}

static int sbi_inspect_cached_sli(const struct silofs_sb_info *sbi,
                                  const struct silofs_spleaf_info *sli,
                                  enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_cached_ui(sbi, &sli->sl_ui, stg_mode);
}

static enum silofs_stype sni_child_stype(const struct silofs_spnode_info *sni)
{
	enum silofs_stype stype;
	const enum silofs_height height = silofs_sni_height(sni);

	switch (height) {
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_SPNODE5:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE2:
		stype = SILOFS_STYPE_SPNODE;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		stype = SILOFS_STYPE_SPLEAF;
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		stype = SILOFS_STYPE_NONE;
		break;
	}
	return stype;
}

static
enum silofs_height sni_child_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void stgc_setup(struct silofs_stage_ctx *stg_ctx,
                       struct silofs_task *task,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stg_mode stg_mode)
{
	memset(stg_ctx, 0, sizeof(*stg_ctx));
	stg_ctx->task = task;
	stg_ctx->uber = task->t_uber;
	stg_ctx->sbi = task->t_uber->ub_sbi;
	stg_ctx->vaddr = vaddr;
	stg_ctx->stg_mode = stg_mode;
	stg_ctx->vspace = vaddr->stype;
	stg_ctx->bk_voff = vaddr_bk_voff(vaddr);
	stg_ctx->bk_lba = off_to_lba(stg_ctx->bk_voff);
	stg_ctx->voff = vaddr->off;
	stg_ctx->retry = 3;
}

static int stgc_do_spawn_blob(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_blobid *blobid,
                              struct silofs_blobf **out_blobf)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_spawn_blob_at(stg_ctx->uber, blobid, out_blobf);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_spawn_blob(const struct silofs_stage_ctx *stg_ctx,
                           const struct silofs_blobid *blobid,
                           enum silofs_stype stype_sub,
                           struct silofs_blobf **out_blobf)
{
	int err;

	err = stgc_do_spawn_blob(stg_ctx, blobid, out_blobf);
	if (!err) {
		silofs_sti_update_blobs(&stg_ctx->sbi->sb_sti, stype_sub, 1);
	}
	return err;
}

static void
stgc_make_blobid_of_spmaps(const struct silofs_stage_ctx *stg_ctx,
                           loff_t voff, enum silofs_height height,
                           struct silofs_blobid *out_blobid)
{
	struct silofs_treeid treeid;
	const enum silofs_stype vspace = stg_ctx->vspace;

	silofs_sbi_treeid(stg_ctx->sbi, &treeid);
	silofs_blobid_setup(out_blobid, &treeid, voff, vspace, height);
}

static void
stgc_make_blobid_of_vdata(const struct silofs_stage_ctx *stg_ctx,
                          loff_t voff, struct silofs_blobid *out_blobid)
{
	struct silofs_treeid treeid;
	const enum silofs_stype vspace = stg_ctx->vspace;
	const enum silofs_height height = SILOFS_HEIGHT_VDATA;
	loff_t voff_base;
	ssize_t blob_size;

	blob_size = (ssize_t)silofs_height_to_blob_size(height);
	voff_base = off_align(voff, blob_size);

	silofs_sbi_treeid(stg_ctx->sbi, &treeid);
	silofs_blobid_setup(out_blobid, &treeid, voff_base, vspace, height);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_update_space_stats(const struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_uaddr *uaddr)
{
	silofs_sti_update_objs(&stg_ctx->sbi->sb_sti, uaddr->stype, 1);
	silofs_sti_update_bks(&stg_ctx->sbi->sb_sti, uaddr->stype, 1);
}

static int stgc_spawn_super_main_blob(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_blobid blobid;
	struct silofs_blobf *blobf = NULL;
	const enum silofs_height height = SILOFS_HEIGHT_SUPER - 1;
	int err;

	stgc_make_blobid_of_spmaps(stg_ctx, 0, height, &blobid);
	err = stgc_spawn_blob(stg_ctx, &blobid, SILOFS_STYPE_SPNODE, &blobf);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_blob(stg_ctx->sbi, stg_ctx->vspace,
	                          &blobf->b_blobid);
	return 0;
}

static int stgc_stage_super_main_blob(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_blobid blobid;
	struct silofs_blobf *blobf = NULL;

	silofs_sbi_main_blob(stg_ctx->sbi, stg_ctx->vspace, &blobid);
	return stgc_do_stage_blob(stg_ctx, &blobid, &blobf);
}

static int stgc_require_super_main_blob(const struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (silofs_sbi_has_main_blob(stg_ctx->sbi, stg_ctx->vspace)) {
		err = stgc_stage_super_main_blob(stg_ctx);
	} else {
		err = stgc_spawn_super_main_blob(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_spawn_spnode_main_blob(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;
	struct silofs_blobf *blobf = NULL;
	const loff_t voff = silofs_sni_base_voff(sni);
	const enum silofs_height height = sni_child_height(sni);
	const enum silofs_stype stype = sni_child_stype(sni);
	int err;

	stgc_make_blobid_of_spmaps(stg_ctx, voff, height, &blobid);
	err = stgc_spawn_blob(stg_ctx, &blobid, stype, &blobf);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_blob(sni, &blobf->b_blobid);
	return 0;
}

static int stgc_stage_spnode_main_blob(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;
	struct silofs_blobf *blobf = NULL;

	silofs_sni_main_blob(sni, &blobid);
	return stgc_do_stage_blob(stg_ctx, &blobid, &blobf);
}

static int
stgc_require_spnode_main_blob(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info *sni)
{
	int err;

	if (silofs_sni_has_main_blob(sni)) {
		err = stgc_stage_spnode_main_blob(stg_ctx, sni);
	} else {
		err = stgc_spawn_spnode_main_blob(stg_ctx, sni);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_inspect_bkaddr(const struct silofs_stage_ctx *stg_ctx,
                               const struct silofs_bkaddr *bkaddr)
{
	if (stage_normal(stg_ctx->stg_mode)) {
		return 0;
	}
	if (sbi_ismutable_bkaddr(stg_ctx->sbi, bkaddr)) {
		return 0;
	}
	return -SILOFS_EPERM; /* address on read-only tree */
}

static int stgc_inspect_cached_ui(const struct silofs_stage_ctx *stg_ctx,
                                  const struct silofs_unode_info *ui)
{
	return stgc_inspect_bkaddr(stg_ctx, ui_bkaddr(ui));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void stgc_increfs(const struct silofs_stage_ctx *stg_ctx,
                         enum silofs_height height_upto)
{
	if (height_upto <= SILOFS_HEIGHT_SUPER) {
		sbi_incref(stg_ctx->sbi);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE5) {
		sni_incref(stg_ctx->sni5);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE4) {
		sni_incref(stg_ctx->sni4);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE3) {
		sni_incref(stg_ctx->sni3);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE2) {
		sni_incref(stg_ctx->sni2);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE1) {
		sni_incref(stg_ctx->sni1);
	}
	if (height_upto <= SILOFS_HEIGHT_SPLEAF) {
		sli_incref(stg_ctx->sli);
	}
}

static void stgc_decrefs(const struct silofs_stage_ctx *stg_ctx,
                         enum silofs_height height_from)
{
	if (height_from <= SILOFS_HEIGHT_SPLEAF) {
		sli_decref(stg_ctx->sli);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE1) {
		sni_decref(stg_ctx->sni1);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE2) {
		sni_decref(stg_ctx->sni2);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE3) {
		sni_decref(stg_ctx->sni3);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE4) {
		sni_decref(stg_ctx->sni4);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE5) {
		sni_decref(stg_ctx->sni5);
	}
	if (height_from <= SILOFS_HEIGHT_SUPER) {
		sbi_decref(stg_ctx->sbi);
	}
}

static int stgc_find_cached_unode(const struct silofs_stage_ctx *stg_ctx,
                                  enum silofs_height height,
                                  struct silofs_unode_info **out_ui)
{
	struct silofs_vrange vrange;
	struct silofs_uakey uakey;

	silofs_vrange_of_spmap(&vrange, height, stg_ctx->bk_voff);
	silofs_uakey_setup_by2(&uakey, &vrange, stg_ctx->vspace);
	*out_ui = silofs_cache_find_ui_by(stgc_cache(stg_ctx), &uakey);
	return (*out_ui != NULL) ? 0 : -ENOENT;
}

static int stgc_stage_cached_spnode(const struct silofs_stage_ctx *stg_ctx,
                                    enum silofs_height height,
                                    struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = stgc_find_cached_unode(stg_ctx, height, &ui);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_ui(stg_ctx, ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	return 0;
}

static int stgc_stage_cached_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                    struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = stgc_find_cached_unode(stg_ctx, SILOFS_HEIGHT_SPLEAF, &ui);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_ui(stg_ctx, ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	return 0;
}

static int stgc_inspect_cached_spnode(const struct silofs_stage_ctx *stg_ctx,
                                      const struct silofs_spnode_info *sni)
{
	return sbi_inspect_cached_sni(stg_ctx->sbi, sni, stg_ctx->stg_mode);
}

static int stgc_inspect_cached_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      const struct silofs_spleaf_info *sli)
{
	return sbi_inspect_cached_sli(stg_ctx->sbi, sli, stg_ctx->stg_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_bind_sni_to_uber(const struct silofs_stage_ctx *stg_ctx,
                                  struct silofs_spnode_info *sni)
{
	silofs_ui_bind_uber(&sni->sn_ui, stg_ctx->uber);
}

static int stgc_do_stage_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spnode_info **out_sni)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_stage_spnode_at(stg_ctx->uber, uaddr, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_stage_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_do_stage_spnode_at(stg_ctx, uaddr, out_sni);
	if (!err) {
		stgc_bind_sni_to_uber(stg_ctx, *out_sni);
	}
	return err;
}

static int stgc_do_spawn_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spnode_info **out_sni)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_spawn_spnode_at(stg_ctx->uber, uaddr, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_spawn_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_do_spawn_spnode_at(stg_ctx, uaddr, out_sni);
	if (!err) {
		stgc_bind_sni_to_uber(stg_ctx, *out_sni);
	}
	return err;
}

static void stgc_bind_sli_to_uber(const struct silofs_stage_ctx *stg_ctx,
                                  struct silofs_spleaf_info *sli)
{
	silofs_ui_bind_uber(&sli->sl_ui, stg_ctx->uber);
}

static int stgc_do_stage_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spleaf_info **out_sli)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_stage_spleaf_at(stg_ctx->uber, uaddr, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_stage_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_do_stage_spleaf_at(stg_ctx, uaddr, out_sli);
	if (!err) {
		stgc_bind_sli_to_uber(stg_ctx, *out_sli);
	}
	return err;
}

static int stgc_do_spawn_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spleaf_info **out_sli)
{
	int err = -ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_spawn_spleaf_at(stg_ctx->uber, uaddr, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_spawn_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_do_spawn_spleaf_at(stg_ctx, uaddr, out_sli);
	if (!err) {
		stgc_bind_sli_to_uber(stg_ctx, *out_sli);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stgc_check_may_rdwr(const struct silofs_stage_ctx *stg_ctx)
{
	return stage_cow(stg_ctx->stg_mode) ? 0 : -SILOFS_EPERM;
}

static int stgc_check_may_clone(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_check_may_rdwr(stg_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_setup_spawned_spnode5(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sbi_uaddr(stg_ctx->sbi),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spnode5_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_super_main_blob(stg_ctx);
	if (err) {
		return err;
	}
	silofs_sbi_main_child_at(stg_ctx->sbi, stg_ctx->voff,
	                         stg_ctx->vspace, &uaddr);

	err = stgc_spawn_spnode_at(stg_ctx, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode5(stg_ctx, *out_sni);
	return 0;
}

static int stgc_spawn_spnode5(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode5_of(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int stgc_do_clone_spnode5(struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni_clone = NULL;
	int err;

	err = stgc_spawn_spnode5(stg_ctx, &sni_clone);
	if (err) {
		return err;
	}
	silofs_sni_clone_subrefs(sni_clone, stg_ctx->sni5);
	silofs_sbi_bind_sproot(stg_ctx->sbi, stg_ctx->vspace, sni_clone);

	*out_sni = sni_clone;
	return 0;
}

static int stgc_clone_spnode5(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE5);
	err = stgc_do_clone_spnode5(stg_ctx, out_sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE5);
	return err;
}

static int stgc_inspect_cached_spnode5(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni5);
}

static int stgc_do_stage_spnode5(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni5 = NULL;
	int err;

	err = silofs_sbi_sproot_of(stg_ctx->sbi, stg_ctx->vspace, &uaddr);
	if (err) {
		return -SILOFS_EFSCORRUPTED;
	}
	err = stgc_stage_spnode_at(stg_ctx, &uaddr, &stg_ctx->sni5);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_spnode5(stg_ctx);
	if (!err) {
		return 0;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_spnode5(stg_ctx, &sni5);
	if (err) {
		return err;
	}
	stg_ctx->sni5 = sni5;
	return 0;
}

static int stgc_stage_spnode5(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SUPER);
	err = stgc_do_stage_spnode5(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SUPER);
	return err;
}

static int stgc_stage_cached_spnode5(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_stage_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE5,
	                                &stg_ctx->sni5);
}

static int stgc_stage_spnode5_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode5(stg_ctx);
	if (err) {
		err = stgc_stage_spnode5(stg_ctx);
	}
	return err;
}

static int stgc_spawn_bind_spnode5(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_spawn_spnode5(stg_ctx, &stg_ctx->sni5);
	if (err) {
		return err;
	}
	silofs_sbi_bind_sproot(stg_ctx->sbi, stg_ctx->vspace, stg_ctx->sni5);
	return 0;
}

static bool stgc_has_spnode5_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_sproot_of(stg_ctx->sbi, stg_ctx->vspace, &uaddr);
	return !err;
}

static int stgc_do_require_spnode5(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spnode5_child_at(stg_ctx)) {
		err = stgc_stage_spnode5_of(stg_ctx);
	} else {
		err = stgc_spawn_bind_spnode5(stg_ctx);
	}
	return err;
}

static int stgc_require_spnode5(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SUPER);
	err = stgc_do_require_spnode5(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SUPER);
	return err;
}

static int stgc_require_spnode5_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode5(stg_ctx);
	if (err) {
		err = stgc_require_spnode5(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_setup_spawned_spnode4(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(stg_ctx->sni5),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spnode4_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_spnode_main_blob(stg_ctx, stg_ctx->sni5);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_at(stg_ctx->sni5, stg_ctx->bk_voff, &uaddr);

	err = stgc_spawn_spnode_at(stg_ctx, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode4(stg_ctx, *out_sni);
	return 0;
}

static int stgc_spawn_spnode4(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode4_of(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int stgc_do_clone_spnode4(struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni_clone = NULL;
	int err;

	err = stgc_spawn_spnode4(stg_ctx, &sni_clone);
	if (err) {
		return err;
	}
	silofs_sni_clone_subrefs(sni_clone, stg_ctx->sni4);
	silofs_sni_bind_child_spnode(stg_ctx->sni5, sni_clone);

	*out_sni = sni_clone;
	return 0;
}

static int stgc_clone_spnode4(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = stgc_do_clone_spnode4(stg_ctx, out_sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	return err;
}

static int stgc_inspect_cached_spnode4(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni4);
}

static int stgc_do_stage_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni4 = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni5, stg_ctx->bk_voff, &uaddr);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &uaddr, &stg_ctx->sni4);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_spnode4(stg_ctx);
	if (!err) {
		return 0;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_spnode4(stg_ctx, &sni4);
	if (err) {
		return err;
	}
	stg_ctx->sni4 = sni4;
	return 0;
}

static int stgc_stage_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE5);
	err = stgc_do_stage_spnode4(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE5);
	return err;
}

static int stgc_stage_cached_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_stage_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE4,
	                                &stg_ctx->sni4);
}

static int stgc_stage_spnode4_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode4(stg_ctx);
	if (err) {
		err = stgc_stage_spnode4(stg_ctx);
	}
	return err;
}

static int stgc_spawn_bind_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_spawn_spnode4(stg_ctx, &stg_ctx->sni4);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spnode(stg_ctx->sni5, stg_ctx->sni4);
	return 0;
}

static bool stgc_has_spnode4_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return silofs_sni_has_child_at(stg_ctx->sni5, stg_ctx->bk_voff);
}

static int stgc_do_require_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spnode4_child_at(stg_ctx)) {
		err = stgc_stage_spnode4_of(stg_ctx);
	} else {
		err = stgc_spawn_bind_spnode4(stg_ctx);
	}
	return err;
}

static int stgc_require_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE5);
	err = stgc_do_require_spnode4(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE5);
	return err;
}

static int stgc_require_spnode4_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode4(stg_ctx);
	if (err) {
		err = stgc_require_spnode4(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_setup_spawned_spnode3(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(stg_ctx->sni4),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spnode3_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_spnode_main_blob(stg_ctx, stg_ctx->sni4);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_at(stg_ctx->sni4, stg_ctx->bk_voff, &uaddr);

	err = stgc_spawn_spnode_at(stg_ctx, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode3(stg_ctx, *out_sni);
	return 0;
}

static int stgc_spawn_spnode3(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode3_of(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int stgc_do_clone_spnode3(struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni_clone = NULL;
	int err;

	err = stgc_spawn_spnode3(stg_ctx, &sni_clone);
	if (err) {
		return err;
	}
	silofs_sni_clone_subrefs(sni_clone, stg_ctx->sni3);
	silofs_sni_bind_child_spnode(stg_ctx->sni4, sni_clone);

	*out_sni = sni_clone;
	return 0;
}

static int stgc_clone_spnode3(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = stgc_do_clone_spnode3(stg_ctx, out_sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	return err;
}

static int stgc_inspect_cached_spnode3(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni3);
}

static int stgc_do_stage_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni3 = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni4, stg_ctx->bk_voff, &uaddr);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &uaddr, &stg_ctx->sni3);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_spnode3(stg_ctx);
	if (!err) {
		return 0;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_spnode3(stg_ctx, &sni3);
	if (err) {
		return err;
	}
	stg_ctx->sni3 = sni3;
	return 0;
}

static int stgc_stage_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = stgc_do_stage_spnode3(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	return err;
}

static int stgc_stage_cached_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_stage_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE3,
	                                &stg_ctx->sni3);
}

static int stgc_stage_spnode3_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode3(stg_ctx);
	if (err) {
		err = stgc_stage_spnode3(stg_ctx);
	}
	return err;
}

static int stgc_spawn_bind_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_spawn_spnode3(stg_ctx, &stg_ctx->sni3);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spnode(stg_ctx->sni4, stg_ctx->sni3);
	return 0;
}

static bool stgc_has_spnode3_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return silofs_sni_has_child_at(stg_ctx->sni4, stg_ctx->bk_voff);
}

static int stgc_do_require_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spnode3_child_at(stg_ctx)) {
		err = stgc_stage_spnode3_of(stg_ctx);
	} else {
		err = stgc_spawn_bind_spnode3(stg_ctx);
	}
	return err;
}

static int stgc_require_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = stgc_do_require_spnode3(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	return err;
}

static int stgc_require_spnode3_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode3(stg_ctx);
	if (err) {
		err = stgc_require_spnode3(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_setup_spawned_spnode2(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(stg_ctx->sni3),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spnode2_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_spnode_main_blob(stg_ctx, stg_ctx->sni3);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_at(stg_ctx->sni3, stg_ctx->bk_voff, &uaddr);

	err = stgc_spawn_spnode_at(stg_ctx, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode2(stg_ctx, *out_sni);
	return 0;
}

static int stgc_spawn_spnode2(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode2_of(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int stgc_do_clone_spnode2(struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni_clone = NULL;
	int err;

	err = stgc_spawn_spnode2(stg_ctx, &sni_clone);
	if (err) {
		return err;
	}
	silofs_sni_clone_subrefs(sni_clone, stg_ctx->sni2);
	silofs_sni_bind_child_spnode(stg_ctx->sni3, sni_clone);

	*out_sni = sni_clone;
	return 0;
}

static int stgc_clone_spnode2(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = stgc_do_clone_spnode2(stg_ctx, out_sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	return err;
}

static int stgc_inspect_cached_spnode2(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni2);
}

static int stgc_do_stage_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni2 = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni3, stg_ctx->bk_voff, &uaddr);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &uaddr, &stg_ctx->sni2);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_spnode2(stg_ctx);
	if (!err) {
		return 0;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_spnode2(stg_ctx, &sni2);
	if (err) {
		return err;
	}
	stg_ctx->sni2 = sni2;
	return 0;
}

static int stgc_stage_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = stgc_do_stage_spnode2(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	return err;
}

static int stgc_stage_cached_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_stage_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE2,
	                                &stg_ctx->sni2);
}

static int stgc_stage_spnode2_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode2(stg_ctx);
	if (err) {
		err = stgc_stage_spnode2(stg_ctx);
	}
	return err;
}

static int stgc_spawn_bind_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_spawn_spnode2(stg_ctx, &stg_ctx->sni2);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spnode(stg_ctx->sni3, stg_ctx->sni2);
	return 0;
}

static bool stgc_has_spnode2_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return silofs_sni_has_child_at(stg_ctx->sni3, stg_ctx->bk_voff);
}

static int stgc_do_require_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spnode2_child_at(stg_ctx)) {
		err = stgc_stage_spnode2_of(stg_ctx);
	} else {
		err = stgc_spawn_bind_spnode2(stg_ctx);
	}
	return err;
}

static int stgc_require_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = stgc_do_require_spnode2(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	return err;
}

static int stgc_require_spnode2_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode2(stg_ctx);
	if (err) {
		err = stgc_require_spnode2(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_setup_spawned_spnode1(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(stg_ctx->sni2),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spnode1_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_spnode_main_blob(stg_ctx, stg_ctx->sni2);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_at(stg_ctx->sni2, stg_ctx->bk_voff, &uaddr);

	err = stgc_spawn_spnode_at(stg_ctx, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode1(stg_ctx, *out_sni);
	return 0;
}

static int stgc_spawn_spnode1(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode1_of(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int stgc_do_clone_spnode1(struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni_clone = NULL;
	int err;

	err = stgc_spawn_spnode1(stg_ctx, &sni_clone);
	if (err) {
		return err;
	}
	silofs_sni_clone_subrefs(sni_clone, stg_ctx->sni1);
	silofs_sni_bind_child_spnode(stg_ctx->sni2, sni_clone);

	*out_sni = sni_clone;
	return 0;
}

static int stgc_clone_spnode1(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = stgc_do_clone_spnode1(stg_ctx, out_sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	return err;
}

static int stgc_inspect_cached_spnode1(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni1);
}

static int stgc_do_stage_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni1 = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni2, stg_ctx->bk_voff, &uaddr);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &uaddr, &stg_ctx->sni1);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_spnode1(stg_ctx);
	if (!err) {
		return 0;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_spnode1(stg_ctx, &sni1);
	if (err) {
		return err;
	}
	stg_ctx->sni1 = sni1;
	return 0;
}

static int stgc_stage_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = stgc_do_stage_spnode1(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	return err;
}

static int stgc_stage_cached_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_stage_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE1,
	                                &stg_ctx->sni1);
}

static int stgc_spawn_bind_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_spawn_spnode1(stg_ctx, &stg_ctx->sni1);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spnode(stg_ctx->sni2, stg_ctx->sni1);
	return 0;
}

static bool stgc_has_spnode1_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return silofs_sni_has_child_at(stg_ctx->sni2, stg_ctx->bk_voff);
}

static int stgc_stage_spnode1_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode1(stg_ctx);
	if (err) {
		err = stgc_stage_spnode1(stg_ctx);
	}
	return err;
}

static int stgc_do_require_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spnode1_child_at(stg_ctx)) {
		err = stgc_stage_spnode1(stg_ctx);
	} else {
		err = stgc_spawn_bind_spnode1(stg_ctx);
	}
	return err;
}

static int stgc_require_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = stgc_do_require_spnode1(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	return err;
}

static int stgc_require_spnode1_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode1(stg_ctx);
	if (err) {
		err = stgc_require_spnode1(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_setup_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      struct silofs_spleaf_info *sli)
{
	silofs_sli_setup_spawned(sli, sni_uaddr(stg_ctx->sni1),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spleaf_of(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_spnode_main_blob(stg_ctx, stg_ctx->sni1);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_at(stg_ctx->sni1, stg_ctx->bk_voff, &uaddr);

	err = stgc_spawn_spleaf_at(stg_ctx, &uaddr, out_sli);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spleaf(stg_ctx, *out_sli);
	return 0;
}

static int
stgc_require_spleaf_main_blob(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spleaf_info *sli)
{
	struct silofs_blobid blobid;
	struct silofs_blobf *blobf = NULL;
	const loff_t voff = silofs_sli_base_voff(sli);
	int err;

	silofs_sli_main_blob(sli, &blobid);
	if (!blobid_isnull(&blobid)) {
		return stgc_do_stage_blob(stg_ctx, &blobid, &blobf);
	}
	/*
	 * TODO-0047: Do not use underlying repo to detect if vdata-blob exists
	 *
	 * Multiple space-leaf share the same underlying vdata blob. Use in
	 * memory logic to detect if one of them has already spawned their
	 * common main-blob.
	 */
	stgc_make_blobid_of_vdata(stg_ctx, voff, &blobid);
	err = stgc_do_stage_blob(stg_ctx, &blobid, &blobf);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOENT) {
		return err;
	}
	err = stgc_spawn_blob(stg_ctx, &blobid, stg_ctx->vspace, &blobf);
	if (err) {
		return err;
	}
out_ok:
	silofs_sli_bind_main_blob(sli, &blobf->b_blobid);
	return 0;
}

static int stgc_spawn_spleaf(const struct silofs_stage_ctx *stg_ctx,
                             struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_spawn_spleaf_of(stg_ctx, out_sli);
	if (err) {
		return err;
	}
	err = stgc_require_spleaf_main_blob(stg_ctx, *out_sli);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sli_uaddr(*out_sli));
	return 0;
}

static int stgc_do_clone_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli_clone = NULL;
	int err;

	err = stgc_spawn_spleaf(stg_ctx, &sli_clone);
	if (err) {
		return err;
	}
	silofs_sli_clone_subrefs(sli_clone, stg_ctx->sli);
	silofs_sni_bind_child_spleaf(stg_ctx->sni1, sli_clone);

	*out_sli = sli_clone;
	return 0;
}

static int stgc_clone_spleaf(const struct silofs_stage_ctx *stg_ctx,
                             struct silofs_spleaf_info **out_sli)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = stgc_do_clone_spleaf(stg_ctx, out_sli);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
}

static int stgc_do_stage_spleaf(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni1, stg_ctx->bk_voff, &uaddr);
	if (err) {
		return err;
	}
	err = stgc_stage_spleaf_at(stg_ctx, &uaddr, &stg_ctx->sli);
	if (err) {
		return err;
	}
	err = stgc_inspect_cached_spleaf(stg_ctx, stg_ctx->sli);
	if (!err) {
		return 0;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_spleaf(stg_ctx, &sli);
	if (err) {
		return err;
	}
	stg_ctx->sli = sli;
	return 0;
}

static int stgc_stage_spleaf(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = stgc_do_stage_spleaf(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	return err;
}

static int stgc_stage_cached_spleaf1(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_stage_cached_spleaf(stg_ctx, &stg_ctx->sli);
}

static int stgc_stage_spleaf_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spleaf1(stg_ctx);
	if (err) {
		err = stgc_stage_spleaf(stg_ctx);
	}
	return err;
}

/*
 * Upon new space leaf, add the entire space range at once. Ignores possible
 * out-of-memory failure.
 */
static struct silofs_spamaps *
stgc_spamaps(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_cache *cache = stgc_cache(stg_ctx);

	return &cache->c_spam;
}

static void stgc_track_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	struct silofs_spamaps *spam = stgc_spamaps(stg_ctx);

	sli_vrange(sli, &vrange);
	silofs_spamaps_store(spam, stg_ctx->vspace, vrange.beg, vrange.len);
}

static void stgc_bind_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                     struct silofs_spleaf_info *sli)
{
	silofs_sni_bind_child_spleaf(stg_ctx->sni1, sli);
}

static int stgc_spawn_bind_spleaf_at(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stgc_spawn_spleaf(stg_ctx, &sli);
	if (err) {
		return err;
	}
	stgc_bind_spawned_spleaf(stg_ctx, sli);
	stgc_track_spawned_spleaf(stg_ctx, sli);
	stg_ctx->sli = sli;
	return 0;
}

static bool stgc_has_spleaf_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return silofs_sni_has_child_at(stg_ctx->sni1, stg_ctx->bk_voff);
}

static int stgc_do_require_spleaf(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spleaf_child_at(stg_ctx)) {
		err = stgc_stage_spleaf_of(stg_ctx);
	} else {
		err = stgc_spawn_bind_spleaf_at(stg_ctx);
	}
	return err;
}

static int stgc_require_spleaf(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = stgc_do_require_spleaf(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_stage_spnodes_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_spnode5_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode4_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode3_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode2_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode1_of(stg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int stgc_require_spnodes_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_require_spnode5_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spnode4_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spnode3_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spnode2_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spnode1_of(stg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_stage_spmaps_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_spnodes_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_spleaf_of(stg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int stgc_voaddr_at(const struct silofs_stage_ctx *stg_ctx,
                          struct silofs_voaddr *out_voa)
{
	struct silofs_bkaddr bkaddr;
	int err;

	err = silofs_sli_resolve_ubk(stg_ctx->sli, stg_ctx->bk_voff, &bkaddr);
	if (err) {
		return err;
	}
	voaddr_by(out_voa, &bkaddr.blobid, stg_ctx->vaddr);
	return 0;
}

static int stgc_stage_spleaf_for_resolve(struct silofs_stage_ctx *stg_ctx)
{
	int ret;

	ret = stgc_stage_cached_spleaf1(stg_ctx);
	if (ret != 0) {
		ret = stgc_stage_spmaps_of(stg_ctx);
	}
	return ret;
}

static int stgc_resolve_voaddr(struct silofs_stage_ctx *stg_ctx,
                               struct silofs_voaddr *out_voa)
{
	int err;

	err = stgc_stage_spleaf_for_resolve(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_voaddr_at(stg_ctx, out_voa);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_spnode1_of(struct silofs_task *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode stg_mode,
                            struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	err = stgc_stage_spnodes_of(&stg_ctx);
	if (err) {
		return err;
	}
	*out_sni = stg_ctx.sni1;
	return 0;
}

int silofs_stage_spmaps_of(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spnode_info **out_sni,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	err = stgc_stage_spmaps_of(&stg_ctx);
	if (err) {
		return err;
	}
	*out_sni = stg_ctx.sni1;
	*out_sli = stg_ctx.sli;
	return 0;
}

int silofs_stage_spleaf_of(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni = NULL;

	return silofs_stage_spmaps_of(task, vaddr, stg_mode, &sni, out_sli);
}

int silofs_require_spmaps_of(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stg_mode stg_mode,
                             struct silofs_spnode_info **out_sni,
                             struct silofs_spleaf_info **out_sli)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	err = stgc_check_may_rdwr(&stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spnodes_of(&stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spleaf(&stg_ctx);
	if (err) {
		return err;
	}
	*out_sni = stg_ctx.sni1;
	*out_sli = stg_ctx.sli;
	return 0;
}

static int stgc_require_stable_vaddr(const struct silofs_stage_ctx *stg_ctx)
{
	const struct silofs_vaddr *vaddr = stg_ctx->vaddr;
	bool allocated;

	allocated = silofs_sli_has_allocated_space(stg_ctx->sli, vaddr);
	if (likely(allocated)) {
		return 0;
	}
	log_err("unstable: off=0x%lx stype=%d", vaddr->off, vaddr->stype);
	return -SILOFS_EFSCORRUPTED;
}

static int require_stable_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, task, vaddr, SILOFS_STG_CUR | SILOFS_STG_RAW);
	err = stgc_stage_spmaps_of(&stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_stable_vaddr(&stg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int stgc_check_stable_vaddr(const struct silofs_stage_ctx *stg_ctx)
{
	const struct silofs_vaddr *vaddr = stg_ctx->vaddr;
	bool allocated;

	allocated = silofs_sli_has_allocated_space(stg_ctx->sli, vaddr);
	return likely(allocated) ? 0 : -ENOENT;
}

static int check_stable_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, task, vaddr, SILOFS_STG_CUR | SILOFS_STG_RAW);
	err = stgc_stage_spmaps_of(&stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_check_stable_vaddr(&stg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stgc_spawn_vbki_by(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_blobf *blobf,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vbk_info **out_vbki)
{
	int ret;

	blobf_incref(blobf);
	ret = stgc_do_spawn_vbki(stg_ctx, vaddr->off, vaddr->stype, out_vbki);
	blobf_decref(blobf);
	return ret;
}

static int stgc_spawn_load_vbk(const struct silofs_stage_ctx *stg_ctx,
                               struct silofs_blobf *blobf,
                               const struct silofs_voaddr *voa,
                               struct silofs_vbk_info **out_vbki)
{
	struct silofs_vbk_info *vbki = NULL;
	int err;

	err = stgc_spawn_vbki_by(stg_ctx, blobf, &voa->vaddr, &vbki);
	if (err) {
		return err;
	}
	err = silofs_blobf_load_bk(blobf, &voa->oaddr.bka, &vbki->vbk_base);
	if (err) {
		stgc_forget_cached_vbki(stg_ctx, vbki);
		return err;
	}
	*out_vbki = vbki;
	return 0;
}

static int stgc_stage_load_vbk(const struct silofs_stage_ctx *stg_ctx,
                               const struct silofs_voaddr *voa,
                               struct silofs_vbk_info **out_vbki)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = stgc_do_stage_blob(stg_ctx, &voa->oaddr.bka.blobid, &blobf);
	if (err) {
		return err;
	}
	err = silofs_blobf_require_bk(blobf, &voa->oaddr.bka);
	if (err) {
		return err;
	}
	err = stgc_spawn_load_vbk(stg_ctx, blobf, voa, out_vbki);
	if (err) {
		return err;
	}
	return 0;
}

static int stgc_stage_vblock(const struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_voaddr *voa,
                             struct silofs_vbk_info **out_vbki)
{
	int err;

	err = stgc_lookup_cached_vbki(stg_ctx, &voa->vaddr, out_vbki);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = stgc_stage_load_vbk(stg_ctx, voa, out_vbki);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int blobf_resolve_bk(struct silofs_blobf *blobf,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_iovec *iov)
{
	struct silofs_oaddr oaddr;
	const loff_t off = lba_to_off(bkaddr->lba);

	silofs_oaddr_setup(&oaddr, &bkaddr->blobid, off, SILOFS_BK_SIZE);
	return silofs_blobf_resolve(blobf, &oaddr, iov);
}

static int stgc_resolve_bks(const struct silofs_stage_ctx *stg_ctx,
                            const struct silofs_bkaddr *bkaddr_src,
                            const struct silofs_bkaddr *bkaddr_dst,
                            struct silofs_iovec *out_iov_src,
                            struct silofs_iovec *out_iov_dst)
{
	struct silofs_blobf *blobf_src = NULL;
	struct silofs_blobf *blobf_dst = NULL;
	int ret;

	ret = stgc_do_stage_blob(stg_ctx, &bkaddr_src->blobid, &blobf_src);
	if (ret) {
		goto out;
	}
	blobf_incref(blobf_src);

	ret = stgc_do_stage_blob(stg_ctx, &bkaddr_dst->blobid, &blobf_dst);
	if (ret) {
		goto out;
	}
	blobf_incref(blobf_dst);

	ret = blobf_resolve_bk(blobf_src, bkaddr_src, out_iov_src);
	if (ret) {
		goto out;
	}

	ret = blobf_resolve_bk(blobf_dst, bkaddr_dst, out_iov_dst);
	if (ret) {
		goto out;
	}
out:
	blobf_decref(blobf_dst);
	blobf_decref(blobf_src);
	return (ret == -ENOENT) ? -SILOFS_EFSCORRUPTED : ret;
}

static int stgc_require_clone_bkaddr(const struct silofs_stage_ctx *stg_ctx,
                                     const struct silofs_vaddr *vaddr,
                                     struct silofs_bkaddr *out_bkaddr_dst)
{
	int err;

	err = stgc_require_spleaf_main_blob(stg_ctx, stg_ctx->sli);
	if (err) {
		return err;
	}
	silofs_sli_resolve_main_ubk(stg_ctx->sli, vaddr->off, out_bkaddr_dst);
	return 0;
}

static int stgc_clone_rebind_vblock(const struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_voaddr *src_voa)
{
	struct silofs_bkaddr bkaddr_dst = { .lba = SILOFS_LBA_NULL };
	struct silofs_iovec iov_src = { .iov_fd = -1 };
	struct silofs_iovec iov_dst = { .iov_fd = -1 };
	int err;

	err = stgc_require_clone_bkaddr(stg_ctx, &src_voa->vaddr, &bkaddr_dst);
	if (err) {
		return err;
	}
	err = stgc_resolve_bks(stg_ctx, &src_voa->oaddr.bka,
	                       &bkaddr_dst, &iov_src, &iov_dst);
	if (err) {
		return err;
	}
	silofs_sli_rebind_ubk(stg_ctx->sli, src_voa->vaddr.off, &bkaddr_dst);
	return 0;
}

static int stgc_stage_vblock_by(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_voaddr *voaddr,
                                struct silofs_vbk_info **out_vbki)
{
	const struct silofs_vaddr *vaddr = &voaddr->vaddr;
	int ret = 0;

	*out_vbki = NULL;
	if (!stype_isdata(vaddr->stype)) {
		ret = stgc_stage_vblock(stg_ctx, voaddr, out_vbki);
		/*
		 * Special case: trying to stage vbk which is located beyond
		 * the current end-of-blob range and the blob is opened in read
		 * only mode. Ignore it.
		 */
		if (ret == -SILOFS_ERDONLY) {
			ret = 0;
		}
	}
	return ret;
}

static int
stgc_pre_clone_stage_inode_at(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_inode_info *ii = NULL;
	ino_t ino;
	int err;

	*out_vi = NULL;
	ino = vaddr_to_ino(vaddr);
	err = silofs_stage_ii(stg_ctx->task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		return err;
	}
	if (vi_may_flush(&ii->i_vi)) {
		*out_vi = &ii->i_vi;
	}
	return 0;
}

static int
stgc_pre_clone_stage_vnode_at(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	*out_vi = NULL;
	err = silofs_stage_vi(stg_ctx->task, NULL, vaddr,
	                      SILOFS_STG_CUR, &vi);
	if (err == -SILOFS_ERDONLY) {
		/* TODO: should not have this case XXX */
		return 0; /* special case: out-of-blob range */
	}
	if (err) {
		return err;
	}
	if (vi_may_flush(vi)) {
		*out_vi = vi;
	}
	return 0;
}

static bool stgc_has_vaddr(const struct silofs_stage_ctx *stg_ctx,
                           const struct silofs_vaddr *vaddr)
{
	return vaddr_isequal(stg_ctx->vaddr, vaddr);
}

static int stgc_pre_clone_stage_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_vnode_info **out_vi)
{
	const int raw = (stg_ctx->stg_mode & SILOFS_STG_RAW) > 0;
	int ret = 0;

	if (vaddr->off == 0) {
		/* ignore off=0 which is allocated-as-numb once upon format */
		*out_vi = NULL;
	} else if (stgc_has_vaddr(stg_ctx, vaddr) &&
	           (raw || vaddr_isdatabk(vaddr))) {
		/* ignore current data-block */
		*out_vi = NULL;
	} else if (vaddr_isinode(vaddr)) {
		/* inode case */
		ret = stgc_pre_clone_stage_inode_at(stg_ctx, vaddr, out_vi);
	} else {
		/* normal case */
		ret = stgc_pre_clone_stage_vnode_at(stg_ctx, vaddr, out_vi);
	}
	return ret;
}

static int stgc_do_pre_clone_vblock(struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_vis *vis)
{
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_vaddr *vaddrj = NULL;
	const silofs_lba_t lba = off_to_lba(vaddr->off);
	int err;

	STATICASSERT_EQ(ARRAY_SIZE(vis->vis), ARRAY_SIZE(vis->vas.vaddr));

	silofs_sli_vaddrs_at(stg_ctx->sli, vaddr->stype, lba, &vis->vas);
	for (size_t j = 0; j < vis->vas.count; ++j) {
		vaddrj = &vis->vas.vaddr[j];
		err = stgc_pre_clone_stage_at(stg_ctx, vaddrj, &vi);
		if (err) {
			return err;
		}
		vi_incref(vi);
		vis->vis[j] = vi;
	}
	return 0;
}

static int stgc_pre_clone_vblock(struct silofs_stage_ctx *stg_ctx,
                                 const struct silofs_vaddr *vaddr,
                                 struct silofs_vis *vis)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = stgc_do_pre_clone_vblock(stg_ctx, vaddr, vis);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
}

static void stgc_post_clone_vblock(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_vis *vis)
{
	struct silofs_vnode_info *vi;

	for (size_t i = 0; i < vis->vas.count; ++i) {
		vi = vis->vis[i];
		vi_dirtify(vi, NULL);
		vi_decref(vi);
	}
	silofs_unused(stg_ctx);
}

static int stgc_clone_vblock(struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_voaddr *src_voa)
{
	struct silofs_vis vis = { .vas.count = 0 };
	int err;

	err = stgc_pre_clone_vblock(stg_ctx, &src_voa->vaddr, &vis);
	if (!err) {
		err = stgc_clone_rebind_vblock(stg_ctx, src_voa);
	}
	stgc_post_clone_vblock(stg_ctx, &vis);
	return err;
}

static int stgc_clone_vblock_of(struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_voaddr *src_voa,
                                struct silofs_vbk_info *vbki)
{
	int ret;

	silofs_vbki_incref(vbki); /* may be NULL */
	ret = stgc_clone_vblock(stg_ctx, src_voa);
	silofs_vbki_decref(vbki);
	return ret;
}

static int stgc_resolve_inspect_voaddr(struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_voaddr *out_voa)
{
	struct silofs_vbk_info *vbki = NULL;
	int err;

	err = stgc_resolve_voaddr(stg_ctx, out_voa);
	if (err) {
		return err;
	}
	err = stgc_inspect_bkaddr(stg_ctx, &out_voa->oaddr.bka);
	if (err != -SILOFS_EPERM) {
		return err;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_vblock_by(stg_ctx, out_voa, &vbki);
	if (err) {
		return err;
	}
	err = stgc_clone_vblock_of(stg_ctx, out_voa, vbki);
	if (err) {
		return err;
	}
	err = stgc_voaddr_at(stg_ctx, out_voa);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_resolve_voaddr_of(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stg_mode stg_mode,
                             struct silofs_voaddr *out_voa)
{
	struct silofs_stage_ctx stg_ctx;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	return stgc_resolve_inspect_voaddr(&stg_ctx, out_voa);
}

int silofs_resolve_oaddr_of(struct silofs_task *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode stg_mode,
                            struct silofs_oaddr *out_oaddr)
{
	struct silofs_voaddr voaddr;
	int err;

	err = silofs_resolve_voaddr_of(task, vaddr, stg_mode, &voaddr);
	if (!err) {
		oaddr_assign(out_oaddr, &voaddr.oaddr);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_stage_vnode_at(struct silofs_stage_ctx *stg_ctx,
                               struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa;
	struct silofs_vbk_info *vbki = NULL;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = stgc_resolve_inspect_voaddr(stg_ctx, &voa);
	if (err) {
		goto out_err;
	}
	err = stgc_stage_vblock(stg_ctx, &voa, &vbki);
	if (err) {
		goto out_err;
	}
	err = stgc_spawn_bind_vi(stg_ctx, &voa, vbki, &vi);
	if (err) {
		goto out_err;
	}
	err = stgc_restore_view_of(stg_ctx, vi);
	if (err) {
		goto out_err;
	}
	*out_vi = vi;
	return 0;
out_err:
	stgc_forget_cached_vi(stg_ctx, vi);
	*out_vi = NULL;
	return err;
}

int silofs_stage_vnode_of(struct silofs_task *task,
                          const struct silofs_vaddr *vaddr,
                          enum silofs_stg_mode stg_mode,
                          struct silofs_vnode_info **out_vi)
{
	struct silofs_stage_ctx stg_ctx;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	return stgc_stage_vnode_at(&stg_ctx, out_vi);
}

static int stage_inode_of(struct silofs_task *task, ino_t ino,
                          const struct silofs_vaddr *vaddr,
                          enum silofs_stg_mode stg_mode,
                          struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_stage_vnode_of(task, vaddr, stg_mode, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);

	silofs_ii_rebind_view(ii, ino);
	silofs_ii_refresh_atime(ii, true);
	*out_ii = ii;
	return 0;
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_cache *task_cache(const struct silofs_task *task)
{
	return task->t_uber->ub.cache;
}

/*
 * Special case where data-node has been unmapped due to forget, yet it still
 * had a live ref-count due to on-going I/O operation.
 */
static int fixup_cached_vi(const struct silofs_task *task,
                           struct silofs_vnode_info *vi)
{
	if (!(vi->v_si.s_ce.ce_flags & SILOFS_CEF_FORGOT)) {
		return 0;
	}
	if (silofs_vi_refcnt(vi)) {
		return 0;
	}
	silofs_cache_forget_vi(task_cache(task), vi);
	return -ENOENT;
}

int silofs_stage_cached_vi(const struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vi)
{
	struct silofs_cache *cache = task_cache(task);
	struct silofs_vnode_info *vi;
	int err;

	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	vi = silofs_cache_lookup_vi(cache, vaddr);
	if (vi == NULL) {
		return -ENOENT;
	}
	err = fixup_cached_vi(task, vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int
resolve_stage_vnode(struct silofs_task *task,
                    const struct silofs_vaddr *vaddr,
                    enum silofs_stg_mode stg_mode,
                    struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_resolve_voaddr_of(task, vaddr, stg_mode, &voa);
	if (err) {
		return err;
	}
	err = silofs_stage_cached_vi(task, vaddr, &vi);
	if (!err) {
		goto out_ok;  /* cache hit */
	}
	err = require_stable_at(task, vaddr);
	if (err) {
		return err;
	}
	err = silofs_stage_vnode_of(task, vaddr, stg_mode, &vi);
	if (err) {
		return err;
	}
out_ok:
	*out_vi = vi;
	return 0;
}

static int check_stage_vnode(const struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stg_mode stg_mode)
{
	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	if ((stg_mode & SILOFS_STG_COW) == 0) {
		return 0;
	}
	return silof_sbi_check_mut_fs(task_sbi(task));
}

static int do_stage_vnode(struct silofs_task *task,
                          const struct silofs_vaddr *vaddr,
                          enum silofs_stg_mode stg_mode,
                          struct silofs_vnode_info **out_vi)
{
	int err;

	err = check_stage_vnode(task, vaddr, stg_mode);
	if (err) {
		return err;
	}
	err = resolve_stage_vnode(task, vaddr, stg_mode, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_vi(struct silofs_task *task,
                    struct silofs_inode_info *pii,
                    const struct silofs_vaddr *vaddr,
                    enum silofs_stg_mode stg_mode,
                    struct silofs_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = do_stage_vnode(task, vaddr, stg_mode, out_vi);
	ii_decref(pii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lookup_cached_ii(const struct silofs_task *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_stage_cached_vi(task, vaddr, &vi);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vi(vi);
	return 0;
}

static int resolve_iaddr(ino_t ino, struct silofs_iaddr *out_iaddr)
{
	const ino_t ino_max = SILOFS_INO_MAX;
	const ino_t ino_root = SILOFS_INO_ROOT;
	loff_t voff;

	if ((ino < ino_root) || (ino > ino_max)) {
		return -EINVAL;
	}
	voff = silofs_ino_to_off(ino);
	if (off_isnull(voff)) {
		return -EINVAL;
	}
	vaddr_setup(&out_iaddr->vaddr, SILOFS_STYPE_INODE, voff);
	out_iaddr->ino = ino;
	return 0;
}

static int check_stage_inode(const struct silofs_task *task, ino_t ino,
                             enum silofs_stg_mode stg_mode)
{
	if (ino_isnull(ino)) {
		return -ENOENT;
	}
	if ((stg_mode & SILOFS_STG_COW) == 0) {
		return 0;
	}
	return silof_sbi_check_mut_fs(task_sbi(task));
}

/*
 * TODO-0027: Support immutable inodes via explicit ioctl
 *
 * Special inode state, correlates to STATX_ATTR_IMMUTABLE
 */
static bool ii_isimmutable(const struct silofs_inode_info *ii)
{
	silofs_unused(ii);
	return false;
}

static int ii_check_post_stage(const struct silofs_inode_info *ii,
                               enum silofs_stg_mode stg_mode)
{
	if ((stg_mode & SILOFS_STG_COW) == 0) {
		return 0;
	}
	if (ii_isimmutable(ii)) {
		return -EACCES;
	}
	return 0;
}

int silofs_stage_ii(struct silofs_task *task, ino_t ino,
                    enum silofs_stg_mode stg_mode,
                    struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = { .ino = ino };
	struct silofs_ivoaddr ivoa = { .ino = ino };
	const struct silofs_vaddr *vaddr = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_stage_inode(task, ino, stg_mode);
	if (err) {
		return err;
	}
	err = resolve_iaddr(ino, &iaddr);
	if (err) {
		return err;
	}
	vaddr = &iaddr.vaddr;
	err = silofs_resolve_voaddr_of(task, vaddr, stg_mode, &ivoa.voa);
	if (err) {
		return err;
	}
	err = lookup_cached_ii(task, vaddr, &ii);
	if (!err) {
		goto out_ok;
	}
	err = check_stable_at(task, vaddr);
	if (err) {
		return err;
	}
	err = stage_inode_of(task, ino, vaddr, stg_mode, &ii);
	if (err) {
		return err;
	}
	err = ii_check_post_stage(ii, stg_mode);
	if (err) {
		return err;
	}
out_ok:
	*out_ii = ii;
	return 0;
}

int silofs_stage_cached_ii(struct silofs_task *task, ino_t ino,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = { .ino = ino };
	int err;

	err = resolve_iaddr(ino, &iaddr);
	if (err) {
		return err;
	}
	err = lookup_cached_ii(task, &iaddr.vaddr, out_ii);
	if (err) {
		return err;
	}
	return 0;
}
