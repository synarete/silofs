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
	struct silofs_vnode_info *vis[SILOFS_NKB_IN_LBK];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool is_low_resource_error(int err)
{
	bool ret;

	switch (abs(err)) {
	case SILOFS_ENOMEM:
		ret = true;
		break;
	case ENOMEM:
	case EMFILE:
	case ENFILE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}
	return ret;
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
	return off_align_to_lbk(vaddr->off);
}

static ino_t vaddr_to_ino(const struct silofs_vaddr *vaddr)
{
	return silofs_off_to_ino(vaddr->off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ismutable(const struct silofs_uber *uber,
                      const struct silofs_laddr *laddr)
{
	bool ret = false;

	if (!laddr_isnull(laddr)) {
		ret = silofs_sbi_ismutable_laddr(uber->ub_sbi, laddr);
	}
	return ret;
}

static bool vi_has_mutable_laddr(const struct silofs_vnode_info *vi)
{
	return ismutable(vi_uber(vi), &vi->v_llink.laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_uber *uber, struct silofs_vbk_info *vbki)
{
	silofs_vi_attach_to(vi, vbki);
	vi->v.uber = uber;
}

static void vi_update_llink(struct silofs_vnode_info *vi,
                            const struct silofs_llink *llink)
{
	silofs_llink_assign(&vi->v_llink, llink);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_bind_child_spnode(struct silofs_sb_info *sbi,
                                  enum silofs_stype vspace,
                                  const struct silofs_spnode_info *sni_child)
{
	silofs_sbi_bind_child(sbi, vspace, sni_ulink(sni_child));
}

static void sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child)
{
	const loff_t voff = sni_base_voff(sni_child);

	silofs_sni_bind_child(sni, voff, sni_ulink(sni_child));
}

static void sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli_child)
{
	const loff_t voff = sli_base_voff(sli_child);

	silofs_sni_bind_child(sni, voff, sli_ulink(sli_child));
}

static bool sni_has_child_at(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_ulink ulink;

	return (silofs_sni_resolve_child(sni, voff, &ulink) == 0);
}

static bool sni_has_main_lext(const struct silofs_spnode_info *sni)
{
	struct silofs_lextid lextid;

	silofs_sni_main_lext(sni, &lextid);
	return (lextid_size(&lextid) > 0);
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
	        "accum_vnodes=%lu ubki=%lu ui=%lu vbki=%lu vi=%lu",
	        dqs->dq_uis.dq_accum, dqs->dq_iis.dq_accum,
	        dqs->dq_vis.dq_accum, cache->c_ubki_lm.lm_lru.sz,
	        cache->c_ui_lm.lm_lru.sz, cache->c_vbki_lm.lm_lru.sz,
	        cache->c_vi_lm.lm_lru.sz);
}

static int stgc_fetch_cached_vbki(const struct silofs_stage_ctx *stg_ctx,
                                  const struct silofs_vaddr *vaddr,
                                  struct silofs_vbk_info **out_vbki)
{
	struct silofs_cache *cache = stgc_cache(stg_ctx);

	*out_vbki = silofs_cache_lookup_vbk(cache, vaddr->off, vaddr->stype);
	return (*out_vbki != NULL) ? 0 : -SILOFS_ENOENT;
}

static void stgc_forget_cached_vbki(const struct silofs_stage_ctx *stg_ctx,
                                    struct silofs_vbk_info *vbki)
{
	silofs_cache_forget_vbk(stgc_cache(stg_ctx), vbki);
}

static int stgc_create_cached_vbki(const struct silofs_stage_ctx *stg_ctx,
                                   loff_t voff, enum silofs_stype vspace,
                                   struct silofs_vbk_info **out_vbki)
{
	*out_vbki = silofs_cache_create_vbk(stgc_cache(stg_ctx), voff, vspace);
	return (*out_vbki != NULL) ? 0 : -SILOFS_ENOMEM;
}

static int stgc_create_cached_vi(const struct silofs_stage_ctx *stg_ctx,
                                 const struct silofs_vaddr *vaddr,
                                 struct silofs_vnode_info **out_vi)
{
	struct silofs_cache *cache = stgc_cache(stg_ctx);

	*out_vi = silofs_cache_create_vi(cache, vaddr);
	return (*out_vi == NULL) ? -SILOFS_ENOMEM : 0;
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
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = stgc_create_cached_vbki(stg_ctx, voff, vspace, out_vbki);
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
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = stgc_create_cached_vi(stg_ctx, vaddr, out_vi);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_do_stage_lext(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_lextid *lextid,
                              struct silofs_lextf **out_lextf)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_stage_lext_at(stg_ctx->uber, lextid, out_lextf);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_do_stage_lext_of(const struct silofs_stage_ctx *stg_ctx,
                                 const struct silofs_bkaddr *bkaddr,
                                 struct silofs_lextf **out_lextf)
{
	return stgc_do_stage_lext(stg_ctx, &bkaddr->laddr.lextid, out_lextf);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_spawn_bind_vi(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_llink *llink,
                              struct silofs_vbk_info *vbki,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	silofs_vbki_incref(vbki);
	err = stgc_do_spawn_vi(stg_ctx, stg_ctx->vaddr, &vi);
	if (!err) {
		vi_bind_to(vi, stg_ctx->uber, vbki);
		vi_update_llink(vi, llink);
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
	err = silofs_restore_vview(stg_ctx->uber, vi, raw);
	if (!err && !raw) {
		err = silofs_vi_verify_view(vi);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
                                const struct silofs_laddr *laddr)
{
	return silofs_sbi_ismutable_lextid(sbi, &laddr->lextid);
}

static int sbi_inspect_laddr(const struct silofs_sb_info *sbi,
                             const struct silofs_laddr *laddr,
                             enum silofs_stg_mode stg_mode)
{
	if (!stage_cow(stg_mode)) {
		return 0;
	}
	if (sbi_ismutable_laddr(sbi, laddr)) {
		return 0;
	}
	return -SILOFS_EPERM;
}

static int sbi_inspect_cached_ui(const struct silofs_sb_info *sbi,
                                 const struct silofs_unode_info *ui,
                                 enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_laddr(sbi, ui_laddr(ui), stg_mode);
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
	case SILOFS_HEIGHT_UBER:
		stype = SILOFS_STYPE_SUPER;
		break;
	case SILOFS_HEIGHT_SUPER:
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

static int stgc_do_spawn_lext(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_lextid *lextid,
                              struct silofs_lextf **out_lextf)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_spawn_lext_at(stg_ctx->uber, lextid, out_lextf);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_spawn_lext(const struct silofs_stage_ctx *stg_ctx,
                           const struct silofs_lextid *lextid,
                           enum silofs_stype stype_sub,
                           struct silofs_lextf **out_lextf)
{
	int err;

	err = stgc_do_spawn_lext(stg_ctx, lextid, out_lextf);
	if (!err) {
		silofs_sti_update_lexts(&stg_ctx->sbi->sb_sti, stype_sub, 1);
	}
	return err;
}

static void
stgc_make_lextid_of_spmaps(const struct silofs_stage_ctx *stg_ctx,
                           loff_t voff, enum silofs_height height,
                           struct silofs_lextid *out_lextid)
{
	struct silofs_treeid treeid;
	const enum silofs_stype vspace = stg_ctx->vspace;

	silofs_sbi_treeid(stg_ctx->sbi, &treeid);
	silofs_lextid_setup(out_lextid, &treeid, voff, vspace, height);
}

static void
stgc_make_lextid_of_vdata(const struct silofs_stage_ctx *stg_ctx,
                          loff_t voff, struct silofs_lextid *out_lextid)
{
	struct silofs_treeid treeid;

	silofs_sbi_treeid(stg_ctx->sbi, &treeid);
	silofs_lextid_setup(out_lextid, &treeid, voff,
	                    stg_ctx->vspace, SILOFS_HEIGHT_VDATA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_update_space_stats(const struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_uaddr *uaddr)
{
	silofs_sti_update_objs(&stg_ctx->sbi->sb_sti, uaddr->stype, 1);
	silofs_sti_update_bks(&stg_ctx->sbi->sb_sti, uaddr->stype, 1);
}

static int stgc_spawn_super_main_lext(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_lextid lextid;
	struct silofs_lextf *lextf = NULL;
	const enum silofs_height height = SILOFS_HEIGHT_SUPER - 1;
	int err;

	stgc_make_lextid_of_spmaps(stg_ctx, 0, height, &lextid);
	err = stgc_spawn_lext(stg_ctx, &lextid, SILOFS_STYPE_SPNODE, &lextf);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_lext(stg_ctx->sbi, stg_ctx->vspace,
	                          &lextf->lex_id);
	return 0;
}

static int stgc_stage_super_main_lext(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_lextid lextid;
	struct silofs_lextf *lextf = NULL;

	silofs_sbi_main_lext(stg_ctx->sbi, stg_ctx->vspace, &lextid);
	return stgc_do_stage_lext(stg_ctx, &lextid, &lextf);
}

static int stgc_require_super_main_lext(const struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (silofs_sbi_has_main_lext(stg_ctx->sbi, stg_ctx->vspace)) {
		err = stgc_stage_super_main_lext(stg_ctx);
	} else {
		err = stgc_spawn_super_main_lext(stg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_spawn_spnode_main_lext(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	struct silofs_lextid lextid;
	struct silofs_lextf *lextf = NULL;
	const loff_t voff = sni_base_voff(sni);
	const enum silofs_height height = sni_child_height(sni);
	const enum silofs_stype stype = sni_child_stype(sni);
	int err;

	stgc_make_lextid_of_spmaps(stg_ctx, voff, height, &lextid);
	err = stgc_spawn_lext(stg_ctx, &lextid, stype, &lextf);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_lext(sni, &lextf->lex_id);
	return 0;
}

static int stgc_stage_spnode_main_lext(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	struct silofs_lextid lextid;
	struct silofs_lextf *lextf = NULL;

	silofs_sni_main_lext(sni, &lextid);
	return stgc_do_stage_lext(stg_ctx, &lextid, &lextf);
}

static int
stgc_require_spnode_main_lext(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info *sni)
{
	int err;

	if (sni_has_main_lext(sni)) {
		err = stgc_stage_spnode_main_lext(stg_ctx, sni);
	} else {
		err = stgc_spawn_spnode_main_lext(stg_ctx, sni);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_inspect_laddr(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_laddr *laddr)
{
	if (stage_normal(stg_ctx->stg_mode)) {
		return 0;
	}
	if (sbi_ismutable_laddr(stg_ctx->sbi, laddr)) {
		return 0;
	}
	return -SILOFS_EPERM; /* address on read-only tree */
}

static int stgc_inspect_llink(const struct silofs_stage_ctx *stg_ctx,
                              const struct silofs_llink *llink)
{
	return stgc_inspect_laddr(stg_ctx, &llink->laddr);
}

static int stgc_inspect_cached_ui(const struct silofs_stage_ctx *stg_ctx,
                                  const struct silofs_unode_info *ui)
{
	return stgc_inspect_laddr(stg_ctx, ui_laddr(ui));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void stgc_increfs(const struct silofs_stage_ctx *stg_ctx,
                         enum silofs_height height_upto)
{
	if (height_upto <= SILOFS_HEIGHT_SUPER) {
		sbi_incref(stg_ctx->sbi);
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
	if (height_from <= SILOFS_HEIGHT_SUPER) {
		sbi_decref(stg_ctx->sbi);
	}
}

static int stgc_find_cached_unode(const struct silofs_stage_ctx *stg_ctx,
                                  enum silofs_height height,
                                  struct silofs_unode_info **out_ui)
{
	struct silofs_uakey uakey;
	struct silofs_vrange vrange;

	silofs_vrange_of_spmap(&vrange, height, stg_ctx->bk_voff);
	silofs_uakey_setup_by2(&uakey, &vrange, stg_ctx->vspace);
	*out_ui = silofs_cache_find_ui_by(stgc_cache(stg_ctx), &uakey);
	return (*out_ui != NULL) ? 0 : -SILOFS_ENOENT;
}

static int stgc_fetch_cached_spnode(const struct silofs_stage_ctx *stg_ctx,
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

static int stgc_fetch_cached_spleaf(const struct silofs_stage_ctx *stg_ctx,
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

static int stgc_resolve_spnode_child(const struct silofs_stage_ctx *stg_ctx,
                                     const struct silofs_spnode_info *sni,
                                     struct silofs_ulink *out_ulink)
{
	return silofs_sni_resolve_child(sni, stg_ctx->bk_voff, out_ulink);
}

static int stgc_resolve_spleaf_child(const struct silofs_stage_ctx *stg_ctx,
                                     const struct silofs_spleaf_info *sli,
                                     struct silofs_blink *out_blink)
{
	return silofs_sli_resolve_child(sli, stg_ctx->bk_voff, out_blink);
}

static int stgc_do_stage_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_spnode_info **out_sni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_stage_spnode_at(stg_ctx->uber, ulink, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_stage_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spnode_info **out_sni)
{
	return stgc_do_stage_spnode_at(stg_ctx, ulink, out_sni);
}

static int stgc_do_spawn_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_spnode_info **out_sni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_spawn_spnode_at(stg_ctx->uber, ulink, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_spawn_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spnode_info **out_sni)
{
	return stgc_do_spawn_spnode_at(stg_ctx, ulink, out_sni);
}

static int stgc_do_stage_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_spleaf_info **out_sli)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_stage_spleaf_at(stg_ctx->uber, ulink, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_stage_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spleaf_info **out_sli)
{
	return stgc_do_stage_spleaf_at(stg_ctx, ulink, out_sli);
}

static int stgc_do_spawn_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_spleaf_info **out_sli)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < stg_ctx->retry; ++i) {
		err = silofs_spawn_spleaf_at(stg_ctx->uber, ulink, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		stgc_try_evict_some(stg_ctx, i > 0);
	}
	return err;
}

static int stgc_spawn_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spleaf_info **out_sli)
{
	return stgc_do_spawn_spleaf_at(stg_ctx, ulink, out_sli);
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

static void stgc_setup_spawned_spnode4(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sbi_uaddr(stg_ctx->sbi),
	                         stg_ctx->bk_voff);
}

static int stgc_spawn_spnode4_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_require_super_main_lext(stg_ctx);
	if (err) {
		return err;
	}
	silofs_sbi_resolve_main_at(stg_ctx->sbi, stg_ctx->voff,
	                           stg_ctx->vspace, &ulink);

	err = stgc_spawn_spnode_at(stg_ctx, &ulink, out_sni);
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
	int err;

	err = stgc_spawn_spnode4(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, stg_ctx->sni4);
	sbi_bind_child_spnode(stg_ctx->sbi, stg_ctx->vspace, *out_sni);
	return 0;
}

static int stgc_clone_spnode4(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = stgc_do_clone_spnode4(stg_ctx, &sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE4);
	*out_sni = sni;
	return err;
}

static int stgc_inspect_cached_spnode4(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni4);
}

static int stgc_do_stage_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = silofs_sbi_resolve_child(stg_ctx->sbi, stg_ctx->vspace, &ulink);
	if (err) {
		return -SILOFS_EFSCORRUPTED;
	}
	err = stgc_stage_spnode_at(stg_ctx, &ulink, &stg_ctx->sni4);
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
	err = stgc_clone_spnode4(stg_ctx, &stg_ctx->sni4);
	if (err) {
		return err;
	}
	return 0;
}

static int stgc_stage_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SUPER);
	err = stgc_do_stage_spnode4(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SUPER);
	return err;
}

static int stgc_fetch_cached_spnode4(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_fetch_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE4,
	                                &stg_ctx->sni4);
}

static int stgc_stage_spnode4_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_fetch_cached_spnode4(stg_ctx);
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
	sbi_bind_child_spnode(stg_ctx->sbi, stg_ctx->vspace, stg_ctx->sni4);
	return 0;
}

static bool stgc_has_spnode4_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_sproot_of(stg_ctx->sbi, stg_ctx->vspace, &uaddr);
	return !err;
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

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SUPER);
	err = stgc_do_require_spnode4(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SUPER);
	return err;
}

static int stgc_require_spnode4_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_fetch_cached_spnode4(stg_ctx);
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
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_require_spnode_main_lext(stg_ctx, stg_ctx->sni4);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(stg_ctx->sni4, stg_ctx->bk_voff, &ulink);

	err = stgc_spawn_spnode_at(stg_ctx, &ulink, out_sni);
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
	int err;

	err = stgc_spawn_spnode3(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, stg_ctx->sni3);
	sni_bind_child_spnode(stg_ctx->sni4, *out_sni);
	return 0;
}

static int stgc_clone_spnode3(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = stgc_do_clone_spnode3(stg_ctx, &sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE3);
	*out_sni = sni;
	return err;
}

static int stgc_inspect_cached_spnode3(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni3);
}

static int stgc_do_stage_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_resolve_spnode_child(stg_ctx, stg_ctx->sni4, &ulink);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &ulink, &stg_ctx->sni3);
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
	err = stgc_clone_spnode3(stg_ctx, &stg_ctx->sni3);
	if (err) {
		return err;
	}
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

static int stgc_fetch_cached_spnode3(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_fetch_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE3,
	                                &stg_ctx->sni3);
}

static int stgc_stage_spnode3_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_fetch_cached_spnode3(stg_ctx);
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
	sni_bind_child_spnode(stg_ctx->sni4, stg_ctx->sni3);
	return 0;
}

static bool stgc_has_spnode3_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return sni_has_child_at(stg_ctx->sni4, stg_ctx->bk_voff);
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

	err = stgc_fetch_cached_spnode3(stg_ctx);
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
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_require_spnode_main_lext(stg_ctx, stg_ctx->sni3);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(stg_ctx->sni3, stg_ctx->bk_voff, &ulink);

	err = stgc_spawn_spnode_at(stg_ctx, &ulink, out_sni);
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
	int err;

	err = stgc_spawn_spnode2(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, stg_ctx->sni2);
	sni_bind_child_spnode(stg_ctx->sni3, *out_sni);
	return 0;
}

static int stgc_clone_spnode2(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = stgc_do_clone_spnode2(stg_ctx, &sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	*out_sni = sni;
	return err;
}

static int stgc_inspect_cached_spnode2(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni2);
}

static int stgc_do_stage_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_resolve_spnode_child(stg_ctx, stg_ctx->sni3, &ulink);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &ulink, &stg_ctx->sni2);
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
	err = stgc_clone_spnode2(stg_ctx, &stg_ctx->sni2);
	if (err) {
		return err;
	}
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

static int stgc_fetch_cached_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_fetch_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE2,
	                                &stg_ctx->sni2);
}

static int stgc_stage_spnode2_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_fetch_cached_spnode2(stg_ctx);
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
	sni_bind_child_spnode(stg_ctx->sni3, stg_ctx->sni2);
	return 0;
}

static bool stgc_has_spnode2_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return sni_has_child_at(stg_ctx->sni3, stg_ctx->bk_voff);
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

	err = stgc_fetch_cached_spnode2(stg_ctx);
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
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_require_spnode_main_lext(stg_ctx, stg_ctx->sni2);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(stg_ctx->sni2, stg_ctx->bk_voff, &ulink);

	err = stgc_spawn_spnode_at(stg_ctx, &ulink, out_sni);
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
	int err;

	err = stgc_spawn_spnode1(stg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, stg_ctx->sni1);
	sni_bind_child_spnode(stg_ctx->sni2, *out_sni);
	return 0;
}

static int stgc_clone_spnode1(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = stgc_do_clone_spnode1(stg_ctx, &sni);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE1);
	*out_sni = sni;
	return err;
}

static int stgc_inspect_cached_spnode1(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_inspect_cached_spnode(stg_ctx, stg_ctx->sni1);
}

static int stgc_do_stage_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_resolve_spnode_child(stg_ctx, stg_ctx->sni2, &ulink);
	if (err) {
		return err;
	}
	err = stgc_stage_spnode_at(stg_ctx, &ulink, &stg_ctx->sni1);
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
	err = stgc_clone_spnode1(stg_ctx, &stg_ctx->sni1);
	if (err) {
		return err;
	}
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

static int stgc_fetch_cached_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_fetch_cached_spnode(stg_ctx, SILOFS_HEIGHT_SPNODE1,
	                                &stg_ctx->sni1);
}

static int stgc_spawn_bind_spnode1(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_spawn_spnode1(stg_ctx, &stg_ctx->sni1);
	if (err) {
		return err;
	}
	sni_bind_child_spnode(stg_ctx->sni2, stg_ctx->sni1);
	return 0;
}

static bool stgc_has_spnode1_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return sni_has_child_at(stg_ctx->sni2, stg_ctx->bk_voff);
}

static int stgc_stage_spnode1_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_fetch_cached_spnode1(stg_ctx);
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

	err = stgc_fetch_cached_spnode1(stg_ctx);
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
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_require_spnode_main_lext(stg_ctx, stg_ctx->sni1);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(stg_ctx->sni1, stg_ctx->bk_voff, &ulink);

	err = stgc_spawn_spleaf_at(stg_ctx, &ulink, out_sli);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spleaf(stg_ctx, *out_sli);
	return 0;
}

static int
stgc_require_spleaf_main_lext(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spleaf_info *sli)
{
	struct silofs_lextid lextid;
	struct silofs_lextf *lextf = NULL;
	int err;

	silofs_sli_main_lext(sli, &lextid);
	if (!lextid_isnull(&lextid)) {
		return stgc_do_stage_lext(stg_ctx, &lextid, &lextf);
	}
	/*
	 * TODO-0047: Do not use underlying repo to detect if vdata-lext exists
	 */
	stgc_make_lextid_of_vdata(stg_ctx, sli_base_voff(sli), &lextid);
	err = stgc_do_stage_lext(stg_ctx, &lextid, &lextf);
	if (!err) {
		goto out_ok;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = stgc_spawn_lext(stg_ctx, &lextid, stg_ctx->vspace, &lextf);
	if (err) {
		return err;
	}
out_ok:
	silofs_sli_bind_main_lext(sli, &lextf->lex_id);
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
	err = stgc_require_spleaf_main_lext(stg_ctx, *out_sli);
	if (err) {
		return err;
	}
	stgc_update_space_stats(stg_ctx, sli_uaddr(*out_sli));
	return 0;
}

static int stgc_do_clone_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_spawn_spleaf(stg_ctx, out_sli);
	if (err) {
		return err;
	}
	silofs_sli_clone_from(*out_sli, stg_ctx->sli);
	sni_bind_child_spleaf(stg_ctx->sni1, *out_sli);
	return 0;
}

static int stgc_clone_spleaf(const struct silofs_stage_ctx *stg_ctx,
                             struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = stgc_do_clone_spleaf(stg_ctx, &sli);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	*out_sli = sli;
	return err;
}

static int stgc_do_stage_spleaf(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = stgc_resolve_spnode_child(stg_ctx, stg_ctx->sni1, &ulink);
	if (err) {
		return err;
	}
	err = stgc_stage_spleaf_at(stg_ctx, &ulink, &stg_ctx->sli);
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
	err = stgc_clone_spleaf(stg_ctx, &stg_ctx->sli);
	if (err) {
		return err;
	}
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

static int stgc_fetch_cached_spleaf1(struct silofs_stage_ctx *stg_ctx)
{
	return stgc_fetch_cached_spleaf(stg_ctx, &stg_ctx->sli);
}

static int stgc_stage_spleaf_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_fetch_cached_spleaf1(stg_ctx);
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

	return &cache->c_spams;
}

static void stgc_track_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	struct silofs_spamaps *spam = stgc_spamaps(stg_ctx);

	sli_vrange(sli, &vrange);
	silofs_spamaps_store(spam, stg_ctx->vspace, vrange.beg, vrange.len);
}

static int stgc_spawn_bind_spleaf_at(struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stgc_spawn_spleaf(stg_ctx, &sli);
	if (err) {
		return err;
	}
	sni_bind_child_spleaf(stg_ctx->sni1, sli);
	stgc_track_spawned_spleaf(stg_ctx, sli);
	stg_ctx->sli = sli;
	return 0;
}

static bool stgc_has_spleaf_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	return sni_has_child_at(stg_ctx->sni1, stg_ctx->bk_voff);
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

static int stgc_resolve_llink_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_llink *out_llink)
{
	struct silofs_blink blink;
	struct silofs_laddr laddr;
	int err;

	err = stgc_resolve_spleaf_child(stg_ctx, stg_ctx->sli, &blink);
	if (err) {
		return err;
	}
	silofs_laddr_setup(&laddr, &blink.bka.laddr.lextid,
	                   stg_ctx->vaddr->off, stg_ctx->vaddr->len);
	silofs_llink_setup(out_llink, &laddr, &blink.riv);
	return 0;
}

static int stgc_stage_spleaf_for_resolve(struct silofs_stage_ctx *stg_ctx)
{
	int ret;

	ret = stgc_fetch_cached_spleaf1(stg_ctx);
	if (ret != 0) {
		ret = stgc_stage_spmaps_of(stg_ctx);
	}
	return ret;
}

static int stgc_resolve_llink(struct silofs_stage_ctx *stg_ctx,
                              struct silofs_llink *out_llink)
{
	int err;

	err = stgc_stage_spleaf_for_resolve(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_resolve_llink_of(stg_ctx, out_llink);
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
	return likely(allocated) ? 0 : -SILOFS_ENOENT;
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
                              struct silofs_lextf *lextf,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vbk_info **out_vbki)
{
	int ret;

	lextf_incref(lextf);
	ret = stgc_do_spawn_vbki(stg_ctx, vaddr->off, vaddr->stype, out_vbki);
	lextf_decref(lextf);
	return ret;
}

static int stgc_spawn_load_vbk(const struct silofs_stage_ctx *stg_ctx,
                               struct silofs_lextf *lextf,
                               const struct silofs_laddr *laddr,
                               struct silofs_vbk_info **out_vbki)
{
	struct silofs_vbk_info *vbki = NULL;
	int err;

	err = stgc_spawn_vbki_by(stg_ctx, lextf, stg_ctx->vaddr, &vbki);
	if (err) {
		return err;
	}
	err = silofs_lextf_load_bk(lextf, laddr, &vbki->vbk);
	if (err) {
		stgc_forget_cached_vbki(stg_ctx, vbki);
		return err;
	}
	*out_vbki = vbki;
	return 0;
}

static int stgc_stage_load_vbk(const struct silofs_stage_ctx *stg_ctx,
                               const struct silofs_laddr *laddr,
                               struct silofs_vbk_info **out_vbki)
{
	struct silofs_lextf *lextf = NULL;
	int err;

	err = stgc_do_stage_lext(stg_ctx, &laddr->lextid, &lextf);
	if (err) {
		return err;
	}
	err = silofs_lextf_require(lextf, laddr);
	if (err) {
		return err;
	}
	err = stgc_spawn_load_vbk(stg_ctx, lextf, laddr, out_vbki);
	if (err) {
		return err;
	}
	return 0;
}

static int stgc_stage_vblock(const struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_laddr *laddr,
                             struct silofs_vbk_info **out_vbki)
{
	int err;

	err = stgc_fetch_cached_vbki(stg_ctx, stg_ctx->vaddr, out_vbki);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = stgc_stage_load_vbk(stg_ctx, laddr, out_vbki);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lextf_resolve_bk(struct silofs_lextf *lextf,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_iovec *iov)
{
	struct silofs_laddr laddr;
	const loff_t off = lba_to_off(bkaddr->lba);
	const size_t len = SILOFS_LBK_SIZE;

	silofs_laddr_setup(&laddr, &bkaddr->laddr.lextid, off, len);
	return silofs_lextf_resolve(lextf, &laddr, iov);
}

static int stgc_resolve_bks(const struct silofs_stage_ctx *stg_ctx,
                            const struct silofs_bkaddr *bkaddr_src,
                            const struct silofs_bkaddr *bkaddr_dst,
                            struct silofs_iovec *out_iov_src,
                            struct silofs_iovec *out_iov_dst)
{
	struct silofs_lextf *lextf_src = NULL;
	struct silofs_lextf *lextf_dst = NULL;
	int ret;

	ret = stgc_do_stage_lext_of(stg_ctx, bkaddr_src, &lextf_src);
	if (ret) {
		goto out;
	}
	lextf_incref(lextf_src);

	ret = stgc_do_stage_lext_of(stg_ctx, bkaddr_dst, &lextf_dst);
	if (ret) {
		goto out;
	}
	lextf_incref(lextf_dst);

	ret = lextf_resolve_bk(lextf_src, bkaddr_src, out_iov_src);
	if (ret) {
		goto out;
	}

	ret = lextf_resolve_bk(lextf_dst, bkaddr_dst, out_iov_dst);
	if (ret) {
		goto out;
	}
out:
	lextf_decref(lextf_dst);
	lextf_decref(lextf_src);
	return (ret == -ENOENT) ? -SILOFS_EFSCORRUPTED : ret;
}

static int stgc_require_clone_bkaddr(const struct silofs_stage_ctx *stg_ctx,
                                     struct silofs_blink *out_blink_dst)
{
	const struct silofs_vaddr *vaddr = stg_ctx->vaddr;
	int err;

	err = stgc_require_spleaf_main_lext(stg_ctx, stg_ctx->sli);
	if (err) {
		return err;
	}
	silofs_sli_resolve_main(stg_ctx->sli, vaddr->off, out_blink_dst);
	return 0;
}

static int stgc_clone_rebind_vblock(const struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_bkaddr *src_bka)
{
	struct silofs_blink dst_blink;
	struct silofs_iovec src_iov = { .iov_fd = -1 };
	struct silofs_iovec dst_iov = { .iov_fd = -1 };
	const struct silofs_bkaddr *dst_bka = NULL;
	int err;

	err = stgc_require_clone_bkaddr(stg_ctx, &dst_blink);
	if (err) {
		return err;
	}
	dst_bka = &dst_blink.bka;
	err = stgc_resolve_bks(stg_ctx, src_bka, dst_bka, &src_iov, &dst_iov);
	if (err) {
		return err;
	}
	silofs_sli_bind_child(stg_ctx->sli, stg_ctx->vaddr->off, &dst_blink);
	return 0;
}

static int stgc_stage_vblock_by(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_laddr *laddr,
                                struct silofs_vbk_info **out_vbki)
{
	const struct silofs_vaddr *vaddr = stg_ctx->vaddr;
	int ret = 0;

	*out_vbki = NULL;
	if (!stype_isdata(vaddr->stype)) {
		ret = stgc_stage_vblock(stg_ctx, laddr, out_vbki);
		silofs_assert_ne(ret, -SILOFS_ERDONLY);
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
	err = silofs_stage_inode(stg_ctx->task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		return err;
	}
	*out_vi = &ii->i_vi;
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
	err = silofs_stage_vnode(stg_ctx->task, NULL, vaddr,
	                         SILOFS_STG_CUR, &vi);
	if (err) {
		silofs_assert_ne(err, -SILOFS_ERDONLY);
		return err;
	}
	*out_vi = vi;
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
                                    struct silofs_vis *vis)
{
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_vaddr *vaddrj = NULL;
	const struct silofs_vaddr *vaddr = stg_ctx->vaddr;
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
                                 struct silofs_vis *vis)
{
	int err;

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = stgc_do_pre_clone_vblock(stg_ctx, vis);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
}

static void stgc_post_clone_vblock(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_vis *vis)
{
	struct silofs_vnode_info *vi = NULL;

	for (size_t i = 0; i < vis->vas.count; ++i) {
		vi = vis->vis[i];
		vi_dirtify(vi, NULL);
		vi_decref(vi);
	}
	silofs_unused(stg_ctx);
}

static int stgc_clone_vblock(struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_bkaddr *src_bka)
{
	struct silofs_vis vis = { .vas.count = 0 };
	int err;

	err = stgc_pre_clone_vblock(stg_ctx, &vis);
	if (!err) {
		err = stgc_clone_rebind_vblock(stg_ctx, src_bka);
	}
	stgc_post_clone_vblock(stg_ctx, &vis);
	return err;
}

static int stgc_clone_vblock_of(struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_laddr *src_laddr,
                                struct silofs_vbk_info *vbki)
{
	struct silofs_bkaddr src_bka = { .lba = SILOFS_LBA_NULL };
	int ret;

	silofs_vbki_incref(vbki); /* may be NULL */
	bkaddr_by_laddr(&src_bka, src_laddr);
	ret = stgc_clone_vblock(stg_ctx, &src_bka);
	silofs_vbki_decref(vbki);
	return ret;
}

static int stgc_resolve_inspect_llink(struct silofs_stage_ctx *stg_ctx,
                                      struct silofs_llink *out_llink)
{
	struct silofs_vbk_info *vbki = NULL;
	int err;

	err = stgc_resolve_llink(stg_ctx, out_llink);
	if (err) {
		return err;
	}
	err = stgc_inspect_llink(stg_ctx, out_llink);
	if (err != -SILOFS_EPERM) {
		return err;
	}
	err = stgc_check_may_clone(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_stage_vblock_by(stg_ctx, &out_llink->laddr, &vbki);
	if (err) {
		return err;
	}
	err = stgc_clone_vblock_of(stg_ctx, &out_llink->laddr, vbki);
	if (err) {
		return err;
	}
	err = stgc_resolve_llink_of(stg_ctx, out_llink);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_resolve_llink_of(struct silofs_task *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode stg_mode,
                            struct silofs_llink *out_llink)
{
	struct silofs_stage_ctx stg_ctx;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	return stgc_resolve_inspect_llink(&stg_ctx, out_llink);
}

int silofs_require_mut_vaddr(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;

	return silofs_resolve_llink_of(task, vaddr, SILOFS_STG_COW, &llink);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_stage_vnode_at(struct silofs_stage_ctx *stg_ctx,
                               struct silofs_vnode_info **out_vi)
{
	struct silofs_llink llink = { .laddr.pos = -1 };
	struct silofs_vbk_info *vbki = NULL;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = stgc_resolve_inspect_llink(stg_ctx, &llink);
	if (err) {
		goto out_err;
	}
	err = stgc_stage_vblock(stg_ctx, &llink.laddr, &vbki);
	if (err) {
		goto out_err;
	}
	err = stgc_spawn_bind_vi(stg_ctx, &llink, vbki, &vi);
	if (err) {
		goto out_err;
	}
	err = stgc_restore_view_of(stg_ctx, vi);
	if (err) {
		goto out_err;
	}
	vi_update_llink(vi, &llink);
	*out_vi = vi;
	return 0;
out_err:
	stgc_forget_cached_vi(stg_ctx, vi);
	*out_vi = NULL;
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*
 * Special case where data-node has been unmapped due to forget, yet it still
 * had a live ref-count due to on-going I/O operation.
 */
static int fixup_cached_vi(const struct silofs_task *task,
                           struct silofs_vnode_info *vi)
{
	if (!(vi->v.ce.ce_flags & SILOFS_CEF_FORGOT)) {
		return 0;
	}
	if (silofs_vi_refcnt(vi)) {
		return 0;
	}
	silofs_cache_forget_vi(task_cache(task), vi);
	return -SILOFS_ENOENT;
}

static int fetch_cached_vi(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi;
	int err;

	vi = silofs_cache_lookup_vi(task_cache(task), vaddr);
	if (vi == NULL) {
		return -SILOFS_ENOENT;
	}
	err = fixup_cached_vi(task, vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

int silofs_fetch_cached_vnode(struct silofs_task *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vi)
{
	int ret = -SILOFS_ENOENT;

	if (!vaddr_isnull(vaddr)) {
		ret = fetch_cached_vi(task, vaddr, out_vi);
	}
	return ret;
}

static int stage_vnode_at(struct silofs_task *task,
                          const struct silofs_vaddr *vaddr,
                          enum silofs_stg_mode stg_mode,
                          struct silofs_vnode_info **out_vi)
{
	struct silofs_stage_ctx stg_ctx;

	stgc_setup(&stg_ctx, task, vaddr, stg_mode);
	return stgc_stage_vnode_at(&stg_ctx, out_vi);
}

static int stage_stable_vnode_at(struct silofs_task *task,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stg_mode stg_mode,
                                 struct silofs_vnode_info **out_vi)
{
	int err;

	err = require_stable_at(task, vaddr);
	if (err) {
		return err;
	}
	err = stage_vnode_at(task, vaddr, stg_mode, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int require_updated_cached_vi(struct silofs_task *task,
                                     struct silofs_vnode_info *vi,
                                     enum silofs_stg_mode stg_mode)
{
	struct silofs_llink llink;
	int err;

	if (!(stg_mode & SILOFS_STG_COW)) {
		return 0;
	}
	if (vi_has_mutable_laddr(vi)) {
		return 0;
	}
	err = silofs_resolve_llink_of(task, vi_vaddr(vi), stg_mode, &llink);
	if (err) {
		return err;
	}
	vi_update_llink(vi, &llink);
	return 0;
}

static int
do_resolve_stage_vnode(struct silofs_task *task,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stg_mode stg_mode,
                       struct silofs_vnode_info **out_vi)
{
	int err;

	err = fetch_cached_vi(task, vaddr, out_vi);
	if (!err) {
		/* cache hit -- require up-to-date */
		err = require_updated_cached_vi(task, *out_vi, stg_mode);
	} else {
		/* cache miss -- stage from objects store */
		err = stage_stable_vnode_at(task, vaddr, stg_mode, out_vi);
	}
	return err;
}

static int check_stage_vnode(const struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stg_mode stg_mode)
{
	if (vaddr_isnull(vaddr)) {
		return -SILOFS_ENOENT;
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
	err = do_resolve_stage_vnode(task, vaddr, stg_mode, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_vnode(struct silofs_task *task,
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

static int fetch_cached_ii(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = fetch_cached_vi(task, vaddr, &vi);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vi(vi);
	return 0;
}

static int resolve_iaddr(ino_t ino, struct silofs_vaddr *out_vaddr)
{
	const ino_t ino_max = SILOFS_INO_MAX;
	const ino_t ino_root = SILOFS_INO_ROOT;
	loff_t voff;

	if ((ino < ino_root) || (ino > ino_max)) {
		return -SILOFS_EINVAL;
	}
	voff = silofs_ino_to_off(ino);
	if (off_isnull(voff)) {
		return -SILOFS_EINVAL;
	}
	vaddr_setup(out_vaddr, SILOFS_STYPE_INODE, voff);
	return 0;
}

static int check_stage_inode(const struct silofs_task *task, ino_t ino,
                             enum silofs_stg_mode stg_mode)
{
	if (ino_isnull(ino)) {
		return -SILOFS_ENOENT;
	}
	if ((stg_mode & SILOFS_STG_COW) == 0) {
		return 0;
	}
	return silof_sbi_check_mut_fs(task_sbi(task));
}

static int resolve_stable_iaddr(struct silofs_task *task, ino_t ino,
                                struct silofs_vaddr *out_vaddr)
{
	int err;

	err = resolve_iaddr(ino, out_vaddr);
	if (err) {
		return err;
	}
	err = check_stable_at(task, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int stage_stable_inode_at(struct silofs_task *task,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stg_mode stg_mode,
                                 struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = stage_stable_vnode_at(task, vaddr, stg_mode, &vi);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vi(vi);
	silofs_ii_rebind_view(*out_ii, vaddr_to_ino(vaddr));
	silofs_ii_refresh_atime(*out_ii, true);
	return 0;
}

static int require_updated_cached_ii(struct silofs_task *task,
                                     struct silofs_inode_info *ii,
                                     enum silofs_stg_mode stg_mode)
{
	return require_updated_cached_vi(task, &ii->i_vi, stg_mode);
}

static int do_resolve_stage_inode(struct silofs_task *task, ino_t ino,
                                  enum silofs_stg_mode stg_mode,
                                  struct silofs_inode_info **out_ii)
{
	struct silofs_vaddr vaddr;
	int err;

	err = resolve_stable_iaddr(task, ino, &vaddr);
	if (err) {
		return err;
	}
	err = fetch_cached_ii(task, &vaddr, out_ii);
	if (!err) {
		/* cache hit -- require up-to-date */
		err = require_updated_cached_ii(task, *out_ii, stg_mode);
	} else {
		/* cache miss -- stage from objects store */
		err = stage_stable_inode_at(task, &vaddr, stg_mode, out_ii);
	}
	return err;
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
		return -SILOFS_EACCES;
	}
	return 0;
}

int silofs_stage_inode(struct silofs_task *task, ino_t ino,
                       enum silofs_stg_mode stg_mode,
                       struct silofs_inode_info **out_ii)
{
	int err;

	err = check_stage_inode(task, ino, stg_mode);
	if (err) {
		return err;
	}
	err = do_resolve_stage_inode(task, ino, stg_mode, out_ii);
	if (err) {
		return err;
	}
	err = ii_check_post_stage(*out_ii, stg_mode);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fetch_cached_inode(struct silofs_task *task, ino_t ino,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_vaddr vaddr = { .off = -1 };
	int err;

	err = resolve_iaddr(ino, &vaddr);
	if (err) {
		return err;
	}
	err = fetch_cached_ii(task, &vaddr, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_refresh_llink_of(struct silofs_task *task,
                            struct silofs_vnode_info *vi)
{
	struct silofs_llink llink;
	const struct silofs_vaddr *vaddr = NULL;
	int err;

	if (vi_has_mutable_laddr(vi)) {
		return 0;
	}
	vaddr = vi_vaddr(vi);
	err = silofs_resolve_llink_of(task, vaddr, SILOFS_STG_CUR, &llink);
	if (err) {
		log_warn("failed to refresh llink: stype=%d off=%ld err=%d",
		         vaddr->stype, vaddr->off, err);
		return err;
	}
	vi_update_llink(vi, &llink);
	return 0;
}

