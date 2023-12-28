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


struct silofs_vstage_ctx {
	struct silofs_task             *task;
	struct silofs_fsenv            *fsenv;
	struct silofs_sb_info          *sbi;
	struct silofs_spnode_info      *sni4;
	struct silofs_spnode_info      *sni3;
	struct silofs_spnode_info      *sni2;
	struct silofs_spnode_info      *sni1;
	struct silofs_spleaf_info      *sli;
	const struct silofs_vaddr      *vaddr;
	loff_t                          voff;
	enum silofs_stg_mode            stg_mode;
	enum silofs_ltype               vspace;
	unsigned int                    retry;
};

struct silofs_vis {
	struct silofs_vaddrs vas;
	struct silofs_vnode_info *vis[SILOFS_NKB_IN_LBK];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t ino_to_off(ino_t ino)
{
	return silofs_ino_isnull(ino) ? SILOFS_OFF_NULL :
	       (loff_t)(ino << SILOFS_INODE_SHIFT);
}

static ino_t off_to_ino(loff_t off)
{
	return silofs_off_isnull(off) ? SILOFS_INO_NULL :
	       (ino_t)(off >> SILOFS_INODE_SHIFT);
}

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

static ino_t vaddr_to_ino(const struct silofs_vaddr *vaddr)
{
	return off_to_ino(vaddr->off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ismutable(const struct silofs_fsenv *fsenv,
                      const struct silofs_laddr *laddr)
{
	bool ret = false;

	if (!laddr_isnull(laddr)) {
		ret = silofs_sbi_ismutable_laddr(fsenv->fse_sbi, laddr);
	}
	return ret;
}

static bool vi_has_mutable_laddr(const struct silofs_vnode_info *vi)
{
	return ismutable(vi_fsenv(vi), &vi->v_llink.laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_fsenv *fsenv)
{
	vi->v_lni.l_fsenv = fsenv;
}

static void vi_update_llink(struct silofs_vnode_info *vi,
                            const struct silofs_llink *llink)
{
	silofs_llink_assign(&vi->v_llink, llink);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_bind_child_spnode(struct silofs_sb_info *sbi,
                                  enum silofs_ltype vspace,
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

static bool sni_has_main_lseg(const struct silofs_spnode_info *sni)
{
	struct silofs_lsegid lsegid;

	silofs_sni_main_lseg(sni, &lsegid);
	return (lsegid_size(&lsegid) > 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_cache *vstgc_cache(const struct silofs_vstage_ctx
                                        *vstg_ctx)
{
	return vstg_ctx->fsenv->fse.cache;
}

static void vstgc_log_cache_stat(const struct silofs_vstage_ctx *vstg_ctx)
{
	const struct silofs_cache *cache = vstgc_cache(vstg_ctx);
	const struct silofs_dirtyqs *dqs = &cache->c_dqs;

	log_dbg("cache-stat: accum_unodes=%lu accum_inodes=%lu "\
	        "accum_vnodes=%lu ui=%lu vi=%lu",
	        dqs->dq_uis.dq_accum,
	        dqs->dq_iis.dq_accum,
	        dqs->dq_vis.dq_accum,
	        cache->c_ui_lm.lm_lru.sz,
	        cache->c_vi_lm.lm_lru.sz);
}

static int vstgc_create_cached_vi(const struct silofs_vstage_ctx *vstg_ctx,
                                  const struct silofs_vaddr *vaddr,
                                  struct silofs_vnode_info **out_vi)
{
	struct silofs_cache *cache = vstgc_cache(vstg_ctx);

	*out_vi = silofs_cache_create_vi(cache, vaddr);
	return (*out_vi == NULL) ? -SILOFS_ENOMEM : 0;
}

static void vstgc_forget_cached_vi(const struct silofs_vstage_ctx *vstg_ctx,
                                   struct silofs_vnode_info *vi)
{
	if (vi != NULL) {
		silofs_cache_forget_vi(vstgc_cache(vstg_ctx), vi);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_flush_dirty_now(const struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = silofs_flush_dirty_now(vstg_ctx->task);
	if (err) {
		log_dbg("flush dirty failed: err=%d", err);
	}
	return err;
}

static void vstgc_relax_caches_now(const struct silofs_vstage_ctx *vstg_ctx)
{
	silofs_fsenv_relax_caches(vstg_ctx->fsenv, SILOFS_F_NOW);
}

static int
vstgc_try_evict_some(const struct silofs_vstage_ctx *vstg_ctx,
                     bool flush_dirty)
{
	int err;

	if (flush_dirty) {
		err = vstgc_flush_dirty_now(vstg_ctx);
		if (err) {
			vstgc_log_cache_stat(vstg_ctx);
			return err;
		}
	}
	vstgc_relax_caches_now(vstg_ctx);
	return 0;
}

static int vstgc_do_spawn_vi(const struct silofs_vstage_ctx *vstg_ctx,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_vnode_info **out_vi)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = vstgc_create_cached_vi(vstg_ctx, vaddr, out_vi);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_do_stage_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_lsegid *lsegid)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_stage_lseg(vstg_ctx->fsenv, lsegid);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_do_stage_lseg_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  const struct silofs_laddr *laddr)
{
	return vstgc_do_stage_lseg(vstg_ctx, &laddr->lsegid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_spawn_vi_at(const struct silofs_vstage_ctx *vstg_ctx,
                             const struct silofs_llink *llink,
                             struct silofs_vnode_info **out_vi)
{
	int err;

	err = vstgc_do_spawn_vi(vstg_ctx, vstg_ctx->vaddr, out_vi);
	if (err) {
		return err;
	}
	vi_bind_to(*out_vi, vstg_ctx->fsenv);
	vi_update_llink(*out_vi, llink);
	return err;
}

static int vstgc_restore_view_of(const struct silofs_vstage_ctx *vstg_ctx,
                                 struct silofs_vnode_info *vi)
{
	int err;
	bool raw;

	raw = (vstg_ctx->stg_mode & SILOFS_STG_RAW) > 0;
	if (raw) {
		return 0; /* no-op */
	}
	err = silofs_refresh_llink(vstg_ctx->task, vi);
	if (err) {
		return err;
	}
	err = silofs_decrypt_vi_view(vstg_ctx->fsenv, vi);
	if (err) {
		return err;
	}
	err = silofs_vi_verify_view(vi);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
                                const struct silofs_laddr *laddr)
{
	return silofs_sbi_ismutable_lsegid(sbi, &laddr->lsegid);
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

static enum silofs_ltype sni_child_ltype(const struct silofs_spnode_info *sni)
{
	enum silofs_ltype ltype;
	const enum silofs_height height = silofs_sni_height(sni);

	switch (height) {
	case SILOFS_HEIGHT_BOOT:
		ltype = SILOFS_LTYPE_SUPER;
		break;
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE2:
		ltype = SILOFS_LTYPE_SPNODE;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		ltype = SILOFS_LTYPE_SPLEAF;
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		ltype = SILOFS_LTYPE_NONE;
		break;
	}
	return ltype;
}

static
enum silofs_height sni_child_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void vstgc_setup(struct silofs_vstage_ctx *vstg_ctx,
                        struct silofs_task *task,
                        const struct silofs_vaddr *vaddr,
                        enum silofs_stg_mode stg_mode)
{
	memset(vstg_ctx, 0, sizeof(*vstg_ctx));
	vstg_ctx->task = task;
	vstg_ctx->fsenv = task->t_fsenv;
	vstg_ctx->sbi = task->t_fsenv->fse_sbi;
	vstg_ctx->vaddr = vaddr;
	vstg_ctx->stg_mode = stg_mode;
	vstg_ctx->vspace = vaddr->ltype;
	vstg_ctx->voff = vaddr->off;
	vstg_ctx->retry = 3;
}

static int vstgc_do_spawn_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_lsegid *lsegid)
{
	return silofs_spawn_lseg(vstg_ctx->fsenv, lsegid);
}

static int vstgc_spawn_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_lsegid *lsegid,
                            enum silofs_ltype ltype_sub)
{
	int err;

	err = vstgc_do_spawn_lseg(vstg_ctx, lsegid);
	if (!err) {
		silofs_sti_update_lsegs(&vstg_ctx->sbi->sb_sti, ltype_sub, 1);
	}
	return err;
}

static void
vstgc_make_lsegid_of_spmaps(const struct silofs_vstage_ctx *vstg_ctx,
                            loff_t voff, enum silofs_height height,
                            struct silofs_lsegid *out_lsegid)
{
	struct silofs_lvid lvid;
	const enum silofs_ltype vspace = vstg_ctx->vspace;

	silofs_sbi_get_lvid(vstg_ctx->sbi, &lvid);
	silofs_lsegid_setup(out_lsegid, &lvid, voff, vspace, height);
}

static void
vstgc_make_lsegid_of_vdata(const struct silofs_vstage_ctx *vstg_ctx,
                           loff_t voff, struct silofs_lsegid *out_lsegid)
{
	struct silofs_lvid lvid;

	silofs_sbi_get_lvid(vstg_ctx->sbi, &lvid);
	silofs_lsegid_setup(out_lsegid, &lvid, voff,
	                    vstg_ctx->vspace, SILOFS_HEIGHT_VDATA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_update_space_stats(const struct silofs_vstage_ctx *vstg_ctx,
                                     const struct silofs_uaddr *uaddr)
{
	silofs_sti_update_objs(&vstg_ctx->sbi->sb_sti, uaddr->ltype, 1);
	silofs_sti_update_bks(&vstg_ctx->sbi->sb_sti, uaddr->ltype, 1);
}

static int vstgc_spawn_super_main_lseg(const struct silofs_vstage_ctx
                                       *vstg_ctx)
{
	struct silofs_lsegid lsegid;
	const enum silofs_height height = SILOFS_HEIGHT_SUPER - 1;
	int err;

	vstgc_make_lsegid_of_spmaps(vstg_ctx, 0, height, &lsegid);
	err = vstgc_spawn_lseg(vstg_ctx, &lsegid, SILOFS_LTYPE_SPNODE);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_lseg(vstg_ctx->sbi, vstg_ctx->vspace, &lsegid);
	return 0;
}

static int vstgc_stage_super_main_lseg(const struct silofs_vstage_ctx
                                       *vstg_ctx)
{
	struct silofs_lsegid lsegid;

	silofs_sbi_main_lseg(vstg_ctx->sbi, vstg_ctx->vspace, &lsegid);
	return vstgc_do_stage_lseg(vstg_ctx, &lsegid);
}

static int vstgc_require_super_main_lseg(const struct silofs_vstage_ctx
                *vstg_ctx)
{
	int err;

	if (silofs_sbi_has_main_lseg(vstg_ctx->sbi, vstg_ctx->vspace)) {
		err = vstgc_stage_super_main_lseg(vstg_ctx);
	} else {
		err = vstgc_spawn_super_main_lseg(vstg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_spawn_spnode_main_lseg(const struct silofs_vstage_ctx
                                        *vstg_ctx,
                                        struct silofs_spnode_info *sni)
{
	struct silofs_lsegid lsegid;
	const loff_t voff = sni_base_voff(sni);
	const enum silofs_height height = sni_child_height(sni);
	const enum silofs_ltype ltype = sni_child_ltype(sni);
	int err;

	vstgc_make_lsegid_of_spmaps(vstg_ctx, voff, height, &lsegid);
	err = vstgc_spawn_lseg(vstg_ctx, &lsegid, ltype);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_lseg(sni, &lsegid);
	return 0;
}

static int vstgc_stage_spnode_main_lseg(const struct silofs_vstage_ctx
                                        *vstg_ctx,
                                        struct silofs_spnode_info *sni)
{
	struct silofs_lsegid lsegid;

	silofs_sni_main_lseg(sni, &lsegid);
	return vstgc_do_stage_lseg(vstg_ctx, &lsegid);
}

static int
vstgc_require_spnode_main_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info *sni)
{
	int err;

	if (sni_has_main_lseg(sni)) {
		err = vstgc_stage_spnode_main_lseg(vstg_ctx, sni);
	} else {
		err = vstgc_spawn_spnode_main_lseg(vstg_ctx, sni);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_inspect_laddr(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_laddr *laddr)
{
	if (stage_normal(vstg_ctx->stg_mode)) {
		return 0;
	}
	if (sbi_ismutable_laddr(vstg_ctx->sbi, laddr)) {
		return 0;
	}
	return -SILOFS_EPERM; /* address on read-only tree */
}

static int vstgc_inspect_llink(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_llink *llink)
{
	return vstgc_inspect_laddr(vstg_ctx, &llink->laddr);
}

static int vstgc_inspect_cached_ui(const struct silofs_vstage_ctx *vstg_ctx,
                                   const struct silofs_unode_info *ui)
{
	return vstgc_inspect_laddr(vstg_ctx, ui_laddr(ui));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void vstgc_increfs(const struct silofs_vstage_ctx *vstg_ctx,
                          enum silofs_height height_upto)
{
	if (height_upto <= SILOFS_HEIGHT_SUPER) {
		sbi_incref(vstg_ctx->sbi);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE4) {
		sni_incref(vstg_ctx->sni4);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE3) {
		sni_incref(vstg_ctx->sni3);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE2) {
		sni_incref(vstg_ctx->sni2);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE1) {
		sni_incref(vstg_ctx->sni1);
	}
	if (height_upto <= SILOFS_HEIGHT_SPLEAF) {
		sli_incref(vstg_ctx->sli);
	}
}

static void vstgc_decrefs(const struct silofs_vstage_ctx *vstg_ctx,
                          enum silofs_height height_from)
{
	if (height_from <= SILOFS_HEIGHT_SPLEAF) {
		sli_decref(vstg_ctx->sli);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE1) {
		sni_decref(vstg_ctx->sni1);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE2) {
		sni_decref(vstg_ctx->sni2);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE3) {
		sni_decref(vstg_ctx->sni3);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE4) {
		sni_decref(vstg_ctx->sni4);
	}
	if (height_from <= SILOFS_HEIGHT_SUPER) {
		sbi_decref(vstg_ctx->sbi);
	}
}

static loff_t vstgc_lbk_voff(const struct silofs_vstage_ctx *vstg_ctx)
{
	return off_align_to_lbk(vstg_ctx->voff);
}

static int vstgc_find_cached_unode(const struct silofs_vstage_ctx *vstg_ctx,
                                   enum silofs_height height,
                                   struct silofs_unode_info **out_ui)
{
	struct silofs_uakey uakey;
	struct silofs_vrange vrange;

	silofs_vrange_of_spmap(&vrange, height, vstgc_lbk_voff(vstg_ctx));
	silofs_uakey_setup_by2(&uakey, &vrange, vstg_ctx->vspace);
	*out_ui = silofs_cache_find_ui_by(vstgc_cache(vstg_ctx), &uakey);
	return (*out_ui != NULL) ? 0 : -SILOFS_ENOENT;
}

static int vstgc_fetch_cached_spnode(const struct silofs_vstage_ctx *vstg_ctx,
                                     enum silofs_height height,
                                     struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = vstgc_find_cached_unode(vstg_ctx, height, &ui);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_ui(vstg_ctx, ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	return 0;
}

static int vstgc_fetch_cached_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                                     struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = vstgc_find_cached_unode(vstg_ctx, SILOFS_HEIGHT_SPLEAF, &ui);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_ui(vstg_ctx, ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	return 0;
}

static int vstgc_inspect_cached_spnode(const struct silofs_vstage_ctx
                                       *vstg_ctx,
                                       const struct silofs_spnode_info *sni)
{
	return sbi_inspect_cached_sni(vstg_ctx->sbi, sni, vstg_ctx->stg_mode);
}

static int vstgc_inspect_cached_spleaf(const struct silofs_vstage_ctx
                                       *vstg_ctx,
                                       const struct silofs_spleaf_info *sli)
{
	return sbi_inspect_cached_sli(vstg_ctx->sbi, sli, vstg_ctx->stg_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_resolve_spnode_child(const struct silofs_vstage_ctx *vstg_ctx,
                                      const struct silofs_spnode_info *sni,
                                      struct silofs_ulink *out_ulink)
{
	const loff_t lbk_voff = vstgc_lbk_voff(vstg_ctx);

	return silofs_sni_resolve_child(sni, lbk_voff, out_ulink);
}

static int vstgc_resolve_spleaf_child(const struct silofs_vstage_ctx *vstg_ctx,
                                      const struct silofs_spleaf_info *sli,
                                      struct silofs_llink *out_llink)
{
	const loff_t lbk_voff = vstgc_lbk_voff(vstg_ctx);

	return silofs_sli_resolve_child(sli, lbk_voff, out_llink);
}

static int vstgc_do_stage_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_ulink *ulink,
                                    struct silofs_spnode_info **out_sni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_stage_spnode(vstg_ctx->fsenv, ulink, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_stage_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_ulink *ulink,
                                 struct silofs_spnode_info **out_sni)
{
	return vstgc_do_stage_spnode_at(vstg_ctx, ulink, out_sni);
}

static int vstgc_do_spawn_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_ulink *ulink,
                                    struct silofs_spnode_info **out_sni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_spawn_spnode(vstg_ctx->fsenv, ulink, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_spawn_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_ulink *ulink,
                                 struct silofs_spnode_info **out_sni)
{
	return vstgc_do_spawn_spnode_at(vstg_ctx, ulink, out_sni);
}

static int vstgc_do_stage_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_ulink *ulink,
                                    struct silofs_spleaf_info **out_sli)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_stage_spleaf(vstg_ctx->fsenv, ulink, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_stage_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_ulink *ulink,
                                 struct silofs_spleaf_info **out_sli)
{
	return vstgc_do_stage_spleaf_at(vstg_ctx, ulink, out_sli);
}

static int vstgc_do_spawn_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_ulink *ulink,
                                    struct silofs_spleaf_info **out_sli)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_spawn_spleaf(vstg_ctx->fsenv, ulink, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_spawn_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_ulink *ulink,
                                 struct silofs_spleaf_info **out_sli)
{
	return vstgc_do_spawn_spleaf_at(vstg_ctx, ulink, out_sli);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int vstgc_check_may_rdwr(const struct silofs_vstage_ctx *vstg_ctx)
{
	return stage_cow(vstg_ctx->stg_mode) ? 0 : -SILOFS_EPERM;
}

static int vstgc_check_may_clone(const struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_check_may_rdwr(vstg_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_setup_spawned_spnode4(const struct silofs_vstage_ctx
                                        *vstg_ctx,
                                        struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sbi_uaddr(vstg_ctx->sbi),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode4_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_require_super_main_lseg(vstg_ctx);
	if (err) {
		return err;
	}
	silofs_sbi_resolve_main_at(vstg_ctx->sbi, vstg_ctx->voff,
	                           vstg_ctx->vspace, &ulink);

	err = vstgc_spawn_spnode_at(vstg_ctx, &ulink, out_sni);
	if (err) {
		return err;
	}
	vstgc_setup_spawned_spnode4(vstg_ctx, *out_sni);
	return 0;
}

static int vstgc_spawn_spnode4(const struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode4_of(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	vstgc_update_space_stats(vstg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int vstgc_do_clone_spnode4(struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode4(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, vstg_ctx->sni4);
	sbi_bind_child_spnode(vstg_ctx->sbi, vstg_ctx->vspace, *out_sni);
	return 0;
}

static int vstgc_clone_spnode4(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = vstgc_do_clone_spnode4(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE4);
	*out_sni = sni;
	return err;
}

static int
vstgc_inspect_cached_spnode4(const struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni4);
}

static int vstgc_do_stage_spnode4(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = silofs_sbi_resolve_child(vstg_ctx->sbi,
	                               vstg_ctx->vspace, &ulink);
	if (err) {
		return -SILOFS_EFSCORRUPTED;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &ulink, &vstg_ctx->sni4);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_spnode4(vstg_ctx);
	if (!err) {
		return 0;
	}
	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_clone_spnode4(vstg_ctx, &vstg_ctx->sni4);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_stage_spnode4(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SUPER);
	err = vstgc_do_stage_spnode4(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SUPER);
	return err;
}

static int vstgc_fetch_cached_spnode4(struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_fetch_cached_spnode(vstg_ctx, SILOFS_HEIGHT_SPNODE4,
	                                 &vstg_ctx->sni4);
}

static int vstgc_stage_spnode4_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode4(vstg_ctx);
	if (err) {
		err = vstgc_stage_spnode4(vstg_ctx);
	}
	return err;
}

static int vstgc_spawn_bind_spnode4(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_spawn_spnode4(vstg_ctx, &vstg_ctx->sni4);
	if (err) {
		return err;
	}
	sbi_bind_child_spnode(vstg_ctx->sbi, vstg_ctx->vspace, vstg_ctx->sni4);
	return 0;
}

static bool vstgc_has_spnode4_child_at(const struct silofs_vstage_ctx
                                       *vstg_ctx)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_sproot_of(vstg_ctx->sbi, vstg_ctx->vspace, &uaddr);
	return !err;
}

static int vstgc_do_require_spnode4(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	if (vstgc_has_spnode4_child_at(vstg_ctx)) {
		err = vstgc_stage_spnode4_of(vstg_ctx);
	} else {
		err = vstgc_spawn_bind_spnode4(vstg_ctx);
	}
	return err;
}

static int vstgc_require_spnode4(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SUPER);
	err = vstgc_do_require_spnode4(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SUPER);
	return err;
}

static int vstgc_require_spnode4_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode4(vstg_ctx);
	if (err) {
		err = vstgc_require_spnode4(vstg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_setup_spawned_spnode3(const struct silofs_vstage_ctx
                                        *vstg_ctx,
                                        struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(vstg_ctx->sni4),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode3_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni4);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni4,
	                        vstgc_lbk_voff(vstg_ctx), &ulink);

	err = vstgc_spawn_spnode_at(vstg_ctx, &ulink, out_sni);
	if (err) {
		return err;
	}
	vstgc_setup_spawned_spnode3(vstg_ctx, *out_sni);
	return 0;
}

static int vstgc_spawn_spnode3(const struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode3_of(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	vstgc_update_space_stats(vstg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int vstgc_do_clone_spnode3(struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode3(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, vstg_ctx->sni3);
	sni_bind_child_spnode(vstg_ctx->sni4, *out_sni);
	return 0;
}

static int vstgc_clone_spnode3(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = vstgc_do_clone_spnode3(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	*out_sni = sni;
	return err;
}

static int vstgc_inspect_cached_spnode3(const struct silofs_vstage_ctx
                                        *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni3);
}

static int vstgc_do_stage_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni4, &ulink);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &ulink, &vstg_ctx->sni3);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_spnode3(vstg_ctx);
	if (!err) {
		return 0;
	}
	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_clone_spnode3(vstg_ctx, &vstg_ctx->sni3);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_stage_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = vstgc_do_stage_spnode3(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE4);
	return err;
}

static int vstgc_fetch_cached_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_fetch_cached_spnode(vstg_ctx, SILOFS_HEIGHT_SPNODE3,
	                                 &vstg_ctx->sni3);
}

static int vstgc_stage_spnode3_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode3(vstg_ctx);
	if (err) {
		err = vstgc_stage_spnode3(vstg_ctx);
	}
	return err;
}

static int vstgc_spawn_bind_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_spawn_spnode3(vstg_ctx, &vstg_ctx->sni3);
	if (err) {
		return err;
	}
	sni_bind_child_spnode(vstg_ctx->sni4, vstg_ctx->sni3);
	return 0;
}

static bool vstgc_has_spnode3_child_at(const struct silofs_vstage_ctx
                                       *vstg_ctx)
{
	return sni_has_child_at(vstg_ctx->sni4, vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_do_require_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	if (vstgc_has_spnode3_child_at(vstg_ctx)) {
		err = vstgc_stage_spnode3_of(vstg_ctx);
	} else {
		err = vstgc_spawn_bind_spnode3(vstg_ctx);
	}
	return err;
}

static int vstgc_require_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE4);
	err = vstgc_do_require_spnode3(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE4);
	return err;
}

static int vstgc_require_spnode3_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode3(vstg_ctx);
	if (err) {
		err = vstgc_require_spnode3(vstg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
vstgc_setup_spawned_spnode2(const struct silofs_vstage_ctx *vstg_ctx,
                            struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(vstg_ctx->sni3),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode2_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni3);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni3,
	                        vstgc_lbk_voff(vstg_ctx), &ulink);

	err = vstgc_spawn_spnode_at(vstg_ctx, &ulink, out_sni);
	if (err) {
		return err;
	}
	vstgc_setup_spawned_spnode2(vstg_ctx, *out_sni);
	return 0;
}

static int vstgc_spawn_spnode2(const struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode2_of(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	vstgc_update_space_stats(vstg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int vstgc_do_clone_spnode2(struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode2(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, vstg_ctx->sni2);
	sni_bind_child_spnode(vstg_ctx->sni3, *out_sni);
	return 0;
}

static int vstgc_clone_spnode2(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = vstgc_do_clone_spnode2(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	*out_sni = sni;
	return err;
}

static int vstgc_inspect_cached_spnode2(const struct silofs_vstage_ctx
                                        *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni2);
}

static int vstgc_do_stage_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni3, &ulink);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &ulink, &vstg_ctx->sni2);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_spnode2(vstg_ctx);
	if (!err) {
		return 0;
	}
	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_clone_spnode2(vstg_ctx, &vstg_ctx->sni2);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_stage_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = vstgc_do_stage_spnode2(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	return err;
}

static int vstgc_fetch_cached_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_fetch_cached_spnode(vstg_ctx, SILOFS_HEIGHT_SPNODE2,
	                                 &vstg_ctx->sni2);
}

static int vstgc_stage_spnode2_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode2(vstg_ctx);
	if (err) {
		err = vstgc_stage_spnode2(vstg_ctx);
	}
	return err;
}

static int vstgc_spawn_bind_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_spawn_spnode2(vstg_ctx, &vstg_ctx->sni2);
	if (err) {
		return err;
	}
	sni_bind_child_spnode(vstg_ctx->sni3, vstg_ctx->sni2);
	return 0;
}

static bool vstgc_has_spnode2_child_at(const struct silofs_vstage_ctx
                                       *vstg_ctx)
{
	return sni_has_child_at(vstg_ctx->sni3, vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_do_require_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	if (vstgc_has_spnode2_child_at(vstg_ctx)) {
		err = vstgc_stage_spnode2_of(vstg_ctx);
	} else {
		err = vstgc_spawn_bind_spnode2(vstg_ctx);
	}
	return err;
}

static int vstgc_require_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = vstgc_do_require_spnode2(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	return err;
}

static int vstgc_require_spnode2_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode2(vstg_ctx);
	if (err) {
		err = vstgc_require_spnode2(vstg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_setup_spawned_spnode1(const struct silofs_vstage_ctx
                                        *vstg_ctx,
                                        struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sni_uaddr(vstg_ctx->sni2),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode1_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni2);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni2,
	                        vstgc_lbk_voff(vstg_ctx), &ulink);

	err = vstgc_spawn_spnode_at(vstg_ctx, &ulink, out_sni);
	if (err) {
		return err;
	}
	vstgc_setup_spawned_spnode1(vstg_ctx, *out_sni);
	return 0;
}

static int vstgc_spawn_spnode1(const struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode1_of(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	vstgc_update_space_stats(vstg_ctx, sni_uaddr(*out_sni));
	return 0;
}

static int vstgc_do_clone_spnode1(struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	int err;

	err = vstgc_spawn_spnode1(vstg_ctx, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_clone_from(*out_sni, vstg_ctx->sni1);
	sni_bind_child_spnode(vstg_ctx->sni2, *out_sni);
	return 0;
}

static int vstgc_clone_spnode1(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = vstgc_do_clone_spnode1(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	*out_sni = sni;
	return err;
}

static int vstgc_inspect_cached_spnode1(const struct silofs_vstage_ctx
                                        *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni1);
}

static int vstgc_do_stage_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni2, &ulink);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &ulink, &vstg_ctx->sni1);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_spnode1(vstg_ctx);
	if (!err) {
		return 0;
	}
	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_clone_spnode1(vstg_ctx, &vstg_ctx->sni1);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_stage_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = vstgc_do_stage_spnode1(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	return err;
}

static int vstgc_fetch_cached_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_fetch_cached_spnode(vstg_ctx, SILOFS_HEIGHT_SPNODE1,
	                                 &vstg_ctx->sni1);
}

static int vstgc_spawn_bind_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_spawn_spnode1(vstg_ctx, &vstg_ctx->sni1);
	if (err) {
		return err;
	}
	sni_bind_child_spnode(vstg_ctx->sni2, vstg_ctx->sni1);
	return 0;
}

static bool vstgc_has_spnode1_child_at(const struct silofs_vstage_ctx
                                       *vstg_ctx)
{
	return sni_has_child_at(vstg_ctx->sni2, vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_stage_spnode1_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode1(vstg_ctx);
	if (err) {
		err = vstgc_stage_spnode1(vstg_ctx);
	}
	return err;
}

static int vstgc_do_require_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	if (vstgc_has_spnode1_child_at(vstg_ctx)) {
		err = vstgc_stage_spnode1(vstg_ctx);
	} else {
		err = vstgc_spawn_bind_spnode1(vstg_ctx);
	}
	return err;
}

static int vstgc_require_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = vstgc_do_require_spnode1(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	return err;
}

static int vstgc_require_spnode1_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spnode1(vstg_ctx);
	if (err) {
		err = vstgc_require_spnode1(vstg_ctx);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_setup_spawned_spleaf(const struct silofs_vstage_ctx
                                       *vstg_ctx,
                                       struct silofs_spleaf_info *sli)
{
	silofs_sli_setup_spawned(sli, sni_uaddr(vstg_ctx->sni1),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spleaf_of(const struct silofs_vstage_ctx *vstg_ctx,
                                 struct silofs_spleaf_info **out_sli)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni1);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni1,
	                        vstgc_lbk_voff(vstg_ctx), &ulink);

	err = vstgc_spawn_spleaf_at(vstg_ctx, &ulink, out_sli);
	if (err) {
		return err;
	}
	vstgc_setup_spawned_spleaf(vstg_ctx, *out_sli);
	return 0;
}

static int
vstgc_require_spleaf_main_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_spleaf_info *sli)
{
	struct silofs_lsegid lsegid;
	int err;

	silofs_sli_main_lseg(sli, &lsegid);
	if (!lsegid_isnull(&lsegid)) {
		return vstgc_do_stage_lseg(vstg_ctx, &lsegid);
	}
	/*
	 * TODO-0047: Do not use underlying repo to detect if vdata-lseg exists
	 */
	vstgc_make_lsegid_of_vdata(vstg_ctx, sli_base_voff(sli), &lsegid);
	err = vstgc_do_stage_lseg(vstg_ctx, &lsegid);
	if (!err) {
		goto out_ok;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = vstgc_spawn_lseg(vstg_ctx, &lsegid, vstg_ctx->vspace);
	if (err) {
		return err;
	}
out_ok:
	silofs_sli_bind_main_lseg(sli, &lsegid);
	return 0;
}

static int vstgc_spawn_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                              struct silofs_spleaf_info **out_sli)
{
	int err;

	err = vstgc_spawn_spleaf_of(vstg_ctx, out_sli);
	if (err) {
		return err;
	}
	err = vstgc_require_spleaf_main_lseg(vstg_ctx, *out_sli);
	if (err) {
		return err;
	}
	vstgc_update_space_stats(vstg_ctx, sli_uaddr(*out_sli));
	return 0;
}

static int vstgc_do_clone_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                                 struct silofs_spleaf_info **out_sli)
{
	int err;

	err = vstgc_spawn_spleaf(vstg_ctx, out_sli);
	if (err) {
		return err;
	}
	silofs_sli_clone_from(*out_sli, vstg_ctx->sli);
	sni_bind_child_spleaf(vstg_ctx->sni1, *out_sli);
	return 0;
}

static int vstgc_clone_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                              struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = vstgc_do_clone_spleaf(vstg_ctx, &sli);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	*out_sli = sli;
	return err;
}

static int vstgc_do_stage_spleaf(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni1, &ulink);
	if (err) {
		return err;
	}
	err = vstgc_stage_spleaf_at(vstg_ctx, &ulink, &vstg_ctx->sli);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_spleaf(vstg_ctx, vstg_ctx->sli);
	if (!err) {
		return 0;
	}
	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_clone_spleaf(vstg_ctx, &vstg_ctx->sli);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_stage_spleaf(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = vstgc_do_stage_spleaf(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	return err;
}

static int vstgc_fetch_cached_spleaf1(struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_fetch_cached_spleaf(vstg_ctx, &vstg_ctx->sli);
}

static int vstgc_stage_spleaf_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_fetch_cached_spleaf1(vstg_ctx);
	if (err) {
		err = vstgc_stage_spleaf(vstg_ctx);
	}
	return err;
}

/*
 * Upon new space leaf, add the entire space range at once. Ignores possible
 * out-of-memory failure.
 */
static struct silofs_spamaps *
vstgc_spamaps(const struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_cache *cache = vstgc_cache(vstg_ctx);

	return &cache->c_spams;
}

static void vstgc_track_spawned_spleaf(const struct silofs_vstage_ctx
                                       *vstg_ctx,
                                       const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	struct silofs_spamaps *spam = vstgc_spamaps(vstg_ctx);

	sli_vrange(sli, &vrange);
	silofs_spamaps_store(spam, vstg_ctx->vspace, vrange.beg, vrange.len);
}

static int vstgc_spawn_bind_spleaf_at(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = vstgc_spawn_spleaf(vstg_ctx, &sli);
	if (err) {
		return err;
	}
	sni_bind_child_spleaf(vstg_ctx->sni1, sli);
	vstgc_track_spawned_spleaf(vstg_ctx, sli);
	vstg_ctx->sli = sli;
	return 0;
}

static bool vstgc_has_spleaf_child_at(const struct silofs_vstage_ctx *vstg_ctx)
{
	return sni_has_child_at(vstg_ctx->sni1, vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_do_require_spleaf(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	if (vstgc_has_spleaf_child_at(vstg_ctx)) {
		err = vstgc_stage_spleaf_of(vstg_ctx);
	} else {
		err = vstgc_spawn_bind_spleaf_at(vstg_ctx);
	}
	return err;
}

static int vstgc_require_spleaf(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = vstgc_do_require_spleaf(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_stage_spnodes_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_stage_spnode4_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode3_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode2_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode1_of(vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_require_spnodes_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_require_spnode4_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_spnode3_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_spnode2_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_spnode1_of(vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_stage_spmaps_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_stage_spnodes_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_stage_spleaf_of(vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_resolve_llink_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_llink *out_llink)
{
	struct silofs_llink llink_lbk;
	struct silofs_laddr laddr;
	int err;

	err = vstgc_resolve_spleaf_child(vstg_ctx, vstg_ctx->sli, &llink_lbk);
	if (err) {
		return err;
	}
	silofs_laddr_setup(&laddr, &llink_lbk.laddr.lsegid,
	                   vstg_ctx->vaddr->off, vstg_ctx->vaddr->len);
	silofs_llink_setup(out_llink, &laddr, &llink_lbk.riv);
	return 0;
}

static int vstgc_stage_spleaf_for_resolve(struct silofs_vstage_ctx *vstg_ctx)
{
	int ret;

	ret = vstgc_fetch_cached_spleaf1(vstg_ctx);
	if (ret != 0) {
		ret = vstgc_stage_spmaps_of(vstg_ctx);
	}
	return ret;
}

static int vstgc_resolve_llink(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_llink *out_llink)
{
	int err;

	err = vstgc_stage_spleaf_for_resolve(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_resolve_llink_of(vstg_ctx, out_llink);
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
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	err = vstgc_stage_spnodes_of(&vstg_ctx);
	if (err) {
		return err;
	}
	*out_sni = vstg_ctx.sni1;
	return 0;
}

int silofs_stage_spmaps_of(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spnode_info **out_sni,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	err = vstgc_stage_spmaps_of(&vstg_ctx);
	if (err) {
		return err;
	}
	*out_sni = vstg_ctx.sni1;
	*out_sli = vstg_ctx.sli;
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
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	err = vstgc_check_may_rdwr(&vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_spnodes_of(&vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_spleaf(&vstg_ctx);
	if (err) {
		return err;
	}
	*out_sni = vstg_ctx.sni1;
	*out_sli = vstg_ctx.sli;
	return 0;
}

static int vstgc_require_stable_vaddr(const struct silofs_vstage_ctx *vstg_ctx)
{
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	bool allocated;

	allocated = silofs_sli_has_allocated_space(vstg_ctx->sli, vaddr);
	if (likely(allocated)) {
		return 0;
	}
	log_err("unstable: off=0x%lx ltype=%d", vaddr->off, vaddr->ltype);
	return -SILOFS_EFSCORRUPTED;
}

static int require_stable_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, SILOFS_STG_CUR | SILOFS_STG_RAW);
	err = vstgc_stage_spmaps_of(&vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_stable_vaddr(&vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_check_stable_vaddr(const struct silofs_vstage_ctx *vstg_ctx)
{
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	bool allocated;

	allocated = silofs_sli_has_allocated_space(vstg_ctx->sli, vaddr);
	return likely(allocated) ? 0 : -SILOFS_ENOENT;
}

static int check_stable_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, SILOFS_STG_CUR | SILOFS_STG_RAW);
	err = vstgc_stage_spmaps_of(&vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_check_stable_vaddr(&vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int vstgc_load_view_at(const struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *laddr,
                              struct silofs_view *view)
{
	struct silofs_repo *repo = vstg_ctx->fsenv->fse.repo;
	int ret = 0;
	bool raw;

	raw = (vstg_ctx->stg_mode & SILOFS_STG_RAW) > 0;
	if (!raw) {
		ret = silofs_repo_read_at(repo, laddr, view);
	}
	return ret;
}

static int vstgc_require_laddr(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_laddr *laddr)
{
	return silofs_repo_require_laddr(vstg_ctx->fsenv->fse.repo, laddr);
}

static int vstgc_do_require_lseg_of(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_laddr *laddr)
{
	int err;

	err = vstgc_require_laddr(vstg_ctx, laddr);
	if (err) {
		return err;
	}
	err = vstgc_do_stage_lseg(vstg_ctx, &laddr->lsegid);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_stage_load_view(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_laddr *laddr,
                                 struct silofs_view *view)
{
	int err;

	silofs_assert_not_null(view);

	err = vstgc_require_laddr(vstg_ctx, laddr);
	if (err) {
		return err;
	}
	err = vstgc_do_stage_lseg(vstg_ctx, &laddr->lsegid);
	if (err) {
		return err;
	}
	err = vstgc_load_view_at(vstg_ctx, laddr, view);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_require_lbks(const struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *laddr_src,
                              const struct silofs_laddr *laddr_dst)
{
	int ret;

	ret = vstgc_do_stage_lseg_of(vstg_ctx, laddr_src);
	if (ret) {
		goto out;
	}
	ret = vstgc_do_stage_lseg_of(vstg_ctx, laddr_dst);
	if (ret) {
		goto out;
	}
	ret = vstgc_require_laddr(vstg_ctx, laddr_src);
	if (ret) {
		goto out;
	}
	ret = vstgc_require_laddr(vstg_ctx, laddr_dst);
	if (ret) {
		goto out;
	}
out:
	return ((ret == -ENOENT) || (ret == -SILOFS_ENOENT)) ?
	       -SILOFS_EFSCORRUPTED : ret;
}

static int vstgc_require_clone_lbk(const struct silofs_vstage_ctx *vstg_ctx,
                                   struct silofs_llink *out_llink_dst)
{
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	int err;

	err = vstgc_require_spleaf_main_lseg(vstg_ctx, vstg_ctx->sli);
	if (err) {
		return err;
	}
	silofs_sli_resolve_main_lbk(vstg_ctx->sli, vaddr->off, out_llink_dst);
	return 0;
}

static int vstgc_clone_rebind_lbk(const struct silofs_vstage_ctx *vstg_ctx,
                                  const struct silofs_laddr *src_laddr)
{
	struct silofs_llink dst_llink;
	int err;

	err = vstgc_require_clone_lbk(vstg_ctx, &dst_llink);
	if (err) {
		return err;
	}
	err = vstgc_require_lbks(vstg_ctx, src_laddr, &dst_llink.laddr);
	if (err) {
		return err;
	}
	silofs_sli_bind_child(vstg_ctx->sli, vstg_ctx->vaddr->off, &dst_llink);
	return 0;
}

static int vstgc_require_lseg_of(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_laddr *laddr)
{
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	int ret = 0;

	if (!ltype_isdata(vaddr->ltype)) {
		ret = vstgc_do_require_lseg_of(vstg_ctx, laddr);
		silofs_assert_ne(ret, -SILOFS_ERDONLY);
	}
	return ret;
}

static int
vstgc_pre_clone_stage_inode_at(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vnode_info **out_vi)
{
	struct silofs_inode_info *ii = NULL;
	ino_t ino;
	int err;

	*out_vi = NULL;
	ino = vaddr_to_ino(vaddr);
	err = silofs_stage_inode(vstg_ctx->task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		return err;
	}
	*out_vi = &ii->i_vi;
	return 0;
}

static int
vstgc_pre_clone_stage_vnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	*out_vi = NULL;
	err = silofs_stage_vnode(vstg_ctx->task, NULL, vaddr,
	                         SILOFS_STG_CUR, &vi);
	if (err) {
		silofs_assert_ne(err, -SILOFS_ERDONLY);
		return err;
	}
	*out_vi = vi;
	return 0;
}

static bool vstgc_has_vaddr(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_vaddr *vaddr)
{
	return vaddr_isequal(vstg_ctx->vaddr, vaddr);
}

static int vstgc_pre_clone_stage_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_vnode_info **out_vi)
{
	const int raw = (vstg_ctx->stg_mode & SILOFS_STG_RAW) > 0;
	int ret = 0;

	if (vaddr->off == 0) {
		/* ignore off=0 which is allocated-as-numb once upon format */
		*out_vi = NULL;
	} else if (vstgc_has_vaddr(vstg_ctx, vaddr) &&
	           (raw || vaddr_isdatabk(vaddr))) {
		/* ignore current data-block */
		*out_vi = NULL;
	} else if (vaddr_isinode(vaddr)) {
		/* inode case */
		ret = vstgc_pre_clone_stage_inode_at(vstg_ctx, vaddr, out_vi);
	} else {
		/* normal case */
		ret = vstgc_pre_clone_stage_vnode_at(vstg_ctx, vaddr, out_vi);
	}
	return ret;
}

static int vstgc_do_pre_clone_vblock(struct silofs_vstage_ctx *vstg_ctx,
                                     struct silofs_vis *vis)
{
	struct silofs_vnode_info *vi = NULL;
	const struct silofs_vaddr *vaddrj = NULL;
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	const silofs_lba_t lba = off_to_lba(vaddr->off);
	int err;

	STATICASSERT_EQ(ARRAY_SIZE(vis->vis), ARRAY_SIZE(vis->vas.vaddr));

	silofs_sli_vaddrs_at(vstg_ctx->sli, vaddr->ltype, lba, &vis->vas);
	for (size_t j = 0; j < vis->vas.count; ++j) {
		vaddrj = &vis->vas.vaddr[j];
		err = vstgc_pre_clone_stage_at(vstg_ctx, vaddrj, &vi);
		if (err) {
			return err;
		}
		vi_incref(vi);
		vis->vis[j] = vi;
	}
	return 0;
}

static int vstgc_pre_clone_lbk(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_vis *vis)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = vstgc_do_pre_clone_vblock(vstg_ctx, vis);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
}

static void vstgc_post_clone_lbk(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_vis *vis)
{
	struct silofs_vnode_info *vi = NULL;

	for (size_t i = 0; i < vis->vas.count; ++i) {
		vi = vis->vis[i];
		vi_dirtify(vi, NULL);
		vi_decref(vi);
	}
	silofs_unused(vstg_ctx);
}

static int vstgc_clone_lbk_at(struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *src_laddr)
{
	struct silofs_vis vis = { .vas.count = 0 };
	int err;

	err = vstgc_pre_clone_lbk(vstg_ctx, &vis);
	if (!err) {
		err = vstgc_clone_rebind_lbk(vstg_ctx, src_laddr);
	}
	vstgc_post_clone_lbk(vstg_ctx, &vis);
	return err;
}

static int vstgc_clone_lbk_of(struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *src_laddr)
{
	struct silofs_laddr laddr_lbk;

	silofs_laddr_setup_lbk(&laddr_lbk, &src_laddr->lsegid, src_laddr->pos);
	return vstgc_clone_lbk_at(vstg_ctx, &laddr_lbk);
}

static int vstgc_resolve_inspect_llink(struct silofs_vstage_ctx *vstg_ctx,
                                       struct silofs_llink *out_llink)
{
	int err;

	err = vstgc_resolve_llink(vstg_ctx, out_llink);
	if (err) {
		return err;
	}
	err = vstgc_inspect_llink(vstg_ctx, out_llink);
	if (err != -SILOFS_EPERM) {
		return err;
	}
	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_lseg_of(vstg_ctx, &out_llink->laddr);
	if (err) {
		return err;
	}
	err = vstgc_clone_lbk_of(vstg_ctx, &out_llink->laddr);
	if (err) {
		return err;
	}
	err = vstgc_resolve_llink_of(vstg_ctx, out_llink);
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
	struct silofs_vstage_ctx vstg_ctx;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	return vstgc_resolve_inspect_llink(&vstg_ctx, out_llink);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_fetch_cached_vnode(const struct silofs_vstage_ctx *vstg_ctx,
                                    struct silofs_vnode_info **out_vi)
{
	return silofs_fetch_cached_vnode(vstg_ctx->task,
	                                 vstg_ctx->vaddr, out_vi);
}

static int vstgc_stage_vnode_at(struct silofs_vstage_ctx *vstg_ctx,
                                struct silofs_vnode_info **out_vi)
{
	struct silofs_llink llink = { .laddr.pos = -1 };
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = vstgc_resolve_inspect_llink(vstg_ctx, &llink);
	if (err) {
		goto out_err;
	}
	err = vstgc_do_require_lseg_of(vstg_ctx, &llink.laddr);
	if (err) {
		goto out_err;
	}
	err = vstgc_fetch_cached_vnode(vstg_ctx, &vi);
	if (!err) {
		/* vnode cached upon inspect -- just update llink */
		goto out_ok;
	}
	err = vstgc_spawn_vi_at(vstg_ctx, &llink, &vi);
	if (err) {
		goto out_err;
	}
	err = vstgc_stage_load_view(vstg_ctx, &llink.laddr, vi->v_lni.l_view);
	if (err) {
		goto out_err;
	}
	err = vstgc_restore_view_of(vstg_ctx, vi);
	if (err) {
		goto out_err;
	}
out_ok:
	vi_update_llink(vi, &llink);
	*out_vi = vi;
	return 0;
out_err:
	vstgc_forget_cached_vi(vstg_ctx, vi);
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
	if (!(vi->v_lni.l_ce.ce_flags & SILOFS_CEF_FORGOT)) {
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
	struct silofs_vstage_ctx vstg_ctx;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	return vstgc_stage_vnode_at(&vstg_ctx, out_vi);
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
	voff = ino_to_off(ino);
	if (off_isnull(voff)) {
		return -SILOFS_EINVAL;
	}
	vaddr_setup(out_vaddr, SILOFS_LTYPE_INODE, voff);
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
	silofs_ii_set_ino(*out_ii, vaddr_to_ino(vaddr));
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

/* TODO: cleanups and resource reclaim upon failure in every path */
static int stage_raw_vnode(struct silofs_task *task,
                           struct silofs_inode_info *pii,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vi)
{
	const enum silofs_stg_mode stg_mode = SILOFS_STG_COW | SILOFS_STG_RAW;

	return silofs_stage_vnode(task, pii, vaddr, stg_mode, out_vi);
}

static int do_spawn_vnode(struct silofs_task *task,
                          struct silofs_inode_info *pii,
                          enum silofs_ltype ltype,
                          struct silofs_vnode_info **out_vi)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_claim_vspace(task, ltype, &vaddr);
	if (err) {
		return err;
	}
	err = stage_raw_vnode(task, pii, &vaddr, &vi);
	if (err) {
		return err;
	}
	vi_dirtify(vi, pii);
	*out_vi = vi;
	return 0;
}

int silofs_spawn_vnode(struct silofs_task *task,
                       struct silofs_inode_info *pii,
                       enum silofs_ltype ltype,
                       struct silofs_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = do_spawn_vnode(task, pii, ltype, out_vi);
	ii_decref(pii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_itype(const struct silofs_task *task, mode_t mode)
{
	/*
	 * TODO-0031: Filter supported modes based on mount flags
	 */
	const mode_t sup = S_IFDIR | S_IFREG | S_IFLNK |
	                   S_IFSOCK | S_IFIFO | S_IFCHR | S_IFBLK;

	silofs_unused(task);
	return (((mode & S_IFMT) | sup) == sup) ? 0 : -SILOFS_EOPNOTSUPP;
}

static int claim_inode(struct silofs_task *task,
                       struct silofs_inode_info **out_ii)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_claim_ispace(task, &vaddr);
	if (err) {
		return err;
	}
	err = stage_raw_vnode(task, NULL, &vaddr, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);
	silofs_ii_set_ino(ii, vaddr_to_ino(&vaddr));
	*out_ii = ii;
	return 0;
}

static void setup_new_inode(struct silofs_inode_info *ii,
                            const struct silofs_inew_params *inp)
{
	silofs_ii_setup_by(ii, inp);
	ii_dirtify(ii);
}

static void setup_uniqe_generation(struct silofs_task *task,
                                   struct silofs_inode_info *ii)
{
	struct silofs_sb_info *sbi = task_sbi(task);
	uint64_t gen = 0;

	silofs_sti_next_generation(&sbi->sb_sti, &gen);
	silofs_ii_set_generation(ii, gen);
}

int silofs_spawn_inode(struct silofs_task *task,
                       const struct silofs_inew_params *inp,
                       struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_itype(task, inp->mode);
	if (err) {
		return err;
	}
	err = claim_inode(task, &ii);
	if (err) {
		return err;
	}
	setup_new_inode(ii, inp);
	setup_uniqe_generation(task, ii);
	*out_ii = ii;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void forget_cached_vi(const struct silofs_task *task,
                             struct silofs_vnode_info *vi)
{
	silofs_cache_forget_vi(task_cache(task), vi);
}

static int reclaim_vspace_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	const enum silofs_stg_mode stg_mode = SILOFS_STG_COW;
	int err;

	err = silofs_resolve_llink_of(task, vaddr, stg_mode, &llink);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(task, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int remove_vnode_of(struct silofs_task *task,
                           struct silofs_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = reclaim_vspace_at(task, vi_vaddr(vi));
	vi_decref(vi);
	return err;
}

int silofs_remove_vnode(struct silofs_task *task,
                        struct silofs_vnode_info *vi)
{
	int err;

	err = remove_vnode_of(task, vi);
	if (err) {
		return err;
	}
	forget_cached_vi(task, vi);
	return 0;
}

int silofs_remove_vnode_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_fetch_cached_vnode(task, vaddr, &vi);
	if (!err) {
		err = silofs_remove_vnode(task, vi);
	} else {
		err = reclaim_vspace_at(task, vaddr);
	}
	return err;
}

static int remove_inode_of(struct silofs_task *task,
                           struct silofs_inode_info *ii)
{
	int err;

	ii_incref(ii);
	err = reclaim_vspace_at(task, ii_vaddr(ii));
	ii_decref(ii);
	return err;
}

static void forget_cached_ii(const struct silofs_task *task,
                             struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vis.dq.sz, 0);

	silofs_ii_undirtify(ii);
	forget_cached_vi(task, &ii->i_vi);
}

int silofs_remove_inode(struct silofs_task *task,
                        struct silofs_inode_info *ii)
{
	int err;

	err = remove_inode_of(task, ii);
	if (err) {
		return err;
	}
	forget_cached_ii(task, ii);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_refresh_llink(struct silofs_task *task,
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
		log_warn("failed to refresh llink: ltype=%d off=%ld err=%d",
		         vaddr->ltype, vaddr->off, err);
		return err;
	}
	vi_update_llink(vi, &llink);
	return 0;
}

