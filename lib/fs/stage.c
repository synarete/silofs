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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stats.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/uber.h>
#include <silofs/fs/private.h>


struct silofs_stage_ctx {
	struct silofs_sb_info     *sbi;
	struct silofs_spnode_info *sni_parent;
	enum silofs_stage_flags    stg_flags;
	enum silofs_stype          stype_sub;
	loff_t                     voff;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool stage_mut(enum silofs_stage_flags stg_flags)
{
	return (stg_flags & SILOFS_STAGE_MUTABLE) > 0;
}

static loff_t voaddr_voff(const struct silofs_voaddr *voa)
{
	return vaddr_off(&voa->vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ui_bind_apex_by(struct silofs_unode_info *ui,
                            const struct silofs_sb_info *sbi)
{
	silofs_ui_bind_apex(ui, sbi_apex(sbi));
}

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_sb_info *sbi,
                       struct silofs_vbk_info *vbi)
{
	struct silofs_fs_apex *apex = sbi_apex(sbi);

	vi->v_si.s_apex = apex;
	/* TODO: move to lower level */
	vi->v_si.s_md = &vi->v_si.s_ce.ce_cache->c_mdigest;
	vi->v_sbi = sbi;
	silofs_vi_attach_to(vi, vbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sni_incref2(struct silofs_spnode_info *sni1,
                        struct silofs_spnode_info *sni2)
{
	sni_incref(sni1);
	sni_incref(sni2);
}

static void sni_decref2(struct silofs_spnode_info *sni1,
                        struct silofs_spnode_info *sni2)
{
	sni_decref(sni1);
	sni_decref(sni2);
}

static void sni_sli_incref(struct silofs_spnode_info *sni,
                           struct silofs_spleaf_info *sli)
{
	sni_incref(sni);
	sli_incref(sli);
}

static void sni_sli_decref(struct silofs_spnode_info *sni,
                           struct silofs_spleaf_info *sli)
{
	sni_decref(sni);
	sli_decref(sli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_log_cache_stat(const struct silofs_sb_info *sbi)
{
	const struct silofs_cache *cache = sbi_cache(sbi);

	log_dbg("cache-stat: dq_accum_nbytes=%lu " \
	        "ubi=%lu ui=%lu vbi=%lu vi=%lu bli=%lu",
	        cache->c_dq.dq_accum_nbytes, cache->c_ubi_lm.lm_lru.sz,
	        cache->c_ui_lm.lm_lru.sz, cache->c_vbi_lm.lm_lru.sz,
	        cache->c_vi_lm.lm_lru.sz, cache->c_bli_lm.lm_lru.sz);
}

static int sbi_lookup_cached_vbi(struct silofs_sb_info *sbi, loff_t voff,
                                 struct silofs_vbk_info **out_vbi)
{
	*out_vbi = silofs_cache_lookup_vbk(sbi_cache(sbi), voff);
	return (*out_vbi != NULL) ? 0 : -ENOENT;
}

static void sbi_forget_cached_vbi(const struct silofs_sb_info *sbi,
                                  struct silofs_vbk_info *vbi)
{
	silofs_cache_forget_vbk(sbi_cache(sbi), vbi);
}

static int sbi_spawn_cached_vbi(struct silofs_sb_info *sbi, loff_t voff,
                                struct silofs_vbk_info **out_vbi)
{
	*out_vbi = silofs_cache_spawn_vbk(sbi_cache(sbi), voff);
	return (*out_vbi != NULL) ? 0 : -ENOMEM;
}

static int sbi_spawn_cached_vi(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vnode_info **out_vi)
{
	*out_vi = silofs_cache_spawn_vnode(sbi_cache(sbi), vaddr);
	return (*out_vi == NULL) ? -ENOMEM : 0;
}

static void sbi_forget_cached_vi(struct silofs_sb_info *sbi,
                                 struct silofs_vnode_info *vi)
{
	silofs_cache_forget_vnode(sbi_cache(sbi), vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_commit_dirty(const struct silofs_sb_info *sbi)
{
	const struct silofs_cache *cache = sbi_cache(sbi);
	int err;

	err = silofs_apex_flush_dirty(sbi_apex(sbi), SILOFS_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: ndirty=%lu err=%d",
		        cache->c_dq.dq_accum_nbytes, err);
	}
	return err;
}

static int sbi_spawn_vbi(struct silofs_sb_info *sbi, loff_t voff,
                         struct silofs_vbk_info **out_vbi)
{
	int err;

	err = sbi_spawn_cached_vbi(sbi, voff, out_vbi);
	if (!err) {
		goto out_ok;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_spawn_cached_vbi(sbi, voff, out_vbi);
	if (err) {
		goto out_err;
	}
out_ok:
	return 0;
out_err:
	sbi_log_cache_stat(sbi);
	return err;
}

static int sbi_spawn_vi(struct silofs_sb_info *sbi,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_vnode_info **out_vi)
{
	int err;

	err = sbi_spawn_cached_vi(sbi, vaddr, out_vi);
	if (!err) {
		goto out_ok;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_spawn_cached_vi(sbi, vaddr, out_vi);
	if (err) {
		goto out_err;
	}
out_ok:
	return 0;
out_err:
	sbi_log_cache_stat(sbi);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *sbi_repo(const struct silofs_sb_info *sbi)
{
	return sbi->sb_ui.u_repo;
}

static int sbi_stage_blob(const struct silofs_sb_info *sbi,
                          const struct silofs_blobid *blobid,
                          struct silofs_blob_info **out_bli)
{
	struct silofs_repo *repo = sbi_repo(sbi);

	return silofs_repo_stage_blob(repo, blobid, out_bli);
}

static int sbi_spawn_blob(const struct silofs_sb_info *sbi,
                          const struct silofs_blobid *blobid,
                          enum silofs_stype stype_sub,
                          struct silofs_blob_info **out_bli)
{
	struct silofs_repo *repo = sbi_repo(sbi);
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		return -EEXIST;
	}
	if (err != -ENOENT) {
		return err;
	}
	err = silofs_repo_spawn_blob(repo, blobid, out_bli);
	if (err) {
		return err;
	}
	silofs_sti_update_blobs(sbi->sb_sti, stype_sub, 1);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_bind_vi(struct silofs_sb_info *sbi,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_vbk_info *vbi,
                             struct silofs_vnode_info **out_vi)
{
	int err;

	silofs_vbi_incref(vbi);
	err = sbi_spawn_vi(sbi, vaddr, out_vi);
	if (!err) {
		vi_bind_to(*out_vi, sbi, vbi);
	}
	silofs_vbi_decref(vbi);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

bool silofs_sbi_ismutable_blobid(const struct silofs_sb_info *sbi,
                                 const struct silofs_blobid *blobid)
{
	struct silofs_xid tree_id;

	silofs_sbi_treeid(sbi, &tree_id);
	return silofs_xid_isequal(&tree_id, &blobid->xxid.u.tid.tree_id);
}

static bool sbi_ismutable_oaddr(const struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr)
{
	return silofs_sbi_ismutable_blobid(sbi, &oaddr->bka.blobid);
}

static int sbi_inspect_oaddr(const struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             enum silofs_stage_flags stg_flags)
{
	return (stage_mut(stg_flags) &&
	        !sbi_ismutable_oaddr(sbi, oaddr)) ? -EPERM : 0;
}

static int sbi_inspect_voa(const struct silofs_sb_info *sbi,
                           const struct silofs_voaddr *voa,
                           enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_oaddr(sbi, &voa->oaddr, stg_flags);
}

static int sbi_inspect_cached_ui(const struct silofs_sb_info *sbi,
                                 const struct silofs_unode_info *ui,
                                 enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_oaddr(sbi, ui_oaddr(ui), stg_flags);
}

static int sbi_inspect_cached_sni(const struct silofs_sb_info *sbi,
                                  const struct silofs_spnode_info *sni,
                                  enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_cached_ui(sbi, &sni->sn_ui, stg_flags);
}

static int sbi_inspect_cached_sli(const struct silofs_sb_info *sbi,
                                  const struct silofs_spleaf_info *sli,
                                  enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_cached_ui(sbi, &sli->sl_ui, stg_flags);
}

static int sbi_find_cached_spmap(struct silofs_sb_info *sbi,
                                 loff_t voff, size_t height,
                                 struct silofs_unode_info **out_ui)
{
	struct silofs_taddr taddr;
	struct silofs_vrange vrange;
	struct silofs_xid tree_id;

	silofs_sbi_treeid(sbi, &tree_id);
	silofs_vrange_setup_by(&vrange, height, voff);
	silofs_taddr_setup(&taddr, &tree_id, vrange.beg, height);

	*out_ui = silofs_cache_find_unode_by(sbi_cache(sbi), &taddr);
	return (*out_ui != NULL) ? 0 : -ENOENT;
}

static int sbi_find_cached_spnode3(struct silofs_sb_info *sbi, loff_t voff,
                                   enum silofs_stage_flags stg_flags,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = sbi_find_cached_spmap(sbi, voff, SILOFS_SPLEAF_HEIGHT + 2, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);

	err = sbi_inspect_cached_sni(sbi, *out_sni, stg_flags);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_find_cached_spnode2(struct silofs_sb_info *sbi, loff_t voff,
                                   enum silofs_stage_flags stg_flags,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = sbi_find_cached_spmap(sbi, voff, SILOFS_SPLEAF_HEIGHT + 1, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);

	err = sbi_inspect_cached_sni(sbi, *out_sni, stg_flags);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_ubk_of(struct silofs_sb_info *sbi,
                            const struct silofs_oaddr *oaddr,
                            struct silofs_ubk_info **out_ubi)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_ubk_info *ubi = NULL;
	int err;

	err = silofs_repo_stage_ubk(sbi_repo(sbi), &oaddr->bka, &ubi);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = silofs_repo_stage_ubk(sbi_repo(sbi), &bkaddr, &ubi);
	if (err) {
		goto out_err;
	}
out_ok:
	*out_ubi = ubi;
	return 0;
out_err:
	sbi_log_cache_stat(sbi);
	return err;
}

static void sbi_bind_sni_to_apex(const struct silofs_sb_info *sbi,
                                 struct silofs_spnode_info *sni)
{
	ui_bind_apex_by(&sni->sn_ui, sbi);
}

static int sbi_do_stage_spnode_at(struct silofs_sb_info *sbi,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spnode_info **out_sni)
{
	return silofs_stage_spnode_at(sbi_apex(sbi), true, uaddr, out_sni);
}

static int sbi_stage_spnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = sbi_do_stage_spnode_at(sbi, uaddr, out_sni);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_do_stage_spnode_at(sbi, uaddr, out_sni);
	if (err) {
		goto out_err;
	}
out_ok:
	sbi_bind_sni_to_apex(sbi, *out_sni);
	return 0;
out_err:
	sbi_log_cache_stat(sbi);
	return err;
}

static void stgc_update_uspace_meta(const struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_uaddr *uaddr)
{
	silofs_sti_update_objs(stg_ctx->sbi->sb_sti, uaddr->stype, 1);
}

static void sbi_make_blobid_for(const struct silofs_sb_info *sbi,
                                enum silofs_stype stype, size_t nobjs,
                                struct silofs_blobid *out_blobid)
{
	struct silofs_xid tree_id;
	const size_t obj_size = stype_size(stype);

	silofs_sbi_treeid(sbi, &tree_id);
	silofs_blobid_make_tas(out_blobid, &tree_id, obj_size, nobjs);
}

static int sbi_spawn_super_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	const size_t nslots = ARRAY_SIZE(sbi->sb->sb_subref);
	const enum silofs_stype stype = SILOFS_STYPE_SPNODE;
	int err;

	sbi_make_blobid_for(sbi, stype, nslots, &blobid);
	err = sbi_spawn_blob(sbi, &blobid, stype, &bli);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_blob(sbi, &bli->blobid);
	return 0;
}

static int sbi_stage_super_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;

	silofs_sbi_main_blob(sbi, &blobid);
	return sbi_stage_blob(sbi, &blobid, &bli);
}

static int sbi_require_main_blob(struct silofs_sb_info *sbi)
{
	int err;

	if (silofs_sbi_has_main_blob(sbi)) {
		err = sbi_stage_super_main_blob(sbi);
	} else {
		err = sbi_spawn_super_main_blob(sbi);
	}
	return err;
}

static int sbi_do_spawn_spnode_at(const struct silofs_sb_info *sbi,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spnode_info **out_sni)
{
	return silofs_spawn_spnode_at(sbi_apex(sbi), true, uaddr, out_sni);
}

static int sbi_spawn_spnode_at(const struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = sbi_do_spawn_spnode_at(sbi, uaddr, out_sni);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_do_spawn_spnode_at(sbi, uaddr, out_sni);
	if (err) {
		goto out_err;
	}
out_ok:
	sbi_bind_sni_to_apex(sbi, *out_sni);
	return 0;
out_err:
	return err;
}

static void stgc_setup_spawned_spnode3(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sbi_uaddr(stg_ctx->sbi),
	                         stg_ctx->voff, SILOFS_STYPE_NONE);
}

static int stgc_spawn_spnode3_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = sbi_require_main_blob(stg_ctx->sbi);
	if (err) {
		return err;
	}
	silofs_sbi_main_child_at(stg_ctx->sbi, stg_ctx->voff, &uaddr);

	err = sbi_spawn_spnode_at(stg_ctx->sbi, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode3(stg_ctx, *out_sni);
	return 0;
}

static int sbi_stage_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;

	silofs_sni_main_blob(sni, &blobid);
	return sbi_stage_blob(sbi, &blobid, &bli);
}

static enum silofs_stype sni_child_stype(const struct silofs_spnode_info *sni)
{
	const size_t height = silofs_sni_height(sni);

	return ((height - 1) > SILOFS_SPLEAF_HEIGHT) ?
	       SILOFS_STYPE_SPNODE : SILOFS_STYPE_SPLEAF;
}

static int sbi_spawn_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sni->sn->sn_subref);
	const enum silofs_stype stype = sni_child_stype(sni);
	int err;

	sbi_make_blobid_for(sbi, stype, nchilds, &blobid);
	err = sbi_spawn_blob(sbi, &blobid, stype, &bli);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_blob(sni, &bli->blobid);
	return 0;
}

static int sbi_require_spnode_main_blob(struct silofs_sb_info *sbi,
                                        struct silofs_spnode_info *sni)
{
	int err;

	if (silofs_sni_has_main_blob(sni)) {
		err = sbi_stage_spnode_main_blob(sbi, sni);
	} else {
		err = sbi_spawn_spnode_main_blob(sbi, sni);
	}
	return err;
}

static void stgc_setup_spawned_spnode2(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_assert_ne(stg_ctx->stype_sub, SILOFS_STYPE_NONE);
	silofs_assert(stype_isvnode(stg_ctx->stype_sub));

	silofs_sni_setup_spawned(sni, sni_uaddr(stg_ctx->sni_parent),
	                         stg_ctx->voff, stg_ctx->stype_sub);
}

static int stgc_spawn_spnode2_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = sbi_require_spnode_main_blob(stg_ctx->sbi, stg_ctx->sni_parent);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_child(stg_ctx->sni_parent,
	                              stg_ctx->voff, &uaddr);

	err = sbi_spawn_spnode_at(stg_ctx->sbi, &uaddr, out_sni);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spnode2(stg_ctx, *out_sni);
	return 0;
}

static int stgc_spawn_spnode3(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode3_of(stg_ctx, out_sni);
	if (!err) {
		stgc_update_uspace_meta(stg_ctx, sni_uaddr(*out_sni));
	}
	return err;
}

static int sbi_clone_spnode3(struct silofs_sb_info *sbi,
                             struct silofs_spnode_info *sni_curr,
                             struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx = {
		.sbi = sbi,
		.sni_parent = NULL,
		.stype_sub = SILOFS_STYPE_NONE, /* XXX FIXME */
	};
	struct silofs_vrange vrange;
	int err;

	sni_incref(sni_curr);
	sni_vrange(sni_curr, &vrange);
	stg_ctx.voff = vrange.beg;
	err = stgc_spawn_spnode3(&stg_ctx, out_sni);
	if (!err) {
		silofs_sni_clone_subrefs(*out_sni, sni_curr);
		silofs_sbi_bind_child(sbi, *out_sni);
	}
	sni_decref(sni_curr);
	return err;
}

static int stgc_stage_spnode3(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr ulink;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sbi_subref_of(stg_ctx->sbi, stg_ctx->voff, &ulink);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode_at(stg_ctx->sbi, &ulink, &sni);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sni(stg_ctx->sbi, sni, stg_ctx->stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_spnode3(stg_ctx->sbi, sni, &sni);
	if (err) {
		return err;
	}
out_ok:
	*out_sni = sni;
	return 0;
}

static int stgc_spawn_spnode2(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode2_of(stg_ctx, out_sni);
	if (!err) {
		stgc_update_uspace_meta(stg_ctx, sni_uaddr(*out_sni));
	}
	return err;
}

static int sbi_clone_spnode2(struct silofs_sb_info *sbi,
                             struct silofs_spnode_info *sni_parent,
                             struct silofs_spnode_info *sni_curr,
                             struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx = {
		.sbi = sbi,
		.sni_parent = sni_parent,
		.stg_flags = SILOFS_STAGE_MUTABLE,
		.stype_sub = silofs_sni_stype_sub(sni_curr),
		.voff = silofs_sni_base_voff(sni_curr),
	};
	int err;

	sni_incref2(sni_parent, sni_curr);
	err = stgc_spawn_spnode2(&stg_ctx, out_sni);
	if (!err) {
		silofs_sni_clone_subrefs(*out_sni, sni_curr);
		silofs_sni_bind_child_spnode(sni_parent, *out_sni);
	}
	sni_decref2(sni_curr, sni_parent);
	return err;
}

static int stgc_stage_spnode2(const struct silofs_stage_ctx *stg_ctx,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr ulink;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni_parent, stg_ctx->voff, &ulink);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode_at(stg_ctx->sbi, &ulink, &sni);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sni(stg_ctx->sbi, sni, stg_ctx->stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_spnode2(stg_ctx->sbi, stg_ctx->sni_parent, sni, &sni);
	if (err) {
		return err;
	}
out_ok:
	*out_sni = sni;
	return 0;
}

static int sbi_stage_spnode3_of(struct silofs_sb_info *sbi, loff_t voff,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx = {
		.sbi = sbi,
		.sni_parent = NULL,
		.stg_flags = stg_flags,
		.voff = voff,
		.stype_sub = SILOFS_STYPE_NONE,
	};

	return stgc_stage_spnode3(&stg_ctx, out_sni);
}

int silofs_sbi_stage_spnode3(struct silofs_sb_info *sbi, loff_t voff,
                             enum silofs_stage_flags stg_flags,
                             struct silofs_spnode_info **out_sni)
{
	int err;

	err = sbi_find_cached_spnode3(sbi, voff, stg_flags, out_sni);
	if (!err) {
		return 0;
	}
	err = sbi_stage_spnode3_of(sbi, voff, stg_flags, out_sni);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_stage_spnode2_of(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                loff_t voff, enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx = {
		.sbi = sbi,
		.sni_parent = sni_parent,
		.stg_flags = stg_flags,
		.voff = voff,
		.stype_sub = SILOFS_STYPE_NONE,
	};
	int err;

	sni_incref(sni_parent);
	err = stgc_stage_spnode2(&stg_ctx, out_sni);
	sni_decref(sni_parent);
	return err;
}

int silofs_sbi_stage_spnode2(struct silofs_sb_info *sbi, loff_t voff,
                             enum silofs_stage_flags stg_flags,
                             struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni_parent = NULL;
	int err;

	err = sbi_find_cached_spnode2(sbi, voff, stg_flags, out_sni);
	if (!err) {
		return 0;
	}
	err = silofs_sbi_stage_spnode3(sbi, voff, stg_flags, &sni_parent);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode2_of(sbi, sni_parent, voff, stg_flags, out_sni);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_find_cached_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_find_cached_spmap(sbi, voff, SILOFS_SPLEAF_HEIGHT, &ui);
	if (err) {
		return err;
	}
	sli = silofs_sli_from_ui(ui);

	err = sbi_inspect_cached_sli(sbi, sli, stg_flags);
	if (err) {
		return err;
	}
	*out_sli = sli;
	return 0;
}

static void sbi_bind_sli_to_apex(const struct silofs_sb_info *sbi,
                                 struct silofs_spleaf_info *sli)
{
	ui_bind_apex_by(&sli->sl_ui, sbi);
}

static int sbi_do_spawn_spleaf_at(const struct silofs_sb_info *sbi,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spleaf_info **out_sli)
{
	return silofs_spawn_spleaf_at(sbi_apex(sbi), true, uaddr, out_sli);
}

static int sbi_spawn_spleaf_at(const struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	int err;

	err = sbi_do_spawn_spleaf_at(sbi, uaddr, out_sli);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_do_spawn_spleaf_at(sbi, uaddr, out_sli);
	if (err) {
		goto out_err;
	}
out_ok:
	sbi_bind_sli_to_apex(sbi, *out_sli);
	return 0;
out_err:
	return err;
}

static void stgc_setup_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      struct silofs_spleaf_info *sli)
{
	silofs_assert_ne(stg_ctx->stype_sub, SILOFS_STYPE_NONE);
	silofs_assert(stype_isvnode(stg_ctx->stype_sub));

	silofs_sli_setup_spawned(sli, sni_uaddr(stg_ctx->sni_parent),
	                         stg_ctx->voff, stg_ctx->stype_sub);
}

static int stgc_spawn_spleaf_of(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni_parent = stg_ctx->sni_parent;
	int err;

	err = sbi_require_spnode_main_blob(stg_ctx->sbi, sni_parent);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_child(sni_parent, stg_ctx->voff, &uaddr);

	err = sbi_spawn_spleaf_at(stg_ctx->sbi, &uaddr, out_sli);
	if (err) {
		return err;
	}
	stgc_setup_spawned_spleaf(stg_ctx, *out_sli);
	return 0;
}

static int stgc_spawn_spleaf_main_blob(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spleaf_info *sli)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	const size_t nbks = ARRAY_SIZE(sli->sl->sl_subref);
	int err;

	sbi_make_blobid_for(stg_ctx->sbi, SILOFS_STYPE_ANONBK, nbks, &blobid);
	err = sbi_spawn_blob(stg_ctx->sbi, &blobid, stg_ctx->stype_sub, &bli);
	if (err) {
		return err;
	}
	silofs_sli_bind_main_blob(sli, &bli->blobid);
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
	err = stgc_spawn_spleaf_main_blob(stg_ctx, *out_sli);
	if (err) {
		return err;
	}
	stgc_update_uspace_meta(stg_ctx, sli_uaddr(*out_sli));
	return 0;
}

static int stgc_clone_spleaf(const struct silofs_stage_ctx *stg_ctx,
                             struct silofs_spleaf_info *sli_curr,
                             struct silofs_spleaf_info **out_sli)
{
	int err;

	sni_sli_incref(stg_ctx->sni_parent, sli_curr);
	err = stgc_spawn_spleaf(stg_ctx, out_sli);
	if (!err) {
		silofs_sli_clone_subrefs(*out_sli, sli_curr);
		silofs_sni_bind_child_spleaf(stg_ctx->sni_parent, *out_sli);
	}
	sni_sli_decref(stg_ctx->sni_parent, sli_curr);
	return err;
}

static int sbi_do_stage_spleaf_at(struct silofs_sb_info *sbi,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf_at(sbi_apex(sbi), true, uaddr, out_sli);
}

static int sbi_stage_spleaf_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	int err;

	err = sbi_do_stage_spleaf_at(sbi, uaddr, out_sli);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_do_stage_spleaf_at(sbi, uaddr, out_sli);
	if (err) {
		goto out_err;
	}
out_ok:
	sbi_bind_sli_to_apex(sbi, *out_sli);
	return 0;
out_err:
	sbi_log_cache_stat(sbi);
	return err;
}

static void stgc_update_by_spleaf(struct silofs_stage_ctx *stg_ctx,
                                  const struct silofs_spleaf_info *sli)
{
	stg_ctx->voff = silofs_sli_voff_beg(sli);
	stg_ctx->stype_sub = silofs_sli_stype_sub(sli);
}

static int stgc_stage_spleaf(struct silofs_stage_ctx *stg_ctx,
                             struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr ulink;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_subref_of(stg_ctx->sni_parent, stg_ctx->voff, &ulink);
	if (err) {
		return err;
	}
	err = sbi_stage_spleaf_at(stg_ctx->sbi, &ulink, &sli);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sli(stg_ctx->sbi, sli, stg_ctx->stg_flags);
	if (!err) {
		goto out_ok;
	}
	stgc_update_by_spleaf(stg_ctx, sli);
	err = stgc_clone_spleaf(stg_ctx, sli, &sli);
	if (err) {
		return err;
	}
out_ok:
	*out_sli = sli;
	return 0;
}

static int sbi_stage_spleaf_of(struct silofs_sb_info *sbi,
                               struct silofs_spnode_info *sni_parent,
                               loff_t voff, enum silofs_stage_flags stg_flags,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_stage_ctx stg_ctx = {
		.sbi = sbi,
		.sni_parent = sni_parent,
		.stg_flags = stg_flags,
		.voff = voff,
		.stype_sub = SILOFS_STYPE_NONE,
	};
	int err;

	sni_incref(sni_parent);
	err = stgc_stage_spleaf(&stg_ctx, out_sli);
	sni_decref(sni_parent);
	return err;
}

int silofs_sbi_stage_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                            enum silofs_stage_flags stg_flags,
                            struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni_parent = NULL;
	int err;

	err = sbi_find_cached_spleaf(sbi, voff, stg_flags, out_sli);
	if (!err) {
		return 0;
	}
	err = silofs_sbi_stage_spnode2(sbi, voff, stg_flags, &sni_parent);
	if (err) {
		return err;
	}
	err = sbi_stage_spleaf_of(sbi, sni_parent, voff, stg_flags, out_sli);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Upon new space leaf, add the entire space range at once. Ignores possible
 * out-of-memory failure.
 */

static struct silofs_spamaps *
stgc_spamaps(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_cache *cache = sbi_cache(stg_ctx->sbi);

	return &cache->c_spam;
}

static void stgc_track_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange = { .stepsz = -1 };
	struct silofs_spamaps *spam = stgc_spamaps(stg_ctx);
	const struct silofs_uaddr *uaddr = sli_uaddr(sli);

	sli_vrange(sli, &vrange);
	silofs_spamaps_store(spam, uaddr->stype, vrange.beg, vrange.len);
}

static void stgc_bind_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                     struct silofs_spleaf_info *sli)
{
	silofs_sni_bind_child_spleaf(stg_ctx->sni_parent, sli);
}

static int stgc_spawn_bind_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                     struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_spawn_spleaf(stg_ctx, out_sli);
	if (!err) {
		stgc_bind_spawned_spleaf(stg_ctx, *out_sli);
		stgc_track_spawned_spleaf(stg_ctx, *out_sli);
	}
	return err;
}

static int stgc_stage_mut_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spleaf_info **out_sli)
{
	return silofs_sbi_stage_spleaf(stg_ctx->sbi, stg_ctx->voff,
	                               SILOFS_STAGE_MUTABLE, out_sli);
}

static bool stgc_has_child_at(const struct silofs_stage_ctx *stg_ctx)
{
	const loff_t voff = stg_ctx->voff;
	bool ret;

	if (stg_ctx->sni_parent != NULL) {
		ret = silofs_sni_has_child_at(stg_ctx->sni_parent, voff);
	} else {
		ret = silofs_sbi_has_child_at(stg_ctx->sbi, voff);
	}
	return ret;
}

static int stgc_require_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                  struct silofs_spleaf_info **out_sli)
{
	int err;

	sni_incref(stg_ctx->sni_parent);
	if (stgc_has_child_at(stg_ctx)) {
		err = stgc_stage_mut_spleaf(stg_ctx, out_sli);
	} else {
		err = stgc_spawn_bind_spleaf_at(stg_ctx, out_sli);
	}
	sni_decref(stg_ctx->sni_parent);
	return err;
}

static int stgc_spawn_bind_spnode3(const struct silofs_stage_ctx *stg_ctx,
                                   struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode3(stg_ctx, out_sni);
	if (!err) {
		silofs_sbi_bind_child(stg_ctx->sbi, *out_sni);
	}
	return err;
}

static int stgc_require_spnode3(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	if (stgc_has_child_at(stg_ctx)) {
		err = stgc_stage_spnode3(stg_ctx, out_sni);
	} else {
		err = stgc_spawn_bind_spnode3(stg_ctx, out_sni);
	}
	return err;
}

static int stgc_spawn_bind_spnode2(const struct silofs_stage_ctx *stg_ctx,
                                   struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_spawn_spnode2(stg_ctx, out_sni);
	if (!err) {
		silofs_sni_bind_child_spnode(stg_ctx->sni_parent, *out_sni);
	}
	return err;
}

static int stgc_require_spnode2(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	if (stgc_has_child_at(stg_ctx)) {
		err = stgc_stage_spnode2(stg_ctx, out_sni);
	} else {
		err = stgc_spawn_bind_spnode2(stg_ctx, out_sni);
	}
	return err;
}

int silofs_sbi_require_spmaps_at(struct silofs_sb_info *sbi, loff_t voff,
                                 enum silofs_stype stype_sub)
{
	struct silofs_stage_ctx stg_ctx = {
		.sbi = sbi,
		.sni_parent = NULL,
		.stg_flags = SILOFS_STAGE_MUTABLE,
		.stype_sub = stype_sub,
		.voff = voff,
	};
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = stgc_require_spnode3(&stg_ctx, &sni);
	if (err) {
		return err;
	}
	stg_ctx.sni_parent = sni;

	err = stgc_require_spnode2(&stg_ctx, &sni);
	if (err) {
		return err;
	}
	stg_ctx.sni_parent = sni;

	err = stgc_require_spleaf_at(&stg_ctx, &sli);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_load_vbk(struct silofs_sb_info *sbi,
                              struct silofs_blob_info *bli,
                              const struct silofs_voaddr *voa,
                              struct silofs_vbk_info **out_vbi)
{
	struct silofs_vbk_info *vbi = NULL;
	int ret;

	bli_incref(bli);
	ret = sbi_spawn_vbi(sbi, voa->vaddr.voff, &vbi);
	if (ret) {
		goto out;
	}
	ret = silofs_bli_load_bk(bli, &voa->oaddr.bka, vbi->vbk);
	if (ret) {
		sbi_forget_cached_vbi(sbi, vbi);
		goto out;
	}
	*out_vbi = vbi;
out:
	bli_decref(bli);
	return ret;
}

static int sbi_stage_load_vbk(struct silofs_sb_info *sbi,
                              const struct silofs_voaddr *voa,
                              struct silofs_vbk_info **out_vbi)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = sbi_stage_blob(sbi, &voa->oaddr.bka.blobid, &bli);
	if (err) {
		return err;
	}
	err = sbi_spawn_load_vbk(sbi, bli, voa, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_stage_vblock(struct silofs_sb_info *sbi,
                            const struct silofs_voaddr *voa,
                            struct silofs_vbk_info **out_vbi)
{
	int err;

	err = sbi_lookup_cached_vbi(sbi, voa->vaddr.voff, out_vbi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = sbi_stage_load_vbk(sbi, voa, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_resolve_rdonly(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_voaddr *out_voa)
{
	struct silofs_uaddr bk_ulink;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	int err;

	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
	if (err) {
		return err;
	}
	err = silofs_sli_subref_of(sli, voff, &bk_ulink);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	silofs_voaddr_setup_by(out_voa, uaddr_blobid(&bk_ulink), vaddr);
	return 0;
}

static int sbi_stage_vblock_of(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vbk_info **out_vbi)
{
	struct silofs_voaddr voa;
	int err;

	err = sbi_resolve_rdonly(sbi, vaddr, &voa);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock(sbi, &voa, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_reload_spleaf_at(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	int err;

	if (!silofs_sni_has_child_at(sni, voff)) {
		return -EFSCORRUPTED;
	}
	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_reload_first_spleaf_of(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;
	int err;

	sni_incref(sni);
	sni_vrange(sni, &vrange);
	err = sbi_reload_spleaf_at(sbi, sni, vrange.beg);
	sni_decref(sni);
	return err;
}

static void sbi_relax_bringup_cache(struct silofs_sb_info *sbi)
{
	silofs_cache_relax(sbi_cache(sbi), SILOFS_F_BRINGUP);
}

static int sbi_reload_ro_spnode2(struct silofs_sb_info *sbi, loff_t voff,
                                 struct silofs_spnode_info **out_sni)
{
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;

	return silofs_sbi_stage_spnode2(sbi, voff, stg_flags, out_sni);
}

static loff_t sbi_vspace_end(const struct silofs_sb_info *sbi)
{
	return silofs_sti_vspace_end(sbi->sb_sti);
}

int silofs_sbi_reload_spmaps(struct silofs_sb_info *sbi)
{
	struct silofs_spnode_info *sni = NULL;
	const loff_t vend = sbi_vspace_end(sbi);
	loff_t voff = 0;
	size_t cnt = 0;
	int err;

	while ((voff < vend) && (cnt++ < 64)) {
		if (!silofs_sbi_has_child_at(sbi, voff)) {
			break;
		}
		err = sbi_reload_ro_spnode2(sbi, voff, &sni);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = sbi_reload_first_spleaf_of(sbi, sni);
		if (err) {
			return err;
		}
		sbi_relax_bringup_cache(sbi);

		voff = silofs_off_to_spnode_next(voff);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_stage_spmaps_of(struct silofs_sb_info *sbi,
                               const struct silofs_voaddr *voa,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_spnode_info **out_sni,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = voaddr_voff(voa);
	int err;

	err = silofs_sbi_stage_spnode2(sbi, voff, stg_flags, &sni);
	if (err) {
		return err;
	}
	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
	if (err) {
		return err;
	}
	*out_sni = sni;
	*out_sli = sli;
	return 0;
}

static int bli_resolve_bk(struct silofs_blob_info *bli,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_xiovec *xiov)
{
	struct silofs_oaddr bk_oaddr;

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->bka.blobid, oaddr->bka.lba);
	return silofs_bli_resolve(bli, &bk_oaddr, xiov);
}

static int sbi_resolve_vbks(struct silofs_sb_info *sbi,
                            const struct silofs_oaddr *oaddr_src,
                            const struct silofs_oaddr *oaddr_dst,
                            struct silofs_xiovec *out_xiov_src,
                            struct silofs_xiovec *out_xiov_dst)
{
	struct silofs_blob_info *bli_src = NULL;
	struct silofs_blob_info *bli_dst = NULL;
	int ret;

	ret = sbi_stage_blob(sbi, &oaddr_src->bka.blobid, &bli_src);
	if (ret) {
		goto out;
	}
	bli_incref(bli_src);

	ret = sbi_stage_blob(sbi, &oaddr_dst->bka.blobid, &bli_dst);
	if (ret) {
		goto out;
	}
	bli_incref(bli_dst);

	ret = bli_resolve_bk(bli_src, oaddr_src, out_xiov_src);
	if (ret) {
		goto out;
	}

	ret = bli_resolve_bk(bli_dst, oaddr_dst, out_xiov_dst);
	if (ret) {
		goto out;
	}
out:
	bli_decref(bli_dst);
	bli_decref(bli_src);
	return ret;
}

static int sbi_kcopy_vblock(struct silofs_sb_info *sbi,
                            const struct silofs_xiovec *xiov_src,
                            const struct silofs_xiovec *xiov_dst)
{
	struct silofs_fs_apex *apex = sbi_apex(sbi);

	return silofs_exec_kcopy_by(apex, xiov_src, xiov_dst, SILOFS_BK_SIZE);
}

static int sbi_clone_vblock(struct silofs_sb_info *sbi,
                            struct silofs_spleaf_info *sli,
                            const struct silofs_voaddr *voa_src)
{
	struct silofs_uaddr ulink_dst;
	struct silofs_xiovec xiov_src;
	struct silofs_xiovec xiov_dst;
	const loff_t voff = voa_src->vaddr.voff;
	int err;

	silofs_sli_resolve_main_at(sli, voff, &ulink_dst);
	err = sbi_resolve_vbks(sbi, &voa_src->oaddr, &ulink_dst.oaddr,
	                       &xiov_src, &xiov_dst);
	if (err == -ENOENT) {
		return -EFSCORRUPTED;
	}
	if (err) {
		return err;
	}
	err = sbi_kcopy_vblock(sbi, &xiov_src, &xiov_dst);
	if (err) {
		return err;
	}
	silofs_sli_rebind_child_at(sli, voff, &ulink_dst);
	return 0;
}

static int sbi_clone_vblock_at(struct silofs_sb_info *sbi,
                               const struct silofs_voaddr *voa)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;
	int err;

	err = sbi_stage_spmaps_of(sbi, voa, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = sbi_clone_vblock(sbi, sli, voa);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_resolve_voa(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_flags stg_flags,
                           struct silofs_voaddr *out_voa)
{
	int ret;

	ret = sbi_resolve_rdonly(sbi, vaddr, out_voa);
	if (ret) {
		return ret;
	}
	ret = sbi_inspect_voa(sbi, out_voa, stg_flags);
	if (ret != -EPERM) {
		return ret;
	}
	ret = sbi_clone_vblock_at(sbi, out_voa);
	if (ret) {
		return ret;
	}
	ret = sbi_resolve_rdonly(sbi, vaddr, out_voa);
	if (ret) {
		return ret;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_spawn_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_voaddr *voa_want,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa;
	struct silofs_vbk_info *vbi = NULL;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_sbi_resolve_voa(sbi, &voa_want->vaddr,
	                             SILOFS_STAGE_MUTABLE, &voa);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock_of(sbi, &voa_want->vaddr, &vbi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_vi(sbi, &voa.vaddr, vbi, &vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int sbi_require_stable_at(struct silofs_sb_info *sbi,
                                 const struct silofs_voaddr *voa,
                                 enum silofs_stage_flags stg_flags)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_spmaps_of(sbi, voa, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = silofs_sli_check_stable_at(sli, &voa->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_voaddr *voa,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = sbi_require_stable_at(sbi, voa, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_sbi_spawn_vnode_at(sbi, voa, &vi);
	if (err) {
		return err;
	}
	err = silofs_vi_verify_view(vi);
	if (err) {
		sbi_forget_cached_vi(sbi, vi);
		return err;
	}
	*out_vi = vi;
	return 0;
}

int silofs_sbi_stage_inode_at(struct silofs_sb_info *sbi,
                              const struct silofs_ivoaddr *ivoa,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_sbi_stage_vnode_at(sbi, &ivoa->voa, stg_flags, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);

	silofs_ii_rebind_view(ii, ivoa->ino);
	silofs_ii_refresh_atime(ii, true);
	*out_ii = ii;
	return 0;
}
