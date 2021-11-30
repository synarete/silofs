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
#include <silofs/fs/cache.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/private.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool stage_mut(enum silofs_stage_flags stg_flags)
{
	return (stg_flags & SILOFS_STAGE_MUTABLE) > 0;
}

static loff_t ovaddr_voff(const struct silofs_ovaddr *ova)
{
	return vaddr_off(&ova->vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ui_stamp_mark_visible(struct silofs_unode_info *ui)
{
	silofs_zero_stamp_view(ui->u_ti.t_view, ui_stype(ui));
	ui->u_verified = true;
	ui_dirtify(ui);
}

static void ui_bind_to(struct silofs_unode_info *ui,
                       struct silofs_fs_apex *apex,
                       struct silofs_ubk_info *ubi)
{
	ui->u_ti.t_apex = apex;
	silofs_ui_attach_bk(ui, ubi);
	silofs_ui_bind_view(ui);
}

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_fs_apex *apex,
                       struct silofs_vbk_info *vbi)
{
	vi->v_ti.t_apex = apex;
	silofs_vi_attach_bk(vi, vbi);
	silofs_vi_bind_view(vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sni_incref(struct silofs_spnode_info *sni)
{
	if (likely(sni != NULL)) {
		silofs_sni_incref(sni);
	}
}

static void sni_decref(struct silofs_spnode_info *sni)
{
	if (likely(sni != NULL)) {
		silofs_sni_decref(sni);
	}
}

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

static void sli_incref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != NULL)) {
		silofs_sli_incref(sli);
	}
}

static void sli_decref(struct silofs_spleaf_info *sli)
{
	if (likely(sli != NULL)) {
		silofs_sli_decref(sli);
	}
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

static int sbi_expects_spawned(const struct silofs_sb_info *sbi, int err)
{
	const struct silofs_cache *cache = sbi_cache(sbi);

	if (err) {
		log_dbg("can not spawn: dq_accum_nbytes=%lu " \
		        "ubi=%lu ui=%lu vbi=%lu vi=%lu err=%d",
		        cache->c_dq.dq_accum_nbytes,
		        cache->c_ubi_lm.lm_lru.sz,
		        cache->c_ui_lm.lm_lru.sz,
		        cache->c_vbi_lm.lm_lru.sz,
		        cache->c_vi_lm.lm_lru.sz, err);
	}
	return err;
}

static int sbi_lookup_cached_ubi(struct silofs_sb_info *sbi,
                                 const struct silofs_oaddr *oaddr,
                                 struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_lookup_ubk(sbi_cache(sbi), oaddr);
	return (*out_ubi != NULL) ? 0 : -ENOENT;
}

static void sbi_forget_cached_ubi(const struct silofs_sb_info *sbi,
                                  struct silofs_ubk_info *ubi)
{
	silofs_cache_forget_ubk(sbi_cache(sbi), ubi);
}

static int sbi_spawn_cached_ubi(struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr,
                                struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(sbi_cache(sbi), oaddr);
	return (*out_ubi != NULL) ? 0 : -ENOMEM;
}


static int sbi_lookup_cached_ui(struct silofs_sb_info *sbi,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_lookup_unode(sbi_cache(sbi), uaddr);
	return (*out_ui != NULL) ? 0 : -ENOENT;
}

static int sbi_spawn_cached_ui(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_spawn_unode(sbi_cache(sbi), uaddr);
	return (*out_ui == NULL) ? -ENOMEM : 0;
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

static int sbi_commit_dirty(struct silofs_sb_info *sbi)
{
	int err;
	const struct silofs_cache *cache = sbi_cache(sbi);

	err = silofs_apex_flush_dirty(sbi_apex(sbi), SILOFS_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: ndirty=%lu err=%d",
		        cache->c_dq.dq_accum_nbytes, err);
	}
	return err;
}

static int sbi_spawn_ubi(struct silofs_sb_info *sbi,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_ubk_info **out_ubi)
{
	int ret;

	ret = sbi_spawn_cached_ubi(sbi, oaddr, out_ubi);
	if (!ret) {
		goto out;
	}
	ret = sbi_commit_dirty(sbi);
	if (ret) {
		goto out;
	}
	ret = sbi_spawn_cached_ubi(sbi, oaddr, out_ubi);
out:
	return sbi_expects_spawned(sbi, ret);
}

static int sbi_spawn_ui(struct silofs_sb_info *sbi,
                        const struct silofs_uaddr *uaddr,
                        struct silofs_unode_info **out_ui)
{
	int ret;

	ret = sbi_spawn_cached_ui(sbi, uaddr, out_ui);
	if (!ret) {
		goto out;
	}
	ret = sbi_commit_dirty(sbi);
	if (ret) {
		goto out;
	}
	ret = sbi_spawn_cached_ui(sbi, uaddr, out_ui);
out:
	return sbi_expects_spawned(sbi, ret);
}

static int sbi_spawn_vbi(struct silofs_sb_info *sbi, loff_t voff,
                         struct silofs_vbk_info **out_vbi)
{
	int ret;

	ret = sbi_spawn_cached_vbi(sbi, voff, out_vbi);
	if (!ret) {
		goto out;
	}
	ret = sbi_commit_dirty(sbi);
	if (ret) {
		goto out;
	}
	ret = sbi_spawn_cached_vbi(sbi, voff, out_vbi);
out:
	return sbi_expects_spawned(sbi, ret);
}

static int sbi_spawn_vi(struct silofs_sb_info *sbi,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_vnode_info **out_vi)
{
	int ret;

	ret  = sbi_spawn_cached_vi(sbi, vaddr, out_vi);
	if (!ret) {
		goto out;
	}
	ret = sbi_commit_dirty(sbi);
	if (ret) {
		goto out;
	}
	ret = sbi_spawn_cached_vi(sbi, vaddr, out_vi);
out:
	return sbi_expects_spawned(sbi, ret);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_blob_at(const struct silofs_sb_info *sbi,
                             const struct silofs_blobid *bid,
                             struct silofs_blob_info **out_bli)
{
	return silofs_apex_spawn_blob(sbi_apex(sbi), bid, out_bli);
}

static int sbi_stage_blob_at(const struct silofs_sb_info *sbi,
                             const struct silofs_blobid *bid,
                             struct silofs_blob_info **out_bli)
{
	return silofs_apex_stage_blob(sbi_apex(sbi), bid, out_bli);
}

static int sbi_stage_blob_of(const struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             struct silofs_blob_info **out_bli)
{
	return sbi_stage_blob_at(sbi, &oaddr->bid, out_bli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_bind_ui(struct silofs_sb_info *sbi,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_ubk_info *ubi,
                             struct silofs_unode_info **out_ui)
{
	int err;

	err = sbi_spawn_ui(sbi, uaddr, out_ui);
	if (err) {
		return err;
	}
	ui_bind_to(*out_ui, sbi_apex(sbi), ubi);
	return 0;
}

static int sbi_spawn_bind_vi(struct silofs_sb_info *sbi,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_vbk_info *vbi,
                             struct silofs_vnode_info **out_vi)
{
	int err;

	err = sbi_spawn_vi(sbi, vaddr, out_vi);
	if (err) {
		return err;
	}
	vi_bind_to(*out_vi, sbi_apex(sbi), vbi);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool sbi_ismutable_blobid(const struct silofs_sb_info *sbi,
                                 const struct silofs_blobid *bid)
{
	struct silofs_metaid tree_id;

	silofs_sbi_main_treeid(sbi, &tree_id);
	return metaid_isequal(&tree_id, &bid->tree_id);
}

static bool sbi_ismutable_oaddr(const struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr)
{
	return sbi_ismutable_blobid(sbi, &oaddr->bid);
}

static int sbi_inspect_oaddr(const struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             enum silofs_stage_flags stg_flags)
{
	return (stage_mut(stg_flags) &&
	        !sbi_ismutable_oaddr(sbi, oaddr)) ? -EPERM : 0;
}

static int sbi_inspect_ova(const struct silofs_sb_info *sbi,
                           const struct silofs_ovaddr *ova,
                           enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_oaddr(sbi, &ova->oaddr, stg_flags);
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
	struct silofs_metaid tree_id;

	silofs_sbi_main_treeid(sbi, &tree_id);
	silofs_vrange_setup_by(&vrange, height, voff);
	silofs_taddr_setup(&taddr, &tree_id, vrange.beg, height);

	*out_ui = silofs_cache_find_unode_by(sbi_cache(sbi), &taddr);
	return (*out_ui != NULL) ? 0 : -ENOENT;
}

static int sbi_find_cached_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = sbi_find_cached_spmap(sbi, voff, SILOFS_SPLEAF_HEIGHT + 1, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);

	err = sbi_inspect_cached_sni(sbi, sni, stg_flags);
	if (err) {
		return err;
	}
	*out_sni = sni;
	return 0;
}

static int sbi_try_stage_cached_spnode(struct silofs_sb_info *sbi,
                                       const struct silofs_uaddr *uaddr,
                                       struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = sbi_lookup_cached_ui(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	return 0;
}

static int sbi_spawn_load_bk(struct silofs_sb_info *sbi,
                             struct silofs_blob_info *bli,
                             const struct silofs_oaddr *oaddr,
                             struct silofs_ubk_info **out_ubi)
{
	int ret;
	struct silofs_ubk_info *ubi = NULL;

	bli_incref(bli);
	ret = sbi_spawn_ubi(sbi, oaddr, &ubi);
	if (ret) {
		goto out;
	}
	ret = silofs_bli_load_bk(bli, ubi->ubk, oaddr);
	if (ret) {
		sbi_forget_cached_ubi(sbi, ubi);
		goto out;
	}
	*out_ubi = ubi;
out:
	bli_decref(bli);
	return ret;
}

static int sbi_stage_load_block(struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr,
                                struct silofs_ubk_info **out_ubi)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = sbi_stage_blob_of(sbi, oaddr, &bli);
	if (err) {
		return err;
	}
	err = sbi_spawn_load_bk(sbi, bli, oaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_stage_block(struct silofs_sb_info *sbi,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_ubk_info **out_ubi)
{
	int err;

	err = sbi_lookup_cached_ubi(sbi, oaddr, out_ubi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = sbi_stage_load_block(sbi, oaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_stage_spmap_at(struct silofs_sb_info *sbi,
                              const struct silofs_uaddr *uaddr,
                              struct silofs_unode_info **out_ui)
{
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_unode_info *ui = NULL;
	int err;

	err = sbi_stage_block(sbi, &uaddr->oaddr, &ubi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_ui(sbi, uaddr, ubi, &ui);
	if (err) {
		return err;
	}
	err = silofs_ui_verify_view(ui);
	if (err) {
		/* TODO: unbind forget here */
		return err;
	}
	*out_ui = ui;
	return 0;
}

static int sbi_stage_spnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_try_stage_cached_spnode(sbi, uaddr, out_sni);
	if (!err) {
		return 0; /* cache hit */
	}
	err = sbi_stage_spmap_at(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);
	silofs_sni_rebind_view(sni);
	silofs_sni_update_staged(sni);

	*out_sni = sni;
	return 0;
}

static void sbi_update_uspace_meta(struct silofs_sb_info *sbi,
                                   enum silofs_stype stype)
{
	const struct silofs_space_stat sp_st = {
		.uspace_nmeta = stype_ssize(stype)
	};
	silofs_sbi_update_stats(sbi, &sp_st);
}

static void sbi_make_blobid_for(const struct silofs_sb_info *sbi,
                                enum silofs_stype stype, size_t nobjs,
                                size_t height, struct silofs_blobid *out_bid)
{
	struct silofs_metaid tree_id;
	const size_t obj_size = stype_size(stype);

	silofs_sbi_main_treeid(sbi, &tree_id);
	silofs_blobid_make(out_bid, &tree_id, obj_size, nobjs, height);
}

static int sbi_spawn_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sbi->sb->sb_usm.su_child);
	const size_t height = SILOFS_SPNODE_HEIGHT_MAX;
	int err;

	sbi_make_blobid_for(sbi, SILOFS_STYPE_SPNODE, nchilds, height, &bid);
	err = sbi_spawn_blob_at(sbi, &bid, &bli);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_blob(sbi, &bli->bl_bid);
	return 0;
}

static int sbi_stage_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;

	silofs_sbi_main_blobid(sbi, &bid);
	return sbi_stage_blob_at(sbi, &bid, &bli);
}

static int sbi_require_main_blob(struct silofs_sb_info *sbi)
{
	int err;

	if (silofs_sbi_has_main_blob(sbi)) {
		err = sbi_stage_main_blob(sbi);
	} else {
		err = sbi_spawn_main_blob(sbi);
	}
	return err;
}

static int sbi_spawn_spmap(struct silofs_sb_info *sbi,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_unode_info **out_ui)
{
	int err;
	struct silofs_ubk_info *ubi = NULL;

	err = sbi_stage_block(sbi, &uaddr->oaddr, &ubi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_ui(sbi, uaddr, ubi, out_ui);
	if (err) {
		return err;
	}
	ui_stamp_mark_visible(*out_ui);
	return 0;
}

static int sbi_spawn_top_spnode_of(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;
	const size_t height = silofs_sbi_space_tree_height(sbi) - 1;
	int err;

	err = sbi_require_main_blob(sbi);
	if (err) {
		return err;
	}

	silofs_vrange_of_spnode(&vrange, height, voff);
	silofs_sbi_main_child_at(sbi, voff, &uaddr);

	err = sbi_spawn_spmap(sbi, &uaddr, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);
	silofs_sni_rebind_view(sni);
	silofs_sni_setup_spawned(sni, height, &vrange);
	*out_sni = sni;
	return 0;
}

static int sbi_spawn_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = sbi_spawn_top_spnode_of(sbi, voff, &sni);
	if (err) {
		return err;
	}
	sbi_update_uspace_meta(sbi, ui_stype(&sni->sn_ui));
	*out_sni = sni;
	return 0;
}

static int sbi_clone_top_spnode(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_curr,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_vrange vrange;
	int err;

	silofs_sni_vspace_range(sni_curr, &vrange);

	sni_incref(sni_curr);
	err = sbi_spawn_top_spnode(sbi, vrange.beg, out_sni);
	if (!err) {
		silofs_sni_clone_childs(*out_sni, sni_curr);
		silofs_sbi_bind_child(sbi, *out_sni);
	}
	sni_decref(sni_curr);
	return err;
}

static int sbi_stage_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;

	err = silofs_sbi_child_at(sbi, voff, &uaddr);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode_at(sbi, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sni(sbi, sni, stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_top_spnode(sbi, sni, &sni);
	if (err) {
		return err;
	}
out_ok:
	*out_sni = sni;
	return 0;
}

static int sbi_stage_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;

	silofs_sni_main_blob(sni, &bid);
	return sbi_stage_blob_at(sbi, &bid, &bli);
}

static int sbi_spawn_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sni->sn->sn_child);
	const size_t height = silofs_sni_child_height(sni);
	const enum silofs_stype stype = silofs_sni_child_stype(sni);
	int err;

	sbi_make_blobid_for(sbi, stype, nchilds, height, &bid);
	err = sbi_spawn_blob_at(sbi, &bid, &bli);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_blob(sni, &bli->bl_bid);
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

static int sbi_spawn_sub_spnode_of(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spnode_info *sni_parent,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;
	const size_t height = silofs_sni_height(sni_parent) - 1;
	int err;

	err = sbi_require_spnode_main_blob(sbi, sni_parent);
	if (err) {
		return err;
	}

	silofs_vrange_of_spnode(&vrange, height, voff);
	silofs_sni_resolve_main_child(sni_parent, voff, &uaddr);

	err = sbi_spawn_spmap(sbi, &uaddr, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);
	silofs_sni_rebind_view(sni);
	silofs_sni_setup_spawned(sni, height, &vrange);
	*out_sni = sni;
	return 0;
}

static int
sbi_spawn_sub_spnode(struct silofs_sb_info *sbi,
                     struct silofs_spnode_info *sni_parent,
                     loff_t voff, struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_spawn_sub_spnode_of(sbi, voff, sni_parent, &sni);
	if (err) {
		return err;
	}
	sbi_update_uspace_meta(sbi, ui_stype(&sni->sn_ui));
	*out_sni = sni;
	return 0;
}

static int sbi_clone_sub_spnode(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                struct silofs_spnode_info *sni_curr,
                                struct silofs_spnode_info **out_sni)
{
	const loff_t voff = silofs_sni_base_voff(sni_curr);
	int err;

	sni_incref2(sni_parent, sni_curr);
	err = sbi_spawn_sub_spnode(sbi, sni_parent, voff, out_sni);
	if (!err) {
		silofs_sni_clone_childs(*out_sni, sni_curr);
		silofs_sni_bind_child_spnode(sni_parent, *out_sni);
	}
	sni_decref2(sni_curr, sni_parent);
	return err;
}

static int sbi_stage_sub_spnode(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                loff_t voff, enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;

	err = silofs_sni_resolve_child(sni_parent, voff, &uaddr);
	if (err) {
		return err;
	}
	silofs_assert_eq(uaddr.stype, SILOFS_STYPE_SPNODE);
	err = sbi_stage_spnode_at(sbi, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sni(sbi, sni, stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_sub_spnode(sbi, sni_parent, sni, &sni);
	if (err) {
		return err;
	}
out_ok:
	*out_sni = sni;
	return 0;
}

static int
sbi_stage_child_spnode(struct silofs_sb_info *sbi, loff_t voff,
                       struct silofs_spnode_info *sni_parent,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_spnode_info **out_sni)
{
	int err;

	if (sni_parent == NULL) {
		err = sbi_stage_top_spnode(sbi, voff, stg_flags, out_sni);
	} else {
		err = sbi_stage_sub_spnode(sbi, sni_parent,
		                           voff, stg_flags, out_sni);
	}
	return err;
}

static int sbi_stage_spnodes_to(struct silofs_sb_info *sbi, loff_t voff,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spnode_info *sni_parent = NULL;
	const size_t spleaf_height = SILOFS_SPLEAF_HEIGHT;
	size_t height;
	int err;

	height = silofs_sbi_space_tree_height(sbi);
	while (--height > spleaf_height) {
		err = sbi_stage_child_spnode(sbi, voff, sni_parent,
		                             stg_flags, &sni);
		if (err) {
			return err;
		}
		sni_parent = sni;
	}
	silofs_assert_eq(silofs_sni_height(sni), 2);
	*out_sni = sni;
	return 0;
}

int silofs_sbi_stage_spnode(struct silofs_sb_info *sbi, loff_t voff,
                            enum silofs_stage_flags stg_flags,
                            struct silofs_spnode_info **out_sni)
{
	int err;

	err = sbi_find_cached_spnode(sbi, voff, stg_flags, out_sni);
	if (!err) {
		return 0;
	}
	err = sbi_stage_spnodes_to(sbi, voff, stg_flags, out_sni);
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
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;

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

static int sbi_spawn_spleaf_of(struct silofs_sb_info *sbi,
                               struct silofs_spnode_info *sni,
                               loff_t voff, enum silofs_stype stype_sub,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_require_spnode_main_blob(sbi, sni);
	if (err) {
		return err;
	}

	silofs_vrange_of_spleaf(&vrange, voff);
	silofs_sni_resolve_main_child(sni, voff, &uaddr);

	err = sbi_spawn_spmap(sbi, &uaddr, &ui);
	if (err) {
		return err;
	}
	sli = silofs_sli_from_ui(ui);
	silofs_sli_rebind_view(sli);
	silofs_sli_setup_spawned(sli, &vrange, stype_sub);
	*out_sli = sli;
	return 0;
}

static int sbi_spawn_spleaf_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spleaf_info *sli)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sli->sl->sl_bkr);
	int err;

	sbi_make_blobid_for(sbi, SILOFS_STYPE_ANONBK, nchilds, 0, &bid);
	err = sbi_spawn_blob_at(sbi, &bid, &bli);
	if (err) {
		return err;
	}
	silofs_sli_bind_main_blob(sli, &bli->bl_bid);
	return 0;
}

static int sbi_spawn_spleaf(struct silofs_sb_info *sbi,
                            struct silofs_spnode_info *sni,
                            loff_t voff, enum silofs_stype stype_sub,
                            struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_spawn_spleaf_of(sbi, sni, voff, stype_sub, &sli);
	if (err) {
		return err;
	}
	err = sbi_spawn_spleaf_main_blob(sbi, sli);
	if (err) {
		return err;
	}
	sbi_update_uspace_meta(sbi, ui_stype(&sli->sl_ui));
	*out_sli = sli;
	return 0;
}

static int sbi_clone_sub_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                struct silofs_spleaf_info *sli_curr,
                                struct silofs_spleaf_info **out_sli)
{
	const loff_t voff = silofs_sli_base_voff(sli_curr);
	const enum silofs_stype stype_sub = silofs_sli_stype_sub(sli_curr);
	int err;

	sni_sli_incref(sni_parent, sli_curr);
	err = sbi_spawn_spleaf(sbi, sni_parent, voff, stype_sub, out_sli);
	if (!err) {
		silofs_sli_clone_childs(*out_sli, sli_curr);
		silofs_sni_bind_child_spleaf(sni_parent, *out_sli);
	}
	sni_sli_decref(sni_parent, sli_curr);
	return err;
}

static int sbi_try_stage_cached_spleaf(struct silofs_sb_info *sbi,
                                       const struct silofs_uaddr *uaddr,
                                       struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = sbi_lookup_cached_ui(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	return 0;
}

static int sbi_stage_spleaf_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_try_stage_cached_spleaf(sbi, uaddr, out_sli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = sbi_stage_spmap_at(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	sli = silofs_sli_from_ui(ui);
	silofs_sli_rebind_view(sli);
	silofs_sli_update_staged(sli);
	*out_sli = sli;
	return 0;
}

static int sbi_stage_sub_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                loff_t voff, enum silofs_stage_flags stg_flags,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_resolve_child(sni_parent, voff, &uaddr);
	if (err) {
		return err;
	}
	err = sbi_stage_spleaf_at(sbi, &uaddr, &sli);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sli(sbi, sli, stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_sub_spleaf(sbi, sni_parent, sli, &sli);
	if (err) {
		return err;
	}
out_ok:
	*out_sli = sli;
	return 0;
}

int silofs_sbi_stage_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                            enum silofs_stage_flags stg_flags,
                            struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = sbi_find_cached_spleaf(sbi, voff, stg_flags, out_sli);
	if (!err) {
		return 0;
	}
	err = sbi_stage_spnodes_to(sbi, voff, stg_flags, &sni);
	if (err) {
		return err;
	}
	err = sbi_stage_sub_spleaf(sbi, sni, voff, stg_flags, out_sli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_spleaf_of(struct silofs_sb_info *sbi,
                               struct silofs_spnode_info *sni, loff_t voff,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_spleaf_info **out_sli)
{
	int ret;

	sni_incref(sni);
	ret = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, out_sli);
	sni_decref(sni);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_bind_spleaf_at(struct silofs_sb_info *sbi,
                                    struct silofs_spnode_info *sni,
                                    const struct silofs_vaddr *vaddr)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	sni_incref(sni);
	err = sbi_spawn_spleaf(sbi, sni, vaddr->voff, vaddr->stype, &sli);
	if (!err) {
		silofs_sni_bind_child_spleaf(sni, sli);
		silofs_sbi_update_vlast_by_spleaf(sbi, sli);
	}
	sni_decref(sni);
	return err;
}

static int sbi_stage_mut_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni, loff_t voff,
                                struct silofs_spleaf_info **out_sli)
{
	return silofs_sbi_stage_spleaf_of(sbi, sni, voff,
	                                  SILOFS_STAGE_MUTABLE, out_sli);
}

static int sbi_require_spleaf_at(struct silofs_sb_info *sbi,
                                 struct silofs_spnode_info *sni,
                                 const struct silofs_vaddr *vaddr)
{
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);
	int err;

	if (silofs_sni_has_child_at(sni, voff)) {
		err = sbi_stage_mut_spleaf(sbi, sni, voff, &sli);
	} else {
		err = sbi_spawn_bind_spleaf_at(sbi, sni, vaddr);
	}
	return err;
}

static int sbi_spawn_bind_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                     struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = sbi_spawn_top_spnode(sbi, voff, &sni);
	if (err) {
		return err;
	}
	silofs_sbi_bind_child(sbi, sni);
	*out_sni = sni;
	return 0;
}

static int
sbi_require_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_spnode_info **out_sni)
{
	int err;

	if (silofs_sbi_has_child_at(sbi, voff)) {
		err = sbi_stage_top_spnode(sbi, voff, stg_flags, out_sni);
	} else {
		err = sbi_spawn_bind_top_spnode(sbi, voff, out_sni);
	}
	return err;
}

static int
sbi_spawn_bind_sub_spnode(struct silofs_sb_info *sbi, loff_t voff,
                          struct silofs_spnode_info *sni_parent,
                          struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = sbi_spawn_sub_spnode(sbi, sni_parent, voff, &sni);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spnode(sni_parent, sni);
	*out_sni = sni;
	return 0;
}

static int
sbi_require_sub_spnode(struct silofs_sb_info *sbi,
                       struct silofs_spnode_info *sni_parent,
                       loff_t voff, enum silofs_stage_flags stg_flags,
                       struct silofs_spnode_info **out_sni)
{
	int err;

	if (silofs_sni_has_child_at(sni_parent, voff)) {
		err = sbi_stage_sub_spnode(sbi, sni_parent,
		                           voff, stg_flags, out_sni);
	} else {
		err = sbi_spawn_bind_sub_spnode(sbi, voff,
		                                sni_parent, out_sni);
	}
	return err;
}

static int
sbi_require_child_spnode(struct silofs_sb_info *sbi,
                         struct silofs_spnode_info *sni_parent,
                         loff_t voff, enum silofs_stage_flags stg_flags,
                         struct silofs_spnode_info **out_sni)
{
	int err;

	if (sni_parent == NULL) {
		err = sbi_require_top_spnode(sbi, voff, stg_flags, out_sni);
	} else {
		err = sbi_require_sub_spnode(sbi, sni_parent,
		                             voff, stg_flags, out_sni);
	}
	return err;
}

static int sbi_require_spnodes_to(struct silofs_sb_info *sbi, loff_t voff,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spnode_info **out_sni)
{

	struct silofs_spnode_info *sni = NULL;
	struct silofs_spnode_info *sni_parent = NULL;
	const size_t spleaf_height = SILOFS_SPLEAF_HEIGHT;
	size_t height;
	int err;

	height = silofs_sbi_space_tree_height(sbi);
	while (--height > spleaf_height) {
		err = sbi_require_child_spnode(sbi, sni_parent,
		                               voff, stg_flags, &sni);
		if (err) {
			return err;
		}
		sni_parent = sni;
	}
	*out_sni = sni;
	return 0;
}

int silofs_sbi_require_spmaps_at(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_flags stg_flags)
{
	struct silofs_spnode_info *sni = NULL;
	const loff_t voff = vaddr_off(vaddr);
	int err;

	err = sbi_require_spnodes_to(sbi, voff, stg_flags, &sni);
	if (err) {
		return err;
	}
	err = sbi_require_spleaf_at(sbi, sni, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_load_vbk(struct silofs_sb_info *sbi,
                              struct silofs_blob_info *bli,
                              const struct silofs_ovaddr *ova,
                              struct silofs_vbk_info **out_vbi)
{
	struct silofs_vbk_info *vbi = NULL;
	int ret;

	bli_incref(bli);
	ret = sbi_spawn_vbi(sbi, ova->vaddr.voff, &vbi);
	if (ret) {
		goto out;
	}
	ret = silofs_bli_load_bk(bli, vbi->vbk, &ova->oaddr);
	if (ret) {
		sbi_forget_cached_vbi(sbi, vbi);
		goto out;
	}
	*out_vbi = vbi;
out:
	bli_decref(bli);
	return ret;
}

static int sbi_stage_load_vblock(struct silofs_sb_info *sbi,
                                 const struct silofs_ovaddr *ova,
                                 struct silofs_vbk_info **out_vbi)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = sbi_stage_blob_of(sbi, &ova->oaddr, &bli);
	if (err) {
		return err;
	}
	err = sbi_spawn_load_vbk(sbi, bli, ova, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_stage_vblock(struct silofs_sb_info *sbi,
                            const struct silofs_ovaddr *ova,
                            struct silofs_vbk_info **out_vbi)
{
	int err;

	err = sbi_lookup_cached_vbi(sbi, ova->vaddr.voff, out_vbi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = sbi_stage_load_vblock(sbi, ova, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_resolve_rdonly(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_ovaddr *out_ova)
{
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	int err;

	err = silofs_sbi_stage_spleaf(sbi, voff, stg_flags, &sli);
	if (err) {
		return err;
	}
	silofs_sli_resolve_child(sli, vaddr, out_ova);
	return 0;
}

static int sbi_stage_vblock_of(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vbk_info **out_vbi)
{
	struct silofs_ovaddr ova;
	int err;

	err = sbi_resolve_rdonly(sbi, vaddr, &ova);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock(sbi, &ova, out_vbi);
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
	silofs_sni_vspace_range(sni, &vrange);
	err = sbi_reload_spleaf_at(sbi, sni, vrange.beg);
	sni_decref(sni);
	return err;
}

static void sbi_relax_bringup_cache(struct silofs_sb_info *sbi)
{
	silofs_cache_relax(sbi_cache(sbi), SILOFS_F_BRINGUP);
}

int silofs_sbi_reload_spmaps(struct silofs_sb_info *sbi)
{
	loff_t vend = silofs_sb_vspace_last(sbi->sb);
	struct silofs_spnode_info *sni = NULL;
	const size_t limit = SILOFS_SPMAP_NODE_NCHILDS;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	size_t cnt = 0;
	loff_t voff = 0;
	int err;

	while ((voff < vend) && (cnt++ < limit)) {
		if (!silofs_sbi_has_child_at(sbi, voff)) {
			break;
		}
		err = silofs_sbi_stage_spnode(sbi, voff, stg_flags, &sni);
		if (err) {
			return err;
		}
		err = sbi_reload_first_spleaf_of(sbi, sni);
		if (err) {
			return err;
		}
		sbi_relax_bringup_cache(sbi);

		voff = silofs_off_to_spnode_next(voff);
		sni = NULL;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_stage_spmaps_of(struct silofs_sb_info *sbi,
                               const struct silofs_ovaddr *ova,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_spnode_info **out_sni,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = ovaddr_voff(ova);
	int err;

	err = silofs_sbi_stage_spnode(sbi, voff, stg_flags, &sni);
	if (err) {
		return err;
	}
	err = silofs_sbi_stage_spleaf_of(sbi, sni, voff, stg_flags, &sli);
	if (err) {
		return err;
	}
	*out_sni = sni;
	*out_sli = sli;
	return 0;
}

static int sbi_resolve_vbks(struct silofs_sb_info *sbi,
                            const struct silofs_ovaddr *ova_src,
                            const struct silofs_ovaddr *ova_dst,
                            struct silofs_fiovec *out_fiov_src,
                            struct silofs_fiovec *out_fiov_dst)
{
	const struct silofs_blobid *bid_src = &ova_src->oaddr.bid;
	const struct silofs_blobid *bid_dst = &ova_dst->oaddr.bid;
	struct silofs_blob_info *bli_src = NULL;
	struct silofs_blob_info *bli_dst = NULL;
	int ret;

	ret = sbi_stage_blob_at(sbi, bid_src, &bli_src);
	if (ret) {
		goto out;
	}
	bli_incref(bli_src);

	ret = sbi_stage_blob_at(sbi, bid_dst, &bli_dst);
	if (ret) {
		goto out;
	}
	bli_incref(bli_dst);

	ret = silofs_bli_resolve_bk(bli_src, &ova_src->oaddr, out_fiov_src);
	if (ret) {
		goto out;
	}

	ret = silofs_bli_resolve_bk(bli_dst, &ova_dst->oaddr, out_fiov_dst);
	if (ret) {
		goto out;
	}
out:
	bli_decref(bli_dst);
	bli_decref(bli_src);
	return ret;
}

static int sbi_kcopy_vblock(struct silofs_sb_info *sbi,
                            const struct silofs_fiovec *fiov_src,
                            const struct silofs_fiovec *fiov_dst)
{
	struct silofs_fs_apex *apex = sbi_apex(sbi);

	return silofs_apex_kcopy(apex, fiov_src, fiov_dst, SILOFS_BK_SIZE);
}

static int sbi_clone_vblock(struct silofs_sb_info *sbi,
                            struct silofs_spleaf_info *sli,
                            const struct silofs_ovaddr *ova_src)
{
	struct silofs_ovaddr ova_dst;
	struct silofs_fiovec fiov_src;
	struct silofs_fiovec fiov_dst;
	const struct silofs_vaddr *vaddr_src = &ova_src->vaddr;
	int err;

	silofs_sli_resolve_main_child(sli, vaddr_src, &ova_dst);
	err = sbi_resolve_vbks(sbi, ova_src, &ova_dst, &fiov_src, &fiov_dst);
	if (err) {
		return err;
	}
	err = sbi_kcopy_vblock(sbi, &fiov_src, &fiov_dst);
	if (err) {
		return err;
	}
	silofs_sli_rebind_child(sli, &ova_dst);
	return 0;
}

static int sbi_clone_vblock_at(struct silofs_sb_info *sbi,
                               const struct silofs_ovaddr *ova)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;
	int err;

	err = sbi_stage_spmaps_of(sbi, ova, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = sbi_clone_vblock(sbi, sli, ova);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_resolve_ova(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_flags stg_flags,
                           struct silofs_ovaddr *out_ova)
{
	int ret;

	ret = sbi_resolve_rdonly(sbi, vaddr, out_ova);
	if (ret) {
		return ret;
	}
	ret = sbi_inspect_ova(sbi, out_ova, stg_flags);
	if (ret != -EPERM) {
		return ret;
	}
	ret = sbi_clone_vblock_at(sbi, out_ova);
	if (ret) {
		return ret;
	}
	ret = sbi_resolve_rdonly(sbi, vaddr, out_ova);
	if (ret) {
		return ret;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_spawn_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_ovaddr *ova_want,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_ovaddr ova;
	struct silofs_vbk_info *vbi = NULL;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_sbi_resolve_ova(sbi, &ova_want->vaddr,
	                             SILOFS_STAGE_MUTABLE, &ova);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock_of(sbi, &ova_want->vaddr, &vbi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_vi(sbi, &ova.vaddr, vbi, &vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int sbi_require_stable_at(struct silofs_sb_info *sbi,
                                 const struct silofs_ovaddr *ova,
                                 enum silofs_stage_flags stg_flags)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_spmaps_of(sbi, ova, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = silofs_sli_check_stable_at(sli, &ova->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_ovaddr *ova,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = sbi_require_stable_at(sbi, ova, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_sbi_spawn_vnode_at(sbi, ova, &vi);
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
                              const struct silofs_iovaddr *iova,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_sbi_stage_vnode_at(sbi, &iova->ova, stg_flags, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);

	silofs_ii_rebind_view(ii, iova->ino);
	silofs_ii_refresh_atime(ii, true);
	*out_ii = ii;
	return 0;
}
