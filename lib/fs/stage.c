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

static loff_t uvaddr_voff(const struct silofs_uvaddr *uva)
{
	return vaddr_off(&uva->vaddr);
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

	vi->v_ti.t_apex = apex;
	vi->v_ti.t_crypto = apex->ap_crypto;
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

static int sbi_spawn_blob(const struct silofs_sb_info *sbi,
                          const struct silofs_blobid *blobid,
                          struct silofs_blob_info **out_bli)
{
	return silofs_repo_spawn_blob(sbi->s_repo, blobid, out_bli);
}

static int sbi_stage_blob(const struct silofs_sb_info *sbi,
                          const struct silofs_blobid *blobid,
                          struct silofs_blob_info **out_bli)
{
	return silofs_repo_stage_blob(sbi->s_repo, blobid, out_bli);
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

static bool sbi_ismutable_blobid(const struct silofs_sb_info *sbi,
                                 const struct silofs_blobid *blobid)
{
	struct silofs_xid tree_id;

	silofs_sbi_treeid(sbi, &tree_id);
	return silofs_xid_isequal(&tree_id, &blobid->xxid.u.tid.tree_id);
}

static bool sbi_ismutable_oaddr(const struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr)
{
	return sbi_ismutable_blobid(sbi, &oaddr->blobid);
}

static int sbi_inspect_oaddr(const struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             enum silofs_stage_flags stg_flags)
{
	return (stage_mut(stg_flags) &&
	        !sbi_ismutable_oaddr(sbi, oaddr)) ? -EPERM : 0;
}

static int sbi_inspect_uva(const struct silofs_sb_info *sbi,
                           const struct silofs_uvaddr *uva,
                           enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_oaddr(sbi, &uva->uaddr.oaddr, stg_flags);
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

int silofs_sbi_stage_ubk(struct silofs_sb_info *sbi,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_ubk_info **out_ubi)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	err = silofs_repo_stage_ubk(sbi->s_repo, oaddr, &ubi);
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
	err = silofs_repo_stage_ubk(sbi->s_repo, oaddr, &ubi);
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

static int sbi_stage_spnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	int err;

	err = silofs_repo_stage_spnode(sbi->s_repo, uaddr, out_sni);
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
	err = silofs_repo_stage_spnode(sbi->s_repo, uaddr, out_sni);
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
                                struct silofs_blobid *out_blobid)
{
	struct silofs_xid tree_id;
	const size_t obj_size = stype_size(stype);

	silofs_sbi_treeid(sbi, &tree_id);
	silofs_blobid_make_tas(out_blobid, &tree_id, obj_size, nobjs);
}

static int sbi_spawn_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	const size_t nslots = ARRAY_SIZE(sbi->sb->sb_subref);
	int err;

	sbi_make_blobid_for(sbi, SILOFS_STYPE_SPNODE, nslots, &blobid);
	err = sbi_spawn_blob(sbi, &blobid, &bli);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_blob(sbi, &bli->blobid);
	return 0;
}

static int sbi_stage_main_blob(struct silofs_sb_info *sbi)
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
		err = sbi_stage_main_blob(sbi);
	} else {
		err = sbi_spawn_main_blob(sbi);
	}
	return err;
}

static int sbi_spawn_spnode(const struct silofs_sb_info *sbi,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spnode_info **out_sni)
{
	int err;

	err = silofs_repo_spawn_spnode(sbi->s_repo, uaddr, out_sni);
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
	err = silofs_repo_spawn_spnode(sbi->s_repo, uaddr, out_sni);
	if (err) {
		goto out_err;
	}
out_ok:
	sbi_bind_sni_to_apex(sbi, *out_sni);
	return 0;
out_err:
	return err;
}

static int sbi_spawn_top_spnode_of(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = sbi_require_main_blob(sbi);
	if (err) {
		return err;
	}
	silofs_sbi_main_child_at(sbi, voff, &uaddr);

	err = sbi_spawn_spnode(sbi, &uaddr, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_setup_spawned(*out_sni, sbi_uaddr(sbi), voff);
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
		silofs_sni_clone_subrefs(*out_sni, sni_curr);
		silofs_sbi_bind_child(sbi, *out_sni);
	}
	sni_decref(sni_curr);
	return err;
}

static int sbi_stage_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_ulink ulink;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sbi_subref_of(sbi, voff, &ulink);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode_at(sbi, &ulink.child, &sni);
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
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;

	silofs_sni_main_blob(sni, &blobid);
	return sbi_stage_blob(sbi, &blobid, &bli);
}

static int sbi_spawn_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sni->sn->sn_subref);
	const enum silofs_stype stype = silofs_sni_child_stype(sni);
	int err;

	sbi_make_blobid_for(sbi, stype, nchilds, &blobid);
	err = sbi_spawn_blob(sbi, &blobid, &bli);
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

static int sbi_spawn_sub_spnode_of(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spnode_info *parent,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = sbi_require_spnode_main_blob(sbi, parent);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_child(parent, voff, &uaddr);

	err = sbi_spawn_spnode(sbi, &uaddr, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_setup_spawned(*out_sni, sni_uaddr(parent), voff);
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
		silofs_sni_clone_subrefs(*out_sni, sni_curr);
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
	struct silofs_ulink ulink;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sni_subref_of(sni_parent, voff, &ulink);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode_at(sbi, &ulink.child, &sni);
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

int silofs_sbi_stage_child_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                  struct silofs_spnode_info *sni_parent,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spnode_info **out_sni)
{
	int err;

	sni_incref(sni_parent);
	err = sbi_stage_child_spnode(sbi, voff, sni_parent,
	                             stg_flags, out_sni);
	sni_decref(sni_parent);
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

static int sbi_spawn_spleaf_at(const struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	int err;

	err = silofs_repo_spawn_spleaf(sbi->s_repo, uaddr, out_sli);
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
	err = silofs_repo_spawn_spleaf(sbi->s_repo, uaddr, out_sli);
	if (err) {
		goto out_err;
	}
out_ok:
	sbi_bind_sli_to_apex(sbi, *out_sli);
	return 0;
out_err:
	return err;
}

static int sbi_spawn_spleaf_of(struct silofs_sb_info *sbi,
                               struct silofs_spnode_info *sni,
                               loff_t voff, enum silofs_stype stype_sub,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr;
	int err;

	err = sbi_require_spnode_main_blob(sbi, sni);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_child(sni, voff, &uaddr);

	err = sbi_spawn_spleaf_at(sbi, &uaddr, out_sli);
	if (err) {
		return err;
	}
	silofs_sli_setup_spawned(*out_sli, sni_uaddr(sni), voff, stype_sub);
	return 0;
}

static int sbi_spawn_spleaf_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spleaf_info *sli)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	const size_t nslots = ARRAY_SIZE(sli->sl->sl_subref);
	int err;

	sbi_make_blobid_for(sbi, SILOFS_STYPE_ANONBK, nslots, &blobid);
	err = sbi_spawn_blob(sbi, &blobid, &bli);
	if (err) {
		return err;
	}
	silofs_sli_bind_main_blob(sli, &bli->blobid);
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
	const loff_t voff = silofs_sli_voff_beg(sli_curr);
	const enum silofs_stype stype_sub = silofs_sli_stype_sub(sli_curr);
	int err;

	sni_sli_incref(sni_parent, sli_curr);
	err = sbi_spawn_spleaf(sbi, sni_parent, voff, stype_sub, out_sli);
	if (!err) {
		silofs_sli_clone_subrefs(*out_sli, sli_curr);
		silofs_sni_bind_child_spleaf(sni_parent, *out_sli);
	}
	sni_sli_decref(sni_parent, sli_curr);
	return err;
}

static int sbi_stage_spleaf_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	int err;

	err = silofs_repo_stage_spleaf(sbi->s_repo, uaddr, out_sli);
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
	err = silofs_repo_stage_spleaf(sbi->s_repo, uaddr, out_sli);
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

static int sbi_stage_sub_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                loff_t voff, enum silofs_stage_flags stg_flags,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_ulink ulink;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_subref_of(sni_parent, voff, &ulink);
	if (err) {
		return err;
	}
	err = sbi_stage_spleaf_at(sbi, &ulink.child, &sli);
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

static struct silofs_spamaps *sbi_spamaps(const struct silofs_sb_info *sbi)
{
	struct silofs_cache *cache = sbi_cache(sbi);

	return &cache->c_spam;
}

static int sbi_spawn_bind_spleaf_at(struct silofs_sb_info *sbi,
                                    struct silofs_spnode_info *sni,
                                    loff_t voff, enum silofs_stype stype)
{
	struct silofs_vrange vrange = { .stepsz = -1 };
	struct silofs_spamaps *spam = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_spawn_spleaf(sbi, sni, voff, stype, &sli);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spleaf(sni, sli);
	silofs_sbi_update_vlast_by_spleaf(sbi, sli);

	/*
	 * New space leaf case: add entire range at once, ignore possible
	 * out-of-memory) failure.
	 */
	silofs_sli_vspace_range(sli, &vrange);
	spam = sbi_spamaps(sbi);
	silofs_spamaps_store(spam, stype, vrange.beg, vrange.len);
	return 0;
}

static int sbi_stage_mut_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_spleaf_info *sli = NULL;
	enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;

	return silofs_sbi_stage_spleaf_of(sbi, sni, voff, stg_flags, &sli);
}

static int sbi_require_spleaf_at(struct silofs_sb_info *sbi,
                                 struct silofs_spnode_info *sni,
                                 const struct silofs_vaddr *vaddr)
{
	const loff_t voff = vaddr_off(vaddr);
	const enum silofs_stype stype = vaddr_stype(vaddr);
	int err;

	sni_incref(sni);
	if (silofs_sni_has_child_at(sni, voff)) {
		err = sbi_stage_mut_spleaf(sbi, sni, voff);
	} else {
		err = sbi_spawn_bind_spleaf_at(sbi, sni, voff, stype);
	}
	sni_decref(sni);
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
                              const struct silofs_uvaddr *uva,
                              struct silofs_vbk_info **out_vbi)
{
	struct silofs_vbk_info *vbi = NULL;
	int ret;

	bli_incref(bli);
	ret = sbi_spawn_vbi(sbi, uva->vaddr.voff, &vbi);
	if (ret) {
		goto out;
	}
	ret = silofs_bli_load_bk(bli, &uva->uaddr.oaddr, vbi->vbk);
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
                              const struct silofs_uvaddr *uva,
                              struct silofs_vbk_info **out_vbi)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = sbi_stage_blob(sbi, uaddr_blobid(&uva->uaddr), &bli);
	if (err) {
		return err;
	}
	err = sbi_spawn_load_vbk(sbi, bli, uva, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_stage_vblock(struct silofs_sb_info *sbi,
                            const struct silofs_uvaddr *uva,
                            struct silofs_vbk_info **out_vbi)
{
	int err;

	err = sbi_lookup_cached_vbi(sbi, uva->vaddr.voff, out_vbi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = sbi_stage_load_vbk(sbi, uva, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_resolve_rdonly(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_uvaddr *out_uva)
{
	struct silofs_ulink bk_ulink;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);
	const struct silofs_blobid *blobid = NULL;
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
	blobid = uaddr_blobid(&bk_ulink.child);
	silofs_uvaddr_setup_by(out_uva, blobid, vaddr);
	return 0;
}

static int sbi_stage_vblock_of(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vbk_info **out_vbi)
{
	struct silofs_uvaddr uva;
	int err;

	err = sbi_resolve_rdonly(sbi, vaddr, &uva);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock(sbi, &uva, out_vbi);
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
	const size_t limit = SILOFS_UNODE_NCHILDS;
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
                               const struct silofs_uvaddr *uva,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_spnode_info **out_sni,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = uvaddr_voff(uva);
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

static int bli_resolve_bk(struct silofs_blob_info *bli,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_xiovec *xiov)
{
	struct silofs_oaddr bk_oaddr;

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->blobid, oaddr_lba(oaddr));
	return silofs_bli_resolve(bli, &bk_oaddr, xiov);
}

static int sbi_resolve_vbks(struct silofs_sb_info *sbi,
                            const struct silofs_uaddr *uaddr_src,
                            const struct silofs_uaddr *uaddr_dst,
                            struct silofs_xiovec *out_xiov_src,
                            struct silofs_xiovec *out_xiov_dst)
{
	const struct silofs_oaddr *oaddr_src = &uaddr_src->oaddr;
	const struct silofs_oaddr *oaddr_dst = &uaddr_dst->oaddr;
	struct silofs_blob_info *bli_src = NULL;
	struct silofs_blob_info *bli_dst = NULL;
	int ret;

	ret = sbi_stage_blob(sbi, &oaddr_src->blobid, &bli_src);
	if (ret) {
		goto out;
	}
	bli_incref(bli_src);

	ret = sbi_stage_blob(sbi, &oaddr_dst->blobid, &bli_dst);
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

	return silofs_apex_kcopy(apex, xiov_src, xiov_dst, SILOFS_BK_SIZE);
}

static int sbi_clone_vblock(struct silofs_sb_info *sbi,
                            struct silofs_spleaf_info *sli,
                            const struct silofs_uvaddr *uva_src)
{
	struct silofs_ulink ulink_dst;
	struct silofs_xiovec xiov_src;
	struct silofs_xiovec xiov_dst;
	const loff_t voff = uva_src->vaddr.voff;
	int err;

	silofs_sli_resolve_main_at(sli, voff, &ulink_dst);
	err = sbi_resolve_vbks(sbi, &uva_src->uaddr, &ulink_dst.child,
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
                               const struct silofs_uvaddr *uva)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;
	int err;

	err = sbi_stage_spmaps_of(sbi, uva, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = sbi_clone_vblock(sbi, sli, uva);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_resolve_uva(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_flags stg_flags,
                           struct silofs_uvaddr *out_uva)
{
	int ret;

	ret = sbi_resolve_rdonly(sbi, vaddr, out_uva);
	if (ret) {
		return ret;
	}
	ret = sbi_inspect_uva(sbi, out_uva, stg_flags);
	if (ret != -EPERM) {
		return ret;
	}
	ret = sbi_clone_vblock_at(sbi, out_uva);
	if (ret) {
		return ret;
	}
	ret = sbi_resolve_rdonly(sbi, vaddr, out_uva);
	if (ret) {
		return ret;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_spawn_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_uvaddr *uva_want,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_uvaddr uva;
	struct silofs_vbk_info *vbi = NULL;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_sbi_resolve_uva(sbi, &uva_want->vaddr,
	                             SILOFS_STAGE_MUTABLE, &uva);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock_of(sbi, &uva_want->vaddr, &vbi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_vi(sbi, &uva.vaddr, vbi, &vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int sbi_require_stable_at(struct silofs_sb_info *sbi,
                                 const struct silofs_uvaddr *uva,
                                 enum silofs_stage_flags stg_flags)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = sbi_stage_spmaps_of(sbi, uva, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = silofs_sli_check_stable_at(sli, &uva->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static const struct silofs_mdigest *
sbi_mdigest(const struct silofs_sb_info *sbi)
{
	const struct silofs_fs_apex *apex = sbi_apex(sbi);

	return &apex->ap_crypto->md;
}

int silofs_sbi_stage_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_uvaddr *uva,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = sbi_require_stable_at(sbi, uva, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_sbi_spawn_vnode_at(sbi, uva, &vi);
	if (err) {
		return err;
	}
	err = silofs_vi_verify_view(vi, sbi_mdigest(sbi));
	if (err) {
		sbi_forget_cached_vi(sbi, vi);
		return err;
	}
	*out_vi = vi;
	return 0;
}

int silofs_sbi_stage_inode_at(struct silofs_sb_info *sbi,
                              const struct silofs_iuvaddr *iuva,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_sbi_stage_vnode_at(sbi, &iuva->uva, stg_flags, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);

	silofs_ii_rebind_view(ii, iuva->ino);
	silofs_ii_refresh_atime(ii, true);
	*out_ii = ii;
	return 0;
}
