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
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs/private.h>

#define SILOFS_EPERM    (1000 + EPERM)


struct silofs_stage_ctx {
	struct silofs_fs_uber          *uber;
	struct silofs_sb_info          *sbi;
	struct silofs_spnode_info      *sni4;
	struct silofs_spnode_info      *sni3;
	struct silofs_spnode_info      *sni2;
	struct silofs_spleaf_info      *sli;
	const struct silofs_vaddr      *vaddr;
	silofs_lba_t                    bk_lba;
	loff_t                          bk_voff;
	loff_t                          voff;
	enum silofs_stage_mode          stg_mode;
	enum silofs_stype               vspace;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool is_low_resource_error(int err)
{
	return (err == -ENOMEM) || (err == -EMFILE) || (err == -ENFILE);
}

static bool stage_ro(enum silofs_stage_mode stg_mode)
{
	return (stg_mode & SILOFS_STAGE_RO) > 0;
}

static bool stage_rw(enum silofs_stage_mode stg_mode)
{
	return (stg_mode & SILOFS_STAGE_RW) > 0;
}

static loff_t vaddr_bk_voff(const struct silofs_vaddr *vaddr)
{
	return off_align_to_bk(vaddr->voff);
}

static void voaddr_by(struct silofs_voaddr *voa,
                      const struct silofs_blobid *blobid,
                      const struct silofs_vaddr *vaddr)
{
	silofs_voaddr_setup_by(voa, blobid, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_sb_info *sbi,
                       struct silofs_vbk_info *vbi)
{
	struct silofs_fs_uber *uber = sbi_uber(sbi);

	vi->v_si.s_uber = uber;
	/* TODO: move to lower level */
	vi->v_si.s_md = &vi->v_si.s_ce.ce_cache->c_mdigest;
	vi->v_sbi = sbi;
	silofs_vi_attach_to(vi, vbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void sbi_log_cache_stat(const struct silofs_sb_info *sbi)
{
	const struct silofs_cache *cache = sbi_cache(sbi);

	log_dbg("cache-stat: dq_accum_nbytes=%lu " \
	        "ubi=%lu ui=%lu vbi=%lu vi=%lu bli=%lu",
	        cache->c_dq.dq_accum_nbytes, cache->c_ubi_lm.lm_lru.sz,
	        cache->c_ui_lm.lm_lru.sz, cache->c_vbi_lm.lm_lru.sz,
	        cache->c_vi_lm.lm_lru.sz, cache->c_bli_lm.lm_lru.sz);
}

static int sbi_lookup_cached_vbi(struct silofs_sb_info *sbi,
                                 loff_t voff, enum silofs_stype vspace,
                                 struct silofs_vbk_info **out_vbi)
{
	*out_vbi = silofs_cache_lookup_vbk(sbi_cache(sbi), voff, vspace);
	return (*out_vbi != NULL) ? 0 : -ENOENT;
}

static void sbi_forget_cached_vbi(const struct silofs_sb_info *sbi,
                                  struct silofs_vbk_info *vbi)
{
	silofs_cache_forget_vbk(sbi_cache(sbi), vbi);
}

static int sbi_spawn_cached_vbi(struct silofs_sb_info *sbi,
                                loff_t voff, enum silofs_stype vspace,
                                struct silofs_vbk_info **out_vbi)
{
	*out_vbi = silofs_cache_spawn_vbk(sbi_cache(sbi), voff, vspace);
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

	err = silofs_uber_flush_dirty(sbi_uber(sbi), SILOFS_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: ndirty=%lu err=%d",
		        cache->c_dq.dq_accum_nbytes, err);
	}
	return err;
}

static int sbi_spawn_vbi(struct silofs_sb_info *sbi,
                         loff_t voff, enum silofs_stype vspace,
                         struct silofs_vbk_info **out_vbi)
{
	int err;

	err = sbi_spawn_cached_vbi(sbi, voff, vspace, out_vbi);
	if (!err) {
		goto out_ok;
	}
	err = sbi_commit_dirty(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_spawn_cached_vbi(sbi, voff, vspace, out_vbi);
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

static int sbi_commit_and_relax(const struct silofs_sb_info *sbi)
{
	int err;

	err = sbi_commit_dirty(sbi);
	if (!err) {
		silofs_uber_relax_caches(sbi_uber(sbi), SILOFS_F_NOW);
	}
	return err;
}

static int sbi_stage_blob(const struct silofs_sb_info *sbi,
                          const struct silofs_blobid *blobid,
                          struct silofs_blob_info **out_bli)
{
	struct silofs_fs_uber *uber = sbi_uber(sbi);
	int err;

	err = silofs_stage_blob_at(uber, true, blobid, out_bli);
	if (!err) {
		goto out_ok;
	}
	if (!is_low_resource_error(err)) {
		return err;
	}
	err = sbi_commit_and_relax(sbi);
	if (err) {
		return err;
	}
	err = silofs_stage_blob_at(uber, true, blobid, out_bli);
	if (err) {
		return err;
	}
out_ok:
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
	struct silofs_treeid treeid;

	silofs_sbi_treeid(sbi, &treeid);
	return blobid_has_treeid(blobid, &treeid);
}

static bool sbi_ismutable_bkaddr(const struct silofs_sb_info *sbi,
                                 const struct silofs_bkaddr *bkaddr)
{
	return silofs_sbi_ismutable_blobid(sbi, &bkaddr->blobid);
}

static int sbi_inspect_bkaddr(const struct silofs_sb_info *sbi,
                              const struct silofs_bkaddr *bkaddr,
                              enum silofs_stage_mode stg_mode)
{
	if (!stage_rw(stg_mode)) {
		return 0;
	}
	if (sbi_ismutable_bkaddr(sbi, bkaddr)) {
		return 0;
	}
	return -SILOFS_EPERM;
}

static int sbi_inspect_cached_ui(const struct silofs_sb_info *sbi,
                                 const struct silofs_unode_info *ui,
                                 enum silofs_stage_mode stg_mode)
{
	return sbi_inspect_bkaddr(sbi, ui_bkaddr(ui), stg_mode);
}

static int sbi_inspect_cached_sni(const struct silofs_sb_info *sbi,
                                  const struct silofs_spnode_info *sni,
                                  enum silofs_stage_mode stg_mode)
{
	return sbi_inspect_cached_ui(sbi, &sni->sn_ui, stg_mode);
}

static int sbi_inspect_cached_sli(const struct silofs_sb_info *sbi,
                                  const struct silofs_spleaf_info *sli,
                                  enum silofs_stage_mode stg_mode)
{
	return sbi_inspect_cached_ui(sbi, &sli->sl_ui, stg_mode);
}

static enum silofs_stype sni_child_stype(const struct silofs_spnode_info *sni)
{
	enum silofs_stype stype;
	const enum silofs_height height = silofs_sni_height(sni);

	switch (height) {
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE3:
		stype = SILOFS_STYPE_SPNODE;
		break;
	case SILOFS_HEIGHT_SPNODE2:
		stype = SILOFS_STYPE_SPLEAF;
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_VDATA:
	default:
		stype = SILOFS_STYPE_NONE;
		break;
	}
	return stype;
}

static enum silofs_height
sni_child_height(const struct silofs_spnode_info *sni) {
	return silofs_sni_height(sni) - 1;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void stgc_setup(struct silofs_stage_ctx *stg_ctx,
                       struct silofs_sb_info *sbi,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stage_mode stg_mode)
{
	memset(stg_ctx, 0, sizeof(*stg_ctx));
	stg_ctx->uber = sbi_uber(sbi);
	stg_ctx->sbi = sbi;
	stg_ctx->vaddr = vaddr;
	stg_ctx->stg_mode = stg_mode;
	stg_ctx->vspace = vaddr->stype;
	stg_ctx->bk_voff = vaddr_bk_voff(vaddr);
	stg_ctx->bk_lba = off_to_lba(stg_ctx->bk_voff);
	stg_ctx->voff = vaddr->voff;
}


static int stgc_flush_and_relax(const struct silofs_stage_ctx *stg_ctx)
{
	const struct silofs_cache *cache = NULL;
	int err;

	err = silofs_uber_flush_dirty(stg_ctx->uber, SILOFS_F_NOW);
	if (err) {
		cache = sbi_cache(stg_ctx->sbi);
		log_dbg("commit dirty failure: ndirty=%lu err=%d",
		        cache->c_dq.dq_accum_nbytes, err);
		return err;
	}
	silofs_uber_relax_caches(stg_ctx->uber, SILOFS_F_NOW);
	return 0;
}

static int stgc_spawn_blob(const struct silofs_stage_ctx *stg_ctx,
                           const struct silofs_blobid *blobid,
                           enum silofs_stype stype_sub,
                           struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_spawn_blob_at(stg_ctx->uber, true, blobid, out_bli);
	if (!err) {
		goto out_ok;
	}
	if (!is_low_resource_error(err)) {
		return err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		return err;
	}
	err = silofs_spawn_blob_at(stg_ctx->uber, true, blobid, out_bli);
	if (err) {
		return err;
	}
out_ok:
	silofs_spi_update_blobs(stg_ctx->sbi->sb_spi, stype_sub, 1);
	return 0;
}

static int stgc_stage_blob(const struct silofs_stage_ctx *stg_ctx,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_stage_blob_at(stg_ctx->uber, true, blobid, out_bli);
	if (!err) {
		goto out_ok;
	}
	if (!is_low_resource_error(err)) {
		return err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		return err;
	}
	err = silofs_stage_blob_at(stg_ctx->uber, true, blobid, out_bli);
	if (err) {
		return err;
	}
out_ok:
	return 0;
}

static void
stgc_make_spmap_main_blobid(const struct silofs_stage_ctx *stg_ctx,
                            loff_t voff, enum silofs_height height,
                            struct silofs_blobid *out_blobid)
{
	struct silofs_treeid treeid;

	silofs_sbi_treeid(stg_ctx->sbi, &treeid);
	silofs_blobid_make_ta(out_blobid, &treeid, voff,
	                      height, stg_ctx->vspace);
}

static void
stgc_make_super_main_blobid(const struct silofs_stage_ctx *stg_ctx,
                            struct silofs_blobid *out_blobid)
{
	struct silofs_treeid treeid;

	silofs_sbi_treeid(stg_ctx->sbi, &treeid);
	silofs_blobid_make_ta(out_blobid, &treeid, 0,
	                      SILOFS_HEIGHT_SPNODE4,
	                      SILOFS_STYPE_SUPER);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stgc_update_space_stats(const struct silofs_stage_ctx *stg_ctx,
                                    const struct silofs_uaddr *uaddr)
{
	silofs_spi_update_objs(stg_ctx->sbi->sb_spi, uaddr->stype, 1);
	silofs_spi_update_bks(stg_ctx->sbi->sb_spi, uaddr->stype, 1);
}

static int stgc_spawn_super_main_blob(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	int err;

	stgc_make_super_main_blobid(stg_ctx, &blobid);
	err = stgc_spawn_blob(stg_ctx, &blobid, SILOFS_STYPE_SPNODE, &bli);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_blob(stg_ctx->sbi, &bli->blobid);
	return 0;
}

static int stgc_stage_super_main_blob(const struct silofs_stage_ctx *stg_ctx)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;

	silofs_sbi_main_blob(stg_ctx->sbi, &blobid);
	silofs_assert(!blobid_isnull(&blobid));
	return stgc_stage_blob(stg_ctx, &blobid, &bli);
}

static int stgc_require_super_main_blob(const struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (silofs_sbi_has_main_blob(stg_ctx->sbi)) {
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
	struct silofs_blob_info *bli = NULL;
	const loff_t voff = silofs_sni_base_voff(sni);
	const enum silofs_height height = sni_child_height(sni);
	const enum silofs_stype stype = sni_child_stype(sni);
	int err;

	stgc_make_spmap_main_blobid(stg_ctx, voff, height, &blobid);
	err = stgc_spawn_blob(stg_ctx, &blobid, stype, &bli);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_blob(sni, &bli->blobid);
	return 0;
}

static int stgc_stage_spnode_main_blob(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;

	silofs_sni_main_blob(sni, &blobid);
	return stgc_stage_blob(stg_ctx, &blobid, &bli);
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
	if (stage_ro(stg_ctx->stg_mode)) {
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
	if (height_upto <= SILOFS_HEIGHT_SPNODE4) {
		sni_incref(stg_ctx->sni4);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE3) {
		sni_incref(stg_ctx->sni3);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE2) {
		sni_incref(stg_ctx->sni2);
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
	struct silofs_vrange vrange;
	struct silofs_uakey uakey;
	struct silofs_cache *cache = sbi_cache(stg_ctx->sbi);

	silofs_vrange_setup_by(&vrange, height, stg_ctx->bk_voff);
	silofs_uakey_setup_by2(&uakey, &vrange, stg_ctx->vspace);
	*out_ui = silofs_cache_find_unode_by(cache, &uakey);
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

static void stgc_log_cache_stat(const struct silofs_stage_ctx *stg_ctx)
{
	sbi_log_cache_stat(stg_ctx->sbi);
}

static void stgc_bind_sni_to_uber(const struct silofs_stage_ctx *stg_ctx,
                                  struct silofs_spnode_info *sni)
{
	silofs_ui_bind_uber(&sni->sn_ui, stg_ctx->uber);
}

static int stgc_do_stage_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spnode_info **out_sni)
{
	return silofs_stage_spnode_at(stg_ctx->uber, true, uaddr, out_sni);
}

static int stgc_stage_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_do_stage_spnode_at(stg_ctx, uaddr, out_sni);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		goto out_err;
	}
	err = stgc_do_stage_spnode_at(stg_ctx, uaddr, out_sni);
	if (err) {
		goto out_err;
	}
out_ok:
	stgc_bind_sni_to_uber(stg_ctx, *out_sni);
	return 0;
out_err:
	stgc_log_cache_stat(stg_ctx);
	return err;
}

static int stgc_do_spawn_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spnode_info **out_sni)
{
	return silofs_spawn_spnode_at(stg_ctx->uber, true, uaddr, out_sni);
}

static int stgc_spawn_spnode_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	err = stgc_do_spawn_spnode_at(stg_ctx, uaddr, out_sni);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		goto out_err;
	}
	err = stgc_do_spawn_spnode_at(stg_ctx, uaddr, out_sni);
	if (err) {
		goto out_err;
	}
out_ok:
	stgc_bind_sni_to_uber(stg_ctx, *out_sni);
	return 0;
out_err:
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
	return silofs_stage_spleaf_at(stg_ctx->uber, true, uaddr, out_sli);
}

static int stgc_stage_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_do_stage_spleaf_at(stg_ctx, uaddr, out_sli);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		goto out_err;
	}
	err = stgc_do_stage_spleaf_at(stg_ctx, uaddr, out_sli);
	if (err) {
		goto out_err;
	}
out_ok:
	stgc_bind_sli_to_uber(stg_ctx, *out_sli);
	return 0;
out_err:
	stgc_log_cache_stat(stg_ctx);
	return err;
}

static int stgc_do_spawn_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                   const struct silofs_uaddr *uaddr,
                                   struct silofs_spleaf_info **out_sli)
{
	return silofs_spawn_spleaf_at(stg_ctx->uber, true, uaddr, out_sli);
}

static int stgc_spawn_spleaf_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spleaf_info **out_sli)
{
	int err;

	err = stgc_do_spawn_spleaf_at(stg_ctx, uaddr, out_sli);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		goto out_err;
	}
	err = stgc_do_spawn_spleaf_at(stg_ctx, uaddr, out_sli);
	if (err) {
		goto out_err;
	}
out_ok:
	stgc_bind_sli_to_uber(stg_ctx, *out_sli);
	return 0;
out_err:
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stgc_check_may_rdwr(const struct silofs_stage_ctx *stg_ctx)
{
	return stage_rw(stg_ctx->stg_mode) ? 0 : -SILOFS_EPERM;
}

static int stgc_check_may_clone(const struct silofs_stage_ctx *stg_ctx)
{
	return stgc_check_may_rdwr(stg_ctx);
}

static void stgc_setup_spawned_spnode4(const struct silofs_stage_ctx *stg_ctx,
                                       struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, sbi_uaddr(stg_ctx->sbi),
	                         stg_ctx->bk_voff, SILOFS_STYPE_NONE);
}

static int stgc_spawn_spnode4_of(const struct silofs_stage_ctx *stg_ctx,
                                 struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_super_main_blob(stg_ctx);
	if (err) {
		return err;
	}
	silofs_sbi_main_child_of(stg_ctx->sbi, stg_ctx->vspace, &uaddr);

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
	silofs_sbi_bind_sproot(stg_ctx->sbi, stg_ctx->vspace, sni_clone);

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

	err = silofs_sbi_sproot_of(stg_ctx->sbi, stg_ctx->vspace, &uaddr);
	if (err) {
		return -EFSCORRUPTED;
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

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SUPER);
	err = stgc_do_stage_spnode4(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SUPER);
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
	silofs_sbi_bind_sproot(stg_ctx->sbi, stg_ctx->vspace, stg_ctx->sni4);
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
	                         stg_ctx->bk_voff, SILOFS_STYPE_NONE);
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
	silofs_assert_ne(stg_ctx->vspace, SILOFS_STYPE_NONE);
	silofs_assert(stype_isvnode(stg_ctx->vspace));

	silofs_sni_setup_spawned(sni, sni_uaddr(stg_ctx->sni3),
	                         stg_ctx->bk_voff, stg_ctx->vspace);
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

	silofs_assert(!stype_isnone(stg_ctx->vspace));

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

static int stgc_stage_spnode2_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_cached_spnode2(stg_ctx);
	if (err) {
		err = stgc_stage_spnode2(stg_ctx);
	}
	return err;
}

static int stgc_do_require_spnode2(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	if (stgc_has_spnode2_child_at(stg_ctx)) {
		err = stgc_stage_spnode2(stg_ctx);
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

static void stgc_setup_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      struct silofs_spleaf_info *sli)
{
	silofs_assert_ne(stg_ctx->vspace, SILOFS_STYPE_NONE);
	silofs_assert(stype_isvnode(stg_ctx->vspace));

	silofs_sli_setup_spawned(sli, sni_uaddr(stg_ctx->sni2),
	                         stg_ctx->bk_voff, stg_ctx->vspace);
}

static int stgc_spawn_spleaf_of(const struct silofs_stage_ctx *stg_ctx,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr;
	int err;

	err = stgc_require_spnode_main_blob(stg_ctx, stg_ctx->sni2);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main_at(stg_ctx->sni2, stg_ctx->bk_voff, &uaddr);

	err = stgc_spawn_spleaf_at(stg_ctx, &uaddr, out_sli);
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
	const loff_t voff = silofs_sli_base_voff(sli);
	const enum silofs_height height = SILOFS_HEIGHT_VDATA;
	int err;

	stgc_make_spmap_main_blobid(stg_ctx, voff, height, &blobid);
	err = stgc_spawn_blob(stg_ctx, &blobid, stg_ctx->vspace, &bli);
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
	silofs_sni_bind_child_spleaf(stg_ctx->sni2, sli_clone);

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

	err = silofs_sni_subref_of(stg_ctx->sni2, stg_ctx->bk_voff, &uaddr);
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

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = stgc_do_stage_spleaf(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
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
	struct silofs_cache *cache = sbi_cache(stg_ctx->sbi);

	return &cache->c_spam;
}

static void stgc_track_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                      const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	struct silofs_spamaps *spam = stgc_spamaps(stg_ctx);
	size_t len;
	enum silofs_stype stype;

	sli_vrange(sli, &vrange);
	len = silofs_vrange_length(&vrange);
	stype = silofs_sli_stype_sub(sli);
	silofs_spamaps_store(spam, stype, vrange.beg, len);
}

static void stgc_bind_spawned_spleaf(const struct silofs_stage_ctx *stg_ctx,
                                     struct silofs_spleaf_info *sli)
{
	silofs_sni_bind_child_spleaf(stg_ctx->sni2, sli);
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
	return silofs_sni_has_child_at(stg_ctx->sni2, stg_ctx->bk_voff);
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

	stgc_increfs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = stgc_do_require_spleaf(stg_ctx);
	stgc_decrefs(stg_ctx, SILOFS_HEIGHT_SPNODE2);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stgc_do_stage_ubk_at(const struct silofs_stage_ctx *stg_ctx,
                                const struct silofs_bkaddr *bkaddr,
                                struct silofs_ubk_info **out_ubi)
{
	return silofs_stage_ubk_at(stg_ctx->uber, true, bkaddr, out_ubi);
}

static int stgc_stage_ubk_at(const struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_bkaddr *bkaddr,
                             struct silofs_ubk_info **out_ubi)
{
	int err;

	err = stgc_do_stage_ubk_at(stg_ctx, bkaddr, out_ubi);
	if (!err) {
		goto out_ok;
	}
	if (!is_low_resource_error(err)) {
		goto out_err;
	}
	err = stgc_flush_and_relax(stg_ctx);
	if (err) {
		goto out_err;
	}
	err = stgc_do_stage_ubk_at(stg_ctx, bkaddr, out_ubi);
	if (err) {
		goto out_err;
	}
out_ok:
	return 0;
out_err:
	stgc_log_cache_stat(stg_ctx);
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


static int stgc_stage_stable_spmaps_of(struct silofs_stage_ctx *stg_ctx)
{
	int err;

	err = stgc_stage_spmaps_of(stg_ctx);
	if (err) {
		return err;
	}
	err = silofs_sli_check_stable_at(stg_ctx->sli, stg_ctx->vaddr);
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

	err = silofs_sli_resolve_vbk(stg_ctx->sli, stg_ctx->bk_voff, &bkaddr);
	if (err) {
		return err;
	}
	voaddr_by(out_voa, &bkaddr.blobid, stg_ctx->vaddr);
	return 0;
}

static int stgc_resolve_voaddr(struct silofs_stage_ctx *stg_ctx,
                               struct silofs_voaddr *out_voa)
{
	int err;

	err = stgc_stage_spmaps_of(stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_voaddr_at(stg_ctx, out_voa);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_stage_spnode2_at(struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                enum silofs_stage_mode stg_mode,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, sbi, vaddr, stg_mode);
	err = stgc_stage_spnodes_of(&stg_ctx);
	if (err) {
		return err;
	}
	*out_sni = stg_ctx.sni2;

	return 0;
}

int silofs_sbi_stage_spmaps_at(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr,
                               enum silofs_stage_mode stg_mode,
                               struct silofs_spnode_info **out_sni,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, sbi, vaddr, stg_mode);
	err = stgc_stage_spmaps_of(&stg_ctx);
	if (err) {
		return err;
	}
	*out_sni = stg_ctx.sni2;
	*out_sli = stg_ctx.sli;
	return 0;
}

int silofs_sbi_require_spnode2_at(struct silofs_sb_info *sbi,
                                  const struct silofs_vaddr *vaddr,
                                  enum silofs_stage_mode stg_mode,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, sbi, vaddr, stg_mode);
	err = stgc_check_may_rdwr(&stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_require_spnodes_of(&stg_ctx);
	if (err) {
		return err;
	}
	*out_sni = stg_ctx.sni2;
	return 0;
}

int silofs_sbi_require_spmaps_at(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_mode stg_mode,
                                 struct silofs_spnode_info **out_sni,
                                 struct silofs_spleaf_info **out_sli)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, sbi, vaddr, stg_mode);
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
	*out_sni = stg_ctx.sni2;
	*out_sli = stg_ctx.sli;
	return 0;
}

int silofs_sbi_stage_ubk_at(struct silofs_sb_info *sbi,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stage_mode stg_mode,
                            struct silofs_ubk_info **out_ubi)
{
	struct silofs_stage_ctx stg_ctx;
	struct silofs_voaddr voa;
	int err;

	stgc_setup(&stg_ctx, sbi, vaddr, stg_mode);
	err = silofs_sbi_resolve_voa(sbi, vaddr, stg_mode, &voa);
	if (err) {
		return err;
	}
	err = stgc_stage_ubk_at(&stg_ctx, &voa.oaddr.bka, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int sbi_spawn_vbi_of(struct silofs_sb_info *sbi,
                            struct silofs_blob_info *bli,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_vbk_info **out_vbi)
{
	int ret;

	bli_incref(bli);
	ret = sbi_spawn_vbi(sbi, vaddr->voff, vaddr->stype, out_vbi);
	bli_decref(bli);
	return ret;
}

static int sbi_spawn_load_vbk(struct silofs_sb_info *sbi,
                              struct silofs_blob_info *bli,
                              const struct silofs_voaddr *voa,
                              struct silofs_vbk_info **out_vbi)
{
	struct silofs_vbk_info *vbi = NULL;
	int err;

	err = sbi_spawn_vbi_of(sbi, bli, &voa->vaddr, &vbi);
	if (err) {
		return err;
	}
	err = silofs_bli_load_bk(bli, &voa->oaddr.bka, vbi->vbk);
	if (err) {
		sbi_forget_cached_vbi(sbi, vbi);
		return err;
	}
	*out_vbi = vbi;
	return 0;
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
	const struct silofs_vaddr *vaddr = &voa->vaddr;
	int err;

	err = sbi_lookup_cached_vbi(sbi, vaddr->voff, vaddr->stype, out_vbi);
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
	struct silofs_stage_ctx stg_ctx;

	stgc_setup(&stg_ctx, sbi, vaddr, SILOFS_STAGE_RO);
	return stgc_resolve_voaddr(&stg_ctx, out_voa);
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

static int bli_resolve_bk(struct silofs_blob_info *bli,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_xiovec *xiov)
{
	struct silofs_oaddr oaddr;
	const loff_t off = lba_to_off(bkaddr->lba);

	silofs_oaddr_setup(&oaddr, &bkaddr->blobid, off, SILOFS_BK_SIZE);
	return silofs_bli_resolve(bli, &oaddr, xiov);
}

static int sbi_resolve_vbks(struct silofs_sb_info *sbi,
                            const struct silofs_bkaddr *src_bkaddr,
                            const struct silofs_bkaddr *dst_bkaddr,
                            struct silofs_xiovec *out_xiov_src,
                            struct silofs_xiovec *out_xiov_dst)
{
	struct silofs_blob_info *bli_src = NULL;
	struct silofs_blob_info *bli_dst = NULL;
	int ret;

	ret = sbi_stage_blob(sbi, &src_bkaddr->blobid, &bli_src);
	if (ret) {
		goto out;
	}
	bli_incref(bli_src);

	ret = sbi_stage_blob(sbi, &dst_bkaddr->blobid, &bli_dst);
	if (ret) {
		goto out;
	}
	bli_incref(bli_dst);

	ret = bli_resolve_bk(bli_src, src_bkaddr, out_xiov_src);
	if (ret) {
		goto out;
	}

	ret = bli_resolve_bk(bli_dst, dst_bkaddr, out_xiov_dst);
	if (ret) {
		goto out;
	}
out:
	bli_decref(bli_dst);
	bli_decref(bli_src);
	return ret;
}

static int stgc_kcopy_vblock(const struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_xiovec *xiov_src,
                             const struct silofs_xiovec *xiov_dst)
{
	return silofs_exec_kcopy_by(stg_ctx->uber, xiov_src,
	                            xiov_dst, SILOFS_BK_SIZE);
}

static int stgc_clone_vblock(const struct silofs_stage_ctx *stg_ctx,
                             const struct silofs_voaddr *voa_src)
{
	struct silofs_bkaddr dst_bkaddr;
	struct silofs_xiovec src_xiov;
	struct silofs_xiovec dst_xiov;
	const loff_t voff = voa_src->vaddr.voff;
	int err;

	silofs_sli_resolve_main_vbk(stg_ctx->sli, voff, &dst_bkaddr);
	err = sbi_resolve_vbks(stg_ctx->sbi, &voa_src->oaddr.bka,
	                       &dst_bkaddr, &src_xiov, &dst_xiov);
	if (err == -ENOENT) {
		return -EFSCORRUPTED;
	}
	if (err) {
		return err;
	}
	err = stgc_kcopy_vblock(stg_ctx, &src_xiov, &dst_xiov);
	if (err) {
		return err;
	}
	silofs_sli_rebind_vbk(stg_ctx->sli, voff, &dst_bkaddr);
	return 0;
}

int silofs_sbi_resolve_voa(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_mode stg_mode,
                           struct silofs_voaddr *out_voa)
{
	struct silofs_stage_ctx stg_ctx;
	int err;

	stgc_setup(&stg_ctx, sbi, vaddr, stg_mode);
	err = stgc_resolve_voaddr(&stg_ctx, out_voa);
	if (err) {
		return err;
	}
	err = stgc_inspect_bkaddr(&stg_ctx, &out_voa->oaddr.bka);
	if (err != -SILOFS_EPERM) {
		return err;
	}
	err = stgc_check_may_clone(&stg_ctx);
	if (err) {
		return err;
	}
	err = stgc_clone_vblock(&stg_ctx, out_voa);
	if (err) {
		return err;
	}
	err = stgc_voaddr_at(&stg_ctx, out_voa);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sbi_spawn_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_voaddr *voa_want,
                              enum silofs_stage_mode stg_mode,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_voaddr voa;
	struct silofs_vbk_info *vbi = NULL;
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = silofs_sbi_resolve_voa(sbi, &voa_want->vaddr, stg_mode, &voa);
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
                                 enum silofs_stage_mode stg_mode)
{
	struct silofs_stage_ctx stg_ctx;

	stgc_setup(&stg_ctx, sbi, &voa->vaddr, stg_mode);
	return stgc_stage_stable_spmaps_of(&stg_ctx);
}

int silofs_sbi_stage_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_voaddr *voa,
                              enum silofs_stage_mode stg_mode,
                              struct silofs_vnode_info **out_vi)
{
	struct silofs_vnode_info *vi = NULL;
	int err;

	err = sbi_require_stable_at(sbi, voa, stg_mode);
	if (err) {
		return err;
	}
	err = silofs_sbi_spawn_vnode_at(sbi, voa, stg_mode, &vi);
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
                              enum silofs_stage_mode stg_mode,
                              struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = silofs_sbi_stage_vnode_at(sbi, &ivoa->voa, stg_mode, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);

	silofs_ii_rebind_view(ii, ivoa->ino);
	silofs_ii_refresh_atime(ii, true);
	*out_ii = ii;
	return 0;
}
