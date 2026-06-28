/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/base.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/run.h>

struct silofs_vstage_ctx {
	struct silofs_task_ctx *task;
	struct silofs_env *env;
	struct silofs_sb_info *sbi;
	struct silofs_spnode_info *sni4;
	struct silofs_spnode_info *sni3;
	struct silofs_spnode_info *sni2;
	struct silofs_spnode_info *sni1;
	struct silofs_spleaf_info *sli;
	struct silofs_lsmap_info *lsi;
	const struct silofs_vaddr *vaddr;
	off_t voff;
	enum silofs_stg_mode stg_mode;
	enum silofs_vtype vspace;
	unsigned int retry;
};

struct silofs_vnis {
	struct silofs_vnode_info *vnis[SILOFS_NKB_IN_LBK];
	size_t count;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool is_low_resource_error(int err)
{
	bool ret;

	switch (abs(err)) {
	case SILOFS_ENOMEM:
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
sbi_bind_child_spnode(struct silofs_sb_info *sbi, enum silofs_vtype vspace,
                      const struct silofs_spnode_info *sni_child)
{
	silofs_sbi_bind_child(sbi, vspace, silofs_sni_uaddr(sni_child));
}

static void sni_bind_child_spnode(struct silofs_spnode_info *sni,
                                  const struct silofs_spnode_info *sni_child)
{
	const off_t voff = silofs_sni_base_voff(sni_child);

	silofs_sni_bind_child(sni, voff, silofs_sni_uaddr(sni_child));
}

static void sni_bind_child_spleaf(struct silofs_spnode_info *sni,
                                  const struct silofs_spleaf_info *sli_child)
{
	const off_t voff = silofs_sli_base_voff(sli_child);

	silofs_sni_bind_child(sni, voff, silofs_sli_uaddr(sli_child));
}

static bool sni_has_child_at(const struct silofs_spnode_info *sni, off_t voff)
{
	struct silofs_uaddr uaddr;

	return (silofs_sni_resolve_child(sni, voff, &uaddr) == 0);
}

static bool sni_has_main_lseg(const struct silofs_spnode_info *sni)
{
	struct silofs_lsid lsid;

	silofs_sni_main_lseg(sni, &lsid);
	return (silofs_lsid_size(&lsid) > 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_lcache *
vstgc_lcache(const struct silofs_vstage_ctx *vstg_ctx)
{
	return vstg_ctx->env->base.lcache;
}

static void vstgc_log_cache_stat(const struct silofs_vstage_ctx *vstg_ctx)
{
	const struct silofs_lcache *lcache = vstgc_lcache(vstg_ctx);

	log_dbg("cache-stat: accum_unodes=%lu accum_inodes=%lu "
	        "accum_vnodes=%lu ui=%lu vi=%lu",
	        lcache->lc_unis_dq.drq_accum,
	        lcache->lc_vc.vc_iis_dq.drq_accum,
	        lcache->lc_vc.vc_vnis_dq.drq_accum,
	        lcache->lc_uni_hmapq.hmq_lru.sz,
	        lcache->lc_vc.vc_vni_hmapq.hmq_lru.sz);
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
	silofs_env_relax_caches(vstg_ctx->env, SILOFS_CTLF_NOW);
}

static int vstgc_try_evict_some(const struct silofs_vstage_ctx *vstg_ctx,
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_do_stage_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_lsid *lsid)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_stage_lseg(vstg_ctx->env, lsid);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int sbi_inspect_laddr(const struct silofs_sb_info *sbi,
                             const struct silofs_laddr *laddr,
                             enum silofs_stg_mode stg_mode)
{
	if (!stage_cow(stg_mode)) {
		return 0;
	}
	if (silofs_sbi_ismutable_laddr(sbi, laddr)) {
		return 0;
	}
	return -SILOFS_EPERM;
}

static int sbi_inspect_cached_uni(const struct silofs_sb_info *sbi,
                                  const struct silofs_unode_info *uni,
                                  enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_laddr(sbi, silofs_uni_laddr(uni), stg_mode);
}

static int sbi_inspect_cached_sni(const struct silofs_sb_info *sbi,
                                  const struct silofs_spnode_info *sni,
                                  enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_cached_uni(sbi, &sni->sn_uni, stg_mode);
}

static int sbi_inspect_cached_sli(const struct silofs_sb_info *sbi,
                                  const struct silofs_spleaf_info *sli,
                                  enum silofs_stg_mode stg_mode)
{
	return sbi_inspect_cached_uni(sbi, &sli->sl_uni, stg_mode);
}

static enum silofs_vtype sni_child_vtype(const struct silofs_spnode_info *sni)
{
	enum silofs_vtype vtype;
	const enum silofs_height height = silofs_sni_height(sni);

	switch (height) {
	case SILOFS_HEIGHT_BOOT:
		vtype = SILOFS_VTYPE_SUPER;
		break;
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE2:
		vtype = SILOFS_VTYPE_SPNODE;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		vtype = SILOFS_VTYPE_SPLEAF;
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		vtype = SILOFS_VTYPE_NONE;
		break;
	}
	return vtype;
}

static enum silofs_height
sni_child_height(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) - 1;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
vstgc_setup(struct silofs_vstage_ctx *vstg_ctx, struct silofs_task_ctx *task,
            const struct silofs_vaddr *vaddr, enum silofs_stg_mode stg_mode)
{
	memset(vstg_ctx, 0, sizeof(*vstg_ctx));
	vstg_ctx->task     = task;
	vstg_ctx->env      = task->env;
	vstg_ctx->sbi      = task->env->sbi;
	vstg_ctx->vaddr    = vaddr;
	vstg_ctx->stg_mode = stg_mode;
	vstg_ctx->vspace   = vaddr->vtype;
	vstg_ctx->voff     = vaddr->off;
	vstg_ctx->retry    = 3;
}

static int vstgc_do_spawn_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_lsid *lsid)
{
	return silofs_spawn_lseg(vstg_ctx->env, lsid);
}

static int vstgc_spawn_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_lsid *lsid)
{
	enum silofs_vtype vtype;
	int err;

	err = vstgc_do_spawn_lseg(vstg_ctx, lsid);
	if (!err) {
		vtype = lsid->blobid.stype.vtype;
		silofs_sbst_update_lsegs(vstg_ctx->sbi, vtype, 1);
	}
	return err;
}

static void
vstgc_make_lsid_of(const struct silofs_vstage_ctx *vstg_ctx, off_t voff,
                   enum silofs_height height, enum silofs_vtype vtype,
                   struct silofs_lsid *out_lsid)
{
	struct silofs_blobid sb_blobid, blobid;
	struct silofs_uniqid uniqid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_VNODE,
		.vtype = vtype,
	};

	/* TODO: crap, re-write this logic */
	silofs_sbi_self_blobid(vstg_ctx->sbi, &sb_blobid);

	silofs_generate_uniqid(vstg_ctx->env->base.prng, &uniqid);
	silofs_blobid_init(&blobid, &stype, &sb_blobid.layerid, &uniqid);
	blobid.height = height;

	silofs_lsid_setup(out_lsid, &blobid, voff);
}

static void
vstgc_make_lsid_of_spmaps(const struct silofs_vstage_ctx *vstg_ctx, off_t voff,
                          enum silofs_height height, enum silofs_vtype vtype,
                          struct silofs_lsid *out_lsid)
{
	silofs_assert_ne(vtype, vstg_ctx->vspace);

	vstgc_make_lsid_of(vstg_ctx, voff, height, vtype, out_lsid);
}

static void
vstgc_make_lsid_of_vdata(const struct silofs_vstage_ctx *vstg_ctx, off_t voff,
                         enum silofs_vtype vtype, struct silofs_lsid *out_lsid)
{
	silofs_assert_eq(vtype, vstg_ctx->vspace);

	vstgc_make_lsid_of(vstg_ctx, voff, SILOFS_HEIGHT_VDATA, vtype,
	                   out_lsid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_update_space_stats(const struct silofs_vstage_ctx *vstg_ctx,
                                     const struct silofs_uaddr *uaddr)
{
	const enum silofs_vtype vtype = silofs_uaddr_vtype(uaddr);

	silofs_sbst_update_objs(vstg_ctx->sbi, vtype, 1);
	silofs_sbst_update_bks(vstg_ctx->sbi, vtype, 1);
}

static int
vstgc_spawn_super_main_lseg(const struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_lsid lsid;
	const enum silofs_height height = SILOFS_HEIGHT_SUPER - 1;
	const enum silofs_vtype vtype   = SILOFS_VTYPE_SPNODE;
	int err;

	vstgc_make_lsid_of_spmaps(vstg_ctx, 0, height, vtype, &lsid);
	err = vstgc_spawn_lseg(vstg_ctx, &lsid);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_lseg(vstg_ctx->sbi, vstg_ctx->vspace, &lsid);
	return 0;
}

static int
vstgc_stage_super_main_lseg(const struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_lsid lsid;

	silofs_sbi_main_lseg(vstg_ctx->sbi, vstg_ctx->vspace, &lsid);
	return vstgc_do_stage_lseg(vstg_ctx, &lsid);
}

static int
vstgc_require_super_main_lseg(const struct silofs_vstage_ctx *vstg_ctx)
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

static int
vstgc_spawn_spnode_main_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                             struct silofs_spnode_info *sni)
{
	struct silofs_lsid lsid;
	const off_t voff                = silofs_sni_base_voff(sni);
	const enum silofs_height height = sni_child_height(sni);
	const enum silofs_vtype vtype   = sni_child_vtype(sni);
	int err;

	vstgc_make_lsid_of_spmaps(vstg_ctx, voff, height, vtype, &lsid);
	err = vstgc_spawn_lseg(vstg_ctx, &lsid);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_lseg(sni, &lsid);
	return 0;
}

static int
vstgc_stage_spnode_main_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                             struct silofs_spnode_info *sni)
{
	struct silofs_lsid lsid;

	silofs_sni_main_lseg(sni, &lsid);
	return vstgc_do_stage_lseg(vstg_ctx, &lsid);
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
	if (silofs_sbi_ismutable_laddr(vstg_ctx->sbi, laddr)) {
		return 0;
	}
	return -SILOFS_EPERM; /* address on read-only tree */
}

static int vstgc_inspect_cached_uni(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_unode_info *uni)
{
	return vstgc_inspect_laddr(vstg_ctx, silofs_uni_laddr(uni));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void vstgc_increfs(const struct silofs_vstage_ctx *vstg_ctx,
                          enum silofs_height height_upto)
{
	if (height_upto <= SILOFS_HEIGHT_SUPER) {
		silofs_sbi_incref(vstg_ctx->sbi);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE4) {
		silofs_sni_incref(vstg_ctx->sni4);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE3) {
		silofs_sni_incref(vstg_ctx->sni3);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE2) {
		silofs_sni_incref(vstg_ctx->sni2);
	}
	if (height_upto <= SILOFS_HEIGHT_SPNODE1) {
		silofs_sni_incref(vstg_ctx->sni1);
	}
	if (height_upto <= SILOFS_HEIGHT_SPLEAF) {
		silofs_sli_incref(vstg_ctx->sli);
	}
}

static void vstgc_decrefs(const struct silofs_vstage_ctx *vstg_ctx,
                          enum silofs_height height_from)
{
	if (height_from <= SILOFS_HEIGHT_SPLEAF) {
		silofs_sli_decref(vstg_ctx->sli);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE1) {
		silofs_sni_decref(vstg_ctx->sni1);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE2) {
		silofs_sni_decref(vstg_ctx->sni2);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE3) {
		silofs_sni_decref(vstg_ctx->sni3);
	}
	if (height_from <= SILOFS_HEIGHT_SPNODE4) {
		silofs_sni_decref(vstg_ctx->sni4);
	}
	if (height_from <= SILOFS_HEIGHT_SUPER) {
		silofs_sbi_decref(vstg_ctx->sbi);
	}
}

static off_t vstgc_lbk_voff(const struct silofs_vstage_ctx *vstg_ctx)
{
	return silofs_off_align_to_lbk(vstg_ctx->voff);
}

static int vstgc_find_cached_unode(const struct silofs_vstage_ctx *vstg_ctx,
                                   enum silofs_height height,
                                   struct silofs_unode_info **out_uni)
{
	struct silofs_uakey uakey;
	struct silofs_lrange lrange;

	silofs_lrange_of_spmap(&lrange, height, vstgc_lbk_voff(vstg_ctx));
	silofs_uakey_setup_by2(&uakey, &lrange, vstg_ctx->vspace);
	*out_uni = silofs_lcache_find_uni_by(vstgc_lcache(vstg_ctx), &uakey);
	return (*out_uni != nullptr) ? 0 : -SILOFS_ENOENT;
}

static int vstgc_fetch_cached_spnode(const struct silofs_vstage_ctx *vstg_ctx,
                                     enum silofs_height height,
                                     struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *uni = nullptr;
	int err;

	err = vstgc_find_cached_unode(vstg_ctx, height, &uni);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_uni(vstg_ctx, uni);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_uni(uni);
	return 0;
}

static int vstgc_fetch_cached_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                                     struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *uni = nullptr;
	int err;

	err = vstgc_find_cached_unode(vstg_ctx, SILOFS_HEIGHT_SPLEAF, &uni);
	if (err) {
		return err;
	}
	err = vstgc_inspect_cached_uni(vstg_ctx, uni);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_uni(uni);
	return 0;
}

static int
vstgc_inspect_cached_spnode(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_spnode_info *sni)
{
	return sbi_inspect_cached_sni(vstg_ctx->sbi, sni, vstg_ctx->stg_mode);
}

static int
vstgc_inspect_cached_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_spleaf_info *sli)
{
	return sbi_inspect_cached_sli(vstg_ctx->sbi, sli, vstg_ctx->stg_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_resolve_spnode_child(const struct silofs_vstage_ctx *vstg_ctx,
                                      const struct silofs_spnode_info *sni,
                                      struct silofs_uaddr *out_uaddr)
{
	const off_t lbk_voff = vstgc_lbk_voff(vstg_ctx);

	return silofs_sni_resolve_child(sni, lbk_voff, out_uaddr);
}

static int vstgc_do_stage_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_uaddr *uaddr,
                                    struct silofs_spnode_info **out_sni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_stage_spnode(vstg_ctx->env, uaddr, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_stage_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_uaddr *uaddr,
                                 struct silofs_spnode_info **out_sni)
{
	return vstgc_do_stage_spnode_at(vstg_ctx, uaddr, out_sni);
}

static int vstgc_do_spawn_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_uaddr *uaddr,
                                    struct silofs_spnode_info **out_sni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_spawn_spnode(vstg_ctx->env, uaddr, out_sni);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_spawn_spnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_uaddr *uaddr,
                                 struct silofs_spnode_info **out_sni)
{
	return vstgc_do_spawn_spnode_at(vstg_ctx, uaddr, out_sni);
}

static int vstgc_do_stage_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_uaddr *uaddr,
                                    struct silofs_spleaf_info **out_sli)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_stage_spleaf(vstg_ctx->env, uaddr, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_stage_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_uaddr *uaddr,
                                 struct silofs_spleaf_info **out_sli)
{
	return vstgc_do_stage_spleaf_at(vstg_ctx, uaddr, out_sli);
}

static int vstgc_do_spawn_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_uaddr *uaddr,
                                    struct silofs_spleaf_info **out_sli)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = silofs_spawn_spleaf(vstg_ctx->env, uaddr, out_sli);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
}

static int vstgc_spawn_spleaf_at(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_uaddr *uaddr,
                                 struct silofs_spleaf_info **out_sli)
{
	return vstgc_do_spawn_spleaf_at(vstg_ctx, uaddr, out_sli);
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

static void
vstgc_setup_spawned_spnode4(const struct silofs_vstage_ctx *vstg_ctx,
                            struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, silofs_sbi_uaddr(vstg_ctx->sbi),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode4_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_require_super_main_lseg(vstg_ctx);
	if (err) {
		return err;
	}
	silofs_sbi_resolve_main_at(vstg_ctx->sbi, vstg_ctx->voff,
	                           vstg_ctx->vspace, &uaddr);

	err = vstgc_spawn_spnode_at(vstg_ctx, &uaddr, out_sni);
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
	vstgc_update_space_stats(vstg_ctx, silofs_sni_uaddr(*out_sni));
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
	struct silofs_spnode_info *sni = nullptr;
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
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = silofs_sbi_resolve_child(vstg_ctx->sbi, vstg_ctx->vspace,
	                               &uaddr);
	if (err) {
		return -SILOFS_EFSCORRUPTED;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &uaddr, &vstg_ctx->sni4);
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

static bool
vstgc_has_spnode4_child_at(const struct silofs_vstage_ctx *vstg_ctx)
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

static void
vstgc_setup_spawned_spnode3(const struct silofs_vstage_ctx *vstg_ctx,
                            struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, silofs_sni_uaddr(vstg_ctx->sni4),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode3_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni4);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni4, vstgc_lbk_voff(vstg_ctx),
	                        &uaddr);

	err = vstgc_spawn_spnode_at(vstg_ctx, &uaddr, out_sni);
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
	vstgc_update_space_stats(vstg_ctx, silofs_sni_uaddr(*out_sni));
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
	struct silofs_spnode_info *sni = nullptr;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	err = vstgc_do_clone_spnode3(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE3);
	*out_sni = sni;
	return err;
}

static int
vstgc_inspect_cached_spnode3(const struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni3);
}

static int vstgc_do_stage_spnode3(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni4, &uaddr);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &uaddr, &vstg_ctx->sni3);
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

static bool
vstgc_has_spnode3_child_at(const struct silofs_vstage_ctx *vstg_ctx)
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
	silofs_sni_setup_spawned(sni, silofs_sni_uaddr(vstg_ctx->sni3),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode2_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni3);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni3, vstgc_lbk_voff(vstg_ctx),
	                        &uaddr);

	err = vstgc_spawn_spnode_at(vstg_ctx, &uaddr, out_sni);
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
	vstgc_update_space_stats(vstg_ctx, silofs_sni_uaddr(*out_sni));
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
	struct silofs_spnode_info *sni = nullptr;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	err = vstgc_do_clone_spnode2(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE2);
	*out_sni = sni;
	return err;
}

static int
vstgc_inspect_cached_spnode2(const struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni2);
}

static int vstgc_do_stage_spnode2(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni3, &uaddr);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &uaddr, &vstg_ctx->sni2);
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

static bool
vstgc_has_spnode2_child_at(const struct silofs_vstage_ctx *vstg_ctx)
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

static void
vstgc_setup_spawned_spnode1(const struct silofs_vstage_ctx *vstg_ctx,
                            struct silofs_spnode_info *sni)
{
	silofs_sni_setup_spawned(sni, silofs_sni_uaddr(vstg_ctx->sni2),
	                         vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spnode1_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni2);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni2, vstgc_lbk_voff(vstg_ctx),
	                        &uaddr);

	err = vstgc_spawn_spnode_at(vstg_ctx, &uaddr, out_sni);
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
	vstgc_update_space_stats(vstg_ctx, silofs_sni_uaddr(*out_sni));
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
	struct silofs_spnode_info *sni = nullptr;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	err = vstgc_do_clone_spnode1(vstg_ctx, &sni);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPNODE1);
	*out_sni = sni;
	return err;
}

static int
vstgc_inspect_cached_spnode1(const struct silofs_vstage_ctx *vstg_ctx)
{
	return vstgc_inspect_cached_spnode(vstg_ctx, vstg_ctx->sni1);
}

static int vstgc_do_stage_spnode1(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni2, &uaddr);
	if (err) {
		return err;
	}
	err = vstgc_stage_spnode_at(vstg_ctx, &uaddr, &vstg_ctx->sni1);
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

static bool
vstgc_has_spnode1_child_at(const struct silofs_vstage_ctx *vstg_ctx)
{
	return sni_has_child_at(vstg_ctx->sni2, vstgc_lbk_voff(vstg_ctx));
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

static void
vstgc_setup_spawned_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                           struct silofs_spleaf_info *sli)
{
	silofs_assert(silofs_vtype_isvnode(vstg_ctx->vspace));

	silofs_sli_setup_spawned(sli, silofs_sni_uaddr(vstg_ctx->sni1),
	                         vstg_ctx->vspace, vstgc_lbk_voff(vstg_ctx));
}

static int vstgc_spawn_spleaf_of(const struct silofs_vstage_ctx *vstg_ctx,
                                 struct silofs_spleaf_info **out_sli)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_require_spnode_main_lseg(vstg_ctx, vstg_ctx->sni1);
	if (err) {
		return err;
	}
	silofs_sni_resolve_main(vstg_ctx->sni1, vstgc_lbk_voff(vstg_ctx),
	                        &uaddr);

	err = vstgc_spawn_spleaf_at(vstg_ctx, &uaddr, out_sli);
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
	struct silofs_lsid lsid       = { .lsize = 0 };
	const enum silofs_vtype vtype = vstg_ctx->vspace;
	off_t voff                    = -1;
	int err;

	silofs_sli_main_lseg(sli, &lsid);
	if (!silofs_lsid_isnull(&lsid)) {
		return vstgc_do_stage_lseg(vstg_ctx, &lsid);
	}
	/*
	 * TODO-0047: Do not use underlying repo to detect if vdata-lseg exists
	 */
	voff = silofs_sli_base_voff(sli);
	vstgc_make_lsid_of_vdata(vstg_ctx, voff, vtype, &lsid);
	err = vstgc_do_stage_lseg(vstg_ctx, &lsid);
	if (!err) {
		goto out_ok;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = vstgc_spawn_lseg(vstg_ctx, &lsid);
	if (err) {
		return err;
	}
out_ok:
	silofs_sli_bind_main_lseg(sli, &lsid);
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
	vstgc_update_space_stats(vstg_ctx, silofs_sli_uaddr(*out_sli));
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
	struct silofs_spleaf_info *sli = nullptr;
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = vstgc_do_clone_spleaf(vstg_ctx, &sli);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	*out_sli = sli;
	return err;
}

static int vstgc_do_stage_spleaf(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = vstgc_resolve_spnode_child(vstg_ctx, vstg_ctx->sni1, &uaddr);
	if (err) {
		return err;
	}
	err = vstgc_stage_spleaf_at(vstg_ctx, &uaddr, &vstg_ctx->sli);
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
	return vstg_ctx->env->base.spamaps;
}

static void
vstgc_track_spawned_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                           const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange;
	struct silofs_spamaps *spam = vstgc_spamaps(vstg_ctx);
	size_t len;

	silofs_sli_get_lrange(sli, &lrange);
	len = silofs_lrange_len(&lrange);
	silofs_spamaps_store(spam, vstg_ctx->vspace, lrange.beg, len);
}

static int vstgc_spawn_bind_spleaf_at(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_spleaf_info *sli = nullptr;
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

int silofs_require_spleaf_of(struct silofs_task_ctx *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stg_mode stg_mode,
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
	*out_sli = vstg_ctx.sli;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
