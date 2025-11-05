/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include "infra.h"
#include "bs.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

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
	enum silofs_mtype vspace;
	unsigned int retry;
};

struct silofs_vnis {
	struct silofs_vnode_info *vnis[SILOFS_NKB_IN_LBK];
	size_t count;
};

static int vstgc_require_lsmap_of(struct silofs_vstage_ctx *vstg_ctx);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static off_t ino_to_off(ino_t ino)
{
	off_t off;

	if (silofs_ino_isnull(ino)) {
		off = SILOFS_OFF_NULL;
	} else {
		off = (off_t)(ino << SILOFS_INODE_SHIFT);
	}
	return off;
}

static ino_t off_to_ino(off_t off)
{
	ino_t ino;

	if (silofs_off_isnull(off)) {
		ino = SILOFS_INO_NULL;
	} else {
		ino = (ino_t)(off >> SILOFS_INODE_SHIFT);
	}
	return ino;
}

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

static ino_t vaddr_to_ino(const struct silofs_vaddr *vaddr)
{
	return off_to_ino(vaddr->off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool
ismutable(const struct silofs_env *env, const struct silofs_laddr *laddr)
{
	bool ret = false;

	if (!silofs_laddr_isnull(laddr)) {
		ret = silofs_sbi_ismutable_laddr(env->sbi, laddr);
	}
	return ret;
}

static bool vni_has_mutable_laddr(const struct silofs_vnode_info *vni)
{
	return ismutable(silofs_vni_env(vni), &vni->vn_llink.laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vni_bind_to(struct silofs_vnode_info *vni, struct silofs_env *env)
{
	vni->vn_lni.ln_env = env;
}

static void vni_update_llink(struct silofs_vnode_info *vni,
                             const struct silofs_llink *llink)
{
	silofs_llink_assign(&vni->vn_llink, llink);
}

static int vni_verify_view(const struct silofs_vnode_info *vni)
{
	return silofs_lni_verify_view(&vni->vn_lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
sbi_bind_child_spnode(struct silofs_sb_info *sbi, enum silofs_mtype vspace,
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
	const struct silofs_dirtyqs *dqs = &lcache->lc_dirtyqs;

	log_dbg("cache-stat: accum_unodes=%lu accum_inodes=%lu "
	        "accum_vnodes=%lu ui=%lu vi=%lu",
	        dqs->dq_unis.dq_accum, dqs->dq_iis.dq_accum,
	        dqs->dq_vnis.dq_accum, lcache->lc_uni_hmapq.hmq_lru.sz,
	        lcache->lc_vni_hmapq.hmq_lru.sz);
}

static int vstgc_create_cached_vni(const struct silofs_vstage_ctx *vstg_ctx,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_vnode_info **out_vni)
{
	*out_vni = silofs_lcache_create_vni(vstgc_lcache(vstg_ctx), vaddr);
	return (*out_vni == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void vstgc_forget_cached_vni(const struct silofs_vstage_ctx *vstg_ctx,
                                    struct silofs_vnode_info *vni)
{
	if (vni != nullptr) {
		silofs_lcache_forget_vni(vstgc_lcache(vstg_ctx), vni);
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

static int vstgc_do_spawn_vni(const struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vni)
{
	int err = -SILOFS_ENOMEM;

	for (size_t i = 0; i < vstg_ctx->retry; ++i) {
		err = vstgc_create_cached_vni(vstg_ctx, vaddr, out_vni);
		if (!is_low_resource_error(err)) {
			break;
		}
		vstgc_try_evict_some(vstg_ctx, i > 0);
	}
	return err;
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

static int vstgc_do_stage_lseg_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  const struct silofs_laddr *laddr)
{
	return vstgc_do_stage_lseg(vstg_ctx, &laddr->lsid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstgc_spawn_vni_at(const struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_llink *llink,
                              struct silofs_vnode_info **out_vni)
{
	int err;

	err = vstgc_do_spawn_vni(vstg_ctx, vstg_ctx->vaddr, out_vni);
	if (err) {
		return err;
	}
	vni_bind_to(*out_vni, vstg_ctx->env);
	vni_update_llink(*out_vni, llink);
	return err;
}

static int vstgc_update_view_of(const struct silofs_vstage_ctx *vstg_ctx,
                                struct silofs_vnode_info *vni)
{
	int err;

	if (vstg_ctx->stg_mode & SILOFS_STG_RAW) {
		return 0; /* no-op */
	}
	err = silofs_refresh_llink(vstg_ctx->task, vni);
	if (err) {
		return err;
	}
	err = silofs_decrypt_vni_view(vstg_ctx->env, vni);
	if (err) {
		return err;
	}
	err = vni_verify_view(vni);
	if (err) {
		return err;
	}
	return 0;
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

static enum silofs_mtype sni_child_mtype(const struct silofs_spnode_info *sni)
{
	enum silofs_mtype mtype;
	const enum silofs_height height = silofs_sni_height(sni);

	switch (height) {
	case SILOFS_HEIGHT_BOOT:
		mtype = SILOFS_MTYPE_SUPER;
		break;
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE2:
		mtype = SILOFS_MTYPE_SPNODE;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		mtype = SILOFS_MTYPE_SPLEAF;
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		mtype = SILOFS_MTYPE_NONE;
		break;
	}
	return mtype;
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
	vstg_ctx->task = task;
	vstg_ctx->env = task->t_env;
	vstg_ctx->sbi = task->t_env->sbi;
	vstg_ctx->vaddr = vaddr;
	vstg_ctx->stg_mode = stg_mode;
	vstg_ctx->vspace = vaddr->mtype;
	vstg_ctx->voff = vaddr->off;
	vstg_ctx->retry = 3;
}

static int vstgc_do_spawn_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_lsid *lsid)
{
	return silofs_spawn_lseg(vstg_ctx->env, lsid);
}

static int vstgc_spawn_lseg(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_lsid *lsid)
{
	enum silofs_mtype mtype;
	int err;

	err = vstgc_do_spawn_lseg(vstg_ctx, lsid);
	if (!err) {
		mtype = silofs_blobid_get_mtype(&lsid->blobid);
		silofs_sbst_update_lsegs(vstg_ctx->sbi, mtype, 1);
	}
	return err;
}

static void
vstgc_make_lsid_of(const struct silofs_vstage_ctx *vstg_ctx, off_t voff,
                   enum silofs_height height, enum silofs_mtype mtype,
                   struct silofs_lsid *out_lsid)
{
	struct silofs_blobid blobid;
	struct silofs_svolid svolid;

	/* TODO: crap, re-write this logic */
	silofs_sbi_self_blobid(vstg_ctx->sbi, &blobid);
	silofs_blobid_get_svolid(&blobid, &svolid);
	silofs_blobid_setup_raw2(&blobid, &svolid, mtype, vstg_ctx->vspace,
	                         height);

	silofs_lsid_setup(out_lsid, &blobid, voff);
}

static void
vstgc_make_lsid_of_spmaps(const struct silofs_vstage_ctx *vstg_ctx, off_t voff,
                          enum silofs_height height, enum silofs_mtype mtype,
                          struct silofs_lsid *out_lsid)
{
	silofs_assert_ne(mtype, vstg_ctx->vspace);

	vstgc_make_lsid_of(vstg_ctx, voff, height, mtype, out_lsid);
}

static void
vstgc_make_lsid_of_vdata(const struct silofs_vstage_ctx *vstg_ctx, off_t voff,
                         enum silofs_mtype mtype, struct silofs_lsid *out_lsid)
{
	silofs_assert_eq(mtype, vstg_ctx->vspace);

	vstgc_make_lsid_of(vstg_ctx, voff, SILOFS_HEIGHT_VDATA, mtype,
	                   out_lsid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vstgc_update_space_stats(const struct silofs_vstage_ctx *vstg_ctx,
                                     const struct silofs_uaddr *uaddr)
{
	const enum silofs_mtype mtype = silofs_uaddr_mtype(uaddr);

	silofs_sbst_update_objs(vstg_ctx->sbi, mtype, 1);
	silofs_sbst_update_bks(vstg_ctx->sbi, mtype, 1);
}

static int
vstgc_spawn_super_main_lseg(const struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_lsid lsid;
	const enum silofs_height height = SILOFS_HEIGHT_SUPER - 1;
	const enum silofs_mtype mtype = SILOFS_MTYPE_SPNODE;
	int err;

	vstgc_make_lsid_of_spmaps(vstg_ctx, 0, height, mtype, &lsid);
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
	const off_t voff = silofs_sni_base_voff(sni);
	const enum silofs_height height = sni_child_height(sni);
	const enum silofs_mtype mtype = sni_child_mtype(sni);
	int err;

	vstgc_make_lsid_of_spmaps(vstg_ctx, voff, height, mtype, &lsid);
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

static void
vstgc_setup_spawned_spleaf(const struct silofs_vstage_ctx *vstg_ctx,
                           struct silofs_spleaf_info *sli)
{
	silofs_assert(silofs_mtype_isvnode(vstg_ctx->vspace));

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
	struct silofs_lsid lsid = { .lsize = 0 };
	const enum silofs_mtype mtype = vstg_ctx->vspace;
	off_t voff = -1;
	int err;

	silofs_sli_main_lseg(sli, &lsid);
	if (!silofs_lsid_isnull(&lsid)) {
		return vstgc_do_stage_lseg(vstg_ctx, &lsid);
	}
	/*
	 * TODO-0047: Do not use underlying repo to detect if vdata-lseg exists
	 */
	voff = silofs_sli_base_voff(sli);
	vstgc_make_lsid_of_vdata(vstg_ctx, voff, mtype, &lsid);
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

static int vstgc_resolve_child_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_laddr *out_laddr)
{
	return silofs_sli_resolve_child(vstg_ctx->sli, vstg_ctx->voff,
	                                out_laddr);
}

static const struct silofs_key *
vstgc_main_key(const struct silofs_vstage_ctx *vstg_ctx)
{
	return &vstg_ctx->env->mbri.fs_mbr.main_ivkey.key;
}

static void vstgc_resolve_main_key(const struct silofs_vstage_ctx *vstg_ctx,
                                   struct silofs_key *out_key)
{
	silofs_key_assign(out_key, vstgc_main_key(vstg_ctx));
}

static int vstgc_resolve_key_of(const struct silofs_vstage_ctx *vstg_ctx,
                                struct silofs_key *out_key)
{
	int ret = 0;

	if (vstg_ctx->vspace != SILOFS_MTYPE_LSMAP) {
		silofs_assert_not_null(vstg_ctx->lsi);

		ret = silofs_lsi_resolve_key(vstg_ctx->lsi, vstg_ctx->vaddr,
		                             out_key);
	} else {
		vstgc_resolve_main_key(vstg_ctx, out_key);
	}
	return ret;
}

static int vstgc_resolve_llink_of(const struct silofs_vstage_ctx *vstg_ctx,
                                  struct silofs_llink *out_llink)
{
	struct silofs_laddr laddr;
	struct silofs_key key;
	struct silofs_iv iv;
	int err;

	err = vstgc_resolve_child_of(vstg_ctx, &laddr);
	if (err) {
		return err;
	}
	err = vstgc_resolve_key_of(vstg_ctx, &key);
	if (err) {
		return err;
	}
	silofs_laddr_setpos(&laddr, vstg_ctx->voff);
	silofs_derive_iv_by_laddr(&vstg_ctx->env->mdigest, &laddr, &iv);
	silofs_llink_setup(out_llink, &laddr, &key, &iv);
	return 0;
}

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

static int vstgc_stage_spleaf_for_resolve(struct silofs_vstage_ctx *vstg_ctx)
{
	int ret;

	ret = vstgc_fetch_cached_spleaf1(vstg_ctx);
	if (ret != 0) {
		ret = vstgc_stage_spmaps_of(vstg_ctx);
	}
	return ret;
}

static int vstgc_stage_lsmap_for_resolve(struct silofs_vstage_ctx *vstg_ctx)
{
	struct silofs_llink llink;
	struct silofs_vaddr vaddr;
	int err = 0;

	silofs_sli_incref(vstg_ctx->sli);
	if (vstg_ctx->vspace == SILOFS_MTYPE_LSMAP) {
		goto out;
	}
	silofs_vaddr_of_lsmap(&vaddr, vstg_ctx->vspace, vstg_ctx->voff);
	err = silofs_resolve_llink_of(vstg_ctx->task, &vaddr,
	                              vstg_ctx->stg_mode, &llink);
	if (err) {
		goto out;
	}
	err = vstgc_require_lsmap_of(vstg_ctx);
out:
	silofs_sli_decref(vstg_ctx->sli);
	return err;
}

static int vstgc_resolve_llink(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_llink *out_llink)
{
	int err;

	err = vstgc_stage_spleaf_for_resolve(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_stage_lsmap_for_resolve(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_resolve_llink_of(vstg_ctx, out_llink);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_spleaf_of(struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stg_mode stg_mode,
                           struct silofs_spleaf_info **out_sli)
{

	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	err = vstgc_stage_spmaps_of(&vstg_ctx);
	if (err) {
		return err;
	}
	*out_sli = vstg_ctx.sli;
	return 0;
}

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

static int vstgc_check_stable_vaddr(const struct silofs_vstage_ctx *vstg_ctx)
{
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	bool stable;

	if (vstg_ctx->vspace != SILOFS_MTYPE_LSMAP) {
		silofs_assert_not_null(vstg_ctx->lsi);
		stable = silofs_lsi_has_allocated_at(vstg_ctx->lsi, vaddr);
	} else {
		stable = silofs_sli_has_child_lbk_at(vstg_ctx->sli, vaddr);
	}
	return likely(stable) ? 0 : -SILOFS_ENOENT;
}

static int vstgc_require_stable_vaddr(const struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_check_stable_vaddr(vstg_ctx);
	if (err) {
		log_err("unstable: off=0x%lx mtype=%d", vstg_ctx->vaddr->off,
		        vstg_ctx->vaddr->mtype);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int vstgc_stage_spmaps_plus(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	err = vstgc_stage_spmaps_of(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_stage_lsmap_for_resolve(vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int require_stable_at(struct silofs_task_ctx *task,
                             const struct silofs_vaddr *vaddr)
{
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, SILOFS_STG_CUR | SILOFS_STG_RAW);
	err = vstgc_stage_spmaps_plus(&vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_stable_vaddr(&vstg_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int
check_stable_at(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr)
{
	struct silofs_vstage_ctx vstg_ctx;
	int err;

	vstgc_setup(&vstg_ctx, task, vaddr, SILOFS_STG_CUR | SILOFS_STG_RAW);
	err = vstgc_stage_spmaps_plus(&vstg_ctx);
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

static bool laddr_isdata(const struct silofs_laddr *laddr)
{
	const enum silofs_mtype mtype = silofs_laddr_mtype(laddr);

	return silofs_mtype_isdata(mtype);
}

static int
vstgc_load_view_at(const struct silofs_vstage_ctx *vstg_ctx,
                   const struct silofs_laddr *laddr, struct silofs_view *view)
{
	struct silofs_repo *repo = vstg_ctx->env->base.repo;
	enum silofs_stg_mode stg_mode = vstg_ctx->stg_mode;
	const size_t len = silofs_laddr_len(laddr);
	int ret = 0;

	if ((stg_mode & SILOFS_STG_RAW) != SILOFS_STG_RAW) {
		/* Normal mode: load encrypted from stable storage */
		ret = silofs_repo_read_at(repo, laddr, view, len);
	} else if (laddr_isdata(laddr)) {
		/* Raw-data mode: force all-zeros for in-memory view */
		silofs_memzero(view, len);
	}
	return ret;
}

static int vstgc_require_laddr(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_laddr *laddr)
{
	struct silofs_repo *repo = vstg_ctx->env->base.repo;
	int err;

	err = silofs_repo_require_lseg(repo, &laddr->lsid);
	if (err) {
		return err;
	}
	err = silofs_repo_require_laddr(repo, laddr);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_do_require_lseg_of(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_laddr *laddr)
{
	int err;

	err = vstgc_require_laddr(vstg_ctx, laddr);
	if (err) {
		return err;
	}
	err = vstgc_do_stage_lseg(vstg_ctx, &laddr->lsid);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_require_lseg_of(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_laddr *laddr)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = vstgc_do_require_lseg_of(vstg_ctx, laddr);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
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
	err = vstgc_do_stage_lseg(vstg_ctx, &laddr->lsid);
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
		goto out_err;
	}
	ret = vstgc_require_laddr(vstg_ctx, laddr_src);
	if (ret) {
		goto out_err;
	}
	ret = vstgc_require_laddr(vstg_ctx, laddr_dst);
	if (ret) {
		goto out_err;
	}
	return 0;
out_err:
	if ((ret == -ENOENT) || (ret == -SILOFS_ENOENT)) {
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static int vstgc_require_lbk_llink(const struct silofs_vstage_ctx *vstg_ctx,
                                   struct silofs_laddr *out_dst_laddr,
                                   struct silofs_key *out_dst_key)
{
	int err;

	err = vstgc_require_spleaf_main_lseg(vstg_ctx, vstg_ctx->sli);
	if (err) {
		return err;
	}
	err = silofs_sli_resolve_main_lbk(vstg_ctx->sli, vstg_ctx->vaddr->off,
	                                  out_dst_laddr);
	if (err) {
		return err;
	}
	err = vstgc_resolve_key_of(vstg_ctx, out_dst_key);
	if (err) {
		return err;
	}
	return 0;
}

static void vstgc_rebind_lbk_llink(const struct silofs_vstage_ctx *vstg_ctx,
                                   const struct silofs_laddr *laddr,
                                   const struct silofs_key *key)
{

	silofs_sli_bind_child(vstg_ctx->sli, vstg_ctx->vaddr->off, laddr);
	if (vstg_ctx->vspace != SILOFS_MTYPE_LSMAP) {
		silofs_assert_not_null(vstg_ctx->lsi);
		silofs_lsi_rebind_key(vstg_ctx->lsi, vstg_ctx->vaddr, key);
	}
}

static int vstgc_clone_rebind_lbk(const struct silofs_vstage_ctx *vstg_ctx,
                                  const struct silofs_laddr *src_laddr)
{
	struct silofs_laddr dst_laddr;
	struct silofs_key dst_key;
	int err;

	err = vstgc_require_lbk_llink(vstg_ctx, &dst_laddr, &dst_key);
	if (err) {
		return err;
	}
	err = vstgc_require_lbks(vstg_ctx, src_laddr, &dst_laddr);
	if (err) {
		return err;
	}
	vstgc_rebind_lbk_llink(vstg_ctx, &dst_laddr, &dst_key);
	return 0;
}

static int
vstgc_pre_clone_stage_inode_at(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vnode_info **out_vni)
{
	struct silofs_inode_info *ii = nullptr;
	ino_t ino;
	int err;

	*out_vni = nullptr;
	ino = vaddr_to_ino(vaddr);
	err = silofs_stage_inode(vstg_ctx->task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		return err;
	}
	*out_vni = &ii->i_vni;
	return 0;
}

static int
vstgc_pre_clone_stage_vnode_at(const struct silofs_vstage_ctx *vstg_ctx,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_vnode_info **out_vni)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	*out_vni = nullptr;
	err = silofs_stage_vnode(vstg_ctx->task, nullptr, vaddr,
	                         SILOFS_STG_CUR, &vni);
	if (err) {
		silofs_assert_ne(err, -SILOFS_ERDONLY);
		return err;
	}
	*out_vni = vni;
	return 0;
}

static bool vstgc_has_vaddr(const struct silofs_vstage_ctx *vstg_ctx,
                            const struct silofs_vaddr *vaddr)
{
	return silofs_vaddr_isequal(vstg_ctx->vaddr, vaddr);
}

static int vstgc_pre_clone_stage_at(const struct silofs_vstage_ctx *vstg_ctx,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_vnode_info **out_vni)
{
	const enum silofs_stg_mode stg_mode = vstg_ctx->stg_mode;
	int ret = 0;

	if (vaddr->off == 0) {
		/* ignore off=0 which is allocated-as-numb once upon format */
		log_dbg("unexpected pre-clone: mtype=%d", vaddr->mtype);
		*out_vni = nullptr;
	} else if (vstgc_has_vaddr(vstg_ctx, vaddr) &&
	           ((stg_mode & SILOFS_STG_RAW) ||
	            silofs_vaddr_isdatabk(vaddr))) {
		/* ignore current data-block */
		*out_vni = nullptr;
	} else if (silofs_vaddr_isinode(vaddr)) {
		/* inode case */
		ret = vstgc_pre_clone_stage_inode_at(vstg_ctx, vaddr, out_vni);
	} else {
		/* normal case */
		ret = vstgc_pre_clone_stage_vnode_at(vstg_ctx, vaddr, out_vni);
	}
	return ret;
}

static int vstgc_do_require_lsmap_of(struct silofs_vstage_ctx *vstg_ctx)
{
	return silofs_require_lsmap_by(vstg_ctx->task, vstg_ctx->vaddr,
	                               &vstg_ctx->lsi);
}

static int vstgc_require_lsmap_of(struct silofs_vstage_ctx *vstg_ctx)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = vstgc_do_require_lsmap_of(vstg_ctx);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
}

static int vstgc_resolve_vaddrs(struct silofs_vstage_ctx *vstg_ctx,
                                struct silofs_vaddrs *out_vaddrs)
{
	const struct silofs_vaddr *vaddr = vstg_ctx->vaddr;
	int err;

	if (vstg_ctx->vspace == SILOFS_MTYPE_LSMAP) {
		silofs_sli_lbk_vaddrs_at(vstg_ctx->sli, vaddr, out_vaddrs);
	} else {
		err = vstgc_require_lsmap_of(vstg_ctx);
		if (err) {
			return err;
		}
		silofs_lsi_vaddrs_at(vstg_ctx->lsi, vaddr, out_vaddrs);
	}
	return 0;
}

static int vstgc_pre_clone_lbk(struct silofs_vstage_ctx *vstg_ctx,
                               struct silofs_vnis *vnis)
{
	struct silofs_vaddrs vas = { .count = 0 };
	struct silofs_vnode_info *vni = nullptr;
	int err = 0;

	STATICASSERT_EQ(ARRAY_SIZE(vnis->vnis), ARRAY_SIZE(vas.vaddr));

	err = vstgc_resolve_vaddrs(vstg_ctx, &vas);
	if (err) {
		return err;
	}
	vnis->count = 0;
	for (size_t i = 0; i < vas.count; ++i) {
		vni = nullptr;
		err = vstgc_pre_clone_stage_at(vstg_ctx, &vas.vaddr[i], &vni);
		if (err) {
			return err;
		}
		if (vni == nullptr) {
			continue;
		}
		silofs_vni_incref(vni);
		vnis->vnis[vnis->count++] = vni;
	}
	return err;
}

static void vstgc_redirtify_vni(const struct silofs_vstage_ctx *vstg_ctx,
                                struct silofs_vnode_info *vni)
{
	silofs_lcache_reditify_vni(vstgc_lcache(vstg_ctx), vni);
}

static void vstgc_post_clone_lbk(const struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_vnis *vnis)
{
	struct silofs_vnode_info *vni = nullptr;

	for (size_t i = 0; i < vnis->count; ++i) {
		vni = vnis->vnis[i];
		silofs_assert_not_null(vni);
		vstgc_redirtify_vni(vstg_ctx, vni);
		silofs_vni_decref(vni);
	}
}

static int vstgc_do_clone_lbk_at(struct silofs_vstage_ctx *vstg_ctx,
                                 const struct silofs_laddr *src_laddr)
{
	struct silofs_vnis vnis = { .count = 0 };
	int err;

	err = vstgc_pre_clone_lbk(vstg_ctx, &vnis);
	if (!err) {
		err = vstgc_clone_rebind_lbk(vstg_ctx, src_laddr);
	}
	vstgc_post_clone_lbk(vstg_ctx, &vnis);
	return err;
}

static int vstgc_clone_lbk_at(struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *src_laddr)
{
	int err;

	vstgc_increfs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	err = vstgc_do_clone_lbk_at(vstg_ctx, src_laddr);
	vstgc_decrefs(vstg_ctx, SILOFS_HEIGHT_SPLEAF);
	return err;
}

static int vstgc_clone_lbk_by(struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *src_laddr)
{
	struct silofs_laddr laddr_lbk;

	silofs_laddr_setup_lbk(&laddr_lbk, &src_laddr->lsid, src_laddr->pos);
	return vstgc_clone_lbk_at(vstg_ctx, &laddr_lbk);
}

static int vstgc_clone_lbk_of(struct silofs_vstage_ctx *vstg_ctx,
                              const struct silofs_laddr *src_laddr)
{
	int err;

	err = vstgc_check_may_clone(vstg_ctx);
	if (err) {
		return err;
	}
	err = vstgc_require_lseg_of(vstg_ctx, src_laddr);
	if (err) {
		silofs_assert_ne(err, -SILOFS_ERDONLY);
		return err;
	}
	err = vstgc_clone_lbk_by(vstg_ctx, src_laddr);
	if (err) {
		return err;
	}
	return 0;
}

static int vstgc_resolve_inspect_llink(struct silofs_vstage_ctx *vstg_ctx,
                                       struct silofs_llink *out_llink)
{
	struct silofs_llink llink;
	int err;

	err = vstgc_resolve_llink(vstg_ctx, &llink);
	if (err) {
		return err;
	}
	err = vstgc_inspect_laddr(vstg_ctx, &llink.laddr);
	if (!err) {
		goto out_ok;
	}
	if (err != -SILOFS_EPERM) {
		return err;
	}
	err = vstgc_clone_lbk_of(vstg_ctx, &llink.laddr);
	if (err) {
		return err;
	}
	err = vstgc_resolve_llink(vstg_ctx, &llink);
	if (err) {
		return err;
	}
out_ok:
	silofs_llink_assign(out_llink, &llink);
	return 0;
}

int silofs_resolve_llink_of(struct silofs_task_ctx *task,
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
                                    struct silofs_vnode_info **out_vni)
{
	return silofs_fetch_cached_vnode(vstg_ctx->task, vstg_ctx->vaddr,
	                                 out_vni);
}

static int vstgc_stage_vnode_at(struct silofs_vstage_ctx *vstg_ctx,
                                struct silofs_vnode_info **out_vni)
{
	struct silofs_llink llink = { .laddr.pos = -1 };
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = vstgc_resolve_inspect_llink(vstg_ctx, &llink);
	if (err) {
		goto out_err;
	}
	err = vstgc_do_require_lseg_of(vstg_ctx, &llink.laddr);
	if (err) {
		goto out_err;
	}
	err = vstgc_fetch_cached_vnode(vstg_ctx, &vni);
	if (!err) {
		/* vnode cached upon inspect -- just update llink */
		goto out_ok;
	}
	err = vstgc_spawn_vni_at(vstg_ctx, &llink, &vni);
	if (err) {
		goto out_err;
	}
	err = vstgc_stage_load_view(vstg_ctx, &llink.laddr,
	                            vni->vn_lni.ln_view);
	if (err) {
		goto out_err;
	}
	err = vstgc_update_view_of(vstg_ctx, vni);
	if (err) {
		goto out_err;
	}
out_ok:
	vni_update_llink(vni, &llink);
	*out_vni = vni;
	return 0;
out_err:
	vstgc_forget_cached_vni(vstg_ctx, vni);
	*out_vni = nullptr;
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*
 * Special case where data-node has been unmapped due to forget, yet it still
 * had a live ref-count due to on-going I/O operation.
 */
static int fixup_cached_vni(const struct silofs_task_ctx *task,
                            struct silofs_vnode_info *vni)
{
	if (!vni->vn_lni.ln_hmqe.hme_forgot) {
		return 0;
	}
	if (silofs_vni_refcnt(vni)) {
		return 0;
	}
	silofs_lcache_forget_vni(task->t_lcache, vni);
	return -SILOFS_ENOENT;
}

static int fetch_cached_vni(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_vnode_info **out_vni)
{
	struct silofs_vnode_info *vni;
	int err;

	vni = silofs_lcache_lookup_vni(task->t_lcache, vaddr);
	if (vni == nullptr) {
		return -SILOFS_ENOENT;
	}
	err = fixup_cached_vni(task, vni);
	if (err) {
		return err;
	}
	*out_vni = vni;
	return 0;
}

int silofs_fetch_cached_vnode(struct silofs_task_ctx *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vni)
{
	int ret = -SILOFS_ENOENT;

	if (!silofs_vaddr_isnull(vaddr)) {
		ret = fetch_cached_vni(task, vaddr, out_vni);
	}
	return ret;
}

static int
stage_vnode_at(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
               enum silofs_stg_mode stg_mode,
               struct silofs_vnode_info **out_vni)
{
	struct silofs_vstage_ctx vstg_ctx;

	vstgc_setup(&vstg_ctx, task, vaddr, stg_mode);
	return vstgc_stage_vnode_at(&vstg_ctx, out_vni);
}

static int stage_stable_vnode_at(struct silofs_task_ctx *task,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stg_mode stg_mode,
                                 struct silofs_vnode_info **out_vni)
{
	int err;

	err = require_stable_at(task, vaddr);
	if (err) {
		return err;
	}
	err = stage_vnode_at(task, vaddr, stg_mode, out_vni);
	if (err) {
		return err;
	}
	return 0;
}

static int require_updated_cached_vni(struct silofs_task_ctx *task,
                                      struct silofs_vnode_info *vni,
                                      enum silofs_stg_mode stg_mode)
{
	struct silofs_llink llink = { .laddr.pos = -1 };
	const struct silofs_vaddr *vaddr = nullptr;
	int err;

	if (!(stg_mode & SILOFS_STG_COW)) {
		return 0;
	}
	if (vni_has_mutable_laddr(vni)) {
		return 0;
	}
	vaddr = silofs_vni_vaddr(vni);
	err = silofs_resolve_llink_of(task, vaddr, stg_mode, &llink);
	if (err) {
		return err;
	}
	vni_update_llink(vni, &llink);
	return 0;
}

static int do_resolve_stage_vnode(struct silofs_task_ctx *task,
                                  const struct silofs_vaddr *vaddr,
                                  enum silofs_stg_mode stg_mode,
                                  struct silofs_vnode_info **out_vni)
{
	int err;

	err = fetch_cached_vni(task, vaddr, out_vni);
	if (!err) {
		/* cache hit -- require up-to-date */
		err = require_updated_cached_vni(task, *out_vni, stg_mode);
	} else {
		/* cache miss -- stage from objects store */
		err = stage_stable_vnode_at(task, vaddr, stg_mode, out_vni);
	}
	return err;
}

static int check_stage_mode(const struct silofs_task_ctx *task,
                            enum silofs_stg_mode stg_mode)
{
	return ((stg_mode & SILOFS_STG_COW) && //
	        (silofs_env_isrdonlyfs(task->t_env))) ?
	               -SILOFS_EROFS :
	               0;
}

static int check_stage_vnode(const struct silofs_task_ctx *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stg_mode stg_mode)
{
	int err = -SILOFS_ENOENT;

	if (!silofs_vaddr_isnull(vaddr)) {
		err = check_stage_mode(task, stg_mode);
	}
	return err;
}

static int
do_stage_vnode(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
               enum silofs_stg_mode stg_mode,
               struct silofs_vnode_info **out_vni)
{
	int err;

	err = check_stage_vnode(task, vaddr, stg_mode);
	if (err) {
		return err;
	}
	err = do_resolve_stage_vnode(task, vaddr, stg_mode, out_vni);
	if (err) {
		return err;
	}
	return 0;
}

static int
pre_stage_vnode(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
                enum silofs_stg_mode stg_mode)
{
	struct silofs_vaddr vaddr2;
	struct silofs_vnode_info *vni = nullptr;
	int ret = 0;

	if (vaddr->mtype != SILOFS_MTYPE_LSMAP) {
		silofs_vaddr_of_lsmap(&vaddr2, vaddr->mtype, vaddr->off);
		ret = silofs_stage_vnode(task, nullptr, &vaddr2, stg_mode,
		                         &vni);
	}
	return ret;
}

int silofs_stage_vnode(struct silofs_task_ctx *task,
                       struct silofs_inode_info *pii,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stg_mode stg_mode,
                       struct silofs_vnode_info **out_vni)
{
	int err;

	silofs_ii_incref(pii);
	err = pre_stage_vnode(task, vaddr, stg_mode);
	if (!err) {
		err = do_stage_vnode(task, vaddr, stg_mode, out_vni);
	}
	silofs_ii_decref(pii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
fetch_cached_ii(struct silofs_task_ctx *task, const struct silofs_vaddr *vaddr,
                struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = fetch_cached_vni(task, vaddr, &vni);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vni(vni);
	return 0;
}

static int resolve_iaddr(ino_t ino, struct silofs_vaddr *out_vaddr)
{
	const ino_t ino_max = SILOFS_INO_MAX;
	const ino_t ino_root = SILOFS_INO_ROOT;
	off_t voff;

	if ((ino < ino_root) || (ino > ino_max)) {
		return -SILOFS_EINVAL;
	}
	voff = ino_to_off(ino);
	if (silofs_off_isnull(voff)) {
		return -SILOFS_EINVAL;
	}
	silofs_vaddr_setup(out_vaddr, SILOFS_MTYPE_INODE, voff);
	return 0;
}

static int check_stage_inode(const struct silofs_task_ctx *task, ino_t ino,
                             enum silofs_stg_mode stg_mode)
{
	int err = -SILOFS_ENOENT;

	if (!silofs_ino_isnull(ino)) {
		err = check_stage_mode(task, stg_mode);
	}
	return err;
}

static int resolve_stable_iaddr(struct silofs_task_ctx *task, ino_t ino,
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

static int stage_stable_inode_at(struct silofs_task_ctx *task,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stg_mode stg_mode,
                                 struct silofs_inode_info **out_ii)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = stage_stable_vnode_at(task, vaddr, stg_mode, &vni);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vni(vni);
	silofs_ii_set_ino(*out_ii, vaddr_to_ino(vaddr));
	silofs_ii_refresh_atime(*out_ii, true);
	return 0;
}

static int require_updated_cached_ii(struct silofs_task_ctx *task,
                                     struct silofs_inode_info *ii,
                                     enum silofs_stg_mode stg_mode)
{
	return require_updated_cached_vni(task, &ii->i_vni, stg_mode);
}

static int do_resolve_stage_inode(struct silofs_task_ctx *task, ino_t ino,
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

int silofs_stage_inode(struct silofs_task_ctx *task, ino_t ino,
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

int silofs_fetch_cached_inode(struct silofs_task_ctx *task, ino_t ino,
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
static int
stage_raw_vnode(struct silofs_task_ctx *task, struct silofs_inode_info *pii,
                const struct silofs_vaddr *vaddr,
                struct silofs_vnode_info **out_vni)
{
	const enum silofs_stg_mode stg_mode = SILOFS_STG_COW | SILOFS_STG_RAW;

	return silofs_stage_vnode(task, pii, vaddr, stg_mode, out_vni);
}

static int
spawn_vnode_at(struct silofs_task_ctx *task, struct silofs_inode_info *pii,
               const struct silofs_vaddr *vaddr,
               struct silofs_vnode_info **out_vni)
{
	int err;

	err = stage_raw_vnode(task, pii, vaddr, out_vni);
	if (err) {
		return err;
	}
	silofs_vni_dirtify(*out_vni, pii);
	return 0;
}

static int
do_spawn_vnode(struct silofs_task_ctx *task, struct silofs_inode_info *pii,
               enum silofs_mtype mtype, struct silofs_vnode_info **out_vni)
{
	struct silofs_vaddr vaddr;
	int err;

	err = silofs_claim_vspace(task, mtype, &vaddr);
	if (err) {
		return err;
	}
	err = spawn_vnode_at(task, pii, &vaddr, out_vni);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_spawn_vnode(struct silofs_task_ctx *task,
                       struct silofs_inode_info *pii, enum silofs_mtype mtype,
                       struct silofs_vnode_info **out_vni)
{
	int err;

	silofs_ii_incref(pii);
	err = do_spawn_vnode(task, pii, mtype, out_vni);
	silofs_ii_decref(pii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_itype(const struct silofs_task_ctx *task, mode_t mode)
{
	/*
	 * TODO-0031: Filter supported modes based on mount flags
	 */
	const mode_t itype = mode & S_IFMT;
	const bool no_ispecial = task->t_env->base.args->no_ispecial;
	int ret;

	switch (itype) {
	case S_IFDIR:
	case S_IFREG:
	case S_IFLNK:
		ret = 0;
		break;
	case S_IFSOCK:
	case S_IFIFO:
		ret = no_ispecial ? -SILOFS_EOPNOTSUPP : 0;
		break;
	case S_IFCHR:
	case S_IFBLK:
	default:
		ret = -SILOFS_EOPNOTSUPP;
		break;
	}
	return ret;
}

static int
claim_inode(struct silofs_task_ctx *task, struct silofs_inode_info **out_ii)
{
	struct silofs_vaddr vaddr;
	struct silofs_vnode_info *vni = nullptr;
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = silofs_claim_ispace(task, &vaddr);
	if (err) {
		return err;
	}
	err = stage_raw_vnode(task, nullptr, &vaddr, &vni);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vni(vni);
	silofs_ii_set_ino(ii, vaddr_to_ino(&vaddr));
	*out_ii = ii;
	return 0;
}

static uint64_t next_igen(const struct silofs_task_ctx *task)
{
	struct silofs_sb_info *sbi = silofs_get_sbi(task);

	return silofs_sbst_next_generation(sbi);
}

int silofs_spawn_inode(struct silofs_task_ctx *task,
                       const struct silofs_inew_params *inp,
                       struct silofs_inode_info **out_ii)
{
	uint64_t gen;
	int err;

	err = check_itype(task, inp->mode);
	if (err) {
		return err;
	}
	err = claim_inode(task, out_ii);
	if (err) {
		return err;
	}
	gen = next_igen(task);
	silofs_ii_setup_new(*out_ii, inp, gen);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void forget_cached_vni(const struct silofs_task_ctx *task,
                              struct silofs_vnode_info *vni)
{
	silofs_lcache_forget_vni(task->t_lcache, vni);
}

static int reclaim_vspace_at(struct silofs_task_ctx *task,
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

static int
remove_vnode_of(struct silofs_task_ctx *task, struct silofs_vnode_info *vni)
{
	int err;

	silofs_vni_incref(vni);
	err = reclaim_vspace_at(task, silofs_vni_vaddr(vni));
	silofs_vni_decref(vni);
	return err;
}

int silofs_remove_vnode(struct silofs_task_ctx *task,
                        struct silofs_vnode_info *vni)
{
	int err;

	err = remove_vnode_of(task, vni);
	if (err) {
		return err;
	}
	forget_cached_vni(task, vni);
	return 0;
}

int silofs_remove_vnode_at(struct silofs_task_ctx *task,
                           const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = silofs_fetch_cached_vnode(task, vaddr, &vni);
	if (!err) {
		err = silofs_remove_vnode(task, vni);
	} else {
		err = reclaim_vspace_at(task, vaddr);
	}
	return err;
}

static int
remove_inode_of(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	int err;

	silofs_ii_incref(ii);
	err = reclaim_vspace_at(task, silofs_ii_vaddr(ii));
	silofs_ii_decref(ii);
	return err;
}

static void forget_cached_ii(const struct silofs_task_ctx *task,
                             struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vnis.dq.sz, 0);

	silofs_ii_undirtify(ii);
	forget_cached_vni(task, &ii->i_vni);
}

int silofs_remove_inode(struct silofs_task_ctx *task,
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

int silofs_refresh_llink(struct silofs_task_ctx *task,
                         struct silofs_vnode_info *vni)
{
	struct silofs_llink llink = { .laddr.pos = -1 };
	const struct silofs_vaddr *vaddr = nullptr;
	int err;

	if (vni_has_mutable_laddr(vni)) {
		return 0;
	}
	vaddr = silofs_vni_vaddr(vni);
	err = silofs_resolve_llink_of(task, vaddr, SILOFS_STG_CUR, &llink);
	if (err) {
		log_warn("failed to refresh llink: mtype=%d off=%ld err=%d",
		         vaddr->mtype, vaddr->off, err);
		return err;
	}
	vni_update_llink(vni, &llink);
	return 0;
}
