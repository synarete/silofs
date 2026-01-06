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
#include <silofs/ioctls.h>
#include "obs.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

/* space-allocation context */
struct silofs_spalloc_ctx {
	struct silofs_task_ctx    *task;
	struct silofs_env         *env;
	struct silofs_sb_info     *sbi;
	struct silofs_spleaf_info *sli;
	struct silofs_lsmap_info  *lsi;
	enum silofs_mtype          mtype;
	bool                       incref_lsi;
};

/* local functions */
static int
require_lsmap_of(struct silofs_task_ctx *task, enum silofs_mtype refmtype,
                 off_t off, struct silofs_lsmap_info **out_lsi);

static int
stage_lsmap_of(struct silofs_task_ctx *task, enum silofs_mtype refmtype,
               off_t off, struct silofs_lsmap_info **out_lsi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t spleaf_span(void)
{
	return SILOFS_SPMAP_NCHILDS * SILOFS_LBK_SIZE;
}

static off_t off_to_spleaf_start(off_t voff)
{
	return silofs_off_align(voff, (long)spleaf_span());
}

static off_t off_to_spleaf_next(off_t voff)
{
	const off_t vsilofs_off_next = silofs_off_end(voff, spleaf_span());

	return off_to_spleaf_start(vsilofs_off_next);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *spac_repo(const struct silofs_spalloc_ctx *spa_ctx)
{
	return spa_ctx->task->t_repo;
}

static struct silofs_spamaps *
spac_spamaps(const struct silofs_spalloc_ctx *spa_ctx)
{
	return spa_ctx->env->base.spamaps;
}

static off_t spac_get_hint(const struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_spamaps *spam = spac_spamaps(spa_ctx);

	return silofs_spamaps_get_hint(spam, spa_ctx->mtype);
}

static void spac_set_hint(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);

	silofs_spamaps_set_hint(spam, spa_ctx->mtype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sbi_is_within_vspace(const struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr   *vaddr)
{
	const size_t vaddr_len  = silofs_vaddr_len(vaddr);
	const off_t  vaddr_beg  = vaddr->off;
	const off_t  vaddr_end  = silofs_off_end(vaddr_beg, vaddr_len);
	const off_t  vspace_end = silofs_sbst_vspace_end(sbi);

	return (vaddr_end <= vspace_end);
}

static void sbi_update_space_stats(struct silofs_sb_info     *sbi,
                                   const struct silofs_vaddr *vaddr,
                                   ssize_t nobjs_take, ssize_t nbks_take)
{
	/*
	 * TODO-0045: Update stats properly for case of shared-blocks
	 *
	 * Current code does not take into account case of shared blocks.
	 * May need more fine-grained logic.
	 */
	silofs_sbst_update_objs(sbi, vaddr->mtype, nobjs_take);
	silofs_sbst_update_bks(sbi, vaddr->mtype, nbks_take);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spac_setup(struct silofs_spalloc_ctx *spa_ctx,
                       struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	silofs_memzero(spa_ctx, sizeof(*spa_ctx));
	spa_ctx->task  = task;
	spa_ctx->env   = task->t_env;
	spa_ctx->sbi   = silofs_get_sbi(task);
	spa_ctx->sli   = nullptr;
	spa_ctx->lsi   = nullptr;
	spa_ctx->mtype = mtype;
}

static void spac_increfs(struct silofs_spalloc_ctx *spa_ctx)
{
	silofs_assert_not_null(spa_ctx->sli);
	silofs_sli_incref(spa_ctx->sli);
	if (spa_ctx->lsi != nullptr) {
		silofs_lsi_incref(spa_ctx->lsi);
		spa_ctx->incref_lsi = true;
	}
}

static void spac_decrefs(struct silofs_spalloc_ctx *spa_ctx)
{
	silofs_assert_not_null(spa_ctx->sli);
	silofs_sli_decref(spa_ctx->sli);
	if (spa_ctx->incref_lsi) {
		silofs_assert_not_null(spa_ctx->lsi);
		silofs_lsi_decref(spa_ctx->lsi);
		spa_ctx->incref_lsi = false;
	}
}

static int spac_stage_spleaf_of(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	struct silofs_vaddr vaddr;

	silofs_vaddr_setup(&vaddr, spa_ctx->mtype, off);
	return silofs_stage_spleaf_of(spa_ctx->task, &vaddr, SILOFS_STG_CUR,
	                              &spa_ctx->sli);
}

static int spac_require_spleaf_of(struct silofs_spalloc_ctx *spa_ctx,
                                  off_t off, bool *out_new)
{
	struct silofs_vaddr vaddr;
	int                 err;

	silofs_vaddr_setup(&vaddr, spa_ctx->mtype, off);
	err = silofs_require_spleaf_of(spa_ctx->task, &vaddr, SILOFS_STG_COW,
	                               &spa_ctx->sli);
	if (err) {
		return err;
	}
	err = silofs_sli_require_child(spa_ctx->sli, &vaddr, out_new);
	if (err) {
		return err;
	}
	return 0;
}

static int spac_check_within_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                    const struct silofs_vaddr *vaddr)
{
	return sbi_is_within_vspace(spa_ctx->sbi, vaddr) ? 0 : -SILOFS_ENOSPC;
}

static int spac_resolve_llink(struct silofs_spalloc_ctx *spa_ctx,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_llink       *out_llink)
{
	return silofs_resolve_llink_of(spa_ctx->task, vaddr, SILOFS_STG_CUR,
	                               out_llink);
}

static int spac_do_find_free_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                       struct silofs_vaddr       *out_vaddr)
{
	enum silofs_mtype refmtype;
	int               err;

	silofs_assert_not_null(spa_ctx->sli);
	silofs_assert_not_null(spa_ctx->lsi);

	refmtype = silofs_sli_refmtype(spa_ctx->sli);
	silofs_assert_eq(refmtype, spa_ctx->mtype);

	err = silofs_lsi_find_free_space(spa_ctx->lsi, out_vaddr);
	if (err) {
		return err;
	}
	err = spac_check_within_vspace(spa_ctx, out_vaddr);
	if (err) {
		return err;
	}
	silofs_lsi_update_off_hint(spa_ctx->lsi, out_vaddr);
	return 0;
}

static int spac_find_free_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                    struct silofs_vaddr       *out_vaddr)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_do_find_free_vspace_at(spa_ctx, out_vaddr);
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_require_lsmap_by(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	const enum silofs_mtype refmtype = silofs_sli_refmtype(spa_ctx->sli);
	int                     err;

	spac_increfs(spa_ctx);
	err = require_lsmap_of(spa_ctx->task, refmtype, off, &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static void spac_unref_spmaps(struct silofs_spalloc_ctx *spa_ctx)
{
	spa_ctx->sli = nullptr;
	spa_ctx->lsi = nullptr;
}

static int spac_require_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                  off_t voff, struct silofs_vaddr *out_vaddr)
{
	bool new_bind = false;
	int  err;

	err = spac_require_spleaf_of(spa_ctx, voff, &new_bind);
	if (err) {
		return err;
	}
	err = spac_require_lsmap_by(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_find_free_vspace_at(spa_ctx, out_vaddr);
	if (err) {
		spac_unref_spmaps(spa_ctx);
		return err;
	}
	return 0;
}

static int
spac_require_vspace_by_spmaps(struct silofs_spalloc_ctx *spa_ctx, off_t hint,
                              struct silofs_vaddr *out_vaddr)
{
	const off_t vend = silofs_sbst_vspace_end(spa_ctx->sbi);
	off_t       voff = hint;
	int         err;

	while (voff < vend) {
		err = spac_require_vspace_at(spa_ctx, voff, out_vaddr);
		if (err != -SILOFS_ENOSPC) {
			return err;
		}
		voff = off_to_spleaf_next(voff);
	}
	return -SILOFS_ENOSPC;
}

static int spac_claim_vspace_from_cache(struct silofs_spalloc_ctx *spa_ctx,
                                        struct silofs_vaddr       *out_vaddr)
{
	struct silofs_spamaps  *spam  = spac_spamaps(spa_ctx);
	const enum silofs_mtype mtype = spa_ctx->mtype;
	const size_t            len   = silofs_mtype_size(mtype);
	off_t                   voff  = SILOFS_OFF_NULL;
	int                     err;

	err = silofs_spamaps_trypop(spam, mtype, len, &voff);
	if (!err) {
		silofs_vaddr_setup(out_vaddr, mtype, voff);
	}
	return err;
}

static int
spac_require_unalloc_vspace(struct silofs_spalloc_ctx *spa_ctx, off_t hint,
                            struct silofs_vaddr *out_vaddr)
{
	int err;

	/* Fast path: there exists an in-memory cached free space; use it */
	err = spac_claim_vspace_from_cache(spa_ctx, out_vaddr);
	if (!err) {
		return 0;
	}
	/* Slow path: stage and search space maps */
	err = spac_require_vspace_by_spmaps(spa_ctx, hint, out_vaddr);
	if (err) {
		return err;
	}
	/* Perhaps in-memory cache was re-popolated due to slow-path search;
	 * if so, ensure that the newly inserted ranged is chopped-out from
	 * in-memory cache (and dont-care if not-in-cache) */
	spac_claim_vspace_from_cache(spa_ctx, out_vaddr);
	return 0;
}

static int spac_check_avail_space(const struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_sb_info *sbi = spa_ctx->sbi;
	const size_t                 nb  = silofs_mtype_size(spa_ctx->mtype);
	bool                         new_file;
	bool                         ok;

	ok = silofs_sbst_mayalloc_some(sbi, nb);
	if (ok) {
		if (silofs_mtype_isdata(spa_ctx->mtype)) {
			ok = silofs_sbst_mayalloc_data(sbi, nb);
		} else {
			new_file = silofs_mtype_isinode(spa_ctx->mtype);
			ok = silofs_sbst_mayalloc_meta(sbi, nb, new_file);
		}
	}
	return ok ? 0 : -SILOFS_ENOSPC;
}

static int spac_check_want_free_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                       const struct silofs_vaddr *vaddr)
{
	if (silofs_vaddr_isnull(vaddr)) {
		return -SILOFS_ENOSPC;
	}
	if (!sbi_is_within_vspace(spa_ctx->sbi, vaddr)) {
		return -SILOFS_ENOSPC;
	}
	return 0;
}

static void spac_mark_allocated(struct silofs_spalloc_ctx *spa_ctx,
                                const struct silofs_vaddr *vaddr)
{
	bool first = true;

	if (spa_ctx->mtype != SILOFS_MTYPE_LSMAP) {
		silofs_assert_not_null(spa_ctx->lsi);

		first = !silofs_lsi_has_allocated_with(spa_ctx->lsi, vaddr);
		silofs_lsi_mark_allocated_at(spa_ctx->lsi, vaddr);
	}

	sbi_update_space_stats(spa_ctx->sbi, vaddr, 1, first ? 1 : 0);
	spac_set_hint(spa_ctx, vaddr->off);
}

static int spac_try_find_unallocated_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                            struct silofs_vaddr *out_vaddr)
{
	const off_t hint = spac_get_hint(spa_ctx);

	return spac_require_unalloc_vspace(spa_ctx, hint, out_vaddr);
}

static int spac_do_resolve_and_claim(struct silofs_spalloc_ctx *spa_ctx,
                                     const struct silofs_vaddr *vaddr,
                                     struct silofs_llink       *out_llink)
{
	int err;

	err = spac_resolve_llink(spa_ctx, vaddr, out_llink);
	if (err) {
		return err;
	}
	spac_mark_allocated(spa_ctx, vaddr);
	return 0;
}

static int spac_resolve_and_claim(struct silofs_spalloc_ctx *spa_ctx,
                                  const struct silofs_vaddr *vaddr,
                                  struct silofs_llink       *out_llink)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_do_resolve_and_claim(spa_ctx, vaddr, out_llink);
	spac_decrefs(spa_ctx);
	return err;
}

static int
spac_require_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	bool new_bind = false;
	int  err;

	err = spac_require_spleaf_of(spa_ctx, off, &new_bind);
	if (!err && (spa_ctx->mtype != SILOFS_MTYPE_LSMAP)) {
		err = spac_require_lsmap_by(spa_ctx, off);
	}
	return err;
}

static int spac_claim_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	int                 err;

	err = spac_check_want_free_vspace(spa_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spac_require_spmaps_of(spa_ctx, vaddr->off);
	if (err) {
		return err;
	}
	err = spac_resolve_and_claim(spa_ctx, vaddr, &llink);
	if (err) {
		return err;
	}
	return 0;
}

static int spac_claim_vspace(struct silofs_spalloc_ctx *spa_ctx,
                             struct silofs_vaddr       *out_vaddr)
{
	int err;

	err = spac_check_avail_space(spa_ctx);
	if (err) {
		return err;
	}
	err = spac_try_find_unallocated_vspace(spa_ctx, out_vaddr);
	if (err) {
		return err;
	}
	err = spac_claim_vspace_at(spa_ctx, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int
claim_vspace_of(struct silofs_task_ctx *task, enum silofs_mtype mtype,
                struct silofs_vaddr *out_vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;

	silofs_assert_ne(mtype, SILOFS_MTYPE_LSMAP);

	spac_setup(&spa_ctx, task, mtype);
	return spac_claim_vspace(&spa_ctx, out_vaddr);
}

static off_t lsmap_base_offset(off_t off)
{
	return silofs_off_align(off, SILOFS_LSEG_SIZE_MAX);
}

static int spac_stage_lsmap(const struct silofs_spalloc_ctx *spa_ctx,
                            const struct silofs_vaddr       *vaddr,
                            enum silofs_stg_mode             stg_mode,
                            struct silofs_lsmap_info       **out_lsi)
{
	struct silofs_vnode_info *vni = nullptr;
	int                       err;

	err = silofs_stage_vnode(spa_ctx->task, nullptr, vaddr, stg_mode,
	                         &vni);
	if (err) {
		return err;
	}
	*out_lsi = silofs_lsi_from_vni(vni);
	return 0;
}

static int spac_spawn_lsmap_at(struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr *vaddr,
                               enum silofs_mtype refmtype, off_t off,
                               struct silofs_lsmap_info **out_lsi)
{
	enum silofs_stg_mode stg_mode;
	int                  err;

	err = spac_claim_vspace_at(spa_ctx, vaddr);
	if (err) {
		return err;
	}
	stg_mode = SILOFS_STG_COW | SILOFS_STG_RAW;
	err      = spac_stage_lsmap(spa_ctx, vaddr, stg_mode, out_lsi);
	if (err) {
		return err;
	}

	silofs_lsi_setup_spawned(*out_lsi, refmtype, lsmap_base_offset(off));
	spac_mark_allocated(spa_ctx, vaddr);

	return 0;
}

static int spac_stage_lsmap_at(struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_lsmap_info **out_lsi)
{
	int err;

	err = spac_stage_lsmap(spa_ctx, vaddr, SILOFS_STG_COW, out_lsi);
	if (err) {
		return err;
	}
	silofs_lsi_update_nused(*out_lsi);
	return 0;
}

static int
spac_require_lsmap_at(struct silofs_spalloc_ctx *spa_ctx,
                      const struct silofs_vaddr *vaddr,
                      enum silofs_mtype refmtype, off_t off, bool new_bind)
{
	int err;

	spac_increfs(spa_ctx);
	if (new_bind) {
		err = spac_spawn_lsmap_at(spa_ctx, vaddr, refmtype, off,
		                          &spa_ctx->lsi);
	} else {
		err = spac_stage_lsmap_at(spa_ctx, vaddr, &spa_ctx->lsi);
	}
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_require_lsmap_of(struct silofs_spalloc_ctx *spa_ctx,
                                 enum silofs_mtype refmtype, off_t off)
{
	struct silofs_vaddr vaddr;
	bool                new_bind = false;
	int                 err;

	silofs_assert_eq(spa_ctx->mtype, SILOFS_MTYPE_LSMAP);
	silofs_assert_ne(refmtype, SILOFS_MTYPE_LSMAP);

	silofs_vaddr_of_lsmap(&vaddr, refmtype, off);
	err = spac_require_spleaf_of(spa_ctx, vaddr.off, &new_bind);
	if (err) {
		return err;
	}
	err = spac_require_lsmap_at(spa_ctx, &vaddr, refmtype, off, new_bind);
	if (err) {
		return err;
	}
	return 0;
}

static int
require_lsmap_of(struct silofs_task_ctx *task, enum silofs_mtype refmtype,
                 off_t off, struct silofs_lsmap_info **out_lsi)
{
	struct silofs_spalloc_ctx spa_ctx;
	int                       err;

	silofs_assert_ne(refmtype, SILOFS_MTYPE_LSMAP);

	spac_setup(&spa_ctx, task, SILOFS_MTYPE_LSMAP);
	err = spac_require_lsmap_of(&spa_ctx, refmtype, off);
	if (err) {
		return err;
	}
	*out_lsi = spa_ctx.lsi;
	return 0;
}

static int spac_try_stage_lsmap_at(struct silofs_spalloc_ctx *spa_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_stage_lsmap_at(spa_ctx, vaddr, &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_stage_lsmap_of(struct silofs_spalloc_ctx *spa_ctx,
                               enum silofs_mtype refmtype, off_t off)
{
	struct silofs_vaddr vaddr;
	int                 err;

	silofs_assert_eq(spa_ctx->mtype, SILOFS_MTYPE_LSMAP);
	silofs_assert_ne(refmtype, SILOFS_MTYPE_LSMAP);

	silofs_vaddr_of_lsmap(&vaddr, refmtype, off);
	err = spac_stage_spleaf_of(spa_ctx, vaddr.off);
	if (err) {
		return err;
	}
	err = spac_try_stage_lsmap_at(spa_ctx, &vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int
stage_lsmap_of(struct silofs_task_ctx *task, enum silofs_mtype refmtype,
               off_t off, struct silofs_lsmap_info **out_lsi)
{
	struct silofs_spalloc_ctx spa_ctx;
	int                       err;

	silofs_assert_ne(refmtype, SILOFS_MTYPE_LSMAP);

	spac_setup(&spa_ctx, task, SILOFS_MTYPE_LSMAP);
	err = spac_stage_lsmap_of(&spa_ctx, refmtype, off);
	if (err) {
		return err;
	}
	*out_lsi = spa_ctx.lsi;
	return 0;
}

int silofs_require_lsmap_by(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_lsmap_info **out_lsi)
{
	return require_lsmap_of(task, vaddr->mtype, vaddr->off, out_lsi);
}

int silofs_claim_vspace(struct silofs_task_ctx *task, enum silofs_mtype mtype,
                        struct silofs_vaddr *out_vaddr)
{
	struct silofs_lsmap_info *lsi = nullptr;
	int                       err;

	silofs_assert_ne(mtype, SILOFS_MTYPE_LSMAP);

	err = claim_vspace_of(task, mtype, out_vaddr);
	if (err) {
		return err;
	}
	err = silofs_require_lsmap_by(task, out_vaddr, &lsi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_claim_ispace(struct silofs_task_ctx *task,
                        struct silofs_vaddr    *out_vaddr)
{
	return silofs_claim_vspace(task, SILOFS_MTYPE_INODE, out_vaddr);
}

static bool spac_has_dbkref_at(const struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr       *vaddr)
{
	size_t refcnt;

	silofs_assert_not_null(spa_ctx->lsi);
	refcnt = silofs_lsi_refcnt_at(spa_ctx->lsi, vaddr);

	return (refcnt > 0);
}

static int spac_try_recache_vspace(const struct silofs_spalloc_ctx *spa_ctx,
                                   const struct silofs_vaddr       *vaddr)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);
	size_t                 len;

	if (vaddr->mtype == SILOFS_MTYPE_LSMAP) {
		return 0;
	}
	if (spac_has_dbkref_at(spa_ctx, vaddr)) {
		return 0;
	}
	len = silofs_vaddr_len(vaddr);
	return silofs_spamaps_store(spam, vaddr->mtype, vaddr->off, len);
}

static bool spac_ismutable_lsid(const struct silofs_spalloc_ctx *spa_ctx,
                                const struct silofs_lsid        *lsid)
{
	return silofs_sbi_ismutable_lsid(spa_ctx->sbi, lsid);
}

static int spac_resolve_main_range(const struct silofs_spalloc_ctx *spa_ctx,
                                   struct silofs_lsid              *out_lsid,
                                   struct silofs_lrange            *out_lrange)
{
	struct silofs_spleaf_info *sli = spa_ctx->sli;
	enum silofs_mtype          mtype;

	silofs_sli_main_lseg(sli, out_lsid);
	if (silofs_lsid_isnull(out_lsid)) {
		return -SILOFS_ENOENT;
	}
	mtype = silofs_blobid_get_mtype(&out_lsid->blobid);
	if (mtype != spa_ctx->mtype) {
		return -SILOFS_EBUG;
	}
	silofs_sli_get_lrange(sli, out_lrange);
	return 0;
}

/*
 * optional operation: in case of data-leaf where no vspace is in-use,
 * reclaim-by-punch the underlying object space.
 */
static int spac_try_reclaim_vlseg(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_lsid   lsid;
	struct silofs_lrange lrange;
	int                  err;

	if (spa_ctx->lsi == nullptr) {
		return 0;
	}
	if (spa_ctx->lsi->ls_nused_bytes) {
		return 0; /* still has in-use blocks: no-op */
	}
	err = spac_resolve_main_range(spa_ctx, &lsid, &lrange);
	if (err) {
		return 0; /* not on main lseg: no-op */
	}
	if (!spac_ismutable_lsid(spa_ctx, &lsid)) {
		return 0; /* not a mutable lseg */
	}
	err = silofs_repo_punch_lseg(spac_repo(spa_ctx), &lsid);
	if (err && (err != -ENOTSUP)) {
		log_err("failed to punch lseg: err=%d", err);
		return err;
	}
	return 0;
}

static void spac_clear_allocate_at(const struct silofs_spalloc_ctx *spa_ctx,
                                   const struct silofs_vaddr       *vaddr)
{
	silofs_assert_not_null(spa_ctx->lsi);

	// silofs_sli_unref_allocated_at(spa_ctx->sli, vaddr);
	silofs_lsi_unref_allocated_at(spa_ctx->lsi, vaddr);

	if (!spac_has_dbkref_at(spa_ctx, vaddr)) {
		sbi_update_space_stats(spa_ctx->sbi, vaddr, -1, 0);
	}
}

static void spac_reclaim_vspace_of(const struct silofs_spalloc_ctx *spa_ctx,
                                   const struct silofs_vaddr       *vaddr)
{
	spac_clear_allocate_at(spa_ctx, vaddr);
	spac_try_recache_vspace(spa_ctx, vaddr);
	spac_try_reclaim_vlseg(spa_ctx);
}

static int spac_resolve_and_reclaim(struct silofs_spalloc_ctx *spa_ctx,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_llink       *out_llink)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_resolve_llink(spa_ctx, vaddr, out_llink);
	if (!err) {
		spac_reclaim_vspace_of(spa_ctx, vaddr);
	}
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_refresh_lsmap(struct silofs_spalloc_ctx *spa_ctx,
                              const struct silofs_vaddr *vaddr)
{
	int err;

	spac_increfs(spa_ctx);
	err = stage_lsmap_of(spa_ctx->task, vaddr->mtype, vaddr->off,
	                     &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_reclaim_vspace(struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	bool                new_bind = false;
	int                 err;

	err = spac_require_spleaf_of(spa_ctx, vaddr->off, &new_bind);
	if (err) {
		return err;
	}
	err = spac_refresh_lsmap(spa_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spac_resolve_and_reclaim(spa_ctx, vaddr, &llink);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_reclaim_vspace(struct silofs_task_ctx    *task,
                          const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;

	silofs_assert_ne(vaddr->mtype, SILOFS_MTYPE_LSMAP);

	spac_setup(&spa_ctx, task, vaddr->mtype);
	return spac_reclaim_vspace(&spa_ctx, vaddr);
}

static int spac_addref_vspace(struct silofs_spalloc_ctx *spa_ctx,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	int                 err;

	spac_increfs(spa_ctx);
	err = spac_resolve_llink(spa_ctx, vaddr, &llink);
	if (!err) {
		silofs_lsi_reref_allocated_at(spa_ctx->lsi, vaddr);
	}
	spac_decrefs(spa_ctx);
	return err;
}

int silofs_addref_vspace(struct silofs_task_ctx    *task,
                         const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;
	bool                      new_bind = false;
	int                       err;

	spac_setup(&spa_ctx, task, vaddr->mtype);
	err = spac_require_spleaf_of(&spa_ctx, vaddr->off, &new_bind);
	if (err) {
		return err;
	}
	err = spac_refresh_lsmap(&spa_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spac_addref_vspace(&spa_ctx, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int spac_stage_lsmap_by(struct silofs_spalloc_ctx *spa_ctx, off_t voff)
{
	int err;

	spac_increfs(spa_ctx);
	err = stage_lsmap_of(spa_ctx->task, spa_ctx->mtype, voff,
	                     &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_rescan_free_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                   struct silofs_vaddr       *out_vaddr)
{
	const off_t vend = silofs_sbst_vspace_end(spa_ctx->sbi);
	off_t       voff = 0;
	int         err;

	while (voff < vend) {
		err = spac_stage_spleaf_of(spa_ctx, voff);
		if (err) {
			return err;
		}
		err = spac_stage_lsmap_by(spa_ctx, voff);
		if (err) {
			return err;
		}

		spac_set_hint(spa_ctx, voff);

		err = spac_find_free_vspace_at(spa_ctx, out_vaddr);
		if (!err) {
			return 0;
		}
		spac_unref_spmaps(spa_ctx);

		voff = off_to_spleaf_next(voff);
	}
	return -SILOFS_ENOSPC;
}

static int
rescan_vspace_of(struct silofs_task_ctx *task, enum silofs_mtype mtype)
{
	struct silofs_spalloc_ctx spa_ctx;
	struct silofs_vaddr       vaddr;
	int                       err;

	spac_setup(&spa_ctx, task, mtype);
	err = spac_rescan_free_vspace(&spa_ctx, &vaddr);
	if (err) {
		return err;
	}
	spac_try_recache_vspace(&spa_ctx, &vaddr);
	return 0;
}

int silofs_reload_vspace(struct silofs_task_ctx *task)
{
	enum silofs_mtype mtype = SILOFS_MTYPE_NONE;
	int               err;

	while (++mtype < SILOFS_MTYPE_LAST) {
		if (!silofs_mtype_isvnode(mtype) ||
		    (mtype == SILOFS_MTYPE_LSMAP)) {
			continue;
		}
		err = rescan_vspace_of(task, mtype);
		if (err && (err != -SILOFS_ENOENT)) {
			log_err("failed to reload vspace: mtype=%d err=%d",
			        mtype, err);
			return err;
		}
	}
	return 0;
}
