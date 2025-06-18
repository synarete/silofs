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
#include <errno.h>
#include <silofs/ioctls.h>
#include "repo.h"
#include "bootrec.h"
#include "lnodes.h"
#include "lcache.h"
#include "exec.h"
#include "super.h"
#include "env.h"
#include "namei.h"
#include "spmaps.h"
#include "lsmap.h"
#include "stage.h"
#include "private.h"

/* space-allocation context */
struct silofs_spalloc_ctx {
	struct silofs_task_ctx *task;
	struct silofs_env *env;
	struct silofs_sb_info *sbi;
	struct silofs_spleaf_info *sli;
	struct silofs_lsmap_info *lsi;
	enum silofs_ltype ltype;
	bool incref_lsi;
};

/* local functions */
static int
require_lsmap_of(struct silofs_task_ctx *task, enum silofs_ltype refltype,
                 loff_t off, struct silofs_lsmap_info **out_lsi);

static int
stage_lsmap_of(struct silofs_task_ctx *task, enum silofs_ltype refltype,
               loff_t off, struct silofs_lsmap_info **out_lsi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t spleaf_span(void)
{
	return SILOFS_SPMAP_NCHILDS * SILOFS_LBK_SIZE;
}

static loff_t off_to_spleaf_start(loff_t voff)
{
	return silofs_off_align(voff, (long)spleaf_span());
}

static loff_t off_to_spleaf_next(loff_t voff)
{
	const loff_t vsilofs_off_next = silofs_off_end(voff, spleaf_span());

	return off_to_spleaf_start(vsilofs_off_next);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *spac_repo(const struct silofs_spalloc_ctx *spa_ctx)
{
	return spa_ctx->task->t_repo;
}

static struct silofs_lcache *
spac_lcache(const struct silofs_spalloc_ctx *spa_ctx)
{
	return spa_ctx->task->t_lcache;
}

static struct silofs_spamaps *
spac_spamaps(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_lcache *cache = spac_lcache(spa_ctx);

	return &cache->lc_spamaps;
}

static loff_t spac_get_hint(const struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_spamaps *spam = spac_spamaps(spa_ctx);

	return silofs_spamaps_get_hint(spam, spa_ctx->ltype);
}

static void spac_set_hint(struct silofs_spalloc_ctx *spa_ctx, loff_t off)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);

	silofs_spamaps_set_hint(spam, spa_ctx->ltype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sbi_is_within_vspace(const struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr)
{
	const size_t vaddr_len = silofs_vaddr_len(vaddr);
	const loff_t vaddr_beg = vaddr->off;
	const loff_t vaddr_end = silofs_off_end(vaddr_beg, vaddr_len);
	const loff_t vspace_end = silofs_sbst_vspace_end(sbi);

	return (vaddr_end <= vspace_end);
}

static void sbi_update_space_stats(struct silofs_sb_info *sbi,
                                   const struct silofs_vaddr *vaddr,
                                   ssize_t nobjs_take, ssize_t nbks_take)
{
	/*
	 * TODO-0045: Update stats properly for case of shared-blocks
	 *
	 * Current code does not take into account case of shared blocks.
	 * May need more fine-grained logic.
	 */
	silofs_sbst_update_objs(sbi, vaddr->ltype, nobjs_take);
	silofs_sbst_update_bks(sbi, vaddr->ltype, nbks_take);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spac_setup(struct silofs_spalloc_ctx *spa_ctx,
                       struct silofs_task_ctx *task, enum silofs_ltype ltype)
{
	silofs_memzero(spa_ctx, sizeof(*spa_ctx));
	spa_ctx->task = task;
	spa_ctx->env = task->t_env;
	spa_ctx->sbi = silofs_get_sbi(task);
	spa_ctx->sli = NULL;
	spa_ctx->lsi = NULL;
	spa_ctx->ltype = ltype;
}

static void spac_increfs(struct silofs_spalloc_ctx *spa_ctx)
{
	silofs_assert_not_null(spa_ctx->sli);
	silofs_sli_incref(spa_ctx->sli);
	if (spa_ctx->lsi != NULL) {
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

static int spac_stage_spleaf_of(struct silofs_spalloc_ctx *spa_ctx, loff_t off)
{
	struct silofs_vaddr vaddr;

	silofs_vaddr_setup(&vaddr, spa_ctx->ltype, off);
	return silofs_stage_spleaf_of(spa_ctx->task, &vaddr, SILOFS_STG_CUR,
	                              &spa_ctx->sli);
}

static int spac_require_spleaf_of(struct silofs_spalloc_ctx *spa_ctx,
                                  loff_t off, bool *out_new)
{
	struct silofs_vaddr vaddr;
	int err;

	silofs_vaddr_setup(&vaddr, spa_ctx->ltype, off);
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
                              struct silofs_llink *out_llink)
{
	return silofs_resolve_llink_of(spa_ctx->task, vaddr, SILOFS_STG_CUR,
	                               out_llink);
}

static int spac_do_find_free_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                       struct silofs_vaddr *out_vaddr)
{
	enum silofs_ltype refltype;
	int err;

	silofs_assert_not_null(spa_ctx->sli);
	silofs_assert_not_null(spa_ctx->lsi);

	refltype = silofs_sli_refltype(spa_ctx->sli);
	silofs_assert_eq(refltype, spa_ctx->ltype);

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
                                    struct silofs_vaddr *out_vaddr)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_do_find_free_vspace_at(spa_ctx, out_vaddr);
	spac_decrefs(spa_ctx);
	return err;
}

static int
spac_require_lsmap_by(struct silofs_spalloc_ctx *spa_ctx, loff_t off)
{
	const enum silofs_ltype refltype = silofs_sli_refltype(spa_ctx->sli);
	int err;

	spac_increfs(spa_ctx);
	err = require_lsmap_of(spa_ctx->task, refltype, off, &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static void spac_unref_spmaps(struct silofs_spalloc_ctx *spa_ctx)
{
	spa_ctx->sli = NULL;
	spa_ctx->lsi = NULL;
}

static int spac_require_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                  loff_t voff, struct silofs_vaddr *out_vaddr)
{
	bool new_bind = false;
	int err;

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
spac_require_vspace_by_spmaps(struct silofs_spalloc_ctx *spa_ctx, loff_t hint,
                              struct silofs_vaddr *out_vaddr)
{
	const loff_t vend = silofs_sbst_vspace_end(spa_ctx->sbi);
	loff_t voff = hint;
	int err;

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
                                        struct silofs_vaddr *out_vaddr)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);
	const enum silofs_ltype ltype = spa_ctx->ltype;
	const size_t len = silofs_ltype_size(ltype);
	loff_t voff = SILOFS_OFF_NULL;
	int err;

	err = silofs_spamaps_trypop(spam, ltype, len, &voff);
	if (!err) {
		silofs_vaddr_setup(out_vaddr, ltype, voff);
	}
	return err;
}

static int
spac_require_unalloc_vspace(struct silofs_spalloc_ctx *spa_ctx, loff_t hint,
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
	const size_t nb = silofs_ltype_size(spa_ctx->ltype);
	bool new_file;
	bool ok;

	ok = silofs_sbst_mayalloc_some(sbi, nb);
	if (ok) {
		if (silofs_ltype_isdata(spa_ctx->ltype)) {
			ok = silofs_sbst_mayalloc_data(sbi, nb);
		} else {
			new_file = silofs_ltype_isinode(spa_ctx->ltype);
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

	if (spa_ctx->ltype != SILOFS_LTYPE_LSMAP) {
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
	const loff_t hint = spac_get_hint(spa_ctx);

	return spac_require_unalloc_vspace(spa_ctx, hint, out_vaddr);
}

static int spac_do_resolve_and_claim(struct silofs_spalloc_ctx *spa_ctx,
                                     const struct silofs_vaddr *vaddr,
                                     struct silofs_llink *out_llink)
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
                                  struct silofs_llink *out_llink)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_do_resolve_and_claim(spa_ctx, vaddr, out_llink);
	spac_decrefs(spa_ctx);
	return err;
}

static int
spac_require_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, loff_t off)
{
	bool new_bind = false;
	int err;

	err = spac_require_spleaf_of(spa_ctx, off, &new_bind);
	if (!err && (spa_ctx->ltype != SILOFS_LTYPE_LSMAP)) {
		err = spac_require_lsmap_by(spa_ctx, off);
	}
	return err;
}

static int spac_claim_vspace_at(struct silofs_spalloc_ctx *spa_ctx,
                                const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	int err;

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
                             struct silofs_vaddr *out_vaddr)
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
claim_vspace_of(struct silofs_task_ctx *task, enum silofs_ltype ltype,
                struct silofs_vaddr *out_vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;

	silofs_assert_ne(ltype, SILOFS_LTYPE_LSMAP);

	spac_setup(&spa_ctx, task, ltype);
	return spac_claim_vspace(&spa_ctx, out_vaddr);
}

static loff_t lsmap_base_offset(loff_t off)
{
	return silofs_off_align(off, SILOFS_LSEG_SIZE_MAX);
}

static int spac_stage_lsmap(const struct silofs_spalloc_ctx *spa_ctx,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode stg_mode,
                            struct silofs_lsmap_info **out_lsi)
{
	struct silofs_vnode_info *vni = NULL;
	int err;

	err = silofs_stage_vnode(spa_ctx->task, NULL, vaddr, stg_mode, &vni);
	if (err) {
		return err;
	}
	*out_lsi = silofs_lsi_from_vni(vni);
	return 0;
}

static int spac_spawn_lsmap_at(struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr *vaddr,
                               enum silofs_ltype refltype, loff_t off,
                               struct silofs_lsmap_info **out_lsi)
{
	enum silofs_stg_mode stg_mode;
	int err;

	err = spac_claim_vspace_at(spa_ctx, vaddr);
	if (err) {
		return err;
	}
	stg_mode = SILOFS_STG_COW | SILOFS_STG_RAW;
	err = spac_stage_lsmap(spa_ctx, vaddr, stg_mode, out_lsi);
	if (err) {
		return err;
	}

	silofs_lsi_setup_spawned(*out_lsi, refltype, lsmap_base_offset(off));
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
                      enum silofs_ltype refltype, loff_t off, bool new_bind)
{
	int err;

	spac_increfs(spa_ctx);
	if (new_bind) {
		err = spac_spawn_lsmap_at(spa_ctx, vaddr, refltype, off,
		                          &spa_ctx->lsi);
	} else {
		err = spac_stage_lsmap_at(spa_ctx, vaddr, &spa_ctx->lsi);
	}
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_require_lsmap_of(struct silofs_spalloc_ctx *spa_ctx,
                                 enum silofs_ltype refltype, loff_t off)
{
	struct silofs_vaddr vaddr;
	bool new_bind = false;
	int err;

	silofs_assert_eq(spa_ctx->ltype, SILOFS_LTYPE_LSMAP);
	silofs_assert_ne(refltype, SILOFS_LTYPE_LSMAP);

	silofs_vaddr_of_lsmap(&vaddr, refltype, off);
	err = spac_require_spleaf_of(spa_ctx, vaddr.off, &new_bind);
	if (err) {
		return err;
	}
	err = spac_require_lsmap_at(spa_ctx, &vaddr, refltype, off, new_bind);
	if (err) {
		return err;
	}
	return 0;
}

static int
require_lsmap_of(struct silofs_task_ctx *task, enum silofs_ltype refltype,
                 loff_t off, struct silofs_lsmap_info **out_lsi)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	silofs_assert_ne(refltype, SILOFS_LTYPE_LSMAP);

	spac_setup(&spa_ctx, task, SILOFS_LTYPE_LSMAP);
	err = spac_require_lsmap_of(&spa_ctx, refltype, off);
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
                               enum silofs_ltype refltype, loff_t off)
{
	struct silofs_vaddr vaddr;
	int err;

	silofs_assert_eq(spa_ctx->ltype, SILOFS_LTYPE_LSMAP);
	silofs_assert_ne(refltype, SILOFS_LTYPE_LSMAP);

	silofs_vaddr_of_lsmap(&vaddr, refltype, off);
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
stage_lsmap_of(struct silofs_task_ctx *task, enum silofs_ltype refltype,
               loff_t off, struct silofs_lsmap_info **out_lsi)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	silofs_assert_ne(refltype, SILOFS_LTYPE_LSMAP);

	spac_setup(&spa_ctx, task, SILOFS_LTYPE_LSMAP);
	err = spac_stage_lsmap_of(&spa_ctx, refltype, off);
	if (err) {
		return err;
	}
	*out_lsi = spa_ctx.lsi;
	return 0;
}

int silofs_require_lsmap_by(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_lsmap_info **out_lsi)
{
	return require_lsmap_of(task, vaddr->ltype, vaddr->off, out_lsi);
}

int silofs_claim_vspace(struct silofs_task_ctx *task, enum silofs_ltype ltype,
                        struct silofs_vaddr *out_vaddr)
{
	struct silofs_lsmap_info *lsi = NULL;
	int err;

	silofs_assert_ne(ltype, SILOFS_LTYPE_LSMAP);

	err = claim_vspace_of(task, ltype, out_vaddr);
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
                        struct silofs_vaddr *out_vaddr)
{
	return silofs_claim_vspace(task, SILOFS_LTYPE_INODE, out_vaddr);
}

static bool spac_has_dbkref_at(const struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr *vaddr)
{
	size_t refcnt;

	silofs_assert_not_null(spa_ctx->lsi);
	refcnt = silofs_lsi_refcnt_at(spa_ctx->lsi, vaddr);

	return (refcnt > 0);
}

static int spac_try_recache_vspace(const struct silofs_spalloc_ctx *spa_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);
	size_t len;

	if (vaddr->ltype == SILOFS_LTYPE_LSMAP) {
		return 0;
	}
	if (spac_has_dbkref_at(spa_ctx, vaddr)) {
		return 0;
	}
	len = silofs_vaddr_len(vaddr);
	return silofs_spamaps_store(spam, vaddr->ltype, vaddr->off, len);
}

static bool spac_ismutable_lsid(const struct silofs_spalloc_ctx *spa_ctx,
                                const struct silofs_lsid *lsid)
{
	return silofs_sbi_ismutable_lsid(spa_ctx->sbi, lsid);
}

static int spac_resolve_main_range(const struct silofs_spalloc_ctx *spa_ctx,
                                   struct silofs_lsid *out_lsid,
                                   struct silofs_lrange *out_lrange)
{
	struct silofs_spleaf_info *sli = spa_ctx->sli;

	silofs_sli_main_lseg(sli, out_lsid);
	if (silofs_lsid_isnull(out_lsid)) {
		return -SILOFS_ENOENT;
	}
	if (out_lsid->ltype != spa_ctx->ltype) {
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
	struct silofs_lsid lsid;
	struct silofs_lrange lrange;
	int err;

	if (spa_ctx->lsi == NULL) {
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
                                   const struct silofs_vaddr *vaddr)
{
	silofs_assert_not_null(spa_ctx->lsi);

	// silofs_sli_unref_allocated_at(spa_ctx->sli, vaddr);
	silofs_lsi_unref_allocated_at(spa_ctx->lsi, vaddr);

	if (!spac_has_dbkref_at(spa_ctx, vaddr)) {
		sbi_update_space_stats(spa_ctx->sbi, vaddr, -1, 0);
	}
}

static void spac_reclaim_vspace_of(const struct silofs_spalloc_ctx *spa_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	spac_clear_allocate_at(spa_ctx, vaddr);
	spac_try_recache_vspace(spa_ctx, vaddr);
	spac_try_reclaim_vlseg(spa_ctx);
}

static int spac_resolve_and_reclaim(struct silofs_spalloc_ctx *spa_ctx,
                                    const struct silofs_vaddr *vaddr,
                                    struct silofs_llink *out_llink)
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
	err = stage_lsmap_of(spa_ctx->task, vaddr->ltype, vaddr->off,
	                     &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_reclaim_vspace(struct silofs_spalloc_ctx *spa_ctx,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	bool new_bind = false;
	int err;

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

int silofs_reclaim_vspace(struct silofs_task_ctx *task,
                          const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;

	silofs_assert_ne(vaddr->ltype, SILOFS_LTYPE_LSMAP);

	spac_setup(&spa_ctx, task, vaddr->ltype);
	return spac_reclaim_vspace(&spa_ctx, vaddr);
}

static int spac_addref_vspace(struct silofs_spalloc_ctx *spa_ctx,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_llink llink;
	int err;

	spac_increfs(spa_ctx);
	err = spac_resolve_llink(spa_ctx, vaddr, &llink);
	if (!err) {
		silofs_lsi_reref_allocated_at(spa_ctx->lsi, vaddr);
	}
	spac_decrefs(spa_ctx);
	return err;
}

int silofs_addref_vspace(struct silofs_task_ctx *task,
                         const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;
	bool new_bind = false;
	int err;

	spac_setup(&spa_ctx, task, vaddr->ltype);
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

static int spac_stage_lsmap_by(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	spac_increfs(spa_ctx);
	err = stage_lsmap_of(spa_ctx->task, spa_ctx->ltype, voff,
	                     &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_rescan_free_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                   struct silofs_vaddr *out_vaddr)
{
	const loff_t vend = silofs_sbst_vspace_end(spa_ctx->sbi);
	loff_t voff = 0;
	int err;

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
rescan_vspace_of(struct silofs_task_ctx *task, enum silofs_ltype ltype)
{
	struct silofs_spalloc_ctx spa_ctx;
	struct silofs_vaddr vaddr;
	int err;

	spac_setup(&spa_ctx, task, ltype);
	err = spac_rescan_free_vspace(&spa_ctx, &vaddr);
	if (err) {
		return err;
	}
	spac_try_recache_vspace(&spa_ctx, &vaddr);
	return 0;
}

int silofs_reload_vspace(struct silofs_task_ctx *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!silofs_ltype_isvnode(ltype) ||
		    (ltype == SILOFS_LTYPE_LSMAP)) {
			continue;
		}
		err = rescan_vspace_of(task, ltype);
		if (err && (err != -SILOFS_ENOENT)) {
			log_err("failed to reload vspace: ltype=%d err=%d",
			        ltype, err);
			return err;
		}
	}
	return 0;
}
