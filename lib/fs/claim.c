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
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/run.h>

/* Space-allocation context. */
struct silofs_spalloc_ctx {
	struct silofs_task_ctx *task;
	struct silofs_env *env;
	struct silofs_sb_info *sbi;
	struct silofs_spleaf_info *sli;
	struct silofs_lsmap_info *lsi;
	enum silofs_vtype vtype;
	bool incref_lsi;
};

/* Local functions. */
static int
require_lsmap_of(struct silofs_task_ctx *task, enum silofs_vtype refvtype,
                 off_t off, struct silofs_lsmap_info **out_lsi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_spamaps *
spac_spamaps(const struct silofs_spalloc_ctx *spa_ctx)
{
	return spa_ctx->env->base.spamaps;
}

static void spac_set_hint(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);

	silofs_spamaps_set_hint(spam, spa_ctx->vtype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sbi_is_within_vspace(const struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr)
{
	const size_t vaddr_len = silofs_vaddr_len(vaddr);
	const off_t vaddr_beg  = vaddr->off;
	const off_t vaddr_end  = silofs_off_end(vaddr_beg, vaddr_len);
	const off_t vspace_end = silofs_sbst_vspace_end(sbi);

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
	silofs_sbst_update_objs(sbi, vaddr->vtype, nobjs_take);
	silofs_sbst_update_bks(sbi, vaddr->vtype, nbks_take);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spac_setup(struct silofs_spalloc_ctx *spa_ctx,
                       struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	silofs_memzero(spa_ctx, sizeof(*spa_ctx));
	spa_ctx->task  = task;
	spa_ctx->env   = task->env;
	spa_ctx->sbi   = silofs_get_sbi(task);
	spa_ctx->sli   = nullptr;
	spa_ctx->lsi   = nullptr;
	spa_ctx->vtype = vtype;
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

static int spac_require_spleaf_of(struct silofs_spalloc_ctx *spa_ctx,
                                  off_t off, bool *out_new)
{
	struct silofs_vaddr vaddr;
	int err;

	silofs_vaddr_setup(&vaddr, spa_ctx->vtype, off);
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

static int spac_resolve_llink(struct silofs_spalloc_ctx *spa_ctx,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_llink *out_llink)
{
	return silofs_resolve_llink_of(spa_ctx->task, vaddr, SILOFS_STG_CUR,
	                               out_llink);
}

static int spac_require_lsmap_by(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	const enum silofs_vtype refvtype = silofs_sli_refvtype(spa_ctx->sli);
	int err;

	spac_increfs(spa_ctx);
	err = require_lsmap_of(spa_ctx->task, refvtype, off, &spa_ctx->lsi);
	spac_decrefs(spa_ctx);
	return err;
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

	if (spa_ctx->vtype != SILOFS_VTYPE_LSMAP) {
		silofs_assert_not_null(spa_ctx->lsi);

		first = !silofs_lsi_has_allocated_with(spa_ctx->lsi, vaddr);
		silofs_lsi_mark_allocated_at(spa_ctx->lsi, vaddr);
	}

	sbi_update_space_stats(spa_ctx->sbi, vaddr, 1, first ? 1 : 0);
	spac_set_hint(spa_ctx, vaddr->off);
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
spac_require_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, off_t off)
{
	bool new_bind = false;
	int err;

	err = spac_require_spleaf_of(spa_ctx, off, &new_bind);
	if (!err && (spa_ctx->vtype != SILOFS_VTYPE_LSMAP)) {
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

static off_t lsmap_base_offset(off_t off)
{
	return silofs_off_align(off, SILOFS_LSEG_SIZE_MAX);
}

static int spac_stage_lsmap(const struct silofs_spalloc_ctx *spa_ctx,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode stg_mode,
                            struct silofs_lsmap_info **out_lsi)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

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
                               enum silofs_vtype refvtype, off_t off,
                               struct silofs_lsmap_info **out_lsi)
{
	enum silofs_stg_mode stg_mode;
	int err;

	err = spac_claim_vspace_at(spa_ctx, vaddr);
	if (err) {
		return err;
	}
	stg_mode = SILOFS_STG_COW | SILOFS_STG_RAW;
	err      = spac_stage_lsmap(spa_ctx, vaddr, stg_mode, out_lsi);
	if (err) {
		return err;
	}

	silofs_lsi_setup_spawned(*out_lsi, refvtype, lsmap_base_offset(off));
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
                      enum silofs_vtype refvtype, off_t off, bool new_bind)
{
	int err;

	spac_increfs(spa_ctx);
	if (new_bind) {
		err = spac_spawn_lsmap_at(spa_ctx, vaddr, refvtype, off,
		                          &spa_ctx->lsi);
	} else {
		err = spac_stage_lsmap_at(spa_ctx, vaddr, &spa_ctx->lsi);
	}
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_require_lsmap_of(struct silofs_spalloc_ctx *spa_ctx,
                                 enum silofs_vtype refvtype, off_t off)
{
	struct silofs_vaddr vaddr;
	bool new_bind = false;
	int err;

	silofs_assert_eq(spa_ctx->vtype, SILOFS_VTYPE_LSMAP);
	silofs_assert_ne(refvtype, SILOFS_VTYPE_LSMAP);

	silofs_vaddr_of_lsmap(&vaddr, refvtype, off);
	err = spac_require_spleaf_of(spa_ctx, vaddr.off, &new_bind);
	if (err) {
		return err;
	}
	err = spac_require_lsmap_at(spa_ctx, &vaddr, refvtype, off, new_bind);
	if (err) {
		return err;
	}
	return 0;
}

static int
require_lsmap_of(struct silofs_task_ctx *task, enum silofs_vtype refvtype,
                 off_t off, struct silofs_lsmap_info **out_lsi)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	silofs_assert_ne(refvtype, SILOFS_VTYPE_LSMAP);

	spac_setup(&spa_ctx, task, SILOFS_VTYPE_LSMAP);
	err = spac_require_lsmap_of(&spa_ctx, refvtype, off);
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
	return require_lsmap_of(task, vaddr->vtype, vaddr->off, out_lsi);
}
