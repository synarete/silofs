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
#include <silofs/fs-private.h>
#include <errno.h>
#include <limits.h>

/* space-allocation context */
struct silofs_spalloc_ctx {
	const struct silofs_task  *task;
	struct silofs_sb_info     *sbi;
	struct silofs_spnode_info *sni;
	struct silofs_spleaf_info *sli;
	struct silofs_voaddr       voa;
	enum silofs_stype          stype;
	silofs_dqid_t              dqid;
};

static void ivoaddr_setup(struct silofs_ivoaddr *ivoa, ino_t ino,
                          const struct silofs_vaddr *vaddr,
                          const struct silofs_oaddr *oaddr)
{
	ivoa->ino = ino;
	silofs_voaddr_setup(&ivoa->voa, vaddr, oaddr);
}

static void ivoaddr_setup2(struct silofs_ivoaddr *ivoa,
                           ino_t ino, const struct silofs_voaddr *voa)
{
	ivoaddr_setup(ivoa, ino, &voa->vaddr, &voa->oaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const loff_t *
sbi_vspa_by_stype(const struct silofs_sb_info *sbi, enum silofs_stype stype)
{
	const loff_t *ret;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		ret = &sbi->sb_vspa.data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		ret = &sbi->sb_vspa.data4k;
		break;
	case SILOFS_STYPE_DATABK:
		ret = &sbi->sb_vspa.databk;
		break;
	case SILOFS_STYPE_ITNODE:
		ret = &sbi->sb_vspa.itnode;
		break;
	case SILOFS_STYPE_INODE:
		ret = &sbi->sb_vspa.inode;
		break;
	case SILOFS_STYPE_XANODE:
		ret = &sbi->sb_vspa.xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		ret = &sbi->sb_vspa.dirnode;
		break;
	case SILOFS_STYPE_FTNODE:
		ret = &sbi->sb_vspa.filenode;
		break;
	case SILOFS_STYPE_SYMVAL:
		ret = &sbi->sb_vspa.symval;
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static loff_t *sbi_vspa_last_of(const struct silofs_sb_info *sbi,
                                enum silofs_stype stype)
{
	const loff_t *p_off = sbi_vspa_by_stype(sbi, stype);

	return unconst(p_off);
}


static loff_t sbi_voff_last_of(const struct silofs_sb_info *sbi,
                               enum silofs_stype stype)
{
	const loff_t *vspa_last = sbi_vspa_last_of(sbi, stype);

	return (vspa_last != NULL) ? *vspa_last : 0;
}

static void sbi_set_voff_last_of(struct silofs_sb_info *sbi,
                                 enum silofs_stype stype, loff_t voff)
{
	loff_t *vspa_last = sbi_vspa_last_of(sbi, stype);

	if (vspa_last != NULL) {
		*vspa_last = voff;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t sbi_vspace_end(const struct silofs_sb_info *sbi)
{
	loff_t voff_end = 0;

	silofs_sti_vspace_end(&sbi->sb_sti, &voff_end);
	return voff_end;
}

static bool sbi_is_within_vspace(const struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr)
{
	const loff_t vaddr_beg = vaddr_off(vaddr);
	const loff_t vaddr_end = off_end(vaddr_beg, vaddr->len);
	const loff_t vspace_end = sbi_vspace_end(sbi);

	return (vaddr_end <= vspace_end);
}

static void sbi_update_voff_last(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr)
{
	sbi_set_voff_last_of(sbi, vaddr_stype(vaddr), vaddr_off(vaddr));
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
	silofs_sti_update_objs(&sbi->sb_sti, vaddr->stype, nobjs_take);
	silofs_sti_update_bks(&sbi->sb_sti, vaddr->stype, nbks_take);
}

static void sbi_mark_allocated_at(struct silofs_sb_info *sbi,
                                  struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	const bool first_bk = !silofs_sli_has_refs_at(sli, vaddr);

	silofs_sli_mark_allocated_space(sli, vaddr);
	sbi_update_space_stats(sbi, vaddr, 1, first_bk ? 1 : 0);
	sbi_update_voff_last(sbi, vaddr);
}

static bool sli_is_shared_databk(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr *vaddr)
{
	bool shared = false;

	if (vaddr_isdatabk(vaddr)) {
		shared = silofs_sli_has_refs_at(sli, vaddr);
	}
	return shared;
}

static void sbi_clear_allocate_at(struct silofs_sb_info *sbi,
                                  struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	silofs_sli_unref_allocated_space(sli, vaddr);

	if (!sli_is_shared_databk(sli, vaddr)) {
		sbi_update_space_stats(sbi, vaddr, -1, 0);
	}
}

/*
 * optional operation: in case of data-leaf where no vspace is in-use,
 * reclaim (TRIM) the underlying object space.
 */
static void sli_base_bkaddr(const struct silofs_spleaf_info *sli,
                            struct silofs_bkaddr *out_bkaddr)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	silofs_sli_resolve_main_ubk(sli, vrange.beg, out_bkaddr);
}

static int sbi_vspace_reclaimed_at(const struct silofs_sb_info *sbi,
                                   const struct silofs_spleaf_info *sli)
{
	struct silofs_blobid blobid;
	struct silofs_bkaddr bkaddr;
	struct silofs_blobref_info *bri = NULL;
	const size_t cnt = ARRAY_SIZE(sli->sl->sl_subref);
	int err;

	if (sli->sl_nused_bytes) {
		return 0;
	}
	silofs_sli_main_blob(sli, &blobid);
	if (blobid_isnull(&blobid)) {
		return 0;
	}
	if (!silofs_sbi_ismutable_blobid(sbi, &blobid)) {
		return 0;
	}
	err = silofs_stage_blob_at(sbi_uber(sbi), true, &blobid, &bri);
	if (err) {
		log_err("failed to stage unused blob: err=%d", err);
		return err;
	}
	sli_base_bkaddr(sli, &bkaddr);
	err = silofs_bri_trim_nbks(bri, &bkaddr, cnt);
	if (err && (err != -ENOTSUP)) {
		log_err("trim blob failure: err=%d", err);
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spac_setup(struct silofs_spalloc_ctx *spa_ctx,
                       const struct silofs_task *task,
                       enum silofs_stype stype, silofs_dqid_t dqid)
{
	silofs_memzero(spa_ctx, sizeof(*spa_ctx));
	spa_ctx->task = task;
	spa_ctx->sbi = task_sbi(task);
	spa_ctx->stype = stype;
	spa_ctx->dqid = dqid;
}

static void spac_setup2(struct silofs_spalloc_ctx *spa_ctx,
                        const struct silofs_task *task,
                        enum silofs_stype stype)
{
	spac_setup(spa_ctx, task, stype, SILOFS_DQID_ALL);
}

static void spac_increfs(const struct silofs_spalloc_ctx *spa_ctx)
{
	sni_incref(spa_ctx->sni);
	sli_incref(spa_ctx->sli);
}

static void spac_decrefs(const struct silofs_spalloc_ctx *spa_ctx)
{
	sni_decref(spa_ctx->sni);
	sli_decref(spa_ctx->sli);
}

static int
spac_stage_ro_spnode1_of(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr vaddr;
	const enum silofs_stage_mode stg_mode = SILOFS_STAGE_RO;

	vaddr_setup(&vaddr, spa_ctx->stype, voff);
	return silofs_stage_spnode1_at(spa_ctx->task, &vaddr,
	                               stg_mode, &spa_ctx->sni);
}

static int
spac_stage_ro_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr vaddr;
	const enum silofs_stage_mode stg_mode = SILOFS_STAGE_RO;

	vaddr_setup(&vaddr, spa_ctx->stype, voff);
	return silofs_stage_spmaps_at(spa_ctx->task, &vaddr, stg_mode,
	                              &spa_ctx->sni, &spa_ctx->sli);
}

static int
spac_require_rw_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr vaddr;
	const enum silofs_stage_mode stg_mode = SILOFS_STAGE_RW;

	vaddr_setup(&vaddr, spa_ctx->stype, voff);
	return silofs_require_spmaps_at(spa_ctx->task, &vaddr, stg_mode,
	                                &spa_ctx->sni, &spa_ctx->sli);
}

static int spac_check_within_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                    const struct silofs_vaddr *vaddr)
{
	return sbi_is_within_vspace(spa_ctx->sbi, vaddr) ? 0 : -ENOSPC;
}

static int spac_resolve_oaddr(struct silofs_spalloc_ctx *spa_ctx)
{
	return silofs_resolve_voaddr_of(spa_ctx->task, &spa_ctx->voa.vaddr,
	                                SILOFS_STAGE_RO, &spa_ctx->voa);
}

static int
spac_do_find_free_vspace_at(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr *out_vaddr = &spa_ctx->voa.vaddr;
	const enum silofs_stype stype = spa_ctx->stype;
	int err;

	err = silofs_sli_find_free_space(spa_ctx->sli, voff, stype, out_vaddr);
	if (err) {
		return err;
	}
	err = spac_check_within_vspace(spa_ctx, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int
spac_find_free_vspace_at(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_do_find_free_vspace_at(spa_ctx, voff);
	spac_decrefs(spa_ctx);
	return err;
}

static int
spac_require_vspace_at(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	err = spac_stage_ro_spnode1_of(spa_ctx, voff);
	if (err && (err != -ENOENT)) {
		return err;
	}
	err = spac_require_rw_spmaps_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_find_free_vspace_at(spa_ctx, voff);
	if (err) {
		return err;
	}
	return 0;
}

static int
spac_require_vspace_by_spmaps(struct silofs_spalloc_ctx *spa_ctx, loff_t hint)
{
	const loff_t vend = sbi_vspace_end(spa_ctx->sbi);
	loff_t voff = hint;
	int err;

	while (voff < vend) {
		err = spac_require_vspace_at(spa_ctx, voff);
		if (err != -ENOSPC) {
			return err;
		}
		voff = silofs_off_to_spleaf_next(voff);
	}
	return -ENOSPC;
}

static struct silofs_spamaps *
spac_spamaps(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_cache *cache = sbi_cache(spa_ctx->sbi);

	return &cache->c_spam;
}

static void spac_setup_vaddr(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	vaddr_setup(&spa_ctx->voa.vaddr, spa_ctx->stype, voff);
}

static int spac_claim_vspace_from_cache(struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);
	const enum silofs_stype stype = spa_ctx->stype;
	loff_t voff = SILOFS_OFF_NULL;
	int err;

	err = silofs_spamaps_trypop(spam, stype, stype_size(stype), &voff);
	if (!err) {
		spac_setup_vaddr(spa_ctx, voff);
	}
	return err;
}

static int
spac_require_unalloc_vspace(struct silofs_spalloc_ctx *spa_ctx, loff_t hint)
{
	int err;

	/* Fast path: there exists an in-memory cached free space; use it */
	err = spac_claim_vspace_from_cache(spa_ctx);
	if (!err) {
		return 0;
	}
	/* Slow path: stage and search space maps */
	err = spac_require_vspace_by_spmaps(spa_ctx, hint);
	if (err) {
		return err;
	}
	/* Perhaps in-memory cache was re-popolated due to slow-path search;
	 * if so, ensure that the newly inserted ranged is chopped-out from
	 * in-memory cache (and dont-care if not-in-cache) */
	spac_claim_vspace_from_cache(spa_ctx);
	return 0;
}

static int spac_check_avail_space(const struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_stats_info *sti = &spa_ctx->sbi->sb_sti;
	const size_t nb = stype_size(spa_ctx->stype);
	bool new_file;
	bool ok;

	ok = silofs_sti_mayalloc_some(sti, nb);
	if (ok) {
		if (stype_isdata(spa_ctx->stype)) {
			ok = silofs_sti_mayalloc_data(sti, nb);
		} else {
			new_file = stype_isinode(spa_ctx->stype);
			ok = silofs_sti_mayalloc_meta(sti, nb, new_file);
		}
	}
	return ok ? 0 : -ENOSPC;
}

static int spac_check_want_free_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;

	if (vaddr_isnull(vaddr)) {
		return -ENOSPC;
	}
	if (!sbi_is_within_vspace(spa_ctx->sbi, vaddr)) {
		return -ENOSPC;
	}
	return 0;
}

static void spac_mark_allocated(const struct silofs_spalloc_ctx *spa_ctx)
{
	sbi_mark_allocated_at(spa_ctx->sbi, spa_ctx->sli, &spa_ctx->voa.vaddr);
}

static int spac_try_find_unallocated_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	const loff_t hint = sbi_voff_last_of(spa_ctx->sbi, spa_ctx->stype);

	return spac_require_unalloc_vspace(spa_ctx, hint);
}

static int spac_resolve_and_claim(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_resolve_oaddr(spa_ctx);
	if (!err) {
		spac_mark_allocated(spa_ctx);
	}
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_claim_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	loff_t voff;
	int err;

	err = spac_check_avail_space(spa_ctx);
	if (err) {
		return err;
	}
	err = spac_try_find_unallocated_vspace(spa_ctx);
	if (err) {
		/* TODO: cleanup */
		return err;
	}
	err = spac_check_want_free_vspace(spa_ctx);
	if (err) {
		return err;
	}
	voff = spa_ctx->voa.vaddr.voff;
	err = spac_require_rw_spmaps_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_resolve_and_claim(spa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_claim_vspace(const struct silofs_task *task,
                        enum silofs_stype stype, silofs_dqid_t dqid,
                        struct silofs_voaddr *out_voa)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	spac_setup(&spa_ctx, task, stype, dqid);
	err = spac_claim_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	silofs_voaddr_assign(out_voa, &spa_ctx.voa);
	return 0;
}

static int spac_claim_mutable_vnode(const struct silofs_spalloc_ctx *spa_ctx,
                                    struct silofs_vnode_info **out_vi)
{
	return silofs_stage_vnode_at(spa_ctx->task, &spa_ctx->voa.vaddr,
	                             SILOFS_STAGE_RW, spa_ctx->dqid,
	                             false, out_vi);
}

/* TODO: cleanups and resource reclaim upon failure in every path */
int silofs_claim_vnode(const struct silofs_task *task,
                       enum silofs_stype stype, silofs_dqid_t dqid,
                       struct silofs_vnode_info **out_vi)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	spac_setup(&spa_ctx, task, stype, dqid);
	err = spac_claim_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	err = spac_claim_mutable_vnode(&spa_ctx, out_vi);
	if (err) {
		/* TODO: spfree vnode */
		return err;
	}
	return 0;
}

static int spac_claim_ispace(struct silofs_spalloc_ctx *spa_ctx,
                             struct silofs_ivoaddr *out_ivoa)
{
	struct silofs_iaddr iaddr;
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;
	int err;

	err = spac_claim_vspace(spa_ctx);
	if (err) {
		return err;
	}
	err = silofs_acquire_ino(spa_ctx->task, vaddr, &iaddr);
	if (err) {
		return err;
	}
	ivoaddr_setup2(out_ivoa, iaddr.ino, &spa_ctx->voa);
	return 0;
}

int silofs_claim_inode(const struct silofs_task *task,
                       struct silofs_inode_info **out_ii)
{
	struct silofs_spalloc_ctx spa_ctx;
	struct silofs_ivoaddr ivoa;
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	spac_setup2(&spa_ctx, task, SILOFS_STYPE_INODE);
	err = spac_claim_ispace(&spa_ctx, &ivoa);
	if (err) {
		return err;
	}
	spa_ctx.dqid = ivoa.ino;
	err = spac_claim_mutable_vnode(&spa_ctx, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);
	silofs_ii_rebind_view(ii, ivoa.ino);
	*out_ii = ii;
	return 0;
}

static bool spac_is_shared_databk(const struct silofs_spalloc_ctx *spa_ctx)
{
	return sli_is_shared_databk(spa_ctx->sli, &spa_ctx->voa.vaddr);
}

static int spac_try_recache_vspace(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_cache *cache = sbi_cache(spa_ctx->sbi);
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;
	int ret = 0;
	bool shared;

	shared = spac_is_shared_databk(spa_ctx);
	if (!shared) {
		ret = silofs_spamaps_store(&cache->c_spam, vaddr->stype,
		                           vaddr->voff, vaddr->len);
	}
	return ret;
}

static void spac_reclaim_vspace_of(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_sb_info *sbi = spa_ctx->sbi;
	struct silofs_spleaf_info *sli = spa_ctx->sli;
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;

	sbi_clear_allocate_at(sbi, sli, vaddr);
	sbi_vspace_reclaimed_at(sbi, sli);

	spac_try_recache_vspace(spa_ctx);
}

static int spac_resolve_and_reclaim(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;

	spac_increfs(spa_ctx);
	err = spac_resolve_oaddr(spa_ctx);
	if (!err) {
		spac_reclaim_vspace_of(spa_ctx);
	}
	spac_decrefs(spa_ctx);
	return err;
}

static int spac_reclaim_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	loff_t voff;
	int err;

	voff = spa_ctx->voa.vaddr.voff;
	err = spac_require_rw_spmaps_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_resolve_and_reclaim(spa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_reclaim_vspace(const struct silofs_task *task,
                          const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;

	spac_setup2(&spa_ctx, task, vaddr_stype(vaddr));
	vaddr_assign(&spa_ctx.voa.vaddr, vaddr);
	return spac_reclaim_vspace(&spa_ctx);
}

static int spac_addref_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;
	int err;

	spac_increfs(spa_ctx);
	err = spac_resolve_oaddr(spa_ctx);
	if (!err) {
		silofs_sli_reref_allocated_space(spa_ctx->sli, vaddr);
	}
	spac_decrefs(spa_ctx);
	return err;
}

int silofs_addref_vspace(const struct silofs_task *task,
                         const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	spac_setup2(&spa_ctx, task, vaddr->stype);
	vaddr_assign(&spa_ctx.voa.vaddr, vaddr);
	err = spac_require_rw_spmaps_of(&spa_ctx, vaddr->voff);
	if (err) {
		return err;
	}
	err = spac_addref_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_recache_vspace(const struct silofs_task *task,
                          const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx;

	spac_setup2(&spa_ctx, task, vaddr->stype);
	vaddr_assign(&spa_ctx.voa.vaddr, vaddr);
	return spac_try_recache_vspace(&spa_ctx);
}

static void
spac_update_voff_hint(const struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	sbi_set_voff_last_of(spa_ctx->sbi, spa_ctx->stype, voff);
}

static int spac_rescan_free_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	const loff_t vend = sbi_vspace_end(spa_ctx->sbi);
	loff_t voff = 0;
	int err;

	while (voff < vend) {
		err = spac_stage_ro_spmaps_of(spa_ctx, voff);
		if (err) {
			return err;
		}
		spac_update_voff_hint(spa_ctx, voff);

		err = spac_find_free_vspace_at(spa_ctx, voff);
		if (!err) {
			return 0;
		}
		voff = silofs_off_to_spleaf_next(voff);
	}
	return -ENOSPC;
}

int silofs_rescan_vspace_of(const struct silofs_task *task,
                            enum silofs_stype stype)
{
	struct silofs_spalloc_ctx spa_ctx;
	int err;

	spac_setup2(&spa_ctx, task, stype);
	err = spac_rescan_free_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	spac_try_recache_vspace(&spa_ctx);
	return 0;
}
