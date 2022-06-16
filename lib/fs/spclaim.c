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
#include <errno.h>
#include <limits.h>

/* space-allocation context */
struct silofs_spalloc_ctx {
	struct silofs_sb_info     *sbi;
	struct silofs_spnode_info *sni;
	struct silofs_spleaf_info *sli;
	struct silofs_voaddr       voa;
	enum silofs_stype          stype;
	bool no_new_blobs;
};

static void ivoaddr_setup(struct silofs_ivoaddr *ivoa, ino_t ino,
                          const struct silofs_vaddr *vaddr,
                          const struct silofs_oaddr *oaddr)
{
	ivoa->ino = ino;
	voaddr_setup(&ivoa->voa, vaddr, oaddr);
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
	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		return &sbi->sb_vspa.data1k;
	case SILOFS_STYPE_DATA4K:
		return &sbi->sb_vspa.data4k;
	case SILOFS_STYPE_DATABK:
		return &sbi->sb_vspa.databk;
	case SILOFS_STYPE_ITNODE:
		return &sbi->sb_vspa.itnode;
	case SILOFS_STYPE_INODE:
		return &sbi->sb_vspa.inode;
	case SILOFS_STYPE_XANODE:
		return &sbi->sb_vspa.xanode;
	case SILOFS_STYPE_DTNODE:
		return &sbi->sb_vspa.dirnode;
	case SILOFS_STYPE_FTNODE:
		return &sbi->sb_vspa.filenode;
	case SILOFS_STYPE_SYMVAL:
		return &sbi->sb_vspa.symval;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPSTATS:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		break;
	}
	return NULL;
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
	return silofs_sti_vspace_end(sbi->sb_sti);
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
	silofs_sti_update_objs(sbi->sb_sti, vaddr->stype, nobjs_take);
	silofs_sti_update_bks(sbi->sb_sti, vaddr->stype, nbks_take);
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

static void sbi_clear_allocate_at(struct silofs_sb_info *sbi,
                                  struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	silofs_sli_clear_allocated_space(sli, vaddr);
	sbi_update_space_stats(sbi, vaddr, -1, 0);
}

/*
 * optional operation: in case of data-leaf where no vspace is in-use,
 * reclaim (TRIM) the underlying object space.
 */
static int sbi_vspace_reclaimed_at(const struct silofs_sb_info *sbi,
                                   const struct silofs_spleaf_info *sli)
{
	struct silofs_blobid blobid = { .size = 0 };
	struct silofs_blob_info *bli = NULL;
	int err;

	if (sli->sl_nused_bytes) {
		return 0;
	}
	silofs_sli_main_blob(sli, &blobid);
	if (!silofs_sbi_ismutable_blobid(sbi, &blobid)) {
		return 0;
	}
	err = silofs_stage_blob_at(sbi_uber(sbi), true, &blobid, &bli);
	if (err) {
		log_err("failed to stage unused blob: err=%d", err);
		return err;
	}
	err = silofs_bli_trim(bli);
	if (err) {
		log_err("trim blob failure: err=%d", err);
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
spac_stage_rdo_spnode2_of(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr vaddr;

	vaddr_setup(&vaddr, spa_ctx->stype, voff);
	return silofs_sbi_stage_spnode2_of(spa_ctx->sbi, &vaddr,
	                                   SILOFS_STAGE_RDONLY, &spa_ctx->sni);
}

static int
spac_require_rdo_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr vaddr;

	vaddr_setup(&vaddr, spa_ctx->stype, voff);
	return silofs_sbi_stage_spmaps_of(spa_ctx->sbi, &vaddr,
	                                  SILOFS_STAGE_RDONLY,
	                                  &spa_ctx->sni, &spa_ctx->sli);
}

static int
spac_require_mut_spmaps_of(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr vaddr;

	vaddr_setup(&vaddr, spa_ctx->stype, voff);
	return silofs_sbi_require_spmaps_of(spa_ctx->sbi, &vaddr,
	                                    &spa_ctx->sni, &spa_ctx->sli);
}

static int spac_require_within_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                      const struct silofs_vaddr *vaddr)
{
	return sbi_is_within_vspace(spa_ctx->sbi, vaddr) ? 0 : -ENOSPC;
}

static int spac_resolve_oaddr(struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;

	silofs_assert(!vaddr_isnull(vaddr));
	return silofs_sbi_resolve_voa(spa_ctx->sbi, vaddr,
	                              SILOFS_STAGE_RDONLY, &spa_ctx->voa);
}

static int
spac_find_free_space_at_leaf(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vaddr *out_vaddr = &spa_ctx->voa.vaddr;
	const enum silofs_stype stype = spa_ctx->stype;
	int err;

	err = spac_require_rdo_spmaps_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = silofs_sli_find_free_space(spa_ctx->sli, voff, stype, out_vaddr);
	if (err) {
		return err;
	}
	err = spac_require_within_vspace(spa_ctx, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int
spac_find_free_space_from(struct silofs_spalloc_ctx *spa_ctx,
                          const struct silofs_vrange *vrange, loff_t *out_voff)
{
	const enum silofs_stype stype = spa_ctx->stype;
	int err;

	err = silofs_sni_search_spleaf(spa_ctx->sni, vrange, stype, out_voff);
	if (err) {
		return err;
	}
	err = spac_find_free_space_at_leaf(spa_ctx, *out_voff);
	if (err) {
		return err;
	}
	return 0;
}

static int spac_find_free_space_within(struct silofs_spalloc_ctx *spa_ctx,
                                       const struct silofs_vrange *vrange)
{
	struct silofs_vrange vrange_sub;
	loff_t voff = vrange->beg;
	loff_t vnxt = voff;
	int err = -ENOSPC;

	while (voff < vrange->end) {
		silofs_vrange_setup_sub(&vrange_sub, vrange, voff);
		err = spac_find_free_space_from(spa_ctx, &vrange_sub, &vnxt);
		if ((err != -ENOSPC) || (vnxt >= vrange->end)) {
			break;
		}
		voff = silofs_off_to_vsec_next(vnxt, 1);
	}
	return err;
}

static int
spac_do_find_free_at_spnode2(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_vrange vrange;

	silofs_sni_active_vrange(spa_ctx->sni, &vrange);
	vrange.beg = off_max(voff, vrange.beg);
	return spac_find_free_space_within(spa_ctx, &vrange);
}

static int
spac_find_free_at_spnode2(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	struct silofs_spnode_info *sni = spa_ctx->sni;
	int err;

	sni_incref(sni);
	err = spac_do_find_free_at_spnode2(spa_ctx, voff);
	sni_decref(sni);
	return err;
}

static int
spac_try_find_free_at_spnode(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	err = spac_stage_rdo_spnode2_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_find_free_at_spnode2(spa_ctx, voff);
	if (err) {
		return err;
	}
	return 0;
}

static int spac_want_spmaps_at(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	const enum silofs_stype stype = spa_ctx->stype;
	int err;

	err = spac_stage_rdo_spnode2_of(spa_ctx, voff);
	if (!err) {
		err = silofs_sni_cap_alloc_at(spa_ctx->sni, voff, stype);
	} else if ((err == -ENOENT) && !spa_ctx->no_new_blobs) {
		err = spac_require_mut_spmaps_of(spa_ctx, voff);
	}
	return err;
}

static int spac_want_free_at(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	err = spac_want_spmaps_at(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_try_find_free_at_spnode(spa_ctx, voff);
	if (err) {
		return err;
	}
	return 0;
}

static int
spac_find_free_by_spmaps(struct silofs_spalloc_ctx *spa_ctx, loff_t hint)
{
	const loff_t vend = sbi_vspace_end(spa_ctx->sbi);
	loff_t voff = hint;
	int ret;

	while (voff < vend) {
		ret = spac_want_free_at(spa_ctx, voff);
		if (ret != -ENOSPC) {
			return ret;
		}
		voff = silofs_off_to_spnode_next(voff);
	}
	return -ENOSPC;
}

static struct silofs_spamaps *
spac_spamaps(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_cache *cache = sbi_cache(spa_ctx->sbi);

	return &cache->c_spam;
}

static int spac_find_free_from_cache(struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_spamaps *spam = spac_spamaps(spa_ctx);
	const enum silofs_stype stype = spa_ctx->stype;
	loff_t voff = SILOFS_OFF_NULL;
	int err;

	err = silofs_spamaps_trypop(spam, stype, stype_size(stype), &voff);
	if (!err) {
		vaddr_setup(&spa_ctx->voa.vaddr, stype, voff);
	}
	return err;
}

static int
spac_find_unallocated_vspace(struct silofs_spalloc_ctx *spa_ctx, loff_t hint)
{
	int err;

	err = spac_find_free_from_cache(spa_ctx);
	if (!err) {
		return 0;
	}
	err = spac_find_free_by_spmaps(spa_ctx, hint);
	if (err) {
		return err;
	}
	return 0;
}

static int spac_check_avail_space(const struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_spstats_info *sti = spa_ctx->sbi->sb_sti;
	const size_t nb = stype_size(spa_ctx->stype);
	bool new_file;
	bool ok;

	ok = silofs_sti_may_alloc_some(sti, nb);
	if (ok) {
		if (stype_isdata(spa_ctx->stype)) {
			ok = silofs_sti_may_alloc_data(sti, nb);
		} else {
			new_file = stype_isinode(spa_ctx->stype);
			ok = silofs_sti_may_alloc_meta(sti, nb, new_file);
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
	const loff_t voff = sbi_voff_last_of(spa_ctx->sbi, spa_ctx->stype);

	return spac_find_unallocated_vspace(spa_ctx, voff);
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
	err = spac_require_mut_spmaps_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_resolve_and_claim(spa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_claim_vspace(struct silofs_sb_info *sbi,
                            enum silofs_stype stype,
                            struct silofs_voaddr *out_voa)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = stype,
	};
	int err;

	err = spac_claim_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	voaddr_assign(out_voa, &spa_ctx.voa);
	return 0;
}

int silofs_sbi_search_vspace(struct silofs_sb_info *sbi,
                             enum silofs_stype stype,
                             struct silofs_voaddr *out_voa)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = stype,
		.no_new_blobs = true,
	};
	int err;

	err = spac_find_unallocated_vspace(&spa_ctx, 0);
	if (err) {
		return err;
	}
	voaddr_assign(out_voa, &spa_ctx.voa);
	return 0;
}


static int spac_spawn_mutable_vnode(const struct silofs_spalloc_ctx *spa_ctx,
                                    struct silofs_vnode_info **out_vi)
{
	return silofs_sbi_spawn_vnode_at(spa_ctx->sbi, &spa_ctx->voa,
	                                 SILOFS_STAGE_MUTABLE, out_vi);
}

/* TODO: cleanups and resource reclaim upon failure in every path */
int silofs_sbi_claim_vnode(struct silofs_sb_info *sbi,
                           enum silofs_stype stype,
                           struct silofs_vnode_info **out_vi)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = stype,
	};
	int err;

	err = spac_claim_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	err = spac_spawn_mutable_vnode(&spa_ctx, out_vi);
	if (err) {
		/* TODO: spfree inode from ag */
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
	err = silofs_acquire_ino(spa_ctx->sbi, vaddr, &iaddr);
	if (err) {
		return err;
	}
	ivoaddr_setup2(out_ivoa, iaddr.ino, &spa_ctx->voa);
	return 0;
}

int silofs_sbi_claim_inode(struct silofs_sb_info *sbi,
                           struct silofs_inode_info **out_ii)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = SILOFS_STYPE_INODE,
	};
	struct silofs_ivoaddr ivoa = {
		.ino = SILOFS_INO_NULL
	};
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	int err;

	err = spac_claim_ispace(&spa_ctx, &ivoa);
	if (err) {
		return err;
	}
	err = spac_spawn_mutable_vnode(&spa_ctx, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);
	silofs_ii_rebind_view(ii, ivoa.ino);
	*out_ii = ii;
	return 0;
}

static int spac_recache_vspace(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_cache *cache = sbi_cache(spa_ctx->sbi);
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;

	return silofs_spamaps_store(&cache->c_spam, vaddr->stype,
	                            vaddr->voff, vaddr->len);
}

static void spac_reclaim_vspace_of(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_sb_info *sbi = spa_ctx->sbi;
	struct silofs_spleaf_info *sli = spa_ctx->sli;
	const struct silofs_vaddr *vaddr = &spa_ctx->voa.vaddr;

	sbi_clear_allocate_at(sbi, sli, vaddr);
	sbi_vspace_reclaimed_at(sbi, sli);

	spac_recache_vspace(spa_ctx);
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
	err = spac_require_mut_spmaps_of(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spac_resolve_and_reclaim(spa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_reclaim_vspace(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = vaddr_stype(vaddr),
	};

	vaddr_assign(&spa_ctx.voa.vaddr, vaddr);
	return spac_reclaim_vspace(&spa_ctx);
}

int silofs_sbi_recache_vspace(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = vaddr_stype(vaddr),
	};

	vaddr_assign(&spa_ctx.voa.vaddr, vaddr);
	return spac_recache_vspace(&spa_ctx);
}

