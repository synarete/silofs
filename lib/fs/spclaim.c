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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/spclaim.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/private.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

/* space-allocation context */
struct silofs_spalloc_ctx {
	struct silofs_sb_info     *sbi;
	struct silofs_spnode_info *sni;
	struct silofs_spleaf_info *sli;
	struct silofs_ovaddr       ova;
	enum silofs_stype          stype;
};

static void iovaddr_setup(struct silofs_iovaddr *iova, ino_t ino,
                          const struct silofs_oaddr *oaddr,
                          const struct silofs_vaddr *vaddr)
{
	iova->ino = ino;
	ovaddr_setup(&iova->ova, oaddr, vaddr);
}

static void iovaddr_setup2(struct silofs_iovaddr *iova, ino_t ino,
                           const struct silofs_ovaddr *ova)
{
	iovaddr_setup(iova, ino, &ova->oaddr, &ova->vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void calc_vspace_stat_diff(const struct silofs_vaddr *vaddr,
                                  int take, struct silofs_space_stat *spst_dif)
{
	const ssize_t nbytes = (ssize_t)vaddr->len;
	const enum silofs_stype stype = vaddr_stype(vaddr);

	silofs_memzero(spst_dif, sizeof(*spst_dif));
	if (take > 0) {
		if (stype_isdata(stype)) {
			spst_dif->vspace_ndata = nbytes;
		} else {
			spst_dif->vspace_nmeta = nbytes;
		}
		if (stype_isinode(stype)) {
			spst_dif->vspace_nfiles = 1;
		}
	} else if (take < 0) {
		if (stype_isdata(stype)) {
			spst_dif->vspace_ndata = -nbytes;
		} else {
			spst_dif->vspace_nmeta = -nbytes;
		}
		if (stype_isinode(stype)) {
			spst_dif->vspace_nfiles = -1;
		}
	}
}

static void sbi_active_vspace_range(const struct silofs_sb_info *sbi,
                                    struct silofs_vrange *out_vrange)
{
	const loff_t voff_last = silofs_sb_vspace_last(sbi->sb);

	silofs_vrange_setup(out_vrange, 0, voff_last);
}

static loff_t sbi_end_of_active_vspace(const struct silofs_sb_info *sbi)
{
	struct silofs_vrange vrange;

	sbi_active_vspace_range(sbi, &vrange);
	silofs_assert_eq(vrange.beg, 0);
	return vrange.end;
}

static bool sbi_is_within_vspace(const struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr)
{
	const loff_t vaddr_beg = vaddr_off(vaddr);
	const loff_t vaddr_end = off_end(vaddr_beg, vaddr->len);
	const loff_t vspace_end = sbi_end_of_active_vspace(sbi);

	return (vaddr_end <= vspace_end);
}

static bool sbi_may_alloc_some(const struct silofs_sb_info *sbi, size_t nb)
{
	const size_t nbytes_pad = SILOFS_BK_SIZE;
	const size_t nbytes_used = silofs_sbi_nused_bytes(sbi);
	const size_t nbytes_cap = silofs_sbi_vspace_capacity(sbi);

	return ((nb + nbytes_used + nbytes_pad) < nbytes_cap);
}

static bool sbi_may_alloc_data(const struct silofs_sb_info *sbi, size_t nb)
{
	const size_t user_limit = (31 * silofs_sbi_vspace_capacity(sbi)) / 32;
	const size_t used_bytes = silofs_sbi_nused_bytes(sbi);

	return ((used_bytes + nb) <= user_limit);
}

static bool sbi_may_alloc_meta(const struct silofs_sb_info *sbi,
                               size_t nb, bool new_file)
{
	bool ret = true;
	fsfilcnt_t files_max;
	fsfilcnt_t files_cur;
	const size_t limit = silofs_sbi_vspace_capacity(sbi);
	const size_t nused = silofs_sbi_nused_bytes(sbi);

	if ((nused + nb) > limit) {
		ret = false;
	} else if (new_file) {
		files_max = silofs_sbi_inodes_limit(sbi);
		files_cur = silofs_sbi_inodes_current(sbi);
		ret = (files_cur < files_max);
	}
	return ret;
}

static void sbi_update_voff_last(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr)
{
	silofs_sb_set_voff_last(sbi->sb, vaddr_stype(vaddr), vaddr_off(vaddr));
	silofs_sbi_dirtify(sbi);
}

static void
sbi_update_vspace_change(struct silofs_sb_info *sbi,
                         struct silofs_spnode_info *sni,
                         const struct silofs_vaddr *vaddr, int take)
{
	struct silofs_space_stat spst_dif;

	calc_vspace_stat_diff(vaddr, take, &spst_dif);

	silofs_sni_update_nused(sni, vaddr, take);
	silofs_sbi_update_stats(sbi, &spst_dif);
}

static void sbi_mark_allocated_at(struct silofs_sb_info *sbi,
                                  struct silofs_spnode_info *sni,
                                  struct silofs_spleaf_info *sli,
                                  const struct silofs_vaddr *vaddr)
{
	silofs_sli_mark_allocated_space(sli, vaddr);
	silofs_sli_update_voff_last(sli, vaddr_off(vaddr));
	sbi_update_vspace_change(sbi, sni, vaddr, 1);
	sbi_update_voff_last(sbi, vaddr);
}

static void sbi_clear_unallocate_at(struct silofs_sb_info *sbi,
                                    struct silofs_spnode_info *sni,
                                    struct silofs_spleaf_info *sli,
                                    const struct silofs_vaddr *vaddr)
{
	silofs_sli_clear_allocated_space(sli, vaddr);
	sbi_update_vspace_change(sbi, sni, vaddr, -1);
}

static loff_t sbi_voff_last_of(const struct silofs_sb_info *sbi,
                               enum silofs_stype stype)
{
	return silofs_sb_vlast_by_stype(sbi->sb, stype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int spc_stage_spnode(struct silofs_spalloc_ctx *spa_ctx, loff_t voff,
                            enum silofs_stage_flags stg_flags)
{
	return silofs_sbi_stage_spnode(spa_ctx->sbi, voff,
	                               stg_flags, &spa_ctx->sni);
}

static int
spc_stage_rdonly_spnode(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	return spc_stage_spnode(spa_ctx, voff, SILOFS_STAGE_RDONLY);
}

static int
spc_stage_mutable_spnode(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	return spc_stage_spnode(spa_ctx, voff, SILOFS_STAGE_MUTABLE);
}

static int spc_stage_spleaf(struct silofs_spalloc_ctx *spa_ctx, loff_t voff,
                            enum silofs_stage_flags stg_flags)
{
	return silofs_sbi_stage_spleaf_of(spa_ctx->sbi, spa_ctx->sni, voff,
	                                  stg_flags, &spa_ctx->sli);
}

static int
spc_stage_rdonly_spleaf(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	return spc_stage_spleaf(spa_ctx, voff, SILOFS_STAGE_RDONLY);
}

static int
spc_stage_mutable_spleaf(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	return spc_stage_spleaf(spa_ctx, voff, SILOFS_STAGE_MUTABLE);
}

static int
spc_stage_mutable_spmaps(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	err = spc_stage_mutable_spnode(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spc_stage_mutable_spleaf(spa_ctx, voff);
	if (err) {
		return err;
	}
	return 0;
}

static int spc_require_within_vspace(struct silofs_spalloc_ctx *spa_ctx,
                                     const struct silofs_vaddr *vaddr)
{
	return sbi_is_within_vspace(spa_ctx->sbi, vaddr) ? 0 : -ENOSPC;
}

static int spc_resolve_oaddr(struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_vaddr *vaddr = &spa_ctx->ova.vaddr;

	silofs_assert(!vaddr_isnull(vaddr));
	return silofs_sbi_resolve_ova(spa_ctx->sbi, vaddr,
	                              SILOFS_STAGE_RDONLY, &spa_ctx->ova);
}

static int
spc_find_free_space_at_leaf(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;
	struct silofs_vaddr *vaddr = &spa_ctx->ova.vaddr;

	err = spc_stage_rdonly_spleaf(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = silofs_sli_find_free_space(spa_ctx->sli, spa_ctx->stype, vaddr);
	if (err) {
		return err;
	}
	err = spc_require_within_vspace(spa_ctx, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int
spc_find_free_space_from(struct silofs_spalloc_ctx *spa_ctx,
                         const struct silofs_vrange *vrange, loff_t *out_voff)
{
	int err;
	const enum silofs_stype stype = spa_ctx->stype;

	err = silofs_sni_search_spleaf(spa_ctx->sni, vrange, stype, out_voff);
	if (err) {
		return err;
	}
	err = spc_find_free_space_at_leaf(spa_ctx, *out_voff);
	if (err) {
		return err;
	}
	return 0;
}

static int spc_find_free_space_within(struct silofs_spalloc_ctx *spa_ctx,
                                      const struct silofs_vrange *vrange)
{
	int err = -ENOSPC;
	loff_t vnxt;
	loff_t voff = vrange->beg;
	struct silofs_vrange sub_vrange;

	while (voff < vrange->end) {
		silofs_vrange_setup(&sub_vrange, voff, vrange->end);
		err = spc_find_free_space_from(spa_ctx, &sub_vrange, &vnxt);
		if ((err != -ENOSPC) || (vnxt >= vrange->end)) {
			break;
		}
		voff = silofs_off_to_vsec_next(vnxt, 1);
	}
	return err;
}

static void
spc_calc_spnode_vrange(const struct silofs_spalloc_ctx *spa_ctx,
                       bool try_use_last, struct silofs_vrange *out_vrange)
{
	loff_t beg;
	loff_t end;
	loff_t voff_last;
	struct silofs_vrange fs_vrange;
	struct silofs_vrange sn_vrange;

	voff_last = sbi_voff_last_of(spa_ctx->sbi, spa_ctx->stype);
	silofs_sni_formatted_vrange(spa_ctx->sni, &sn_vrange);
	sbi_active_vspace_range(spa_ctx->sbi, &fs_vrange);

	if (try_use_last && silofs_vrange_within(&sn_vrange, voff_last)) {
		beg = off_max(fs_vrange.beg, voff_last);
		end = off_min(fs_vrange.end, sn_vrange.end);
	} else {
		beg = off_max(fs_vrange.beg, sn_vrange.beg);
		end = off_min(fs_vrange.end, sn_vrange.end);
	}
	silofs_vrange_setup(out_vrange, beg, end);
}

static int spc_find_free_space_for(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;
	struct silofs_vrange vrange;

	/* fast search */
	spc_calc_spnode_vrange(spa_ctx, true, &vrange);
	err = spc_find_free_space_within(spa_ctx, &vrange);
	if (err != -ENOSPC) {
		return err;
	}
	/* slow search */
	spc_calc_spnode_vrange(spa_ctx, false, &vrange);
	err = spc_find_free_space_within(spa_ctx, &vrange);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int spc_find_free_at_node(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;

	silofs_sni_incref(spa_ctx->sni);
	err = silofs_sni_check_may_alloc(spa_ctx->sni, spa_ctx->stype);
	if (!err) {
		err = spc_find_free_space_for(spa_ctx);
	}
	silofs_sni_decref(spa_ctx->sni);
	return err;
}

static int
spc_try_find_free_at_node(struct silofs_spalloc_ctx *spa_ctx, loff_t voff)
{
	int err;

	err = spc_stage_rdonly_spnode(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spc_find_free_at_node(spa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int
spc_find_free_by_spmaps(struct silofs_spalloc_ctx *spa_ctx, loff_t hint)
{
	int ret = -ENOSPC;
	loff_t voff = hint;
	const loff_t vend = sbi_end_of_active_vspace(spa_ctx->sbi);

	while (voff < vend) {
		ret = spc_try_find_free_at_node(spa_ctx, voff);
		if (!ret || (ret != -ENOSPC)) {
			break;
		}
		voff = silofs_off_to_spnode_next(voff);
	}
	return ret;
}

static struct silofs_spvmap *
spc_spvmap(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_cache *cache = sbi_cache(spa_ctx->sbi);

	return &cache->c_spvm;
}

static int spc_find_free_from_cache(struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_spvmap *spvm = spc_spvmap(spa_ctx);

	return silofs_spvmap_trypop(spvm, spa_ctx->stype, &spa_ctx->ova.vaddr);
}

static int
spc_find_unallocated_vspace(struct silofs_spalloc_ctx *spa_ctx, loff_t hint)
{
	int err;

	err = spc_find_free_from_cache(spa_ctx);
	if (err) {
		err = spc_find_free_by_spmaps(spa_ctx, hint);
	}
	return err;
}

static int spc_check_avail_space(const struct silofs_spalloc_ctx *spa_ctx)
{
	bool ok;
	bool new_file;
	const size_t nbytes_want = stype_size(spa_ctx->stype);
	const struct silofs_sb_info *sbi = spa_ctx->sbi;

	ok = sbi_may_alloc_some(sbi, nbytes_want);
	if (ok) {
		if (stype_isdata(spa_ctx->stype)) {
			ok = sbi_may_alloc_data(sbi, nbytes_want);
		} else {
			new_file = stype_isinode(spa_ctx->stype);
			ok = sbi_may_alloc_meta(sbi, nbytes_want, new_file);
		}
	}
	return ok ? 0 : -ENOSPC;
}

static int spc_check_want_free_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	const struct silofs_sb_info *sbi = spa_ctx->sbi;
	const struct silofs_vaddr *vaddr = &spa_ctx->ova.vaddr;

	if (vaddr_isnull(vaddr)) {
		return -ENOSPC;
	}
	if (!sbi_is_within_vspace(sbi, vaddr)) {
		return -ENOSPC;
	}
	return 0;
}

static void spc_mark_allocated(const struct silofs_spalloc_ctx *spa_ctx)
{
	sbi_mark_allocated_at(spa_ctx->sbi, spa_ctx->sni,
	                      spa_ctx->sli, &spa_ctx->ova.vaddr);
}

static int spc_try_find_unallocated_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;
	loff_t voff;
	struct silofs_sb_info *sbi = spa_ctx->sbi;

	voff = sbi_voff_last_of(sbi, spa_ctx->stype);
	err = spc_find_unallocated_vspace(spa_ctx, voff);
	if (err != -ENOSPC) {
		return err;
	}
	err = silofs_sbi_expand_vspace(sbi, spa_ctx->stype, &voff);
	if (err) {
		return err;
	}
	err = spc_find_unallocated_vspace(spa_ctx, voff);
	if (err) {
		return err;
	}
	return 0;
}

static int spc_claim_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;
	const struct silofs_vaddr *vaddr = &spa_ctx->ova.vaddr;

	err = spc_check_avail_space(spa_ctx);
	if (err) {
		return err;
	}
	err = spc_try_find_unallocated_vspace(spa_ctx);
	if (err) {
		/* TODO: cleanup */
		return err;
	}
	err = spc_check_want_free_vspace(spa_ctx);
	if (err) {
		return err;
	}
	err = spc_stage_mutable_spmaps(spa_ctx, vaddr_off(vaddr));
	if (err) {
		return err;
	}
	err = spc_resolve_oaddr(spa_ctx);
	if (err) {
		return err;
	}
	spc_mark_allocated(spa_ctx);
	return 0;
}

int silofs_sbi_claim_vspace(struct silofs_sb_info *sbi,
                            enum silofs_stype stype,
                            struct silofs_ovaddr *out_ova)
{
	int err;
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = stype,
	};

	err = spc_claim_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	ovaddr_assign(out_ova, &spa_ctx.ova);
	return 0;
}

static int spc_spawn_vnode_at(const struct silofs_spalloc_ctx *spa_ctx,
                              struct silofs_vnode_info **out_vi)
{
	return silofs_sbi_spawn_vnode_at(spa_ctx->sbi, &spa_ctx->ova, out_vi);
}

/* TODO: cleanups and resource reclaim upon failure in every path */
int silofs_sbi_claim_vnode(struct silofs_sb_info *sbi,
                           enum silofs_stype stype,
                           struct silofs_vnode_info **out_vi)
{
	int err;
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = stype,
	};

	err = spc_claim_vspace(&spa_ctx);
	if (err) {
		return err;
	}
	err = spc_spawn_vnode_at(&spa_ctx, out_vi);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	return 0;
}

static int spc_claim_ispace(struct silofs_spalloc_ctx *spa_ctx,
                            struct silofs_iovaddr *out_iova)
{
	int err;
	struct silofs_iaddr iaddr;
	const struct silofs_vaddr *vaddr = &spa_ctx->ova.vaddr;

	err = spc_claim_vspace(spa_ctx);
	if (err) {
		return err;
	}
	err = silofs_acquire_ino(spa_ctx->sbi, vaddr, &iaddr);
	if (err) {
		return err;
	}
	iovaddr_setup2(out_iova, iaddr.ino, &spa_ctx->ova);
	return 0;
}

int silofs_sbi_claim_inode(struct silofs_sb_info *sbi,
                           struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;
	struct silofs_iovaddr iova = {
		.ino = SILOFS_INO_NULL
	};
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = SILOFS_STYPE_INODE,
	};

	err = spc_claim_ispace(&spa_ctx, &iova);
	if (err) {
		return err;
	}
	err = spc_spawn_vnode_at(&spa_ctx, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);
	silofs_ii_rebind_view(ii, iova.ino);
	*out_ii = ii;
	return 0;
}

static void spc_reclaim_unallocate(const struct silofs_spalloc_ctx *spa_ctx)
{
	struct silofs_sb_info *sbi = spa_ctx->sbi;
	struct silofs_spvmap *spvm = spc_spvmap(spa_ctx);
	const struct silofs_vaddr *vaddr = &spa_ctx->ova.vaddr;

	sbi_clear_unallocate_at(sbi, spa_ctx->sni, spa_ctx->sli, vaddr);
	silofs_spvmap_store(spvm, vaddr);
}

static int spc_reclaim_vspace(struct silofs_spalloc_ctx *spa_ctx)
{
	int err;
	loff_t voff;

	voff = vaddr_off(&spa_ctx->ova.vaddr);
	err = spc_stage_mutable_spmaps(spa_ctx, voff);
	if (err) {
		return err;
	}
	err = spc_resolve_oaddr(spa_ctx);
	if (err) {
		return err;
	}
	spc_reclaim_unallocate(spa_ctx);
	return 0;
}

int silofs_sbi_reclaim_vspace(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr)
{
	struct silofs_spalloc_ctx spa_ctx = {
		.sbi = sbi,
		.stype = vaddr_stype(vaddr),
	};

	vaddr_assign(&spa_ctx.ova.vaddr, vaddr);
	return spc_reclaim_vspace(&spa_ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/



