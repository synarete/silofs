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
#include <sys/statvfs.h>
#include <limits.h>

#include <silofs/ioctls.h>
#include <silofs/base.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>
#include <silofs/fs.h>

/* Local functions. */
static ssize_t *
spgs_mut_gauge_of(struct silofs_space_gauges *spgs, enum silofs_vtype vtype);

static const ssize_t *
spgs_gauge_of(const struct silofs_space_gauges *spgs, enum silofs_vtype vtype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t silofs_cpu_to_gauge(int64_t k)
{
	const uint64_t mask = 1UL << 63;
	uint64_t n;

	if (k < 0) {
		n = (uint64_t)(-k) | mask;
	} else {
		n = (uint64_t)k;
	}
	return silofs_cpu_to_le64(n);
}

static int64_t silofs_gauge_to_cpu(uint64_t n)
{
	const uint64_t mask = 1UL << 63;
	uint64_t v;
	int64_t k;

	v = silofs_le64_to_cpu(n);
	if (v & mask) {
		k = -((int64_t)(v & ~mask));
	} else {
		k = (int64_t)(v & ~mask);
	}
	return k;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int verify_gauge(ssize_t val)
{
	const ssize_t val_max = LONG_MAX / 2;
	const ssize_t val_min = -val_max;
	int ret               = 0;

	if ((val < val_min) || (val_max < val)) {
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static int verify_size(size_t sz)
{
	const size_t sz_max = ULONG_MAX / 4;

	return (sz <= sz_max) ? 0 : -SILOFS_EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const uint64_t *
spgs256_gauge_of(const struct silofs_space_gauges256 *spgs256,
                 enum silofs_vtype vtype)
{
	const uint64_t *ret;

	switch (vtype) {
	case SILOFS_VTYPE_SUPER:
		ret = &spgs256->sg_nsuper;
		break;
	case SILOFS_VTYPE_SPNODE:
		ret = &spgs256->sg_nspnode;
		break;
	case SILOFS_VTYPE_SPLEAF:
		ret = &spgs256->sg_nspleaf;
		break;
	case SILOFS_VTYPE_LSMAP:
		ret = &spgs256->sg_nlsmap;
		break;
	case SILOFS_VTYPE_INODE:
		ret = &spgs256->sg_ninode;
		break;
	case SILOFS_VTYPE_XANODE:
		ret = &spgs256->sg_nxanode;
		break;
	case SILOFS_VTYPE_SYMVAL:
		ret = &spgs256->sg_nsymval;
		break;
	case SILOFS_VTYPE_DTNODE:
		ret = &spgs256->sg_ndtnode;
		break;
	case SILOFS_VTYPE_FTNODE:
		ret = &spgs256->sg_nftnode;
		break;
	case SILOFS_VTYPE_DATA1K:
		ret = &spgs256->sg_ndata1k;
		break;
	case SILOFS_VTYPE_DATA4K:
		ret = &spgs256->sg_ndata4k;
		break;
	case SILOFS_VTYPE_DATA64K:
		ret = &spgs256->sg_ndata64k;
		break;
	case SILOFS_VTYPE_SPNODE2:
	case SILOFS_VTYPE_SUPER2:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		ret = nullptr;
		break;
	}
	return ret;
}

static uint64_t *spgs256_gauge_of2(struct silofs_space_gauges256 *spgs256,
                                   enum silofs_vtype vtype)
{
	return silofs_unconst(spgs256_gauge_of(spgs256, vtype));
}

static void spgs256_xtoh(const struct silofs_space_gauges256 *spgs256,
                         struct silofs_space_gauges *spgs)
{
	ssize_t *dst            = nullptr;
	const uint64_t *src     = nullptr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		src = spgs256_gauge_of(spgs256, vtype);
		dst = spgs_mut_gauge_of(spgs, vtype);
		if ((src != nullptr) && (dst != nullptr)) {
			*dst = silofs_gauge_to_cpu(*src);
		}
	}
}

static void spgs256_htox(struct silofs_space_gauges256 *spgs256,
                         const struct silofs_space_gauges *spgs)
{
	uint64_t *dst           = nullptr;
	const ssize_t *src      = nullptr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		src = spgs_gauge_of(spgs, vtype);
		dst = spgs256_gauge_of2(spgs256, vtype);
		if ((src != nullptr) && (dst != nullptr)) {
			*dst = silofs_cpu_to_gauge(*src);
		}
	}
}

static int spgs256_verify(const struct silofs_space_gauges256 *spgs256)
{
	const uint64_t *pcnt    = nullptr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	ssize_t cnt;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		pcnt = spgs256_gauge_of(spgs256, vtype);
		if (unlikely(pcnt == nullptr)) {
			continue;
		}
		cnt = silofs_gauge_to_cpu(*pcnt);
		err = verify_gauge(cnt);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static time_t spst1k_btime(const struct silofs_space_stats1k *spst1k)
{
	return silofs_time_to_cpu(spst1k->sp_btime);
}

static void spst1k_set_btime(struct silofs_space_stats1k *spst1k, time_t tm)
{
	spst1k->sp_btime = silofs_cpu_to_time(tm);
}

static time_t spst1k_ctime(const struct silofs_space_stats1k *spst1k)
{
	return silofs_time_to_cpu(spst1k->sp_ctime);
}

static void spst1k_set_ctime(struct silofs_space_stats1k *spst1k, time_t tm)
{
	spst1k->sp_ctime = silofs_cpu_to_time(tm);
}

static size_t spst1k_capacity(const struct silofs_space_stats1k *spst1k)
{
	return silofs_le64_to_cpu(spst1k->sp_capacity);
}

static void
spst1k_set_capacity(struct silofs_space_stats1k *spst1k, size_t nbytes)
{
	spst1k->sp_capacity = silofs_cpu_to_le64(nbytes);
}

static size_t spst1k_vspacesize(const struct silofs_space_stats1k *spst1k)
{
	return silofs_le64_to_cpu(spst1k->sp_vspacesize);
}

static void
spst1k_set_vspacesize(struct silofs_space_stats1k *spst1k, size_t vsz)
{
	spst1k->sp_vspacesize = silofs_cpu_to_le64(vsz);
}

static uint64_t spst1k_generation(const struct silofs_space_stats1k *spst1k)
{
	return silofs_le64_to_cpu(spst1k->sp_generation);
}

static void
spst1k_set_generation(struct silofs_space_stats1k *spst1k, uint64_t gen)
{
	spst1k->sp_generation = silofs_cpu_to_le64(gen);
}

static void spst1k_xtoh(const struct silofs_space_stats1k *spst1k,
                        struct silofs_space_stats *spst)
{
	spst->btime      = spst1k_btime(spst1k);
	spst->ctime      = spst1k_ctime(spst1k);
	spst->capacity   = spst1k_capacity(spst1k);
	spst->vspacesize = spst1k_vspacesize(spst1k);
	spst->generation = spst1k_generation(spst1k);
	spgs256_xtoh(&spst1k->sp_objs, &spst->objs);
	spgs256_xtoh(&spst1k->sp_bks, &spst->bks);
	spgs256_xtoh(&spst1k->sp_lsegs, &spst->lsegs);
}

static void spst1k_htox(struct silofs_space_stats1k *spst1k,
                        const struct silofs_space_stats *spst)
{
	spst1k_set_btime(spst1k, spst->btime);
	spst1k_set_ctime(spst1k, spst->ctime);
	spst1k_set_capacity(spst1k, spst->capacity);
	spst1k_set_vspacesize(spst1k, spst->vspacesize);
	spst1k_set_generation(spst1k, spst->generation);
	spgs256_htox(&spst1k->sp_objs, &spst->objs);
	spgs256_htox(&spst1k->sp_bks, &spst->bks);
	spgs256_htox(&spst1k->sp_lsegs, &spst->lsegs);
}

int silofs_verify_space_stats(const struct silofs_space_stats1k *spst1k)
{
	int err;

	err = verify_size(spst1k_capacity(spst1k));
	if (err) {
		return err;
	}
	err = verify_size(spst1k_vspacesize(spst1k));
	if (err) {
		return err;
	}
	err = spgs256_verify(&spst1k->sp_objs);
	if (err) {
		return err;
	}
	err = spgs256_verify(&spst1k->sp_bks);
	if (err) {
		return err;
	}
	err = spgs256_verify(&spst1k->sp_lsegs);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const ssize_t *
spgs_gauge_of(const struct silofs_space_gauges *spgs, enum silofs_vtype vtype)
{
	const ssize_t *ret;

	switch (vtype) {
	case SILOFS_VTYPE_SUPER:
		ret = &spgs->nsuper;
		break;
	case SILOFS_VTYPE_SPNODE:
		ret = &spgs->nspnode;
		break;
	case SILOFS_VTYPE_SPLEAF:
		ret = &spgs->nspleaf;
		break;
	case SILOFS_VTYPE_LSMAP:
		ret = &spgs->nlsmap;
		break;
	case SILOFS_VTYPE_INODE:
		ret = &spgs->ninode;
		break;
	case SILOFS_VTYPE_XANODE:
		ret = &spgs->nxanode;
		break;
	case SILOFS_VTYPE_SYMVAL:
		ret = &spgs->nsymval;
		break;
	case SILOFS_VTYPE_DTNODE:
		ret = &spgs->ndtnode;
		break;
	case SILOFS_VTYPE_FTNODE:
		ret = &spgs->nftnode;
		break;
	case SILOFS_VTYPE_DATA1K:
		ret = &spgs->ndata1k;
		break;
	case SILOFS_VTYPE_DATA4K:
		ret = &spgs->ndata4k;
		break;
	case SILOFS_VTYPE_DATA64K:
		ret = &spgs->ndata64k;
		break;
	case SILOFS_VTYPE_SUPER2:
	case SILOFS_VTYPE_SPNODE2:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		ret = nullptr;
		break;
	}
	return ret;
}

static ssize_t *
spgs_mut_gauge_of(struct silofs_space_gauges *spgs, enum silofs_vtype vtype)
{
	return silofs_unconst(spgs_gauge_of(spgs, vtype));
}

static void spgs_reset(struct silofs_space_gauges *spgs)
{
	ssize_t *cnt            = nullptr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		cnt = spgs_mut_gauge_of(spgs, vtype);
		if (likely(cnt != nullptr)) {
			*cnt = 0;
		}
	}
}

static void spgs_assign(struct silofs_space_gauges *spgs,
                        const struct silofs_space_gauges *spgs_other)
{
	ssize_t *dst            = nullptr;
	const ssize_t *src      = nullptr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		dst = spgs_mut_gauge_of(spgs, vtype);
		src = spgs_gauge_of(spgs_other, vtype);
		if (likely((src != nullptr) && (dst != nullptr))) {
			*dst = *src;
		}
	}
}

static void spgs_update_take(struct silofs_space_gauges *spgs,
                             enum silofs_vtype vtype, ssize_t take)
{
	ssize_t *cnt = spgs_mut_gauge_of(spgs, vtype);

	if (likely(cnt != nullptr)) {
		*cnt += take;
	}
}

static void spgs_accum(struct silofs_space_gauges *spgs,
                       const struct silofs_space_gauges *spgs_other)
{
	ssize_t *dst            = nullptr;
	const ssize_t *src      = nullptr;
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;

	while (++vtype < SILOFS_VTYPE_LAST) {
		src = spgs_gauge_of(spgs_other, vtype);
		dst = spgs_mut_gauge_of(spgs, vtype);
		if ((src != nullptr) && (dst != nullptr)) {
			*dst += *src;
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spst_reset_spgs(struct silofs_space_stats *spst)
{
	spgs_reset(&spst->objs);
	spgs_reset(&spst->bks);
	spgs_reset(&spst->lsegs);
}

static void spst_init(struct silofs_space_stats *spst)
{
	silofs_memzero(spst, sizeof(*spst));
	spst->btime = spst->ctime = silofs_time_real_now();
	spst->capacity            = 0;
	spst->vspacesize          = SILOFS_VSPACE_SIZE_MAX;
	spst->generation          = 0;
	spst_reset_spgs(spst);
}

static void spst_assign(struct silofs_space_stats *spst,
                        const struct silofs_space_stats *spst_other)
{
	silofs_memzero(spst, sizeof(*spst));
	spst->btime      = spst_other->btime;
	spst->ctime      = spst_other->ctime;
	spst->capacity   = spst_other->capacity;
	spst->vspacesize = spst_other->vspacesize;
	spst->generation = spst_other->generation;
	spgs_assign(&spst->objs, &spst_other->objs);
	spgs_assign(&spst->bks, &spst_other->bks);
	spgs_assign(&spst->lsegs, &spst_other->lsegs);
}

static void spst_update_lsegs(struct silofs_space_stats *spst,
                              enum silofs_vtype vtype, ssize_t take)
{
	spgs_update_take(&spst->lsegs, vtype, take);
}

static void spst_accum_gauges(struct silofs_space_stats *spst,
                              const struct silofs_space_stats *spst_other)
{
	spgs_accum(&spst->lsegs, &spst_other->lsegs);
	spgs_accum(&spst->bks, &spst_other->bks);
	spgs_accum(&spst->objs, &spst_other->objs);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void sbst_collect_stats(const struct silofs_sb_info *sbi,
                               struct silofs_space_stats *out_spst)
{
	spst_assign(out_spst, &sbi->sb_spst_curr);
	spst_accum_gauges(out_spst, &sbi->sb_spst_prev);
}

void silofs_sbst_setup_spawned(struct silofs_sb_info *sbi)
{
	spst_init(&sbi->sb_spst_curr);
}

void silofs_sbst_setup_forked(struct silofs_sb_info *sbi,
                              const struct silofs_sb_info *sbi_from)
{
	struct silofs_space_stats spst;

	sbst_collect_stats(sbi_from, &spst);
	spst_assign(&sbi->sb_spst_curr, &spst);
	spst_assign(&sbi->sb_spst_prev, &spst);
	spst_reset_spgs(&sbi->sb_spst_curr);
	silofs_sbi_setdirty(sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbst_update_lsegs(struct silofs_sb_info *sbi,
                              enum silofs_vtype vtype, ssize_t take)
{
	if (take != 0) {
		spst_update_lsegs(&sbi->sb_spst_curr, vtype, take);
		silofs_sbi_setdirty(sbi);
	}
}

off_t silofs_sbst_vspace_end(const struct silofs_sb_info *sbi)
{
	return (off_t)(sbi->sb_spst_curr.vspacesize);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbst_fetch_from_sb(struct silofs_sb_info *sbi)
{
	const struct silofs_super_block *sb = sbi->sb;

	spst1k_xtoh(&sb->sb_space_stats_curr, &sbi->sb_spst_curr);
	spst1k_xtoh(&sb->sb_space_stats_prev, &sbi->sb_spst_prev);
}

void silofs_sbst_force_into_sb(struct silofs_sb_info *sbi)
{
	struct silofs_super_block *sb = sbi->sb;

	spst1k_htox(&sb->sb_space_stats_curr, &sbi->sb_spst_curr);
	spst1k_htox(&sb->sb_space_stats_prev, &sbi->sb_spst_prev);
}
