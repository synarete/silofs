/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <sys/statvfs.h>
#include <limits.h>


/* local functions */
static ssize_t *
spgs_gauge_of2(struct silofs_spacegauges *spgs, enum silofs_ltype ltype);

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

	return ((val_min <= val) && (val <= val_max)) ?
	       0 : -SILOFS_EFSCORRUPTED;
}

static int verify_size(size_t sz)
{
	const size_t sz_max = ULONG_MAX / 4;

	return (sz <= sz_max) ? 0 : -SILOFS_EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spg_bzero_all(struct silofs_space_gauges *spg)
{
	memset(spg, 0, sizeof(*spg));
}

static void spg_make_clone(struct silofs_space_gauges *spg,
                           const struct silofs_space_gauges *spg_other)
{
	memcpy(spg, spg_other, sizeof(*spg));
}

static const uint64_t *
spg_gauge_of(const struct silofs_space_gauges *spg, enum silofs_ltype ltype)
{
	const uint64_t *ret;

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		ret = &spg->sg_nsuper;
		break;
	case SILOFS_LTYPE_SPNODE:
		ret = &spg->sg_nspnode;
		break;
	case SILOFS_LTYPE_SPLEAF:
		ret = &spg->sg_nspleaf;
		break;
	case SILOFS_LTYPE_INODE:
		ret = &spg->sg_ninode;
		break;
	case SILOFS_LTYPE_XANODE:
		ret = &spg->sg_nxanode;
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = &spg->sg_nsymval;
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = &spg->sg_ndtnode;
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = &spg->sg_nftnode;
		break;
	case SILOFS_LTYPE_DATA1K:
		ret = &spg->sg_ndata1k;
		break;
	case SILOFS_LTYPE_DATA4K:
		ret = &spg->sg_ndata4k;
		break;
	case SILOFS_LTYPE_DATABK:
		ret = &spg->sg_ndatabk;
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static uint64_t *
spg_gauge_of2(struct silofs_space_gauges *spg, enum silofs_ltype ltype)
{
	return silofs_unconst(spg_gauge_of(spg, ltype));
}

static void spg_export_to(const struct silofs_space_gauges *spg,
                          struct silofs_spacegauges *spgs)
{
	ssize_t *dst = NULL;
	const uint64_t *src = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		src = spg_gauge_of(spg, ltype);
		if (unlikely(src == NULL)) {
			continue;
		}
		dst = spgs_gauge_of2(spgs, ltype);
		if (unlikely(dst == NULL)) {
			continue;
		}
		*dst = silofs_gauge_to_cpu(*src);
	}
}

static ssize_t spg_ninodes(const struct silofs_space_gauges *spg)
{
	ssize_t cnt = 0;
	const uint64_t *src = spg_gauge_of(spg, SILOFS_LTYPE_INODE);

	if (likely(src != NULL)) {
		cnt = silofs_gauge_to_cpu(*src);
	}
	return cnt;
}

static void spg_update_take(struct silofs_space_gauges *spg,
                            enum silofs_ltype ltype, ssize_t take)
{
	ssize_t cur_val;
	ssize_t new_val;
	uint64_t *cnt = spg_gauge_of2(spg, ltype);

	if (likely(cnt != NULL)) {
		cur_val = silofs_gauge_to_cpu(*cnt);
		new_val = cur_val + take;
		*cnt = silofs_cpu_to_gauge(new_val);
	}
}

static int spg_verify(const struct silofs_space_gauges *spg)
{
	const uint64_t *pcnt = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	ssize_t cnt;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		pcnt = spg_gauge_of(spg, ltype);
		if (unlikely(pcnt == NULL)) {
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

static time_t spst_btime(const struct silofs_space_stats *spst)
{
	return silofs_time_to_cpu(spst->sp_btime);
}

static void spst_set_btime(struct silofs_space_stats *spst, time_t tm)
{
	spst->sp_btime = silofs_cpu_to_time(tm);
}

static time_t spst_ctime(const struct silofs_space_stats *spst)
{
	return silofs_time_to_cpu(spst->sp_ctime);
}

static void spst_set_ctime(struct silofs_space_stats *spst, time_t tm)
{
	spst->sp_ctime = silofs_cpu_to_time(tm);
}

static size_t spst_capacity(const struct silofs_space_stats *spst)
{
	return silofs_le64_to_cpu(spst->sp_capacity);
}

static void spst_set_capacity(struct silofs_space_stats *spst, size_t nbytes)
{
	spst->sp_capacity = silofs_cpu_to_le64(nbytes);
}

static size_t spst_vspacesize(const struct silofs_space_stats *spst)
{
	return silofs_le64_to_cpu(spst->sp_vspacesize);
}

static void spst_set_vspacesize(struct silofs_space_stats *spst, size_t vsz)
{
	spst->sp_vspacesize = silofs_cpu_to_le64(vsz);
}

static uint64_t spst_generation(const struct silofs_space_stats *spst)
{
	return silofs_le64_to_cpu(spst->sp_generation);
}

static void spst_set_generation(struct silofs_space_stats *spst, uint64_t gen)
{
	spst->sp_generation = silofs_cpu_to_le64(gen);
}

static uint64_t spst_inc_generation(struct silofs_space_stats *spst)
{
	uint64_t next_gen = spst_generation(spst) + 1;

	spst_set_generation(spst, next_gen);
	return next_gen;
}

static void spst_init(struct silofs_space_stats *spst)
{
	spst_set_btime(spst, silofs_time_now());
	spst_set_ctime(spst, silofs_time_now());
	spst_set_capacity(spst, 0);
	spst_set_vspacesize(spst, SILOFS_VSPACE_SIZE_MAX);
	spst_set_generation(spst, 0);
	spg_bzero_all(&spst->sp_objs);
	spg_bzero_all(&spst->sp_bks);
	spg_bzero_all(&spst->sp_lsegs);
}

static void spst_renew(struct silofs_space_stats *spst)
{
	spg_bzero_all(&spst->sp_objs);
	spg_bzero_all(&spst->sp_bks);
	spg_bzero_all(&spst->sp_lsegs);
}

static void spst_make_clone(struct silofs_space_stats *spst,
                            const struct silofs_space_stats *spst_other)
{
	spst_set_btime(spst, spst_btime(spst_other));
	spst_set_ctime(spst, spst_ctime(spst_other));
	spst_set_capacity(spst, spst_capacity(spst_other));
	spst_set_vspacesize(spst, spst_vspacesize(spst_other));
	spst_set_generation(spst, spst_generation(spst_other));
	spg_make_clone(&spst->sp_objs, &spst_other->sp_objs);
	spg_make_clone(&spst->sp_bks, &spst_other->sp_bks);
	spg_make_clone(&spst->sp_lsegs, &spst_other->sp_lsegs);
}

static void spst_export_to(const struct silofs_space_stats *spst,
                           struct silofs_spacestats *sst)
{
	sst->btime = spst_btime(spst);
	sst->ctime = spst_ctime(spst);
	sst->capacity = spst_capacity(spst);
	sst->vspacesize = spst_vspacesize(spst);
	sst->generation = spst_generation(spst);
	spg_export_to(&spst->sp_objs, &sst->objs);
	spg_export_to(&spst->sp_bks, &sst->bks);
	spg_export_to(&spst->sp_lsegs, &sst->lsegs);
}

static void spst_update_lsegs(struct silofs_space_stats *spst,
                              enum silofs_ltype ltype, ssize_t take)
{
	spg_update_take(&spst->sp_lsegs, ltype, take);
}

static void spst_update_objs(struct silofs_space_stats *spst,
                             enum silofs_ltype ltype, ssize_t take)
{
	spg_update_take(&spst->sp_objs, ltype, take);
}

static void spst_update_bks(struct silofs_space_stats *spst,
                            enum silofs_ltype ltype, ssize_t take)
{
	spg_update_take(&spst->sp_bks, ltype, take);
}

static ssize_t spst_ninodes(const struct silofs_space_stats *spst)
{
	return spg_ninodes(&spst->sp_objs);
}

int silofs_verify_space_stats(const struct silofs_space_stats *spst)
{
	int err;

	err = verify_size(spst_capacity(spst));
	if (err) {
		return err;
	}
	err = verify_size(spst_vspacesize(spst));
	if (err) {
		return err;
	}
	err = spg_verify(&spst->sp_objs);
	if (err) {
		return err;
	}
	err = spg_verify(&spst->sp_bks);
	if (err) {
		return err;
	}
	err = spg_verify(&spst->sp_lsegs);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const ssize_t *
spgs_gauge_of(const struct silofs_spacegauges *spgs, enum silofs_ltype ltype)
{
	const ssize_t *ret;

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		ret = &spgs->nsuper;
		break;
	case SILOFS_LTYPE_SPNODE:
		ret = &spgs->nspnode;
		break;
	case SILOFS_LTYPE_SPLEAF:
		ret = &spgs->nspleaf;
		break;
	case SILOFS_LTYPE_INODE:
		ret = &spgs->ninode;
		break;
	case SILOFS_LTYPE_XANODE:
		ret = &spgs->nxanode;
		break;
	case SILOFS_LTYPE_SYMVAL:
		ret = &spgs->nsymval;
		break;
	case SILOFS_LTYPE_DTNODE:
		ret = &spgs->ndtnode;
		break;
	case SILOFS_LTYPE_FTNODE:
		ret = &spgs->nftnode;
		break;
	case SILOFS_LTYPE_DATA1K:
		ret = &spgs->ndata1k;
		break;
	case SILOFS_LTYPE_DATA4K:
		ret = &spgs->ndata4k;
		break;
	case SILOFS_LTYPE_DATABK:
		ret = &spgs->ndatabk;
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = NULL;
		break;
	}
	return ret;
}

static ssize_t *
spgs_gauge_of2(struct silofs_spacegauges *spgs, enum silofs_ltype ltype)
{
	return silofs_unconst(spgs_gauge_of(spgs, ltype));
}

static ssize_t spgs_sum(const struct silofs_spacegauges *spgs)
{
	ssize_t sum = 0;
	const ssize_t *cnt = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		cnt = spgs_gauge_of(spgs, ltype);
		if (likely(cnt != NULL)) {
			sum += *cnt * ltype_ssize(ltype);
		}
	}
	return sum;
}

static void spgs_accum(struct silofs_spacegauges *spgs,
                       const struct silofs_spacegauges *spgs_other)
{
	ssize_t *dst = NULL;
	const ssize_t *src = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		dst = spgs_gauge_of2(spgs, ltype);
		if (dst == NULL) {
			continue;
		}
		src = spgs_gauge_of(spgs_other, ltype);
		if (unlikely(src == NULL)) {
			continue;
		}
		*dst += *src;
	}
}

static void spgs_export(const struct silofs_spacegauges *spgs,
                        struct silofs_space_gauges *out_spg)
{
	uint64_t *dst = NULL;
	const ssize_t *src = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		dst = spg_gauge_of2(out_spg, ltype);
		if (dst == NULL) {
			continue;
		}
		src = spgs_gauge_of(spgs, ltype);
		if (src == NULL) {
			continue;
		}
		*dst = silofs_cpu_to_gauge(*src);
	}
}

static void spgs_import(struct silofs_spacegauges *spgs,
                        const struct silofs_space_gauges *in_spg)
{
	ssize_t *dst = NULL;
	const uint64_t *src = NULL;
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;

	while (++ltype < SILOFS_LTYPE_LAST) {
		src = spg_gauge_of(in_spg, ltype);
		if (src == NULL) {
			continue;
		}
		dst = spgs_gauge_of2(spgs, ltype);
		if (dst == NULL) {
			continue;
		}
		*dst = silofs_gauge_to_cpu(*src);
	}
}

static void spacestats_accum_gauges(struct silofs_spacestats *spst,
                                    const struct silofs_spacestats *spst_other)
{
	spgs_accum(&spst->lsegs, &spst_other->lsegs);
	spgs_accum(&spst->bks, &spst_other->bks);
	spgs_accum(&spst->objs, &spst_other->objs);
}

void silofs_spacestats_export(const struct silofs_spacestats *spst,
                              struct silofs_space_stats *out_spst)
{
	silofs_memzero(out_spst, sizeof(*out_spst));
	out_spst->sp_btime = silofs_cpu_to_time(spst->btime);
	out_spst->sp_ctime = silofs_cpu_to_time(spst->ctime);
	out_spst->sp_capacity = silofs_cpu_to_le64(spst->capacity);
	out_spst->sp_vspacesize = silofs_cpu_to_le64(spst->vspacesize);
	out_spst->sp_generation = silofs_cpu_to_le64(spst->generation);
	spgs_export(&spst->lsegs, &out_spst->sp_lsegs);
	spgs_export(&spst->bks, &out_spst->sp_bks);
	spgs_export(&spst->objs, &out_spst->sp_objs);
}

void silofs_spacestats_import(struct silofs_spacestats *spst,
                              const struct silofs_space_stats *in_spst)
{
	silofs_memzero(spst, sizeof(*spst));
	spst->btime = silofs_time_to_cpu(in_spst->sp_btime);
	spst->ctime = silofs_time_to_cpu(in_spst->sp_ctime);
	spst->capacity = silofs_le64_to_cpu(in_spst->sp_capacity);
	spst->vspacesize = silofs_le64_to_cpu(in_spst->sp_vspacesize);
	spst->generation = silofs_le64_to_cpu(in_spst->sp_generation);
	spgs_import(&spst->lsegs, &in_spst->sp_lsegs);
	spgs_import(&spst->bks, &in_spst->sp_bks);
	spgs_import(&spst->objs, &in_spst->sp_objs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sti_dirtify(struct silofs_stats_info *sti)
{
	sbi_dirtify(sti->sbi);
}

void silofs_sti_setup_spawned(struct silofs_stats_info *sti,
                              struct silofs_sb_info *sbi)
{
	spst_init(sti->spst_curr);
	sti->sbi = sbi;
}

void silofs_sti_make_clone(struct silofs_stats_info *sti,
                           const struct silofs_stats_info *sti_other)
{
	spst_make_clone(sti->spst_curr, sti_other->spst_curr);
	sti_dirtify(sti);
}

void silofs_sti_renew_stats(struct silofs_stats_info *sti)
{
	struct silofs_spacestats spst;

	silofs_sti_collect_stats(sti, &spst);
	silofs_spacestats_export(&spst, sti->spst_base);
	spst_renew(sti->spst_curr);
	sti_dirtify(sti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t silofs_sti_capacity(const struct silofs_stats_info *sti)
{
	return spst_capacity(sti->spst_curr);
}

void silofs_sti_set_capacity(struct silofs_stats_info *sti,
                             size_t capacity)
{
	spst_set_capacity(sti->spst_curr, capacity);
	sti_dirtify(sti);
}

void silofs_sti_update_lsegs(struct silofs_stats_info *sti,
                             enum silofs_ltype ltype, ssize_t take)
{
	if (take != 0) {
		spst_update_lsegs(sti->spst_curr, ltype, take);
		sti_dirtify(sti);
	}
}

void silofs_sti_update_bks(struct silofs_stats_info *sti,
                           enum silofs_ltype ltype, ssize_t take)
{
	if (take != 0) {
		spst_update_bks(sti->spst_curr, ltype, take);
		sti_dirtify(sti);
	}
}

void silofs_sti_update_objs(struct silofs_stats_info *sti,
                            enum silofs_ltype ltype, ssize_t take)
{
	if (take != 0) {
		spst_update_objs(sti->spst_curr, ltype, take);
		sti_dirtify(sti);
	}
}

void silofs_sti_collect_stats(const struct silofs_stats_info *sti,
                              struct silofs_spacestats *spst)
{
	struct silofs_spacestats spst_base;

	spst_export_to(sti->spst_base, &spst_base);
	spst_export_to(sti->spst_curr, spst);
	spacestats_accum_gauges(spst, &spst_base);
}

void silofs_sti_vspace_end(const struct silofs_stats_info *sti, loff_t *out)
{
	const size_t vspsz = spst_vspacesize(sti->spst_curr);

	*out = (loff_t)vspsz;
}

static size_t silofs_sti_bytes_used(const struct silofs_stats_info *sti)
{
	struct silofs_spacestats spst = { .btime = 0 };
	ssize_t total;

	/*
	 * TODO-0046: Cache nbytes-used as volatile member of sti
	 *
	 * Do not collect-stats for each call; speed-up using cached in-memory
	 * counter.
	 */
	silofs_sti_collect_stats(sti, &spst);
	total = spgs_sum(&spst.objs);
	return (size_t)total;
}

static fsfilcnt_t sti_inodes_used(const struct silofs_stats_info *sti)
{
	const ssize_t ninodes_base = spst_ninodes(sti->spst_base);
	const ssize_t ninodes_curr = spst_ninodes(sti->spst_curr);
	const ssize_t ninodes = ninodes_base + ninodes_curr;

	return (fsfilcnt_t)ninodes;
}

static fsfilcnt_t sti_inodes_max(const struct silofs_stats_info *sti)
{
	return (silofs_sti_capacity(sti) / SILOFS_INODE_SIZE) >> 2;
}

void silofs_sti_next_generation(struct silofs_stats_info *sti, uint64_t *out)
{
	*out = spst_inc_generation(sti->spst_curr);
	sti_dirtify(sti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_sti_mayalloc_some(const struct silofs_stats_info *sti,
                              size_t nbytes_want)
{
	const size_t nbytes_used = silofs_sti_bytes_used(sti);
	const size_t nbytes_cap = silofs_sti_capacity(sti);
	const size_t nbytes_pad = SILOFS_LBK_SIZE;

	return ((nbytes_want + nbytes_used + nbytes_pad) < nbytes_cap);
}

bool silofs_sti_mayalloc_data(const struct silofs_stats_info *sti,
                              size_t nbytes_want)
{
	const size_t user_limit = (31 * silofs_sti_capacity(sti)) / 32;
	const size_t used_bytes = silofs_sti_bytes_used(sti);

	return ((used_bytes + nbytes_want) <= user_limit);
}

bool silofs_sti_mayalloc_meta(const struct silofs_stats_info *sti,
                              size_t nbytes_want, bool new_file)
{
	const size_t limit = silofs_sti_capacity(sti);
	const size_t nused = silofs_sti_bytes_used(sti);
	fsfilcnt_t files_max;
	fsfilcnt_t files_cur;
	bool ret = true;

	if ((nused + nbytes_want) > limit) {
		ret = false;
	} else if (new_file) {
		files_max = sti_inodes_max(sti);
		files_cur = sti_inodes_used(sti);
		ret = (files_cur < files_max);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * TODO-0028: Use statvfs.f_bsize=BK (64K) and KB to statvfs.f_frsize=KB (1K)
 *
 * The semantics of statvfs and statfs are not entirely clear; in particular,
 * statvfs(3p) states that statvfs.f_blocks define the file-system's size in
 * f_frsize units, where f_bfree is number of free blocks (but without stating
 * explicit units). For now, we force 4K units to both, but need more
 * investigations before changing, especially with respect to various
 * user-space tools.
 */
static fsblkcnt_t bytes_to_fsblkcnt(size_t nbytes, size_t unit)
{
	return (fsblkcnt_t)nbytes / unit;
}

void silofs_sti_fill_statvfs(const struct silofs_stats_info *sti,
                             struct statvfs *out_stv)
{
	const size_t funit = 4 * SILOFS_KB_SIZE;
	const size_t bsize = funit;
	const size_t frsize = funit;
	const size_t nbytes_max = silofs_sti_capacity(sti);
	const size_t nbytes_use = silofs_sti_bytes_used(sti);
	const size_t nbytes_free = nbytes_max - nbytes_use;
	const fsfilcnt_t nfiles_max = sti_inodes_max(sti);
	const fsfilcnt_t nfiles_cur = sti_inodes_used(sti);

	silofs_memzero(out_stv, sizeof(*out_stv));
	out_stv->f_bsize = bsize;
	out_stv->f_frsize = frsize;
	out_stv->f_blocks = bytes_to_fsblkcnt(nbytes_max, frsize);
	out_stv->f_bfree = bytes_to_fsblkcnt(nbytes_free, bsize);
	out_stv->f_bavail = out_stv->f_bfree;
	out_stv->f_files = nfiles_max;
	out_stv->f_ffree = nfiles_max - nfiles_cur;
	out_stv->f_favail = out_stv->f_ffree;
	out_stv->f_namemax = SILOFS_NAME_MAX;
	out_stv->f_fsid = SILOFS_FSID_MAGIC;
}
