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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/stats.h>
#include <silofs/fs/private.h>
#include <sys/statvfs.h>
#include <limits.h>


static size_t safe_sum(size_t cur, size_t dif, ssize_t take)
{
	size_t val = cur;

	if (take > 0) {
		val += dif * (size_t)take;
		silofs_assert_gt(val, cur);
	} else if (take < 0) {
		silofs_assert_ge((ssize_t)val, -take * (ssize_t)dif);
		val -= (size_t)(labs(take)) * dif;
	}
	return val;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const size_t *spstats_counter(const struct silofs_spacestats *spst,
                                     enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_SUPER:
		return &spst->sp_nsuper;
	case SILOFS_STYPE_STATS:
		return &spst->sp_nstats;
	case SILOFS_STYPE_SPNODE:
		return &spst->sp_nspnode;
	case SILOFS_STYPE_SPLEAF:
		return &spst->sp_nspleaf;
	case SILOFS_STYPE_ITNODE:
		return &spst->sp_nitnode;
	case SILOFS_STYPE_INODE:
		return &spst->sp_ninode;
	case SILOFS_STYPE_XANODE:
		return &spst->sp_nxanode;
	case SILOFS_STYPE_SYMVAL:
		return &spst->sp_nsymval;
	case SILOFS_STYPE_DTNODE:
		return &spst->sp_ndtnode;
	case SILOFS_STYPE_FTNODE:
		return &spst->sp_nftnode;
	case SILOFS_STYPE_DATA1K:
		return &spst->sp_ndata1k;
	case SILOFS_STYPE_DATA4K:
		return &spst->sp_ndata4k;
	case SILOFS_STYPE_DATABK:
		return &spst->sp_ndatabk;
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		break;
	}
	return NULL;
}

static size_t *spstats_counter2(struct silofs_spacestats *spst,
                                enum silofs_stype stype)
{
	return silofs_unconst(spstats_counter(spst, stype));
}

void silofs_spstats_reset(struct silofs_spacestats *spst)
{
	silofs_memzero(spst, sizeof(*spst));
	spst->sp_timestamp = silofs_time_now();
}

void silofs_spstats_add(struct silofs_spacestats *spst,
                        const struct silofs_spacestats *other)
{
	size_t *cnt = NULL;
	const size_t *cnt_other = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		cnt = spstats_counter2(spst, stype);
		cnt_other = spstats_counter(other, stype);
		if (likely(cnt != NULL) && likely(cnt_other != NULL)) {
			*cnt += *cnt_other;
		}
	}
}

void silofs_spstats_by_stype(struct silofs_spacestats *spst,
                             enum silofs_stype stype, size_t cnt)
{
	size_t *pcnt = spstats_counter2(spst, stype);

	silofs_spstats_reset(spst);
	if (likely(pcnt != NULL)) {
		*pcnt = cnt;
	}
}

static size_t spstats_nbytes_sum(const struct silofs_spacestats *spst)
{
	size_t sum = 0;
	const size_t *cnt = NULL;
	enum silofs_stype stype = SILOFS_STYPE_NONE;

	while (++stype < SILOFS_STYPE_MAX) {
		cnt = spstats_counter(spst, stype);
		if (likely(cnt != NULL)) {
			sum += *cnt * stype_size(stype);
		}
	}
	return sum;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int verify_cnt(size_t cnt)
{
	const size_t cnt_max = ULONG_MAX / 2;

	return (cnt <= cnt_max) ? 0 : -EFSCORRUPTED;
}

static int verify_size(size_t sz)
{
	const size_t sz_max = ULONG_MAX / 4;

	return (sz <= sz_max) ? 0 : -EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const uint64_t *
sr_counter_of(const struct silofs_stats_record *sr, enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_SUPER:
		return &sr->sr_nsuper;
	case SILOFS_STYPE_STATS:
		return &sr->sr_nstats;
	case SILOFS_STYPE_SPNODE:
		return &sr->sr_nspnode;
	case SILOFS_STYPE_SPLEAF:
		return &sr->sr_nspleaf;
	case SILOFS_STYPE_ITNODE:
		return &sr->sr_nitnode;
	case SILOFS_STYPE_INODE:
		return &sr->sr_ninode;
	case SILOFS_STYPE_XANODE:
		return &sr->sr_nxanode;
	case SILOFS_STYPE_SYMVAL:
		return &sr->sr_nsymval;
	case SILOFS_STYPE_DTNODE:
		return &sr->sr_ndtnode;
	case SILOFS_STYPE_FTNODE:
		return &sr->sr_nftnode;
	case SILOFS_STYPE_DATA1K:
		return &sr->sr_ndata1k;
	case SILOFS_STYPE_DATA4K:
		return &sr->sr_ndata4k;
	case SILOFS_STYPE_DATABK:
		return &sr->sr_ndatabk;
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		break;
	}
	return NULL;
}

static uint64_t *
sr_counter_of2(struct silofs_stats_record *sr, enum silofs_stype stype)
{
	return silofs_unconst(sr_counter_of(sr, stype));
}

static uint64_t *sr_safe_counter_of2(struct silofs_stats_record *sr,
                                     enum silofs_stype stype, uint64_t *alt)
{
	uint64_t *cnt = sr_counter_of2(sr, stype);

	return likely(cnt != NULL) ? cnt : alt;
}

static void sr_export_stypes_to(const struct silofs_stats_record *sr,
                                struct silofs_spacestats *spst)
{
	size_t *dst = NULL;
	const uint64_t *src = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_MAX; ++stype) {
		src = sr_counter_of(sr, stype);
		if (unlikely(src == NULL)) {
			continue;
		}
		dst = spstats_counter2(spst, stype);
		if (unlikely(dst == NULL)) {
			continue;
		}
		*dst = silofs_le64_to_cpu(*src);
	}
}

static fsfilcnt_t sr_ninodes(const struct silofs_stats_record *sr)
{
	fsfilcnt_t cnt = 0;
	const uint64_t *src = sr_counter_of(sr, SILOFS_STYPE_INODE);

	if (likely(src != NULL)) {
		cnt = silofs_le64_to_cpu(*src);
	}
	return cnt;
}

static void sr_export_to(const struct silofs_stats_record *sr,
                         struct silofs_spacestats *spst)
{
	sr_export_stypes_to(sr, spst);
}

static void sr_update_take(struct silofs_stats_record *sr,
                           enum silofs_stype stype, ssize_t take)
{
	size_t cur_val;
	size_t new_val;
	uint64_t tmp = 0; /* make clang-scan happy */
	uint64_t *cnt = sr_safe_counter_of2(sr, stype, &tmp);

	cur_val = silofs_le64_to_cpu(*cnt);
	new_val = safe_sum(cur_val, 1, take);
	*cnt = silofs_cpu_to_le64(new_val);
}



static int sr_verify(const struct silofs_stats_record *sr)
{
	const uint64_t *pcnt = NULL;
	enum silofs_stype stype;
	size_t cnt;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_MAX; ++stype) {
		pcnt = sr_counter_of(sr, stype);
		if (unlikely(pcnt == NULL)) {
			continue;
		}
		cnt = silofs_le64_to_cpu(*pcnt);
		err = verify_cnt(cnt);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spst_set_btime(struct silofs_space_stats *spst, time_t tm)
{
	spst->sp_btime = silofs_cpu_to_time(tm);
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

static void spst_set_vspacesize(struct silofs_space_stats *spst, size_t nbytes)
{
	spst->sp_vspacesize = silofs_cpu_to_le64(nbytes);
}

static void spst_init(struct silofs_space_stats *spst)
{
	silofs_memzero(spst, sizeof(*spst));
	spst_set_btime(spst, silofs_time_now());
	spst_set_ctime(spst, silofs_time_now());
	spst_set_capacity(spst, 0);
	spst_set_vspacesize(spst, SILOFS_PETA); /* XXX */
}

static void spst_make_clone(struct silofs_space_stats *spst,
                            const struct silofs_space_stats *other)
{
	/* XXX rethink */
	memcpy(spst, other, sizeof(*spst));
}

static void spst_update_objs(struct silofs_space_stats *spst,
                             enum silofs_stype stype, ssize_t take)
{
	sr_update_take(&spst->sp_objs, stype, take);
}

static void spst_export_to(const struct silofs_space_stats *spst,
                           struct silofs_spacestats *out_spst)
{
	sr_export_to(&spst->sp_objs, out_spst);
}

static fsfilcnt_t spst_ninodes(const struct silofs_space_stats *spst)
{
	return sr_ninodes(&spst->sp_objs);
}

static int spst_verify(const struct silofs_space_stats *spst)
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
	err = sr_verify(&spst->sp_objs);
	if (err) {
		return err;
	}
	err = sr_verify(&spst->sp_bks);
	if (err) {
		return err;
	}
	err = sr_verify(&spst->sp_blobs);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stnode_init(struct silofs_stats_node *stn)
{
	spst_init(&stn->st_sp);
}

static void stnode_make_clone(struct silofs_stats_node *stn,
                              const struct silofs_stats_node *other)
{
	spst_make_clone(&stn->st_sp, &other->st_sp);
}

static void stnode_update_curr(struct silofs_stats_node *stn,
                               enum silofs_stype stype, ssize_t take)
{
	spst_update_objs(&stn->st_sp, stype, take);
}

static void stnode_collect_curr(const struct silofs_stats_node *stn,
                                struct silofs_spacestats *out_spst)
{
	spst_export_to(&stn->st_sp, out_spst);
}

static int stnode_verify(const struct silofs_stats_node *stn)
{
	return spst_verify(&stn->st_sp);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sti_bind_apex(struct silofs_stats_info *sti,
                          struct silofs_fs_apex *apex)
{
	silofs_ui_bind_apex(&sti->st_ui, apex);
}

static void sti_dirtify(struct silofs_stats_info *sti)
{
	ui_dirtify(&sti->st_ui);
}

void silofs_sti_setup_spawned(struct silofs_stats_info *sti)
{
	union silofs_view *view = sti->st_ui.u_si.s_view;

	silofs_zero_stamp_meta(view, SILOFS_STYPE_STATS);
	stnode_init(sti->st);
	sti_dirtify(sti);
}

void silofs_sti_make_clone(struct silofs_stats_info *sti,
                           const struct silofs_stats_info *sti_other)
{
	stnode_make_clone(sti->st, sti_other->st);
	sti_dirtify(sti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_sti_capacity(const struct silofs_stats_info *sti)
{
	return spst_capacity(&sti->st->st_sp);
}

void silofs_sti_set_capacity(struct silofs_stats_info *sti, size_t capacity)
{
	spst_set_capacity(&sti->st->st_sp, capacity);
	sti_dirtify(sti);
}

void silofs_sti_inc_nblobs(struct silofs_stats_info *sti)
{
	/* XXX sr_inc_nblobs(&sti->st->st_curr); */
	sti_dirtify(sti);
}

void silofs_sti_update_curr(struct silofs_stats_info *sti,
                            enum silofs_stype stype, ssize_t take)
{
	stnode_update_curr(sti->st, stype, take);
	sti_dirtify(sti);
}

void silofs_sti_collect_curr(const struct silofs_stats_info *sti,
                             struct silofs_spacestats *spst)
{
	stnode_collect_curr(sti->st, spst);
}

loff_t silofs_sti_vspace_end(const struct silofs_stats_info *sti)
{
	const size_t vspsz = spst_vspacesize(&sti->st->st_sp);

	return (loff_t)vspsz;
}

size_t silofs_sti_bytes_used(const struct silofs_stats_info *sti)
{
	struct silofs_spacestats spst = { .sp_timestamp = 0 };

	stnode_collect_curr(sti->st, &spst);
	return spstats_nbytes_sum(&spst);
}

fsfilcnt_t silofs_sti_inodes_used(const struct silofs_stats_info *sti)
{
	return spst_ninodes(&sti->st->st_sp);
}

fsfilcnt_t silofs_sti_inodes_max(const struct silofs_stats_info *sti)
{
	return (silofs_sti_capacity(sti) / SILOFS_INODE_SIZE) >> 2;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_sti_may_alloc_some(const struct silofs_stats_info *sti, size_t nb)
{
	const size_t nbytes_used = silofs_sti_bytes_used(sti);
	const size_t nbytes_cap = silofs_sti_capacity(sti);
	const size_t nbytes_pad = SILOFS_BK_SIZE;

	return ((nb + nbytes_used + nbytes_pad) < nbytes_cap);
}

bool silofs_sti_may_alloc_data(const struct silofs_stats_info *sti, size_t nb)
{
	const size_t user_limit = (31 * silofs_sti_capacity(sti)) / 32;
	const size_t used_bytes = silofs_sti_bytes_used(sti);

	return ((used_bytes + nb) <= user_limit);
}

bool silofs_sti_may_alloc_meta(const struct silofs_stats_info *sti,
                               size_t nb, bool new_file)
{
	const size_t limit = silofs_sti_capacity(sti);
	const size_t nused = silofs_sti_bytes_used(sti);
	fsfilcnt_t files_max;
	fsfilcnt_t files_cur;
	bool ret = true;

	if ((nused + nb) > limit) {
		ret = false;
	} else if (new_file) {
		files_max = silofs_sti_inodes_max(sti);
		files_cur = silofs_sti_inodes_used(sti);
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
	silofs_assert_eq(nbytes % 1024, 0);
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
	const fsfilcnt_t nfiles_max = silofs_sti_inodes_max(sti);
	const fsfilcnt_t nfiles_cur = silofs_sti_inodes_used(sti);

	silofs_assert_ge(nbytes_max, nbytes_use);

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_stats_node(const struct silofs_stats_node *st)
{
	return stnode_verify(st);
}
