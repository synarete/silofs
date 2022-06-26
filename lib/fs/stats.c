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

static const size_t *
spsr_counter(const struct silofs_spacestat_rec *spsr, enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_SUPER:
		return &spsr->nsuper;
	case SILOFS_STYPE_SPSTATS:
		return &spsr->nspstats;
	case SILOFS_STYPE_SPNODE:
		return &spsr->nspnode;
	case SILOFS_STYPE_SPLEAF:
		return &spsr->nspleaf;
	case SILOFS_STYPE_ITNODE:
		return &spsr->nitnode;
	case SILOFS_STYPE_INODE:
		return &spsr->ninode;
	case SILOFS_STYPE_XANODE:
		return &spsr->nxanode;
	case SILOFS_STYPE_SYMVAL:
		return &spsr->nsymval;
	case SILOFS_STYPE_DTNODE:
		return &spsr->ndtnode;
	case SILOFS_STYPE_FTNODE:
		return &spsr->nftnode;
	case SILOFS_STYPE_DATA1K:
		return &spsr->ndata1k;
	case SILOFS_STYPE_DATA4K:
		return &spsr->ndata4k;
	case SILOFS_STYPE_DATABK:
		return &spsr->ndatabk;
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		break;
	}
	return NULL;
}

static size_t *
spsr_counter2(struct silofs_spacestat_rec *spsr, enum silofs_stype stype)
{
	return silofs_unconst(spsr_counter(spsr, stype));
}

static size_t spsr_sum(const struct silofs_spacestat_rec *spsr)
{
	size_t sum = 0;
	const size_t *cnt = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_MAX; ++stype) {
		cnt = spsr_counter(spsr, stype);
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

static void sr_bzero_all(struct silofs_spstat_record *sr)
{
	memset(sr, 0, sizeof(*sr));
}

static void sr_make_clone(struct silofs_spstat_record *sr,
                          const struct silofs_spstat_record *sr_other)
{
	memcpy(sr, sr_other, sizeof(*sr));
}

static const uint64_t *
sr_counter_of(const struct silofs_spstat_record *sr, enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_SUPER:
		return &sr->sr_nsuper;
	case SILOFS_STYPE_SPSTATS:
		return &sr->sr_nspstats;
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
sr_counter_of2(struct silofs_spstat_record *sr, enum silofs_stype stype)
{
	return silofs_unconst(sr_counter_of(sr, stype));
}

static uint64_t *sr_safe_counter_of2(struct silofs_spstat_record *sr,
                                     enum silofs_stype stype, uint64_t *alt)
{
	uint64_t *cnt = sr_counter_of2(sr, stype);

	return likely(cnt != NULL) ? cnt : alt;
}

static void sr_export_to(const struct silofs_spstat_record *sr,
                         struct silofs_spacestat_rec *spsr)
{
	size_t *dst = NULL;
	const uint64_t *src = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_MAX; ++stype) {
		src = sr_counter_of(sr, stype);
		if (unlikely(src == NULL)) {
			continue;
		}
		dst = spsr_counter2(spsr, stype);
		if (unlikely(dst == NULL)) {
			continue;
		}
		*dst = silofs_le64_to_cpu(*src);
	}
}

static fsfilcnt_t sr_ninodes(const struct silofs_spstat_record *sr)
{
	fsfilcnt_t cnt = 0;
	const uint64_t *src = sr_counter_of(sr, SILOFS_STYPE_INODE);

	if (likely(src != NULL)) {
		cnt = silofs_le64_to_cpu(*src);
	}
	return cnt;
}

static void sr_update_take(struct silofs_spstat_record *sr,
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

static int sr_verify(const struct silofs_spstat_record *sr)
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

static time_t spst_btime(const struct silofs_spstats_node *sp)
{
	return silofs_time_to_cpu(sp->sp_st.sp_btime);
}

static void spst_set_btime(struct silofs_spstats_node *sp, time_t tm)
{
	sp->sp_st.sp_btime = silofs_cpu_to_time(tm);
}

static time_t spst_ctime(const struct silofs_spstats_node *sp)
{
	return silofs_time_to_cpu(sp->sp_st.sp_ctime);
}

static void spst_set_ctime(struct silofs_spstats_node *sp, time_t tm)
{
	sp->sp_st.sp_ctime = silofs_cpu_to_time(tm);
}

static size_t spst_capacity(const struct silofs_spstats_node *sp)
{
	return silofs_le64_to_cpu(sp->sp_st.sp_capacity);
}

static void spst_set_capacity(struct silofs_spstats_node *sp, size_t nbytes)
{
	sp->sp_st.sp_capacity = silofs_cpu_to_le64(nbytes);
}

static size_t spst_vspacesize(const struct silofs_spstats_node *sp)
{
	return silofs_le64_to_cpu(sp->sp_st.sp_vspacesize);
}

static void spst_set_vspacesize(struct silofs_spstats_node *sp, size_t vsz)
{
	sp->sp_st.sp_vspacesize = silofs_cpu_to_le64(vsz);
}

static void spst_init(struct silofs_spstats_node *sp)
{
	spst_set_btime(sp, silofs_time_now());
	spst_set_ctime(sp, silofs_time_now());
	spst_set_capacity(sp, 0);
	spst_set_vspacesize(sp, SILOFS_VSPACE_SIZE_MAX);
	sr_bzero_all(&sp->sp_st.sp_objs);
	sr_bzero_all(&sp->sp_st.sp_bks);
	sr_bzero_all(&sp->sp_st.sp_blobs);
}

static void spst_make_clone(struct silofs_spstats_node *sp,
                            const struct silofs_spstats_node *stn_other)
{
	spst_set_btime(sp, spst_btime(stn_other));
	spst_set_ctime(sp, spst_ctime(stn_other));
	spst_set_capacity(sp, spst_capacity(stn_other));
	spst_set_vspacesize(sp, spst_vspacesize(stn_other));
	sr_make_clone(&sp->sp_st.sp_objs, &stn_other->sp_st.sp_objs);
	sr_make_clone(&sp->sp_st.sp_bks, &stn_other->sp_st.sp_bks);
	sr_make_clone(&sp->sp_st.sp_blobs, &stn_other->sp_st.sp_blobs);
}

static void spst_export_to(const struct silofs_spstats_node *sp,
                           struct silofs_spacestats *spst)
{
	spst->btime = spst_btime(sp);
	spst->ctime = spst_ctime(sp);
	spst->capacity = spst_capacity(sp);
	spst->vspacesize = spst_vspacesize(sp);
	sr_export_to(&sp->sp_st.sp_objs, &spst->objs);
	sr_export_to(&sp->sp_st.sp_bks, &spst->bks);
	sr_export_to(&sp->sp_st.sp_blobs, &spst->blobs);
}

static void spst_update_blobs(struct silofs_spstats_node *sp,
                              enum silofs_stype stype, ssize_t take)
{
	sr_update_take(&sp->sp_st.sp_blobs, stype, take);
}

static void spst_update_objs(struct silofs_spstats_node *sp,
                             enum silofs_stype stype, ssize_t take)
{
	sr_update_take(&sp->sp_st.sp_objs, stype, take);
}

static void spst_update_bks(struct silofs_spstats_node *sp,
                            enum silofs_stype stype, ssize_t take)
{
	sr_update_take(&sp->sp_st.sp_bks, stype, take);
}

static fsfilcnt_t spst_ninodes(const struct silofs_spstats_node *sp)
{
	return sr_ninodes(&sp->sp_st.sp_objs);
}

static int spst_verify(const struct silofs_spstats_node *sp)
{
	int err;

	err = verify_size(spst_capacity(sp));
	if (err) {
		return err;
	}
	err = verify_size(spst_vspacesize(sp));
	if (err) {
		return err;
	}
	err = sr_verify(&sp->sp_st.sp_objs);
	if (err) {
		return err;
	}
	err = sr_verify(&sp->sp_st.sp_bks);
	if (err) {
		return err;
	}
	err = sr_verify(&sp->sp_st.sp_blobs);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spacestat_rec_export(const struct silofs_spacestat_rec *spsr,
                                 struct silofs_spstat_record *out_sr)
{
	uint64_t *dst = NULL;
	const size_t *src = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_MAX; ++stype) {
		dst = sr_counter_of2(out_sr, stype);
		if (dst == NULL) {
			continue;
		}
		src = spsr_counter(spsr, stype);
		if (src == NULL) {
			continue;
		}
		*dst = *src;
	}
}

static void spacestat_rec_import(struct silofs_spacestat_rec *spsr,
                                 const struct silofs_spstat_record *in_sr)
{
	size_t *dst = NULL;
	const uint64_t *src = NULL;
	enum silofs_stype stype;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_MAX; ++stype) {
		src = sr_counter_of(in_sr, stype);
		if (src == NULL) {
			continue;
		}
		dst = spsr_counter2(spsr, stype);
		if (dst == NULL) {
			continue;
		}
		*dst = *src;
	}
}

void silofs_spacestats_export(const struct silofs_spacestats *spst,
                              struct silofs_spstats *out_spst)
{
	silofs_memzero(out_spst, sizeof(*out_spst));
	out_spst->sp_btime = (uint64_t)(spst->btime);
	out_spst->sp_ctime = (uint64_t)(spst->ctime);
	out_spst->sp_capacity = spst->capacity;
	out_spst->sp_vspacesize = spst->vspacesize;
	spacestat_rec_export(&spst->blobs, &out_spst->sp_blobs);
	spacestat_rec_export(&spst->bks, &out_spst->sp_bks);
	spacestat_rec_export(&spst->objs, &out_spst->sp_objs);
}

void silofs_spacestats_import(struct silofs_spacestats *spst,
                              const struct silofs_spstats *in_spst)
{
	silofs_memzero(spst, sizeof(*spst));
	spst->btime = (time_t)in_spst->sp_btime;
	spst->ctime = (time_t)in_spst->sp_ctime;
	spst->capacity = in_spst->sp_capacity;
	spst->vspacesize = in_spst->sp_vspacesize;
	spacestat_rec_import(&spst->blobs, &in_spst->sp_blobs);
	spacestat_rec_import(&spst->bks, &in_spst->sp_bks);
	spacestat_rec_import(&spst->objs, &in_spst->sp_objs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_spi_bind_uber(struct silofs_spstats_info *spi,
                          struct silofs_fs_uber *uber)
{
	silofs_ui_bind_uber(&spi->sp_ui, uber);
}

static void spi_dirtify(struct silofs_spstats_info *spi)
{
	ui_dirtify(&spi->sp_ui);
}

void silofs_spi_setup_spawned(struct silofs_spstats_info *spi)
{
	union silofs_view *view = spi->sp_ui.u_si.s_view;

	silofs_zero_stamp_meta(view, SILOFS_STYPE_SPSTATS);
	spst_init(spi->sp);
	spi_dirtify(spi);
}

void silofs_spi_make_clone(struct silofs_spstats_info *spi,
                           const struct silofs_spstats_info *spi_other)
{
	spst_make_clone(spi->sp, spi_other->sp);
	spi_dirtify(spi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_spi_capacity(const struct silofs_spstats_info *spi)
{
	return spst_capacity(spi->sp);
}

void silofs_spi_set_capacity(struct silofs_spstats_info *spi, size_t capacity)
{
	spst_set_capacity(spi->sp, capacity);
	spi_dirtify(spi);
}

void silofs_spi_update_blobs(struct silofs_spstats_info *spi,
                             enum silofs_stype stype, ssize_t take)
{
	if (take != 0) {
		spst_update_blobs(spi->sp, stype, take);
		spi_dirtify(spi);
	}
}

void silofs_spi_update_bks(struct silofs_spstats_info *spi,
                           enum silofs_stype stype, ssize_t take)
{
	if (take != 0) {
		spst_update_bks(spi->sp, stype, take);
		spi_dirtify(spi);
	}
}

void silofs_spi_update_objs(struct silofs_spstats_info *spi,
                            enum silofs_stype stype, ssize_t take)
{
	if (take != 0) {
		spst_update_objs(spi->sp, stype, take);
		spi_dirtify(spi);
	}
}

void silofs_spi_collect_stats(const struct silofs_spstats_info *spi,
                              struct silofs_spacestats *spst)
{
	spst_export_to(spi->sp, spst);
}

loff_t silofs_spi_vspace_end(const struct silofs_spstats_info *spi)
{
	const size_t vspsz = spst_vspacesize(spi->sp);

	return (loff_t)vspsz;
}

size_t silofs_spi_bytes_used(const struct silofs_spstats_info *spi)
{
	struct silofs_spacestats spst = { .btime = 0 };

	spst_export_to(spi->sp, &spst);
	return spsr_sum(&spst.objs);
}

fsfilcnt_t silofs_spi_inodes_used(const struct silofs_spstats_info *spi)
{
	return spst_ninodes(spi->sp);
}

fsfilcnt_t silofs_spi_inodes_max(const struct silofs_spstats_info *spi)
{
	return (silofs_spi_capacity(spi) / SILOFS_INODE_SIZE) >> 2;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_spi_mayalloc_some(const struct silofs_spstats_info *spi, size_t n)
{
	const size_t nbytes_used = silofs_spi_bytes_used(spi);
	const size_t nbytes_cap = silofs_spi_capacity(spi);
	const size_t nbytes_pad = SILOFS_BK_SIZE;

	return ((n + nbytes_used + nbytes_pad) < nbytes_cap);
}

bool silofs_spi_mayalloc_data(const struct silofs_spstats_info *spi, size_t n)
{
	const size_t user_limit = (31 * silofs_spi_capacity(spi)) / 32;
	const size_t used_bytes = silofs_spi_bytes_used(spi);

	return ((used_bytes + n) <= user_limit);
}

bool silofs_spi_mayalloc_meta(const struct silofs_spstats_info *spi,
                              size_t nbytes, bool new_file)
{
	const size_t limit = silofs_spi_capacity(spi);
	const size_t nused = silofs_spi_bytes_used(spi);
	fsfilcnt_t files_max;
	fsfilcnt_t files_cur;
	bool ret = true;

	if ((nused + nbytes) > limit) {
		ret = false;
	} else if (new_file) {
		files_max = silofs_spi_inodes_max(spi);
		files_cur = silofs_spi_inodes_used(spi);
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

void silofs_spi_fill_statvfs(const struct silofs_spstats_info *sti,
                             struct statvfs *out_stv)
{
	const size_t funit = 4 * SILOFS_KB_SIZE;
	const size_t bsize = funit;
	const size_t frsize = funit;
	const size_t nbytes_max = silofs_spi_capacity(sti);
	const size_t nbytes_use = silofs_spi_bytes_used(sti);
	const size_t nbytes_free = nbytes_max - nbytes_use;
	const fsfilcnt_t nfiles_max = silofs_spi_inodes_max(sti);
	const fsfilcnt_t nfiles_cur = silofs_spi_inodes_used(sti);

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

int silofs_verify_spstats_node(const struct silofs_spstats_node *st)
{
	return spst_verify(st);
}
