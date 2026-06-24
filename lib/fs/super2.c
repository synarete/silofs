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
#include <inttypes.h>

#include <silofs/version.h>
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/fs.h>

static void swv64b_htox(struct silofs_sw_version64b *swv64,
                        const struct silofs_sw_version *swv)
{
	STATICASSERT_EQ_SIZEOF(swv64->sw_revision, swv->revision);

	memset(swv64, 0, sizeof(*swv64));
	swv64->sw_major    = silofs_cpu_to_le32(swv->major);
	swv64->sw_minor    = silofs_cpu_to_le32(swv->minor);
	swv64->sw_sublevel = silofs_cpu_to_le32(swv->sublevel);
	memcpy(swv64->sw_revision, swv->revision, sizeof(swv64->sw_revision));
}

static void swv64b_xtoh(const struct silofs_sw_version64b *swv64,
                        struct silofs_sw_version *swv)
{
	STATICASSERT_EQ_SIZEOF(swv->revision, swv64->sw_revision);

	memset(swv, 0, sizeof(*swv));
	swv->major    = silofs_le32_to_cpu(swv64->sw_major);
	swv->minor    = silofs_le32_to_cpu(swv64->sw_minor);
	swv->sublevel = silofs_le32_to_cpu(swv64->sw_sublevel);

	memcpy(swv->revision, swv64->sw_revision, sizeof(swv->revision));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void tm64b_htox(struct silofs_tm64b *tm64, const struct tm *tm)
{
	tm64->tm_sec      = silofs_cpu_to_le16((uint16_t)tm->tm_sec);
	tm64->tm_min      = silofs_cpu_to_le16((uint16_t)tm->tm_min);
	tm64->tm_hour     = (uint8_t)(tm->tm_hour);
	tm64->tm_mday     = (uint8_t)(tm->tm_mday);
	tm64->tm_mon      = (uint8_t)(tm->tm_mon);
	tm64->tm_wday     = (uint8_t)(tm->tm_wday);
	tm64->tm_year     = silofs_cpu_to_le32((uint32_t)tm->tm_year);
	tm64->tm_yday     = silofs_cpu_to_le32((uint32_t)tm->tm_yday);
	tm64->tm_gmtoff   = silofs_cpu_to_le64((uint64_t)tm->tm_gmtoff);
	tm64->tm_reserved = 0;
}

static void tm64b_xtoh(const struct silofs_tm64b *tm64, struct tm *tm)
{
	tm->tm_sec    = (int)silofs_le16_to_cpu(tm64->tm_sec);
	tm->tm_min    = (int)silofs_le16_to_cpu(tm64->tm_min);
	tm->tm_hour   = (int)(tm64->tm_hour);
	tm->tm_mday   = (int)(tm64->tm_mday);
	tm->tm_mon    = (int)(tm64->tm_mon);
	tm->tm_wday   = (int)(tm64->tm_wday);
	tm->tm_year   = (int)silofs_le32_to_cpu(tm64->tm_year);
	tm->tm_yday   = (int)silofs_le32_to_cpu(tm64->tm_yday);
	tm->tm_gmtoff = (long)silofs_le64_to_cpu(tm64->tm_gmtoff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
sbn_slot_of(const struct silofs_superb_node *sbn, enum silofs_vtype vtype)
{
	const size_t slot = (size_t)vtype;

	STATICASSERT_LT(SILOFS_VTYPE_LAST, ARRAY_SIZE(sbn->s_nodes_count));
	STATICASSERT_LT(SILOFS_VTYPE_LAST, ARRAY_SIZE(sbn->s_apex_voff));
	silofs_assert_lt(slot, ARRAY_SIZE(sbn->s_nodes_count));
	silofs_assert_lt(slot, ARRAY_SIZE(sbn->s_apex_voff));

	return slot;
}

static uint64_t sbn_magic(const struct silofs_superb_node *sbn)
{
	return silofs_le64_to_cpu(sbn->s_magic);
}

static void sbn_set_magic(struct silofs_superb_node *sbn, uint64_t magic)
{
	sbn->s_magic = silofs_cpu_to_le64(magic);
}

static uint64_t sbn_version(const struct silofs_superb_node *sbn)
{
	return silofs_le64_to_cpu(sbn->s_version);
}

static void sbn_set_version(struct silofs_superb_node *sbn, uint64_t vers)
{
	sbn->s_version = silofs_cpu_to_le64(vers);
}

static enum silofs_superf sbn_flags(const struct silofs_superb_node *sbn)
{
	const uint32_t flags = silofs_le32_to_cpu(sbn->s_flags);

	return (enum silofs_superf)flags;
}

static void
sbn_set_flags(struct silofs_superb_node *sbn, enum silofs_superf flags)
{
	sbn->s_flags = silofs_cpu_to_le32((uint32_t)flags);
}

static void sbn_sw_version(const struct silofs_superb_node *sbn,
                           struct silofs_sw_version *out_swv)
{
	swv64b_xtoh(&sbn->s_sw_version, out_swv);
}

static void sbn_set_sw_version(struct silofs_superb_node *sbn,
                               const struct silofs_sw_version *swv)
{
	swv64b_htox(&sbn->s_sw_version, swv);
}

static void sbn_btime(const struct silofs_superb_node *sbn, struct tm *tm)
{
	tm64b_xtoh(&sbn->s_btime, tm);
}

static void sbn_set_btime(struct silofs_superb_node *sbn, const struct tm *tm)
{
	tm64b_htox(&sbn->s_btime, tm);
}

static size_t sbn_fs_capacity(const struct silofs_superb_node *sbn)
{
	return silofs_le64_to_cpu(sbn->s_fs_capacity);
}

static void sbn_set_fs_capacity(struct silofs_superb_node *sbn, size_t nbytes)
{
	sbn->s_fs_capacity = silofs_cpu_to_le64(nbytes);
}

static size_t sbn_fs_usage(const struct silofs_superb_node *sbn)
{
	return silofs_le64_to_cpu(sbn->s_fs_usage);
}

static void sbn_set_fs_usage(struct silofs_superb_node *sbn, size_t nbytes)
{
	sbn->s_fs_usage = silofs_cpu_to_le64(nbytes);
}

static uint64_t sbn_ino_generation(const struct silofs_superb_node *sbn)
{
	return silofs_le64_to_cpu(sbn->s_ino_generation);
}

static void
sbn_set_ino_generation(struct silofs_superb_node *sbn, uint64_t gen)
{
	sbn->s_ino_generation = silofs_cpu_to_le64(gen);
}

static size_t
sbn_nodes_count_at(const struct silofs_superb_node *sbn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(sbn->s_nodes_count));

	return silofs_le64_to_cpu(sbn->s_nodes_count[slot]);
}

static void sbn_set_nodes_count_at(struct silofs_superb_node *sbn, size_t slot,
                                   size_t count)
{
	silofs_assert_lt(slot, ARRAY_SIZE(sbn->s_nodes_count));

	sbn->s_nodes_count[slot] = silofs_cpu_to_le64(count);
}

static void sbn_reset_nodes_count(struct silofs_superb_node *sbn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(sbn->s_nodes_count); ++slot) {
		sbn_set_nodes_count_at(sbn, slot, 0);
	}
}

static void
sbn_inc_nodes_count(struct silofs_superb_node *sbn, enum silofs_vtype vtype)
{
	const size_t slot  = sbn_slot_of(sbn, vtype);
	const size_t count = sbn_nodes_count_at(sbn, slot);

	silofs_assert_lt(count, UINT64_MAX);
	sbn_set_nodes_count_at(sbn, slot, count + 1);
}

static void
sbn_dec_nodes_count(struct silofs_superb_node *sbn, enum silofs_vtype vtype)
{
	const size_t slot  = sbn_slot_of(sbn, vtype);
	const size_t count = sbn_nodes_count_at(sbn, slot);

	silofs_assert_gt(count, 0);
	sbn_set_nodes_count_at(sbn, slot, count - 1);
}

static off_t
sbn_apex_voff_at(const struct silofs_superb_node *sbn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(sbn->s_apex_voff));

	return silofs_off_to_cpu(sbn->s_apex_voff[slot]);
}

static void
sbn_set_apex_voff_at(struct silofs_superb_node *sbn, size_t slot, off_t voff)
{
	silofs_assert_lt(slot, ARRAY_SIZE(sbn->s_apex_voff));

	sbn->s_apex_voff[slot] = silofs_cpu_to_off(voff);
}

static void sbn_reset_apex_voff(struct silofs_superb_node *sbn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(sbn->s_apex_voff); ++slot) {
		sbn_set_apex_voff_at(sbn, slot, 0);
	}
}

static off_t
sbn_apex_voff(const struct silofs_superb_node *sbn, enum silofs_vtype vtype)
{
	const size_t slot = sbn_slot_of(sbn, vtype);

	return sbn_apex_voff_at(sbn, slot);
}

static void sbn_set_apex_voff(struct silofs_superb_node *sbn,
                              enum silofs_vtype vtype, off_t voff)
{
	const size_t slot = sbn_slot_of(sbn, vtype);

	sbn_set_apex_voff_at(sbn, slot, voff);
}

static void sbn_init(struct silofs_superb_node *sbn)
{
	sbn_set_magic(sbn, SILOFS_SUPER_MAGIC);
	sbn_set_version(sbn, SILOFS_FMT_VERSION);
	sbn_set_flags(sbn, SILOFS_SUPERF_NONE);
	sbn_set_sw_version(sbn, &silofs_sw_vers);
	sbn_set_fs_capacity(sbn, SILOFS_CAPACITY_SIZE_MIN);
	sbn_set_fs_usage(sbn, 0);
	sbn_set_ino_generation(sbn, 1);
	sbn_reset_nodes_count(sbn);
	sbn_reset_apex_voff(sbn);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_super_magic(const struct silofs_superb_node *sbn)
{
	const uint64_t magic = sbn_magic(sbn);

	if (magic != SILOFS_SUPER_MAGIC) {
		log_err("bad super: magic=%" PRIx64, magic);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_version(const struct silofs_superb_node *sbn)
{
	const uint64_t vers = sbn_version(sbn);

	if (vers != SILOFS_FMT_VERSION) {
		log_err("bad super: version=%" PRIx64, vers);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_flags(const struct silofs_superb_node *sbn)
{
	const enum silofs_superf flags = sbn_flags(sbn);

	if (flags != SILOFS_SUPERF_NONE) {
		log_err("bad super: flags=%d", flags);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_sw_version(const struct silofs_superb_node *sbn)
{
	struct silofs_sw_version swv;

	sbn_sw_version(sbn, &swv);
	if (swv.revision[0] == 0) {
		log_err("bad super: major=%u minor=%u sublevel=%u", swv.major,
		        swv.minor, swv.sublevel);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_btime(const struct silofs_superb_node *sbn)
{
	struct tm tm = {};

	sbn_btime(sbn, &tm);
	if (tm.tm_year <= 0) {
		log_err("bad super: tm_year=%d", tm.tm_year);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_fs_capacity(const struct silofs_superb_node *sbn)
{
	const size_t fs_capacity = sbn_fs_capacity(sbn);
	const size_t fs_usage    = sbn_fs_usage(sbn);

	if ((fs_capacity < SILOFS_CAPACITY_SIZE_MIN) ||
	    (fs_capacity > SILOFS_CAPACITY_SIZE_MAX)) {
		log_err("bad super: fs_capacity=%zu", fs_capacity);
		return -SILOFS_EFSCORRUPTED;
	}
	if (fs_usage > fs_capacity) {
		log_err("bad super: fs_capacity=%zu fs_usage=%zu", fs_capacity,
		        fs_usage);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_superb_node(const struct silofs_superb_node *sbn)
{
	int err;

	err = verify_super_magic(sbn);
	return_if_err(err);

	err = verify_super_version(sbn);
	return_if_err(err);

	err = verify_super_flags(sbn);
	return_if_err(err);

	err = verify_super_sw_version(sbn);
	return_if_err(err);

	err = verify_super_btime(sbn);
	return_if_err(err);

	err = verify_super_fs_capacity(sbn);
	return_if_err(err);

	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t vsize_of(enum silofs_vtype vtype)
{
	return silofs_vtype_size(vtype);
}

static void sbi_setdirty(struct silofs_sbnode_info2 *sbi)
{
	silofs_vni_setdirty(&sbi->sbn_vni, nullptr);
}

void silofs_sbi2_setdirty(struct silofs_sbnode_info2 *sbi)
{
	sbi_setdirty(sbi);
}

static void sbi2_setup_btime_now(struct silofs_sbnode_info2 *sbi)
{
	struct tm now;

	silofs_localtime_now(&now);
	sbn_set_btime(sbi->sbn, &now);
}

static void
sbi2_set_capacity(struct silofs_sbnode_info2 *sbi, size_t fs_capacity)
{
	silofs_assert_ge(fs_capacity, SILOFS_CAPACITY_SIZE_MIN);
	silofs_assert_le(fs_capacity, SILOFS_CAPACITY_SIZE_MAX);

	sbn_set_fs_capacity(sbi->sbn, fs_capacity);
}

void silofs_sbi2_setup_spawned(struct silofs_sbnode_info2 *sbi,
                               size_t fs_capacity)
{
	sbn_init(sbi->sbn);
	sbi2_set_capacity(sbi, fs_capacity);
	sbi2_setup_btime_now(sbi);
	sbi_setdirty(sbi);
}

int silofs_sbi2_check_avail(const struct silofs_sbnode_info2 *sbi,
                            enum silofs_vtype vtype)
{
	constexpr size_t safezone = SILOFS_MEGA;
	const size_t capacity     = sbn_fs_capacity(sbi->sbn);
	const size_t usage        = sbn_fs_usage(sbi->sbn);
	const size_t nwant        = vsize_of(vtype);

	return ((usage + nwant + safezone) < capacity) ? 0 : -SILOFS_ENOSPC;
}

void silofs_sbi2_take_node(struct silofs_sbnode_info2 *sbi,
                           enum silofs_vtype vtype)
{
	const size_t capacity = sbn_fs_capacity(sbi->sbn);
	const size_t usage    = sbn_fs_usage(sbi->sbn);
	const size_t ntake    = vsize_of(vtype);

	silofs_assert_lt(usage + ntake, capacity);

	sbn_inc_nodes_count(sbi->sbn, vtype);
	sbn_set_fs_usage(sbi->sbn, usage + ntake);
	sbi_setdirty(sbi);
}

void silofs_sbi2_give_node(struct silofs_sbnode_info2 *sbi,
                           enum silofs_vtype vtype)
{
	const size_t usage = sbn_fs_usage(sbi->sbn);
	const size_t ngive = vsize_of(vtype);

	silofs_assert_ge(usage, ngive);

	sbn_dec_nodes_count(sbi->sbn, vtype);
	sbn_set_fs_usage(sbi->sbn, usage - ngive);
	sbi_setdirty(sbi);
}

void silofs_sbi2_apex_of(const struct silofs_sbnode_info2 *sbi,
                         enum silofs_vtype vtype,
                         struct silofs_vaddr *out_vaddr)
{
	const off_t off = sbn_apex_voff(sbi->sbn, vtype);

	silofs_vaddr_setup(out_vaddr, vtype, off);
}

void silofs_sbi2_update_apex(struct silofs_sbnode_info2 *sbi,
                             const struct silofs_vaddr *vaddr)
{
	const off_t off = sbn_apex_voff(sbi->sbn, vaddr->vtype);

	if (vaddr->off > off) {
		sbn_set_apex_voff(sbi->sbn, vaddr->vtype, vaddr->off);
		sbi_setdirty(sbi);
	}
}

uint64_t silofs_sbi2_next_igen(struct silofs_sbnode_info2 *sbi)
{
	const uint64_t igen = sbn_ino_generation(sbi->sbn);

	sbn_set_ino_generation(sbi->sbn, igen + 1);
	sbi_setdirty(sbi);

	return igen;
}
