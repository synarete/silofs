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

static uint64_t sun_magic(const struct silofs_super_node *sun)
{
	return silofs_le64_to_cpu(sun->s_magic);
}

static void sun_set_magic(struct silofs_super_node *sun, uint64_t magic)
{
	sun->s_magic = silofs_cpu_to_le64(magic);
}

static uint64_t sun_version(const struct silofs_super_node *sun)
{
	return silofs_le64_to_cpu(sun->s_version);
}

static void sun_set_version(struct silofs_super_node *sun, uint64_t vers)
{
	sun->s_version = silofs_cpu_to_le64(vers);
}

static inline enum silofs_superf sun_flags(const struct silofs_super_node *sun)
{
	const uint32_t flags = silofs_le32_to_cpu(sun->s_flags);

	return (enum silofs_superf)flags;
}

static void
sun_set_flags(struct silofs_super_node *sun, enum silofs_superf flags)
{
	sun->s_flags = silofs_cpu_to_le32((uint32_t)flags);
}

static inline void sun_sw_version(const struct silofs_super_node *sun,
                                  struct silofs_sw_version *out_swv)
{
	swv64b_xtoh(&sun->s_sw_version, out_swv);
}

static void sun_set_sw_version(struct silofs_super_node *sun,
                               const struct silofs_sw_version *swv)
{
	swv64b_htox(&sun->s_sw_version, swv);
}

static inline void
sun_btime(const struct silofs_super_node *sun, struct tm *tm)
{
	tm64b_xtoh(&sun->s_btime, tm);
}

static inline void
sun_set_btime(struct silofs_super_node *sun, const struct tm *tm)
{
	tm64b_htox(&sun->s_btime, tm);
}

static size_t sun_fs_capacity(const struct silofs_super_node *sun)
{
	return silofs_le64_to_cpu(sun->s_fs_capacity);
}

static void sun_set_fs_capacity(struct silofs_super_node *sun, size_t nbytes)
{
	sun->s_fs_capacity = silofs_cpu_to_le64(nbytes);
}

static size_t
sun_nodes_count_at(const struct silofs_super_node *sun, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(sun->s_nodes_count));

	return silofs_le64_to_cpu(sun->s_nodes_count[slot]);
}

static void sun_set_nodes_count_at(struct silofs_super_node *sun, size_t slot,
                                   size_t count)
{
	silofs_assert_lt(slot, ARRAY_SIZE(sun->s_nodes_count));

	sun->s_nodes_count[slot] = silofs_cpu_to_le64(count);
}

static void sun_reset_nodes_count(struct silofs_super_node *sun)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(sun->s_nodes_count); ++slot) {
		sun_set_nodes_count_at(sun, slot, 0);
	}
}

static size_t
sun_slot_of(const struct silofs_super_node *sun, enum silofs_vtype vtype)
{
	const size_t slot = (size_t)vtype;

	STATICASSERT_LT(SILOFS_VTYPE_LAST, ARRAY_SIZE(sun->s_nodes_count));
	silofs_assert_lt(slot, ARRAY_SIZE(sun->s_nodes_count));

	return slot;
}

static inline void
sun_inc_nodes_count(struct silofs_super_node *sun, enum silofs_vtype vtype)
{
	const size_t slot  = sun_slot_of(sun, vtype);
	const size_t count = sun_nodes_count_at(sun, slot);

	silofs_assert_lt(count, UINT64_MAX);
	sun_set_nodes_count_at(sun, slot, count + 1);
}

static inline void
sun_dec_nodes_count(struct silofs_super_node *sun, enum silofs_vtype vtype)
{
	const size_t slot  = sun_slot_of(sun, vtype);
	const size_t count = sun_nodes_count_at(sun, slot);

	silofs_assert_gt(count, 0);
	sun_set_nodes_count_at(sun, slot, count - 1);
}

static inline void sun_init(struct silofs_super_node *sun)
{
	sun_set_magic(sun, SILOFS_SUPER_MAGIC);
	sun_set_version(sun, SILOFS_FMT_VERSION);
	sun_set_flags(sun, SILOFS_SUPERF_NONE);
	sun_set_sw_version(sun, &silofs_sw_vers);
	sun_set_fs_capacity(sun, SILOFS_CAPACITY_SIZE_MIN);
	sun_reset_nodes_count(sun);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_super_magic(const struct silofs_super_node *sun)
{
	const uint64_t magic = sun_magic(sun);

	if (magic != SILOFS_SUPER_MAGIC) {
		log_err("bad super: magic=%" PRIx64, magic);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_version(const struct silofs_super_node *sun)
{
	const uint64_t vers = sun_version(sun);

	if (vers != SILOFS_FMT_VERSION) {
		log_err("bad super: version=%" PRIx64, vers);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_super_fs_capacity(const struct silofs_super_node *sun)
{
	const size_t fs_capacity = sun_fs_capacity(sun);

	if ((fs_capacity < SILOFS_CAPACITY_SIZE_MIN) ||
	    (fs_capacity > SILOFS_CAPACITY_SIZE_MAX)) {
		log_err("bad super: fs_capacity=%zu", fs_capacity);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_super_node(const struct silofs_super_node *sun)
{
	int err;

	err = verify_super_magic(sun);
	return_if_err(err);

	err = verify_super_version(sun);
	return_if_err(err);

	err = verify_super_fs_capacity(sun);
	return_if_err(err);

	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
