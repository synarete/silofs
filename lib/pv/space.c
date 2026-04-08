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
#include <limits.h>

#include <silofs/base.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>

static bool isdata(const struct silofs_vaddr *vaddr)
{
	return silofs_vaddr_isdata(vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t spr_refcnt(const struct silofs_space_ref *spr)
{
	return silofs_le64_to_cpu(spr->spr_refcnt);
}

static void spr_set_refcnt(struct silofs_space_ref *spr, uint64_t n)
{
	spr->spr_refcnt = silofs_cpu_to_le64(n);
}

static void spr_inc_refcnt(struct silofs_space_ref *spr)
{
	const uint64_t refcnt = spr_refcnt(spr);

	silofs_assert_lt(refcnt, UINT64_MAX / 2);

	spr_set_refcnt(spr, refcnt + 1);
}

static void spr_dec_refcnt(struct silofs_space_ref *spr)
{
	const uint64_t refcnt = spr_refcnt(spr);

	silofs_assert_lt(refcnt, UINT64_MAX / 2);
	silofs_assert_gt(refcnt, 0);

	spr_set_refcnt(spr, refcnt - 1);
}

static enum silofs_spacef spr_flags(const struct silofs_space_ref *spr)
{
	const uint32_t flags = silofs_le32_to_cpu(spr->spr_flags);

	return (enum silofs_spacef)flags;
}

static void spr_set_flags(struct silofs_space_ref *spr, enum silofs_spacef sf)
{
	spr->spr_flags = silofs_cpu_to_le32((uint32_t)sf);
}

static void spr_add_flags(struct silofs_space_ref *spr, enum silofs_spacef sf)
{
	uint32_t flags = spr_flags(spr);

	flags |= (uint32_t)sf;
	spr_set_flags(spr, (enum silofs_spacef)flags);
}

static void
spr_clear_flags(struct silofs_space_ref *spr, enum silofs_spacef sf)
{
	uint32_t flags = spr_flags(spr);

	flags &= ~((uint32_t)sf);
	spr_set_flags(spr, (enum silofs_spacef)flags);
}

static void spr_reset_flags(struct silofs_space_ref *spr)
{
	spr_set_flags(spr, SILOFS_SPACEF_NONE);
}

static void spr_init(struct silofs_space_ref *spr)
{
	spr_set_refcnt(spr, 0);
	spr_reset_flags(spr);
	memset(spr->spr_reserved, 0, sizeof(spr->spr_reserved));
}

static void spr_init_arr(struct silofs_space_ref *spr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		spr_init(&spr[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static off_t spn_base_off(const struct silofs_space_node *spn)
{
	return silofs_off_to_cpu(spn->sp_base_off);
}

static void spn_set_base_off(struct silofs_space_node *spn, off_t off)
{
	spn->sp_base_off = silofs_cpu_to_off(off);
}

static enum silofs_vtype spn_ref_vtype(const struct silofs_space_node *spn)
{
	return (enum silofs_vtype)(spn->sp_ref_vtype);
}

static void
spn_set_ref_vtype(struct silofs_space_node *spn, enum silofs_vtype ref_vtype)
{
	spn->sp_ref_vtype = (uint8_t)ref_vtype;
}

static void
spn_init(struct silofs_space_node *spn, enum silofs_vtype ref_vtype, off_t off)
{
	spn_set_base_off(spn, off);
	spn_set_ref_vtype(spn, ref_vtype);
	spr_init_arr(spn->sp_ref, ARRAY_SIZE(spn->sp_ref));
}

static const struct silofs_space_ref *
spn_ref_at(const struct silofs_space_node *spn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_ref));

	return &spn->sp_ref[slot];
}

static struct silofs_space_ref *
spn_mut_ref_at(struct silofs_space_node *spn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_ref));

	return &spn->sp_ref[slot];
}

static size_t spn_nused_refs(const struct silofs_space_node *spn)
{
	const struct silofs_space_ref *spr;
	size_t nused = 0;

	for (size_t slot = 0; slot < ARRAY_SIZE(spn->sp_ref); ++slot) {
		spr = spn_ref_at(spn, slot);
		if (spr_refcnt(spr) > 0) {
			nused += 1;
		}
	}
	return nused;
}

static size_t spn_ref_size(const struct silofs_space_node *spn)
{
	const enum silofs_vtype ref_vtype = spn_ref_vtype(spn);
	size_t ref_size;

	ref_size = silofs_vtype_size(ref_vtype);
	silofs_assert_gt(ref_size, 0);
	return ref_size;
}

static off_t spn_slot_to_off(const struct silofs_space_node *spn, size_t slot)
{
	const size_t ref_size = spn_ref_size(spn);
	const off_t base_off  = spn_base_off(spn);
	off_t off;

	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_ref));

	off = base_off + (off_t)((slot + 1) * ref_size);
	return off;
}

static size_t spn_off_to_slot(const struct silofs_space_node *spn, off_t off)
{
	const size_t nslots   = ARRAY_SIZE(spn->sp_ref);
	const size_t ref_size = spn_ref_size(spn);
	const off_t base_off  = spn_base_off(spn);
	off_t roff, off_end;
	size_t slot;

	off_end = silofs_off_end(base_off, (nslots + 1) * ref_size);

	silofs_assert_gt(off, base_off);
	silofs_assert_lt(off, off_end);
	silofs_assert_eq((size_t)off % ref_size, 0);

	roff = (off - base_off);
	slot = (size_t)roff / ref_size;
	silofs_assert_gt(slot, 0);
	silofs_assert_le(slot, ARRAY_SIZE(spn->sp_ref));

	return slot - 1;
}

static size_t spn_find_free(const struct silofs_space_node *spn, size_t hint)
{
	const struct silofs_space_ref *spr;
	const size_t nslots = ARRAY_SIZE(spn->sp_ref);
	size_t slot;

	for (slot = hint; slot < nslots; ++slot) {
		spr = spn_ref_at(spn, slot);
		if (spr_refcnt(spr) == 0) {
			return slot;
		}
	}
	for (slot = 0; slot < hint; ++slot) {
		spr = spn_ref_at(spn, slot);
		if (spr_refcnt(spr) == 0) {
			return slot;
		}
	}
	return nslots;
}

static size_t spn_get_refcnt(struct silofs_space_node *spn, size_t slot)
{
	const struct silofs_space_ref *spr = spn_ref_at(spn, slot);

	return spr_refcnt(spr);
}

static void spn_inc_refcnt(struct silofs_space_node *spn, size_t slot)
{
	struct silofs_space_ref *spr = spn_mut_ref_at(spn, slot);

	spr_inc_refcnt(spr);
}

static void spn_dec_refcnt(struct silofs_space_node *spn, size_t slot)
{
	struct silofs_space_ref *spr = spn_mut_ref_at(spn, slot);

	spr_dec_refcnt(spr);
}

static enum silofs_spacef
spn_flags(const struct silofs_space_node *spn, size_t slot)
{
	const struct silofs_space_ref *spr = spn_ref_at(spn, slot);

	return spr_flags(spr);
}

static bool spn_test_flags(const struct silofs_space_node *spn, size_t slot,
                           enum silofs_spacef sf)
{
	return ((spn_flags(spn, slot) & sf) == sf);
}

static void spn_add_flags(struct silofs_space_node *spn, size_t slot,
                          enum silofs_spacef sf)
{
	struct silofs_space_ref *spr = spn_mut_ref_at(spn, slot);

	spr_add_flags(spr, sf);
}

static void spn_clear_flags(struct silofs_space_node *spn, size_t slot,
                            enum silofs_spacef sf)
{
	struct silofs_space_ref *spr = spn_mut_ref_at(spn, slot);

	spr_clear_flags(spr, sf);
}

static void spn_reset_flags(struct silofs_space_node *spn, size_t slot)
{
	struct silofs_space_ref *spr = spn_mut_ref_at(spn, slot);

	spr_reset_flags(spr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_space_info *silofs_spi_from_vni(struct silofs_space_info *spi)
{
	return container_of(spi, struct silofs_space_info, spn_vni);
}

void silofs_spi_incref(struct silofs_space_info *spi)
{
	if (likely(spi != nullptr)) {
		silofs_vni_incref(&spi->spn_vni);
	}
}

void silofs_spi_decref(struct silofs_space_info *spi)
{
	if (likely(spi != nullptr)) {
		silofs_vni_decref(&spi->spn_vni);
	}
}

static void spi_dirtify(struct silofs_space_info *spi)
{
	silofs_vni_dirtify(&spi->spn_vni, nullptr);
}

void silofs_spi_setup_spawned(struct silofs_space_info *spi,
                              enum silofs_vtype ref_vtype, off_t off)
{
	spn_init(spi->spn, ref_vtype, off);
	spi->spn_nused_ref = 0;
	spi_dirtify(spi);
}

void silofs_spi_setup_staged(struct silofs_space_info *spi)
{
	spi->spn_nused_ref = (unsigned)spn_nused_refs(spi->spn);
}

static bool spi_cap_allocate(const struct silofs_space_info *spi)
{
	return spi->spn_nused_ref < ARRAY_SIZE(spi->spn->sp_ref);
}

static void spi_vaddr_at(const struct silofs_space_info *spi, size_t slot,
                         struct silofs_vaddr *out_vaddr)
{
	const off_t off = spn_slot_to_off(spi->spn, slot);

	silofs_vaddr_setup(out_vaddr, spn_ref_vtype(spi->spn), off);
}

int silofs_spi_find_free(const struct silofs_space_info *spi,
                         struct silofs_vaddr *out_vaddr)
{
	const struct silofs_space_node *spn = spi->spn;
	size_t slot;

	if (!spi_cap_allocate(spi)) {
		return -SILOFS_ENOSPC;
	}
	slot = spn_find_free(spn, spi->spn_nused_ref);
	if (slot == ARRAY_SIZE(spn->sp_ref)) {
		/* should no happen -- contradicts cap-allocate */
		silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_ref));
		return -SILOFS_ENOSPC;
	}
	spi_vaddr_at(spi, slot, out_vaddr);
	return 0;
}

static size_t spi_slot_of(const struct silofs_space_info *spi,
                          const struct silofs_vaddr *vaddr)
{
	const enum silofs_vtype ref_vtype = spn_ref_vtype(spi->spn);

	silofs_assert_eq(ref_vtype, vaddr->vtype);

	return spn_off_to_slot(spi->spn, vaddr->off);
}

static size_t spi_refcnt_at(const struct silofs_space_info *spi, size_t slot)
{
	return spn_get_refcnt(spi->spn, slot);
}

static void spi_update_nused_ref(struct silofs_space_info *spi, int c)
{
	if (c > 0) {
		silofs_assert_le(spi->spn_nused_ref + (unsigned)c,
		                 ARRAY_SIZE(spi->spn->sp_ref));
		spi->spn_nused_ref += (unsigned)c;
	} else if (c < 0) {
		silofs_assert_ge(spi->spn_nused_ref, -c);
		spi->spn_nused_ref -= (unsigned)abs(c);
	}
}

void silofs_spi_inc_allocated(struct silofs_space_info *spi,
                              const struct silofs_vaddr *vaddr)
{
	const size_t slot = spi_slot_of(spi, vaddr);
	const bool first  = (spi_refcnt_at(spi, slot) == 0);

	spn_inc_refcnt(spi->spn, slot);
	if (!first) {
		goto out;
	}
	spi_update_nused_ref(spi, 1);
	if (!isdata(vaddr)) {
		goto out;
	}
	spn_add_flags(spi->spn, slot, SILOFS_SPACEF_UNWRITTEN);
out:
	spi_dirtify(spi);
}

void silofs_spi_dec_allocated(struct silofs_space_info *spi,
                              const struct silofs_vaddr *vaddr)
{
	const size_t slot = spi_slot_of(spi, vaddr);
	const bool last   = (spi_refcnt_at(spi, slot) == 1);

	spn_dec_refcnt(spi->spn, slot);
	if (!last) {
		goto out;
	}
	spi_update_nused_ref(spi, -1);
	spn_reset_flags(spi->spn, slot);
out:
	spi_dirtify(spi);
}

bool silofs_spi_test_unwritten(const struct silofs_space_info *spi,
                               const struct silofs_vaddr *vaddr)
{
	const size_t slot = spi_slot_of(spi, vaddr);

	return spn_test_flags(spi->spn, slot, SILOFS_SPACEF_UNWRITTEN);
}

void silofs_spi_clear_unwritten(struct silofs_space_info *spi,
                                const struct silofs_vaddr *vaddr)
{
	const size_t slot     = spi_slot_of(spi, vaddr);
	enum silofs_spacef sf = SILOFS_SPACEF_UNWRITTEN;

	if (spn_test_flags(spi->spn, slot, sf)) {
		spn_clear_flags(spi->spn, slot, sf);
		spi_dirtify(spi);
	}
}
