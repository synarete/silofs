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

static off_t calc_base_offset_of(enum silofs_vtype vtype, off_t off)
{
	const ssize_t nrefs = SILOFS_SPNODE_NREFS;
	const ssize_t vsize = silofs_vtype_ssize(vtype);

	return silofs_off_align(off, nrefs * vsize);
}

static bool isdata(const struct silofs_vaddr *vaddr)
{
	return silofs_vaddr_isdata(vaddr);
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

static enum silofs_spacef
spn_flags_at(const struct silofs_space_node *spn, size_t slot)
{
	uint16_t flags;

	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_flags));
	flags = silofs_le16_to_cpu(spn->sp_flags[slot]);
	return (enum silofs_spacef)flags;
}

static bool spn_test_flags_at(const struct silofs_space_node *spn, size_t slot,
                              enum silofs_spacef spacef)
{
	return ((spn_flags_at(spn, slot) & spacef) == spacef);
}

static void spn_set_flags_at(struct silofs_space_node *spn, size_t slot,
                             enum silofs_spacef spacef)
{
	enum silofs_spacef currf = spn_flags_at(spn, slot);
	const uint16_t flags     = (uint16_t)currf | (uint16_t)spacef;

	spn->sp_flags[slot] = silofs_cpu_to_le16(flags);
}

static void spn_clear_flags_at(struct silofs_space_node *spn, size_t slot,
                               enum silofs_spacef spacef)
{
	enum silofs_spacef currf = spn_flags_at(spn, slot);
	const uint16_t flags     = (uint16_t)currf & ~((uint16_t)spacef);

	spn->sp_flags[slot] = silofs_cpu_to_le16(flags);
}

static void spn_reset_flags_at(struct silofs_space_node *spn, size_t slot)
{
	const uint16_t flags = (uint16_t)SILOFS_SPACEF_NONE;

	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_flags));
	spn->sp_flags[slot] = silofs_cpu_to_le16(flags);
}

static void spn_reset_flags(struct silofs_space_node *spn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(spn->sp_flags); ++slot) {
		spn_reset_flags_at(spn, slot);
	}
}

static void spn_clone_flags(struct silofs_space_node *spn,
                            const struct silofs_space_node *spn_other)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(spn->sp_flags); ++slot) {
		spn_set_flags_at(spn, slot, spn_flags_at(spn_other, slot));
	}
}

static uint32_t spn_refcnt_at(const struct silofs_space_node *spn, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_refcnt));

	return silofs_le32_to_cpu(spn->sp_refcnt[slot]);
}

static void
spn_set_refcnt_at(struct silofs_space_node *spn, size_t slot, uint32_t refcnt)
{
	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_refcnt));

	spn->sp_refcnt[slot] = silofs_cpu_to_le32(refcnt);
}

static void spn_inc_refcnt_at(struct silofs_space_node *spn, size_t slot)
{
	const uint32_t refcnt = spn_refcnt_at(spn, slot);

	silofs_assert_lt(refcnt, UINT32_MAX);
	spn_set_refcnt_at(spn, slot, refcnt + 1);
}

static void spn_dec_refcnt_at(struct silofs_space_node *spn, size_t slot)
{
	const uint32_t refcnt = spn_refcnt_at(spn, slot);

	silofs_assert_gt(refcnt, 0);
	spn_set_refcnt_at(spn, slot, refcnt - 1);
}

static void spn_reset_refcnts(struct silofs_space_node *spn)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(spn->sp_refcnt); ++slot) {
		spn_set_refcnt_at(spn, slot, 0);
	}
}

static void spn_clone_refcnts(struct silofs_space_node *spn,
                              const struct silofs_space_node *spn_other)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(spn->sp_refcnt); ++slot) {
		spn_set_refcnt_at(spn, slot, spn_refcnt_at(spn_other, slot));
	}
}

static void
spn_init(struct silofs_space_node *spn, enum silofs_vtype ref_vtype, off_t off)
{
	spn_set_base_off(spn, off);
	spn_set_ref_vtype(spn, ref_vtype);
	spn_reset_flags(spn);
	spn_reset_refcnts(spn);
}

static void spn_clone(struct silofs_space_node *spn,
                      const struct silofs_space_node *spn_other)
{
	spn_set_base_off(spn, spn_base_off(spn_other));
	spn_set_ref_vtype(spn, spn_ref_vtype(spn_other));
	spn_clone_flags(spn, spn_other);
	spn_clone_refcnts(spn, spn_other);
}

static size_t spn_nused_refs(const struct silofs_space_node *spn)
{
	size_t nused = 0;

	for (size_t slot = 0; slot < ARRAY_SIZE(spn->sp_refcnt); ++slot) {
		if (spn_refcnt_at(spn, slot) > 0) {
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

	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_refcnt));

	off = base_off + (off_t)(slot * ref_size);
	return off;
}

static size_t spn_off_to_slot(const struct silofs_space_node *spn, off_t off)
{
	const size_t nslots   = ARRAY_SIZE(spn->sp_refcnt);
	const size_t ref_size = spn_ref_size(spn);
	const off_t base_off  = spn_base_off(spn);
	off_t roff, off_end = silofs_off_end(base_off, nslots * ref_size);
	size_t slot;

	silofs_assert_ge(off, base_off);
	silofs_assert_lt(off, off_end);
	silofs_assert_eq((size_t)off % ref_size, 0);

	roff = (off - base_off);
	slot = (size_t)roff / ref_size;
	silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_refcnt));

	return slot;
}

static size_t spn_find_free(const struct silofs_space_node *spn, size_t hint)
{
	const size_t nslots = ARRAY_SIZE(spn->sp_refcnt);
	size_t slot;

	for (slot = hint; slot < nslots; ++slot) {
		if (spn_refcnt_at(spn, slot) == 0) {
			return slot;
		}
	}
	for (slot = 0; slot < hint; ++slot) {
		if (spn_refcnt_at(spn, slot) == 0) {
			return slot;
		}
	}
	return nslots;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_space_info *silofs_spi_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_space_info, spn_vni);
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

static void spi_markdirty(struct silofs_space_info *spi)
{
	silofs_vni_markdirty(&spi->spn_vni, nullptr);
}

void silofs_spi_setup_spawned(struct silofs_space_info *spi,
                              const struct silofs_vaddr *ref_vaddr)
{
	const off_t base_off =
		calc_base_offset_of(ref_vaddr->vtype, ref_vaddr->off);

	spn_init(spi->spn, ref_vaddr->vtype, base_off);
	spi->spn_nused_ref = 0;
	spi_markdirty(spi);
}

void silofs_spi_setup_staged(struct silofs_space_info *spi)
{
	spi->spn_nused_ref = (unsigned)spn_nused_refs(spi->spn);
}

static bool spi_cap_allocate(const struct silofs_space_info *spi)
{
	return spi->spn_nused_ref < ARRAY_SIZE(spi->spn->sp_refcnt);
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
	if (slot == ARRAY_SIZE(spn->sp_refcnt)) {
		/* should no happen -- contradicts cap-allocate */
		silofs_assert_lt(slot, ARRAY_SIZE(spn->sp_refcnt));
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
	return spn_refcnt_at(spi->spn, slot);
}

static void spi_update_nused_ref(struct silofs_space_info *spi, int c)
{
	if (c > 0) {
		silofs_assert_le(spi->spn_nused_ref + (unsigned)c,
		                 ARRAY_SIZE(spi->spn->sp_refcnt));
		spi->spn_nused_ref += (unsigned)c;
	} else if (c < 0) {
		silofs_assert_ge(spi->spn_nused_ref, -c);
		spi->spn_nused_ref -= (unsigned)abs(c);
	}
}

static bool
spi_test_unwritten_at(const struct silofs_space_info *spi, size_t slot)
{
	return spn_test_flags_at(spi->spn, slot, SILOFS_SPACEF_UNWRITTEN);
}

static void spi_mark_unwritten_at(struct silofs_space_info *spi, size_t slot)
{
	spn_set_flags_at(spi->spn, slot, SILOFS_SPACEF_UNWRITTEN);
}

static void spi_clear_unwritten_at(struct silofs_space_info *spi, size_t slot)
{
	spn_clear_flags_at(spi->spn, slot, SILOFS_SPACEF_UNWRITTEN);
}

void silofs_spi_inc_allocated(struct silofs_space_info *spi,
                              const struct silofs_vaddr *vaddr)
{
	const size_t slot = spi_slot_of(spi, vaddr);
	const bool first  = (spi_refcnt_at(spi, slot) == 0);

	spn_inc_refcnt_at(spi->spn, slot);
	if (!first) {
		goto out;
	}
	spi_update_nused_ref(spi, 1);
	if (!isdata(vaddr)) {
		goto out;
	}
	spi_mark_unwritten_at(spi, slot);
out:
	spi_markdirty(spi);
}

void silofs_spi_dec_allocated(struct silofs_space_info *spi,
                              const struct silofs_vaddr *vaddr)
{
	const size_t slot = spi_slot_of(spi, vaddr);
	const bool last   = (spi_refcnt_at(spi, slot) == 1);

	spn_dec_refcnt_at(spi->spn, slot);
	if (!last) {
		goto out;
	}
	spi_update_nused_ref(spi, -1);
	spn_reset_flags_at(spi->spn, slot);
out:
	spi_markdirty(spi);
}

void silofs_spi_clear_unwritten(struct silofs_space_info *spi,
                                const struct silofs_vaddr *vaddr)
{
	const size_t slot = spi_slot_of(spi, vaddr);

	if (spi_test_unwritten_at(spi, slot)) {
		spi_clear_unwritten_at(spi, slot);
		spi_markdirty(spi);
	}
}

void silofs_spi_vspace_ref(const struct silofs_space_info *spi,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vspace_ref *out_vspref)
{
	const size_t slot = spi_slot_of(spi, vaddr);

	out_vspref->refcnt = spn_refcnt_at(spi->spn, slot);
	out_vspref->flags  = spn_flags_at(spi->spn, slot);
}

void silofs_spi_clone_from(struct silofs_space_info *spi,
                           const struct silofs_space_info *spi_other)
{
	spn_clone(spi->spn, spi_other->spn);
	spi->spn_nused_ref = spi_other->spn_nused_ref;
	spi_markdirty(spi);
}
