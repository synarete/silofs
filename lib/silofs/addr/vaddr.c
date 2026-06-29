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
#include <silofs/base.h>
#include <silofs/addr.h>

static uint64_t cpu_to_off_vtype(off_t off, enum silofs_vtype vtype)
{
	const uint64_t mask   = 0xFF;
	const uint64_t uoff   = (uint64_t)off;
	const uint64_t uvtype = (uint64_t)vtype;
	uint64_t off_vtype;

	if (!silofs_vtype_isnone(vtype)) {
		silofs_assert_eq(uoff & mask, 0);

		off_vtype = ((uoff & ~mask) | (uvtype & mask));
		off_vtype = silofs_cpu_to_le64(off_vtype);
	} else {
		off_vtype = 0;
	}
	return off_vtype;
}

static void voff_vtype_to_cpu(uint64_t off_vtype, off_t *out_off,
                              enum silofs_vtype *out_vtype)
{
	const uint64_t mask   = 0xFF;
	const uint64_t uoff   = off_vtype & ~mask;
	const uint64_t uvtype = off_vtype & mask;

	if (off_vtype > 0) {
		*out_off   = (off_t)uoff;
		*out_vtype = (enum silofs_vtype)uvtype;
	} else {
		*out_off   = SILOFS_OFF_NULL;
		*out_vtype = SILOFS_VTYPE_NONE;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr s_silofs_vaddr_none = {
	.off   = SILOFS_OFF_NULL,
	.vtype = SILOFS_VTYPE_NONE,
};

const struct silofs_vaddr *silofs_vaddr_none(void)
{
	return &s_silofs_vaddr_none;
}

size_t silofs_vaddr_len(const struct silofs_vaddr *vaddr)
{
	return silofs_vtype_size(vaddr->vtype);
}

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2)
{
	long cmp;

	cmp = vaddr1->vtype - vaddr2->vtype;
	if (cmp) {
		return cmp;
	}
	cmp = vaddr1->off - vaddr2->off;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_vaddr_isequal(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2)
{
	return (silofs_vaddr_compare(vaddr1, vaddr2) == 0);
}

void silofs_vaddr_setup(struct silofs_vaddr *vaddr, enum silofs_vtype vtype,
                        off_t voff)
{
	vaddr->vtype = vtype;
	vaddr->off   = voff;
}

void silofs_vaddr_advance(const struct silofs_vaddr *vaddr, size_t nsteps,
                          struct silofs_vaddr *out_vaddr)
{
	const size_t len = nsteps * silofs_vtype_size(vaddr->vtype);
	const off_t off  = silofs_off_end(vaddr->off, len);

	silofs_vaddr_setup(out_vaddr, vaddr->vtype, off);
}

void silofs_vaddr_assign(struct silofs_vaddr *vaddr,
                         const struct silofs_vaddr *other)
{
	vaddr->vtype = other->vtype;
	vaddr->off   = other->off;
}

void silofs_vaddr_reset(struct silofs_vaddr *vaddr)
{
	vaddr->vtype = SILOFS_VTYPE_NONE;
	vaddr->off   = SILOFS_OFF_NULL;
}

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr)
{
	return silofs_off_isnull(vaddr->off) ||
	       silofs_vtype_isnone(vaddr->vtype);
}

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr)
{
	return silofs_vtype_isdata(vaddr->vtype);
}

bool silofs_vaddr_isdata64k(const struct silofs_vaddr *vaddr)
{
	return vaddr->vtype == SILOFS_VTYPE_DATA64K;
}

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr)
{
	return silofs_vtype_isinode(vaddr->vtype);
}

static silofs_lba_t lba_kbn_to_off(silofs_lba_t lba, size_t kbn)
{
	return silofs_lba_to_off(lba) + (silofs_lba_t)(kbn * SILOFS_KB_SIZE);
}

static silofs_lba_t lba_plus(silofs_lba_t lba, size_t nlbk)
{
	return lba + (silofs_lba_t)nlbk;
}

void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_vtype vtype, off_t voff_base,
                            size_t bn, size_t kbn)
{
	const silofs_lba_t lba_base = silofs_off_to_lba(voff_base);
	const silofs_lba_t lba      = lba_plus(lba_base, bn);
	const off_t off             = lba_kbn_to_off(lba, kbn);

	silofs_vaddr_setup(vaddr, vtype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr56 s_vaddr56_null = {
	.b = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
};

void silofs_vaddr56_htox(struct silofs_vaddr56 *vaddr56, off_t off)
{
	const uint64_t uoff = (uint64_t)off;

	if (!silofs_off_isnull(off)) {
		silofs_assert_eq(uoff & 0xFFL, 0);

		vaddr56->b[0] = (uint8_t)((uoff >> 8) & 0xFF);
		vaddr56->b[1] = (uint8_t)((uoff >> 16) & 0xFF);
		vaddr56->b[2] = (uint8_t)((uoff >> 24) & 0xFF);
		vaddr56->b[3] = (uint8_t)((uoff >> 32) & 0xFF);
		vaddr56->b[4] = (uint8_t)((uoff >> 40) & 0xFF);
		vaddr56->b[5] = (uint8_t)((uoff >> 48) & 0xFF);
		vaddr56->b[6] = (uint8_t)((uoff >> 56) & 0xFF);
	} else {
		memcpy(vaddr56, &s_vaddr56_null, sizeof(*vaddr56));
	}
}

void silofs_vaddr56_xtoh(const struct silofs_vaddr56 *vaddr56, off_t *out_off)
{
	int cmp;
	off_t off = 0;

	cmp = memcmp(vaddr56, &s_vaddr56_null, sizeof(*vaddr56));
	if (cmp) {
		off |= (off_t)(vaddr56->b[0]) << 8;
		off |= (off_t)(vaddr56->b[1]) << 16;
		off |= (off_t)(vaddr56->b[2]) << 24;
		off |= (off_t)(vaddr56->b[3]) << 32;
		off |= (off_t)(vaddr56->b[4]) << 40;
		off |= (off_t)(vaddr56->b[5]) << 48;
		off |= (off_t)(vaddr56->b[6]) << 56;
	} else {
		off = SILOFS_OFF_NULL;
	}
	*out_off = off;
}

void silofs_vaddr64_htox(struct silofs_vaddr64 *vaddr64,
                         const struct silofs_vaddr *vaddr)
{
	vaddr64->off_vtype = cpu_to_off_vtype(vaddr->off, vaddr->vtype);
}

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vaddr64,
                         struct silofs_vaddr *vaddr)
{
	off_t voff;
	enum silofs_vtype vtype;

	voff_vtype_to_cpu(vaddr64->off_vtype, &voff, &vtype);
	silofs_vaddr_setup(vaddr, vtype, voff);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_resolve_spnode2_vaddr(const struct silofs_vaddr *ref_vaddr,
                                  struct silofs_vaddr *out_vaddr)
{
	const uint64_t ref_vtype = (uint64_t)(ref_vaddr->vtype);
	uint64_t ref_vsize, ref_voff, ref_index;
	uint64_t spnode_vsize, spnode_index, spnode_off;
	off_t off;

	ref_voff  = (uint64_t)ref_vaddr->off;
	ref_vsize = silofs_vtype_size(ref_vaddr->vtype);
	ref_index = ref_voff / ref_vsize;

	spnode_index = ref_index / SILOFS_SPNODE_NREFS;
	spnode_vsize = silofs_vtype_size(SILOFS_VTYPE_SPNODE2);
	spnode_off   = spnode_index * spnode_vsize;

	off = (off_t)((ref_vtype << 56) | spnode_off);
	silofs_vaddr_setup(out_vaddr, SILOFS_VTYPE_SPNODE2, off);

	/* TODO: Remove debug assertions after stabilization. */
	silofs_assert_ge(ref_vsize, 1024);
	silofs_assert_gt(ref_vtype, 0);
	silofs_assert_eq((uint64_t)off % spnode_vsize, 0);
}

static off_t ino_to_off(ino_t ino)
{
	if (unlikely(ino == SILOFS_INO_NULL)) {
		return SILOFS_OFF_NULL;
	}
	if (unlikely(ino > SILOFS_INO_MAX)) {
		return SILOFS_OFF_NULL;
	}
	return (off_t)(ino << SILOFS_INODE_SHIFT);
}

static ino_t off_to_ino(off_t off)
{
	ino_t ino;
	off_t off2;

	if (unlikely(off == SILOFS_OFF_NULL)) {
		return SILOFS_INO_NULL;
	}
	if (unlikely(off < 0)) {
		return SILOFS_INO_NULL;
	}
	ino  = (ino_t)(off >> SILOFS_INODE_SHIFT);
	off2 = ino_to_off(ino);
	if (unlikely(off != off2)) {
		return SILOFS_INO_NULL;
	}
	return ino;
}

void silofs_ino_to_vaddr(ino_t ino, struct silofs_vaddr *out_vaddr)
{
	const off_t off = ino_to_off(ino);

	silofs_vaddr_setup(out_vaddr, SILOFS_VTYPE_INODE, off);
}

ino_t silofs_vaddr_to_ino(const struct silofs_vaddr *vaddr)
{
	ino_t ino;

	if (silofs_vaddr_isinode(vaddr)) {
		ino = off_to_ino(vaddr->off);
	} else {
		ino = SILOFS_INO_NULL;
	}
	return ino;
}
