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
#include <silofs/infra.h>
#include <silofs/addr.h>

bool silofs_ltype_isnone(enum silofs_ltype ltype)
{
	const int val = (int)ltype;

	return (val <= SILOFS_LTYPE_NONE) || (val >= SILOFS_LTYPE_LAST);
}

bool silofs_ltype_isinode(enum silofs_ltype ltype)
{
	return ltype == SILOFS_LTYPE_INODE;
}

bool silofs_ltype_isdata(enum silofs_ltype ltype)
{
	bool ret;

	switch (ltype) {
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATA64K:
		ret = true;
		break;
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_INODE:
	case SILOFS_LTYPE_XANODE:
	case SILOFS_LTYPE_DTNODE:
	case SILOFS_LTYPE_FTNODE:
	case SILOFS_LTYPE_SYMVAL:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_ltype_usespmap(enum silofs_ltype ltype)
{
	bool ret;

	switch (ltype) {
	case SILOFS_LTYPE_INODE:
	case SILOFS_LTYPE_XANODE:
	case SILOFS_LTYPE_SYMVAL:
	case SILOFS_LTYPE_DTNODE:
	case SILOFS_LTYPE_FTNODE:
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATA64K:
		ret = true;
		break;
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

size_t silofs_ltype_size(enum silofs_ltype ltype)
{
	size_t size;

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		size = sizeof(struct silofs_superb_node);
		break;
	case SILOFS_LTYPE_SPNODE:
		size = sizeof(struct silofs_space_node);
		break;
	case SILOFS_LTYPE_INODE:
		size = sizeof(struct silofs_inode);
		break;
	case SILOFS_LTYPE_XANODE:
		size = sizeof(struct silofs_xattr_node);
		break;
	case SILOFS_LTYPE_DTNODE:
		size = sizeof(struct silofs_dtree_node);
		break;
	case SILOFS_LTYPE_FTNODE:
		size = sizeof(struct silofs_ftree_node);
		break;
	case SILOFS_LTYPE_SYMVAL:
		size = sizeof(struct silofs_symval_node);
		break;
	case SILOFS_LTYPE_DATA1K:
		size = sizeof(struct silofs_data_node1);
		break;
	case SILOFS_LTYPE_DATA4K:
		size = sizeof(struct silofs_data_node4);
		break;
	case SILOFS_LTYPE_DATA64K:
		size = sizeof(struct silofs_data_node64);
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		size = 0;
		break;
	}
	return size;
}

ssize_t silofs_ltype_ssize(enum silofs_ltype ltype)
{
	return (ssize_t)silofs_ltype_size(ltype);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t cpu_to_off_ltype(off_t off, enum silofs_ltype ltype)
{
	const uint64_t mask   = 0xFF;
	const uint64_t uoff   = (uint64_t)off;
	const uint64_t ultype = (uint64_t)ltype;
	uint64_t off_ltype;

	if (!silofs_ltype_isnone(ltype)) {
		silofs_assert_eq(uoff & mask, 0);

		off_ltype = ((uoff & ~mask) | (ultype & mask));
		off_ltype = silofs_cpu_to_le64(off_ltype);
	} else {
		off_ltype = 0;
	}
	return off_ltype;
}

static void voff_ltype_to_cpu(uint64_t off_ltype, off_t *out_off,
                              enum silofs_ltype *out_ltype)
{
	const uint64_t mask   = 0xFF;
	const uint64_t uoff   = off_ltype & ~mask;
	const uint64_t ultype = off_ltype & mask;

	if (off_ltype > 0) {
		*out_off   = (off_t)uoff;
		*out_ltype = (enum silofs_ltype)ultype;
	} else {
		*out_off   = SILOFS_OFF_NULL;
		*out_ltype = SILOFS_LTYPE_NONE;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr s_silofs_laddr_none = {
	.off   = SILOFS_OFF_NULL,
	.ltype = SILOFS_LTYPE_NONE,
};

const struct silofs_laddr *silofs_laddr_none(void)
{
	return &s_silofs_laddr_none;
}

size_t silofs_laddr_len(const struct silofs_laddr *laddr)
{
	return silofs_ltype_size(laddr->ltype);
}

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2)
{
	long cmp;

	cmp = laddr1->ltype - laddr2->ltype;
	if (cmp) {
		return cmp;
	}
	cmp = laddr1->off - laddr2->off;
	if (cmp) {
		return cmp;
	}
	return 0;
}

bool silofs_laddr_isequal(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2)
{
	return (silofs_laddr_compare(laddr1, laddr2) == 0);
}

void silofs_laddr_setup(struct silofs_laddr *laddr, enum silofs_ltype ltype,
                        off_t voff)
{
	laddr->ltype = ltype;
	laddr->off   = voff;
}

void silofs_laddr_advance(const struct silofs_laddr *laddr, size_t nsteps,
                          struct silofs_laddr *out_laddr)
{
	const size_t len = nsteps * silofs_ltype_size(laddr->ltype);
	const off_t off  = silofs_off_end(laddr->off, len);

	silofs_laddr_setup(out_laddr, laddr->ltype, off);
}

void silofs_laddr_assign(struct silofs_laddr *laddr,
                         const struct silofs_laddr *other)
{
	laddr->ltype = other->ltype;
	laddr->off   = other->off;
}

void silofs_laddr_reset(struct silofs_laddr *laddr)
{
	laddr->ltype = SILOFS_LTYPE_NONE;
	laddr->off   = SILOFS_OFF_NULL;
}

bool silofs_laddr_isnull(const struct silofs_laddr *laddr)
{
	return silofs_off_isnull(laddr->off) ||
	       silofs_ltype_isnone(laddr->ltype);
}

bool silofs_laddr_isdata(const struct silofs_laddr *laddr)
{
	return silofs_ltype_isdata(laddr->ltype);
}

bool silofs_laddr_isinode(const struct silofs_laddr *laddr)
{
	return silofs_ltype_isinode(laddr->ltype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr56 s_laddr56_null = {
	.b = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
};

void silofs_laddr56_htox(struct silofs_laddr56 *laddr56, off_t off)
{
	const uint64_t uoff = (uint64_t)off;

	if (!silofs_off_isnull(off)) {
		silofs_assert_eq(uoff & 0xFFL, 0);

		laddr56->b[0] = (uint8_t)((uoff >> 8) & 0xFF);
		laddr56->b[1] = (uint8_t)((uoff >> 16) & 0xFF);
		laddr56->b[2] = (uint8_t)((uoff >> 24) & 0xFF);
		laddr56->b[3] = (uint8_t)((uoff >> 32) & 0xFF);
		laddr56->b[4] = (uint8_t)((uoff >> 40) & 0xFF);
		laddr56->b[5] = (uint8_t)((uoff >> 48) & 0xFF);
		laddr56->b[6] = (uint8_t)((uoff >> 56) & 0xFF);
	} else {
		memcpy(laddr56, &s_laddr56_null, sizeof(*laddr56));
	}
}

void silofs_laddr56_xtoh(const struct silofs_laddr56 *laddr56, off_t *out_off)
{
	int cmp;
	off_t off = 0;

	cmp = memcmp(laddr56, &s_laddr56_null, sizeof(*laddr56));
	if (cmp) {
		off |= (off_t)(laddr56->b[0]) << 8;
		off |= (off_t)(laddr56->b[1]) << 16;
		off |= (off_t)(laddr56->b[2]) << 24;
		off |= (off_t)(laddr56->b[3]) << 32;
		off |= (off_t)(laddr56->b[4]) << 40;
		off |= (off_t)(laddr56->b[5]) << 48;
		off |= (off_t)(laddr56->b[6]) << 56;
	} else {
		off = SILOFS_OFF_NULL;
	}
	*out_off = off;
}

void silofs_laddr64_htox(struct silofs_laddr64 *laddr64,
                         const struct silofs_laddr *laddr)
{
	laddr64->off_ltype = cpu_to_off_ltype(laddr->off, laddr->ltype);
}

void silofs_laddr64_xtoh(const struct silofs_laddr64 *laddr64,
                         struct silofs_laddr *laddr)
{
	off_t voff;
	enum silofs_ltype ltype;

	voff_ltype_to_cpu(laddr64->off_ltype, &voff, &ltype);
	silofs_laddr_setup(laddr, ltype, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

void silofs_ino_to_laddr(ino_t ino, struct silofs_laddr *out_laddr)
{
	const off_t off = ino_to_off(ino);

	silofs_laddr_setup(out_laddr, SILOFS_LTYPE_INODE, off);
}

void silofs_laddr_to_ino(const struct silofs_laddr *laddr, ino_t *out_ino)
{
	if (silofs_laddr_isinode(laddr)) {
		*out_ino = off_to_ino(laddr->off);
	} else {
		*out_ino = SILOFS_INO_NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_resolve_spnode_laddr(const struct silofs_laddr *ref_laddr,
                                 struct silofs_laddr *out_laddr)
{
	const uint64_t ref_ltype = (uint64_t)(ref_laddr->ltype);
	uint64_t ref_vsize, ref_voff, ref_index = 0;
	uint64_t spnode_vsize, spnode_index, spnode_off;
	off_t off;

	ref_voff  = (uint64_t)ref_laddr->off;
	ref_vsize = silofs_ltype_size(ref_laddr->ltype);
	if (likely(ref_vsize > 0)) {
		ref_index = ref_voff / ref_vsize;
	}

	spnode_index = ref_index / SILOFS_SPNODE_NREFS;
	spnode_vsize = silofs_ltype_size(SILOFS_LTYPE_SPNODE);
	spnode_off   = spnode_index * spnode_vsize;

	off = (off_t)((ref_ltype << 56) | spnode_off);
	silofs_laddr_setup(out_laddr, SILOFS_LTYPE_SPNODE, off);

	/* TODO: Remove debug assertions after stabilization. */
	silofs_assert_ge(ref_vsize, 1024);
	silofs_assert_gt(ref_ltype, 0);
	silofs_assert_eq((uint64_t)off % spnode_vsize, 0);
}
