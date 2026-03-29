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

size_t silofs_ptype_size(enum silofs_ptype ptype)
{
	size_t sz;

	switch (ptype) {
	case SILOFS_PTYPE_MBR:
		sz = sizeof(struct silofs_mbr1k);
		break;
	case SILOFS_PTYPE_UBER:
		sz = sizeof(struct silofs_uber_node);
		break;
	case SILOFS_PTYPE_BLDESC:
		sz = sizeof(struct silofs_blob_desc);
		break;
	case SILOFS_PTYPE_BTNODE:
		sz = sizeof(struct silofs_btree_node);
		break;
	case SILOFS_PTYPE_VNODE:
		sz = sizeof(struct silofs_data_block1); /* min vnode size */
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		sz = 0;
		break;
	}
	return sz;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool vtype_isequal(enum silofs_vtype st1, enum silofs_vtype st2)
{
	return (st1 == st2);
}

bool silofs_vtype_issuper(enum silofs_vtype vtype)
{
	return vtype_isequal(vtype, SILOFS_VTYPE_SUPER);
}

bool silofs_vtype_isspnode(enum silofs_vtype vtype)
{
	return vtype_isequal(vtype, SILOFS_VTYPE_SPNODE);
}

bool silofs_vtype_isspleaf(enum silofs_vtype vtype)
{
	return vtype_isequal(vtype, SILOFS_VTYPE_SPLEAF);
}

bool silofs_vtype_isinode(enum silofs_vtype vtype)
{
	return vtype_isequal(vtype, SILOFS_VTYPE_INODE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_vtype_isnone(enum silofs_vtype vtype)
{
	return (vtype == SILOFS_VTYPE_NONE);
}

bool silofs_vtype_isunode(enum silofs_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_LSMAP:
	case SILOFS_VTYPE_INODE:
	case SILOFS_VTYPE_XANODE:
	case SILOFS_VTYPE_SYMVAL:
	case SILOFS_VTYPE_DTNODE:
	case SILOFS_VTYPE_FTNODE:
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_vtype_isvnode(enum silofs_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case SILOFS_VTYPE_LSMAP:
	case SILOFS_VTYPE_INODE:
	case SILOFS_VTYPE_XANODE:
	case SILOFS_VTYPE_SYMVAL:
	case SILOFS_VTYPE_DTNODE:
	case SILOFS_VTYPE_FTNODE:
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		ret = true;
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_vtype_isdata(enum silofs_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		ret = true;
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
	case SILOFS_VTYPE_LSMAP:
	case SILOFS_VTYPE_INODE:
	case SILOFS_VTYPE_XANODE:
	case SILOFS_VTYPE_DTNODE:
	case SILOFS_VTYPE_FTNODE:
	case SILOFS_VTYPE_SYMVAL:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

size_t silofs_vtype_size(enum silofs_vtype vtype)
{
	switch (vtype) {
	case SILOFS_VTYPE_ARIX:
		return sizeof(struct silofs_arix_node);
	case SILOFS_VTYPE_SUPER:
		return sizeof(struct silofs_super_block);
	case SILOFS_VTYPE_SPNODE:
		return sizeof(struct silofs_spmap_node);
	case SILOFS_VTYPE_SPLEAF:
		return sizeof(struct silofs_spmap_leaf);
	case SILOFS_VTYPE_LSMAP:
		return sizeof(struct silofs_lsmap);
	case SILOFS_VTYPE_INODE:
		return sizeof(struct silofs_inode);
	case SILOFS_VTYPE_XANODE:
		return sizeof(struct silofs_xattr_node);
	case SILOFS_VTYPE_DTNODE:
		return sizeof(struct silofs_dtree_node);
	case SILOFS_VTYPE_FTNODE:
		return sizeof(struct silofs_ftree_node);
	case SILOFS_VTYPE_SYMVAL:
		return sizeof(struct silofs_symlnk_value);
	case SILOFS_VTYPE_DATA1K:
		return sizeof(struct silofs_data_block1);
	case SILOFS_VTYPE_DATA4K:
		return sizeof(struct silofs_data_block4);
	case SILOFS_VTYPE_DATA64K:
		return sizeof(struct silofs_data_block64);
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		break;
	}
	return 0;
}

ssize_t silofs_vtype_ssize(enum silofs_vtype vtype)
{
	return (ssize_t)silofs_vtype_size(vtype);
}

size_t silofs_vtype_nkbs(enum silofs_vtype vtype)
{
	const size_t size = silofs_vtype_size(vtype);

	return silofs_div_round_up(size, SILOFS_KB_SIZE);
}
