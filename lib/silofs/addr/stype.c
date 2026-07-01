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
		sz = sizeof(struct silofs_data_node1); /* min lnode size */
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

static bool ltype_isequal(enum silofs_ltype st1, enum silofs_ltype st2)
{
	return (st1 == st2);
}

bool silofs_ltype_isinode(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_INODE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_ltype_isnone(enum silofs_ltype ltype)
{
	const int val = ltype;

	return (val <= SILOFS_LTYPE_NONE) || (val >= SILOFS_LTYPE_LAST);
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

size_t silofs_ltype_nkbs(enum silofs_ltype ltype)
{
	const size_t size = silofs_ltype_size(ltype);

	return silofs_div_round_up(size, SILOFS_KB_SIZE);
}
