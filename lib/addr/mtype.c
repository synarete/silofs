/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include "infra.h"
#include "mtype.h"

static bool mtype_isequal(enum silofs_mtype st1, enum silofs_mtype st2)
{
	return (st1 == st2);
}

bool silofs_mtype_issuper(enum silofs_mtype mtype)
{
	return mtype_isequal(mtype, SILOFS_MTYPE_SUPER);
}

bool silofs_mtype_isspnode(enum silofs_mtype mtype)
{
	return mtype_isequal(mtype, SILOFS_MTYPE_SPNODE);
}

bool silofs_mtype_isspleaf(enum silofs_mtype mtype)
{
	return mtype_isequal(mtype, SILOFS_MTYPE_SPLEAF);
}

bool silofs_mtype_isinode(enum silofs_mtype mtype)
{
	return mtype_isequal(mtype, SILOFS_MTYPE_INODE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_mtype_isnone(enum silofs_mtype mtype)
{
	bool ret;

	switch (mtype) {
	case SILOFS_MTYPE_BLDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_BOOTREC:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
		ret = false;
		break;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		ret = true;
		break;
	}
	return ret;
}

bool silofs_mtype_isunode(enum silofs_mtype mtype)
{
	bool ret;

	switch (mtype) {
	case SILOFS_MTYPE_BOOTREC:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_MTYPE_BLDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_mtype_isvnode(enum silofs_mtype mtype)
{
	bool ret;

	switch (mtype) {
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
		ret = true;
		break;
	case SILOFS_MTYPE_BLDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_BOOTREC:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_mtype_isdata(enum silofs_mtype mtype)
{
	bool ret;

	switch (mtype) {
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
		ret = true;
		break;
	case SILOFS_MTYPE_BLDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_BOOTREC:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

uint32_t silofs_mtype_size(enum silofs_mtype mtype)
{
	switch (mtype) {
	case SILOFS_MTYPE_BLDESC:
		return sizeof(struct silofs_blob_desc);
	case SILOFS_MTYPE_BTNODE:
		return sizeof(struct silofs_btree_node);
	case SILOFS_MTYPE_BOOTREC:
		return sizeof(struct silofs_bootrec1k);
	case SILOFS_MTYPE_SUPER:
		return sizeof(struct silofs_super_block);
	case SILOFS_MTYPE_SPNODE:
		return sizeof(struct silofs_spmap_node);
	case SILOFS_MTYPE_SPLEAF:
		return sizeof(struct silofs_spmap_leaf);
	case SILOFS_MTYPE_LSMAP:
		return sizeof(struct silofs_lsmap);
	case SILOFS_MTYPE_INODE:
		return sizeof(struct silofs_inode);
	case SILOFS_MTYPE_XANODE:
		return sizeof(struct silofs_xattr_node);
	case SILOFS_MTYPE_DTNODE:
		return sizeof(struct silofs_dtree_node);
	case SILOFS_MTYPE_FTNODE:
		return sizeof(struct silofs_ftree_node);
	case SILOFS_MTYPE_SYMVAL:
		return sizeof(struct silofs_symlnk_value);
	case SILOFS_MTYPE_DATA1K:
		return sizeof(struct silofs_data_block1);
	case SILOFS_MTYPE_DATA4K:
		return sizeof(struct silofs_data_block4);
	case SILOFS_MTYPE_DATABK:
		return sizeof(struct silofs_data_block64);
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		break;
	}
	return 0;
}

ssize_t silofs_mtype_ssize(enum silofs_mtype mtype)
{
	return (ssize_t)silofs_mtype_size(mtype);
}

size_t silofs_mtype_nkbs(enum silofs_mtype mtype)
{
	const size_t size = silofs_mtype_size(mtype);

	return silofs_div_round_up(size, SILOFS_KB_SIZE);
}
