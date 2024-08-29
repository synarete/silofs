/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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


static bool ltype_isequal(enum silofs_ltype st1, enum silofs_ltype st2)
{
	return (st1 == st2);
}

bool silofs_ltype_isnone(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_NONE);
}

bool silofs_ltype_isbootrec(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_BOOTREC);
}

bool silofs_ltype_issuper(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_SUPER);
}

bool silofs_ltype_isspnode(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_SPNODE);
}

bool silofs_ltype_isspleaf(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_SPLEAF);
}

bool silofs_ltype_isinode(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_INODE);
}

bool silofs_ltype_isxanode(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_XANODE);
}

bool silofs_ltype_issymval(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_SYMVAL);
}

bool silofs_ltype_isdtnode(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_DTNODE);
}

bool silofs_ltype_isftnode(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_FTNODE);
}

bool silofs_ltype_isdata1k(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_DATA1K);
}

bool silofs_ltype_isdata4k(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_DATA4K);
}

bool silofs_ltype_isdatabk(enum silofs_ltype ltype)
{
	return ltype_isequal(ltype, SILOFS_LTYPE_DATABK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_ltype_isunode(enum silofs_ltype ltype)
{
	bool ret;

	switch (ltype) {
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_LTYPE_INODE:
	case SILOFS_LTYPE_XANODE:
	case SILOFS_LTYPE_SYMVAL:
	case SILOFS_LTYPE_DTNODE:
	case SILOFS_LTYPE_FTNODE:
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_ltype_isvnode(enum silofs_ltype ltype)
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
	case SILOFS_LTYPE_DATABK:
		ret = true;
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_ltype_isdata(enum silofs_ltype ltype)
{
	bool ret;

	switch (ltype) {
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
		ret = true;
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
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

uint32_t silofs_ltype_size(enum silofs_ltype ltype)
{
	switch (ltype) {
	case SILOFS_LTYPE_BOOTREC:
		return sizeof(struct silofs_bootrec1k);
	case SILOFS_LTYPE_SUPER:
		return sizeof(struct silofs_super_block);
	case SILOFS_LTYPE_SPNODE:
		return sizeof(struct silofs_spmap_node);
	case SILOFS_LTYPE_SPLEAF:
		return sizeof(struct silofs_spmap_leaf);
	case SILOFS_LTYPE_INODE:
		return sizeof(struct silofs_inode);
	case SILOFS_LTYPE_XANODE:
		return sizeof(struct silofs_xattr_node);
	case SILOFS_LTYPE_DTNODE:
		return sizeof(struct silofs_dtree_node);
	case SILOFS_LTYPE_FTNODE:
		return sizeof(struct silofs_ftree_node);
	case SILOFS_LTYPE_SYMVAL:
		return sizeof(struct silofs_symlnk_value);
	case SILOFS_LTYPE_DATA1K:
		return sizeof(struct silofs_data_block1);
	case SILOFS_LTYPE_DATA4K:
		return sizeof(struct silofs_data_block4);
	case SILOFS_LTYPE_DATABK:
		return sizeof(struct silofs_data_block64);
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		break;
	}
	return 0;
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
