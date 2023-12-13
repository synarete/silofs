/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

static bool stype_isequal(enum silofs_stype st1, enum silofs_stype st2)
{
	return (st1 == st2);
}

bool silofs_stype_isnone(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_NONE);
}

bool silofs_stype_issuper(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_SUPER);
}

bool silofs_stype_isspnode(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_SPNODE);
}

bool silofs_stype_isspleaf(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_SPLEAF);
}

bool silofs_stype_isinode(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_INODE);
}

bool silofs_stype_isxanode(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_XANODE);
}

bool silofs_stype_issymval(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_SYMVAL);
}

bool silofs_stype_isdtnode(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_DTNODE);
}

bool silofs_stype_isftnode(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_FTNODE);
}

bool silofs_stype_isdata1k(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_DATA1K);
}

bool silofs_stype_isdata4k(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_DATA4K);
}

bool silofs_stype_isdatabk(enum silofs_stype stype)
{
	return stype_isequal(stype, SILOFS_STYPE_DATABK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_stype_isunode(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
		ret = true;
		break;
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_stype_isvnode(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		ret = true;
		break;
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool silofs_stype_isdata(enum silofs_stype stype)
{
	bool ret;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		ret = true;
		break;
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ret = false;
		break;
	}
	return ret;
}

uint32_t silofs_stype_size(enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_BOOTREC:
		return sizeof(struct silofs_bootrec1k);
	case SILOFS_STYPE_SUPER:
		return sizeof(struct silofs_super_block);
	case SILOFS_STYPE_SPNODE:
		return sizeof(struct silofs_spmap_node);
	case SILOFS_STYPE_SPLEAF:
		return sizeof(struct silofs_spmap_leaf);
	case SILOFS_STYPE_INODE:
		return sizeof(struct silofs_inode);
	case SILOFS_STYPE_XANODE:
		return sizeof(struct silofs_xattr_node);
	case SILOFS_STYPE_DTNODE:
		return sizeof(struct silofs_dtree_node);
	case SILOFS_STYPE_FTNODE:
		return sizeof(struct silofs_ftree_node);
	case SILOFS_STYPE_SYMVAL:
		return sizeof(struct silofs_symlnk_value);
	case SILOFS_STYPE_DATA1K:
		return sizeof(struct silofs_data_block1);
	case SILOFS_STYPE_DATA4K:
		return sizeof(struct silofs_data_block4);
	case SILOFS_STYPE_DATABK:
		return sizeof(struct silofs_data_block64);
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		break;
	}
	return 0;
}

ssize_t silofs_stype_ssize(enum silofs_stype stype)
{
	return (ssize_t)silofs_stype_size(stype);
}

size_t silofs_stype_nkbs(enum silofs_stype stype)
{
	const size_t size = silofs_stype_size(stype);

	return silofs_div_round_up(size, SILOFS_KB_SIZE);
}
