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
#include <stdio.h>
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "blobid.h"
#include "baddr.h"

void silofs_baddr_reset(struct silofs_baddr *baddr)
{
	silofs_memffff(baddr, sizeof(*baddr));
	baddr->ba_mode = SILOFS_BA_NONE;
}

static void
baddr_setup(struct silofs_baddr *baddr, const struct silofs_blobid *blobid)
{
	silofs_blobid_assign(&baddr->ba.blobid, blobid);
	baddr->ba_mode = SILOFS_BA_CAS;
}

void silofs_baddr_setup(struct silofs_baddr *baddr,
                        const struct silofs_hash256 *hash)
{
	struct silofs_blobid blobid;

	silofs_blobid_assign_hash(&blobid, hash);
	baddr_setup(baddr, &blobid);
}

void silofs_baddr_setup1(struct silofs_baddr *baddr,
                         const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&baddr->ba.paddr, paddr);
	baddr->ba_mode = SILOFS_BA_RAW;
}

void silofs_baddr_assign(struct silofs_baddr *baddr,
                         const struct silofs_baddr *other)
{
	/* XXX FIXME */
	silofs_blobid_assign(&baddr->ba.blobid, &other->ba.blobid);
	baddr->ba_mode = other->ba_mode;
}

static bool baddr_isequal_raw(const struct silofs_baddr *baddr,
                              const struct silofs_baddr *other)
{
	return silofs_paddr_isequal(&baddr->ba.paddr, &other->ba.paddr);
}

static bool baddr_isequal_cas(const struct silofs_baddr *baddr,
                              const struct silofs_baddr *other)
{
	return silofs_blobid_isequal(&baddr->ba.blobid, &other->ba.blobid);
}

bool silofs_baddr_isequal(const struct silofs_baddr *baddr,
                          const struct silofs_baddr *other)
{
	bool res = false;

	if (baddr->ba_mode == other->ba_mode) {
		switch (baddr->ba_mode) {
		case SILOFS_BA_RAW:
			res = baddr_isequal_raw(baddr, other);
			break;
		case SILOFS_BA_CAS:
			res = baddr_isequal_cas(baddr, other);
			break;
		case SILOFS_BA_NONE:
		default:
			res = false;
			break;
		}
	}
	return res;
}

bool silofs_baddr_isnone(const struct silofs_baddr *baddr)
{
	return (baddr->ba_mode == SILOFS_BA_NONE) ||
	       silofs_blobid_isnone(&baddr->ba.blobid);
}

int silofs_baddr_to_str(const struct silofs_baddr *baddr, char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	const int vers = SILOFS_FMT_VERSION;
	const int mode = baddr->ba_mode;
	int k;

	silofs_blobid_to_sbuf(&baddr->ba.blobid, &sbuf);
	k = snprintf(s, n, "silofs.v%d:%d:%s", vers, mode, sbuf.str);

	return ((k > 0) && (k < (int)n)) ? 0 : -SILOFS_ERANGE;
}

int silofs_baddr_from_str(struct silofs_baddr *baddr, const char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	struct silofs_strbuf hname;
	struct silofs_strview sv;
	struct silofs_blobid blobid;
	int vers = 0;
	int mode = 0;
	int k = 0;
	int err = 0;

	if (n >= sizeof(sbuf.str)) {
		return -SILOFS_EINVAL;
	}
	silofs_strbuf_setup_by2(&sbuf, s, n);

	silofs_strbuf_reset(&hname);
	k = sscanf(sbuf.str, "silofs.v%d:%d:%64s", &vers, &mode, hname.str);
	if (k != 3) {
		return -SILOFS_EINVAL;
	}
	if (vers != SILOFS_FMT_VERSION) {
		return -SILOFS_EPROTO;
	}
	if ((mode != SILOFS_BA_RAW) && (mode != SILOFS_BA_CAS)) {
		return -SILOFS_EPROTO;
	}
	silofs_strview_init(&sv, hname.str);
	err = silofs_blobid_from_str(&blobid, &sv);
	if (err) {
		return err;
	}
	baddr_setup(baddr, &blobid);
	return 0;
}

static enum silofs_ba_mode baddr64_mode(const union silofs_baddr64b *baddr64)
{
	return baddr64->b.mode;
}

static void
baddr64_set_type(union silofs_baddr64b *baddr64, enum silofs_ba_mode adt)
{
	baddr64->b.mode = (uint8_t)adt;
}

void silofs_baddr64b_reset(union silofs_baddr64b *baddr64)
{
	silofs_memzero(baddr64, sizeof(*baddr64));
	baddr64_set_type(baddr64, SILOFS_BA_NONE);
}

void silofs_baddr64b_htox(union silofs_baddr64b *baddr64,
                          const struct silofs_baddr *baddr)
{
	switch (baddr->ba_mode) {
	case SILOFS_BA_RAW:
		silofs_paddr64b_htox(&baddr64->paddr, &baddr->ba.paddr);
		baddr64_set_type(baddr64, SILOFS_BA_RAW);
		break;
	case SILOFS_BA_CAS:
		silofs_blobid_assign(&baddr64->blobid, &baddr->ba.blobid);
		baddr64_set_type(baddr64, SILOFS_BA_CAS);
		break;
	case SILOFS_BA_NONE:
	default:
		silofs_baddr64b_reset(baddr64);
		break;
	}
}

void silofs_baddr64b_xtoh(const union silofs_baddr64b *baddr64,
                          struct silofs_baddr *baddr)
{
	enum silofs_ba_mode adt = baddr64_mode(baddr64);

	switch (adt) {
	case SILOFS_BA_RAW:
		silofs_paddr64b_xtoh(&baddr64->paddr, &baddr->ba.paddr);
		baddr->ba_mode = SILOFS_BA_RAW;
		break;
	case SILOFS_BA_CAS:
		silofs_blobid_assign(&baddr->ba.blobid, &baddr64->blobid);
		baddr->ba_mode = SILOFS_BA_CAS;
		break;
	case SILOFS_BA_NONE:
	default:
		silofs_baddr_reset(baddr);
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_bcursor s_silofs_cursor_none = {
	.blobsz = 0,
};

const struct silofs_bcursor *silofs_cursor_none(void)
{
	return &s_silofs_cursor_none;
}

void silofs_bcursor128b_reset(struct silofs_bcursor128b *bcur128)
{
	silofs_bcursor128b_htox(bcur128, silofs_cursor_none());
}

void silofs_bcursor128b_xtoh(const struct silofs_bcursor128b *bcur128,
                             struct silofs_bcursor *bcur)
{
	silofs_baddr64b_xtoh(&bcur128->bc_baddr, &bcur->baddr);
	bcur->blobsz = silofs_le64_to_cpu(bcur128->bc_blobsz);
}

void silofs_bcursor128b_htox(struct silofs_bcursor128b *bcur128,
                             const struct silofs_bcursor *bcur)
{
	silofs_baddr64b_htox(&bcur128->bc_baddr, &bcur->baddr);
	bcur128->bc_blobsz = silofs_cpu_to_le64(bcur->blobsz);
}
