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
#include "crypt.h"
#include "htox.h"
#include "mtype.h"
#include "blobid.h"
#include "baddr.h"

static const struct silofs_baddr s_silofs_baddr_none = {
	.pos = SILOFS_OFF_NULL,
};

const struct silofs_baddr *silofs_baddr_none(void)
{
	return &s_silofs_baddr_none;
}

void silofs_baddr_init(struct silofs_baddr *baddr,
                       const struct silofs_blobid *blobid, off_t pos)
{
	silofs_blobid_copyto(blobid, &baddr->blobid);
	baddr->pos = pos;
	baddr->mtype = silofs_blobid_get_mtype(blobid);
	baddr->bmode = silofs_blobid_get_bmode(blobid);
}

void silofs_baddr_fini(struct silofs_baddr *baddr)
{
	silofs_baddr_reset(baddr);
}

void silofs_baddr_reset(struct silofs_baddr *baddr)
{
	silofs_blobid_reset(&baddr->blobid);
	baddr->pos = SILOFS_OFF_NULL;
}

void silofs_baddr_assign(struct silofs_baddr *baddr,
                         const struct silofs_baddr *other)
{
	silofs_blobid_copyto(&other->blobid, &baddr->blobid);
	baddr->pos = other->pos;
	baddr->mtype = other->mtype;
	baddr->bmode = other->bmode;
}

bool silofs_baddr_isequal(const struct silofs_baddr *baddr,
                          const struct silofs_baddr *other)
{
	return (baddr->pos == other->pos) &&
	       silofs_blobid_isequal(&baddr->blobid, &other->blobid);
}

bool silofs_baddr_isnull(const struct silofs_baddr *baddr)
{
	return (baddr->pos == SILOFS_OFF_NULL);
}

long silofs_baddr_compare(const struct silofs_baddr *baddr1,
                          const struct silofs_baddr *baddr2)
{
	long cmp;

	cmp = (long)(baddr1->pos - baddr2->pos);
	if (cmp) {
		return cmp;
	}
	cmp = silofs_blobid_compare(&baddr1->blobid, &baddr2->blobid);
	if (cmp) {
		return cmp;
	}
	return 0;
}

void silofs_baddr64b_htox(struct silofs_baddr64b *baddr64,
                          const struct silofs_baddr *baddr)
{
	memset(baddr64, 0, sizeof(*baddr64));
	silofs_blobid_copyto(&baddr->blobid, &baddr64->blobid);
	baddr64->pos = silofs_cpu_to_off(baddr->pos);
}

void silofs_baddr64b_xtoh(const struct silofs_baddr64b *baddr64,
                          struct silofs_baddr *baddr)
{
	silofs_blobid_copyto(&baddr64->blobid, &baddr->blobid);
	baddr->pos = silofs_off_to_cpu(baddr64->pos);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
baddr_to_hash(const struct silofs_baddr *baddr,
              const struct silofs_mdigest *md, struct silofs_hash256 *out_hash)
{
	struct silofs_baddr64b baddr64 = {};

	silofs_baddr64b_htox(&baddr64, baddr);
	silofs_sha3_256_of(md, &baddr64, sizeof(baddr64), out_hash);
}

void silofs_derive_iv_by_baddr(const struct silofs_mdigest *md,
                               const struct silofs_baddr *baddr,
                               struct silofs_iv *out_iv)
{
	struct silofs_hash256 hash = {};

	baddr_to_hash(baddr, md, &hash);
	silofs_derive_iv_by_hash256(out_iv, &hash);
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
	silofs_baddr64b_xtoh(&bcur128->baddr, &bcur->baddr);
	bcur->blobsz = silofs_le64_to_cpu(bcur128->blobsz);
}

void silofs_bcursor128b_htox(struct silofs_bcursor128b *bcur128,
                             const struct silofs_bcursor *bcur)
{
	silofs_baddr64b_htox(&bcur128->baddr, &bcur->baddr);
	bcur128->blobsz = silofs_cpu_to_le64(bcur->blobsz);
}
