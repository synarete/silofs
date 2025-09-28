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
#include "mtype.h"
#include "blobid.h"
#include "baddr.h"

static const struct silofs_baddr s_silofs_baddr_none = {
	.pos = SILOFS_OFF_NULL,
	.mtype = SILOFS_MTYPE_NONE,
	.bmode = SILOFS_BMODE_NONE,
};

const struct silofs_baddr *silofs_baddr_none(void)
{
	return &s_silofs_baddr_none;
}

void silofs_baddr_init(struct silofs_baddr *baddr,
                       const struct silofs_blobid *blobid,
                       enum silofs_bmode bmode, enum silofs_mtype mtype,
                       off_t pos)
{
	silofs_blobid_assign(&baddr->blobid, blobid);
	baddr->pos = pos;
	baddr->mtype = mtype;
	baddr->bmode = bmode;
}

void silofs_baddr_init_raw(struct silofs_baddr *baddr,
                           const struct silofs_blobid *blobid,
                           enum silofs_mtype mtype, off_t pos)
{
	silofs_baddr_init(baddr, blobid, SILOFS_BMODE_RAW, mtype, pos);
}

void silofs_baddr_fini(struct silofs_baddr *baddr)
{
	silofs_baddr_reset(baddr);
}

void silofs_baddr_reset(struct silofs_baddr *baddr)
{
	silofs_blobid_reset(&baddr->blobid);
	baddr->pos = SILOFS_OFF_NULL;
	baddr->mtype = SILOFS_MTYPE_NONE;
	baddr->bmode = SILOFS_BMODE_NONE;
}

void silofs_baddr_assign(struct silofs_baddr *baddr,
                         const struct silofs_baddr *other)
{
	silofs_blobid_assign(&baddr->blobid, &other->blobid);
	baddr->pos = other->pos;
	baddr->mtype = other->mtype;
	baddr->bmode = other->bmode;
}

bool silofs_baddr_isequal(const struct silofs_baddr *baddr,
                          const struct silofs_baddr *other)
{
	return (baddr->pos == other->pos) && (baddr->mtype == other->mtype) &&
	       (baddr->bmode == other->bmode) &&
	       silofs_blobid_isequal(&baddr->blobid, &other->blobid);
}

bool silofs_baddr_isnull(const struct silofs_baddr *baddr)
{
	return (baddr->bmode == SILOFS_BMODE_NONE) ||
	       (baddr->mtype == SILOFS_MTYPE_NONE) ||
	       (baddr->pos == SILOFS_OFF_NULL);
}

long silofs_baddr_compare(const struct silofs_baddr *baddr1,
                          const struct silofs_baddr *baddr2)
{
	long cmp;

	cmp = (long)(baddr1->bmode - baddr2->bmode);
	if (cmp) {
		return cmp;
	}
	cmp = (long)(baddr1->mtype - baddr2->mtype);
	if (cmp) {
		return cmp;
	}
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

int silofs_baddr_to_str(const struct silofs_baddr *baddr, char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	const int vers = SILOFS_FMT_VERSION;
	const int mtype = (int)(baddr->mtype);
	int k;

	if ((baddr->bmode != SILOFS_BMODE_CAS) || (baddr->pos != 0)) {
		return -SILOFS_EOPNOTSUPP;
	}

	silofs_blobid_to_sbuf(&baddr->blobid, &sbuf);
	k = snprintf(s, n, "silofs.v%d:%d:%s", vers, mtype, sbuf.str);

	return ((k > 0) && (k < (int)n)) ? 0 : -SILOFS_ERANGE;
}

int silofs_baddr_from_str(struct silofs_baddr *baddr, const char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	struct silofs_strbuf hname;
	struct silofs_strview sv;
	struct silofs_blobid blobid;
	enum silofs_mtype mtype;
	int vers = 0;
	int mt = 0;
	int k = 0;
	int err = 0;

	if (n >= sizeof(sbuf.str)) {
		return -SILOFS_EINVAL;
	}
	silofs_strbuf_setup_by2(&sbuf, s, n);

	silofs_strbuf_reset(&hname);
	k = sscanf(sbuf.str, "silofs.v%d:%d:%64s", &vers, &mt, hname.str);
	if (k != 3) {
		return -SILOFS_EINVAL;
	}
	if (vers != SILOFS_FMT_VERSION) {
		return -SILOFS_EPROTO;
	}
	mtype = (enum silofs_mtype)mt;
	if (!silofs_mtype_size(mtype)) {
		return -SILOFS_EPROTO;
	}
	silofs_strview_init(&sv, hname.str);
	err = silofs_blobid_from_str(&blobid, &sv);
	if (err) {
		return err;
	}
	silofs_baddr_init(baddr, &blobid, SILOFS_BMODE_CAS, mtype, 0);
	return 0;
}

void silofs_baddr64b_reset(struct silofs_baddr64b *baddr64)
{
	silofs_memzero(baddr64, sizeof(*baddr64));
}

void silofs_baddr64b_htox(struct silofs_baddr64b *baddr64,
                          const struct silofs_baddr *baddr)
{
	silofs_baddr64b_reset(baddr64);
	silofs_blobid_assign(&baddr64->blobid, &baddr->blobid);
	baddr64->pos = silofs_cpu_to_off(baddr->pos);
	baddr64->mtype = silofs_cpu_to_le16((uint16_t)(baddr->mtype));
	baddr64->bmode = silofs_cpu_to_le16((uint16_t)(baddr->bmode));
}

void silofs_baddr64b_xtoh(const struct silofs_baddr64b *baddr64,
                          struct silofs_baddr *baddr)
{
	uint16_t m;

	silofs_blobid_assign(&baddr->blobid, &baddr64->blobid);
	baddr->pos = silofs_off_to_cpu(baddr64->pos);
	m = silofs_le16_to_cpu(baddr64->mtype);
	baddr->mtype = (enum silofs_mtype)m;
	m = silofs_le16_to_cpu(baddr64->bmode);
	baddr->bmode = (enum silofs_bmode)m;
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
