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
#include <stdlib.h>
#include <stdio.h>
#include <silofs/errors.h>
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "meta.h"
#include "blobid.h"
#include "caddr.h"

void silofs_caddr_reset(struct silofs_caddr *caddr)
{
	silofs_blobid_reset(&caddr->blobid);
}

void silofs_caddr_setup(struct silofs_caddr *caddr,
                        const struct silofs_hash256 *hash)
{
	silofs_blobid_assign_hash(&caddr->blobid, hash);
}

void silofs_caddr_assign(struct silofs_caddr *caddr,
                         const struct silofs_caddr *other)
{
	silofs_blobid_assign(&caddr->blobid, &other->blobid);
}

bool silofs_caddr_isequal(const struct silofs_caddr *caddr,
                          const struct silofs_caddr *other)
{
	return silofs_blobid_isequal(&caddr->blobid, &other->blobid);
}

static size_t caddr_to_str(const struct silofs_caddr *caddr, char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	const int vers = SILOFS_FMT_VERSION;
	size_t hn = 0;
	size_t pn = 0;
	char *d = s;

	silofs_blobid_to_sbuf(&caddr->blobid, &sbuf);
	hn = silofs_str_length(sbuf.str);
	pn = (size_t)snprintf(d, n, "silofs.v%d:", vers);
	if ((pn + hn) < n) {
		d += pn;
		strncpy(d, sbuf.str, hn);
		d += hn;
		*d = '\0';
		d += 1;
	} else {
		d += silofs_min(n, pn);
	}
	return (size_t)(d - s);
}

int silofs_caddr_to_str(const struct silofs_caddr *caddr, char *s, size_t n)
{
	size_t k;

	k = caddr_to_str(caddr, s, n);
	return (k < n) ? 0 : -SILOFS_ERANGE;
}

int silofs_caddr_from_str(struct silofs_caddr *caddr, const char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	struct silofs_strbuf hname;
	struct silofs_hash256 hash;
	int vers = 0;
	int k = 0;
	int err = 0;

	if (n >= sizeof(sbuf.str)) {
		return -SILOFS_EINVAL;
	}
	silofs_strbuf_setup_by2(&sbuf, s, n);

	silofs_strbuf_reset(&hname);
	k = sscanf(sbuf.str, "silofs.v%d:%64s", &vers, hname.str);
	if (k != 2) {
		return -SILOFS_EINVAL;
	}
	if (vers != SILOFS_FMT_VERSION) {
		return -SILOFS_EPROTO;
	}
	err = silofs_hash256_by_name(&hash, &hname);
	if (err) {
		return err;
	}
	silofs_caddr_setup(caddr, &hash);
	return 0;
}

static int
caddr_from_strview(struct silofs_caddr *caddr, const struct silofs_strview *sv)
{
	struct silofs_strview sv2;
	int ret = -SILOFS_EILLSTR;

	silofs_strview_strip_ws(sv, &sv2);
	if (silofs_strview_isascii(&sv2)) {
		ret = silofs_caddr_from_str(caddr, sv2.str, sv2.len);
	}
	return ret;
}

void silofs_caddr_to_name2(const struct silofs_caddr *caddr,
                           char s[SILOFS_XREFLEN_MAX + 1])
{
	silofs_caddr_to_str(caddr, s, SILOFS_XREFLEN_MAX + 1);
}

int silofs_caddr_by_name2(struct silofs_caddr *caddr,
                          const struct silofs_strview *name)
{
	return caddr_from_strview(caddr, name);
}

uint64_t silofs_caddr_to_u64(const struct silofs_caddr *caddr)
{
	union {
		struct silofs_caddr64b caddr64b;
		uint8_t d[64];
	} u;
	uint64_t n = 0;

	STATICASSERT_EQ(sizeof(u), 64);

	silofs_caddr64b_htox(&u.caddr64b, caddr);
	for (size_t i = 0; i < sizeof(u); i += 8) {
		n ^= silofs_u8b_as_u64(&u.d[i]);
	}
	return n;
}

void silofs_caddr64b_htox(struct silofs_caddr64b *caddr64b,
                          const struct silofs_caddr *caddr)
{
	memset(caddr64b, 0, sizeof(*caddr64b));
	silofs_blobid_assign(&caddr64b->blobid, &caddr->blobid);
}

void silofs_caddr64b_xtoh(const struct silofs_caddr64b *caddr64b,
                          struct silofs_caddr *caddr)
{
	silofs_blobid_assign(&caddr->blobid, &caddr64b->blobid);
}
