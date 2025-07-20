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
	caddr->ctype = SILOFS_CTYPE_NONE;
}

void silofs_caddr_setup(struct silofs_caddr *caddr,
                        const struct silofs_hash256 *hash,
                        enum silofs_ctype ctype)
{
	silofs_blobid_assign_hash(&caddr->blobid, hash);
	caddr->ctype = ctype;
}

void silofs_caddr_assign(struct silofs_caddr *caddr,
                         const struct silofs_caddr *other)
{
	silofs_blobid_assign(&caddr->blobid, &other->blobid);
	caddr->ctype = other->ctype;
}

bool silofs_caddr_isnone(const struct silofs_caddr *caddr)
{
	return (caddr->ctype == SILOFS_CTYPE_NONE);
}

bool silofs_caddr_isequal(const struct silofs_caddr *caddr,
                          const struct silofs_caddr *other)
{
	return (caddr->ctype == other->ctype) &&
	       silofs_blobid_isequal(&caddr->blobid, &other->blobid);
}

static size_t caddr_to_str(const struct silofs_caddr *caddr, char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	const int vers = SILOFS_FMT_VERSION;
	const int ctype = (int)(caddr->ctype);
	size_t hn = 0;
	size_t pn = 0;
	char *d = s;

	silofs_blobid_to_sbuf(&caddr->blobid, &sbuf);
	hn = silofs_str_length(sbuf.str);
	pn = (size_t)snprintf(d, n, "silofs.v%d.%d:", vers, ctype);
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

static int check_ctype(enum silofs_ctype ctype)
{
	int ret;

	switch (ctype) {
	case SILOFS_CTYPE_MBR:
	case SILOFS_CTYPE_ENCSEG:
	case SILOFS_CTYPE_PACKIDX:
		ret = 0;
		break;
	case SILOFS_CTYPE_NONE:
	default:
		ret = -SILOFS_EPROTO;
		break;
	}
	return ret;
}

int silofs_caddr_from_str(struct silofs_caddr *caddr, const char *s, size_t n)
{
	struct silofs_strbuf sbuf;
	struct silofs_strbuf hname;
	struct silofs_hash256 hash;
	enum silofs_ctype ctype;
	int vers = 0;
	int ctyp = 0;
	int k = 0;
	int err = 0;

	if (n >= sizeof(sbuf.str)) {
		return -SILOFS_EINVAL;
	}
	silofs_strbuf_setup_by2(&sbuf, s, n);

	silofs_strbuf_reset(&hname);
	k = sscanf(sbuf.str, "silofs.v%d.%d:%64s", &vers, &ctyp, hname.str);
	if (k != 3) {
		return -SILOFS_EINVAL;
	}
	if (vers != SILOFS_FMT_VERSION) {
		return -SILOFS_EPROTO;
	}
	ctype = (enum silofs_ctype)ctyp;
	err = check_ctype(ctype);
	if (err) {
		return err;
	}
	err = silofs_hash256_by_name(&hash, &hname);
	if (err) {
		return err;
	}
	silofs_caddr_setup(caddr, &hash, ctype);
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

void silofs_caddr_to_name(const struct silofs_caddr *caddr,
                          struct silofs_strbuf *out_name)
{
	const size_t n = sizeof(out_name->str);

	caddr_to_str(caddr, out_name->str, n);
	out_name->str[n - 1] = '\0';
}

void silofs_caddr_to_name2(const struct silofs_caddr *caddr,
                           char s[SILOFS_XREFLEN_MAX + 1])
{
	caddr_to_str(caddr, s, SILOFS_XREFLEN_MAX + 1);
}

int silofs_caddr_by_name(struct silofs_caddr *caddr,
                         const struct silofs_strbuf *name)
{
	struct silofs_strview sv;

	silofs_strbuf_as_sv(name, &sv);
	return silofs_caddr_by_name2(caddr, &sv);
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
	caddr64b->ctype = silofs_cpu_to_le16((uint16_t)caddr->ctype);
}

void silofs_caddr64b_xtoh(const struct silofs_caddr64b *caddr64b,
                          struct silofs_caddr *caddr)
{
	silofs_blobid_assign(&caddr->blobid, &caddr64b->blobid);
	caddr->ctype = silofs_le16_to_cpu(caddr64b->ctype);
}
