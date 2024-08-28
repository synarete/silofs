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
#include <silofs/str.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <stdio.h>


void silofs_caddr_reset(struct silofs_caddr *caddr)
{
	silofs_memzero(&caddr->hash, sizeof(caddr->hash));
	caddr->size = 0;
	caddr->ctype = SILOFS_CTYPE_NONE;
}

void silofs_caddr_setup(struct silofs_caddr *caddr,
                        const struct silofs_hash256 *hash,
                        uint32_t size, enum silofs_ctype ctype)
{
	silofs_hash256_assign(&caddr->hash, hash);
	caddr->size = size;
	caddr->ctype = ctype;
}

void silofs_caddr_assign(struct silofs_caddr *caddr,
                         const struct silofs_caddr *other)
{
	silofs_hash256_assign(&caddr->hash, &other->hash);
	caddr->size = other->size;
	caddr->ctype = other->ctype;
}

bool silofs_caddr_isnone(const struct silofs_caddr *caddr)
{
	return (caddr->ctype == SILOFS_CTYPE_NONE) || (caddr->size == 0);
}

bool silofs_caddr_isequal(const struct silofs_caddr *caddr,
                          const struct silofs_caddr *other)
{
	return (caddr->size == other->size) &&
	       (caddr->ctype == other->ctype) &&
	       silofs_hash256_isequal(&caddr->hash, &other->hash);
}

static size_t caddr_to_str(const struct silofs_caddr *caddr, char *s, size_t n)
{
	struct silofs_strbuf hname;
	const int vers = SILOFS_FMT_VERSION;
	const int ctype = (int)(caddr->ctype);
	const uint32_t size = caddr->size;
	size_t hn = 0;
	size_t pn = 0;
	char *d = s;

	hn = silofs_hash256_to_name(&caddr->hash, &hname);
	pn = (size_t)snprintf(d, n, "silofs.v%d.%d.%x:", vers, ctype, size);
	if ((pn + hn) < n) {
		d += pn;
		strncpy(d, hname.str, hn);
		d += hn;
		*d = '\0';
	}
	return (size_t)(d - s);
}

static int check_ctype_size(enum silofs_ctype ctype, size_t size)
{
	int ret;

	switch (ctype) {
	case SILOFS_CTYPE_BOOTREC:
		ret = (size == SILOFS_BOOTREC_SIZE) ? 0 : -SILOFS_EPROTO;
		break;
	case SILOFS_CTYPE_ENCSEG:
	case SILOFS_CTYPE_PACKIDX:
		ret = !(size % SILOFS_KB_SIZE) ? 0 : -SILOFS_EPROTO;
		break;
	case SILOFS_CTYPE_NONE:
	default:
		ret = -SILOFS_EPROTO;
		break;
	}
	return ret;
}

static int caddr_from_str(struct silofs_caddr *caddr,
                          const char *s, size_t len)
{
	struct silofs_strbuf sbuf;
	struct silofs_strbuf hname;
	struct silofs_hash256 hash;
	enum silofs_ctype ctype;
	int vers = 0;
	int ctyp = 0;
	uint32_t size = 0;
	int k = 0;
	int err = 0;

	if (len >= sizeof(sbuf.str)) {
		return -SILOFS_EINVAL;
	}
	silofs_strbuf_setup_by2(&sbuf, s, len);

	silofs_strbuf_reset(&hname);
	k = sscanf(sbuf.str, "silofs.v%d.%d.%x:%64s",
	           &vers, &ctyp, &size, hname.str);
	if (k != 4) {
		return -SILOFS_EINVAL;
	}
	if (vers != SILOFS_FMT_VERSION) {
		return -SILOFS_EPROTO;
	}
	ctype = (enum silofs_ctype)ctyp;
	err = check_ctype_size(ctype, size);
	if (err) {
		return err;
	}
	err = silofs_hash256_by_name(&hash, &hname);
	if (err) {
		return err;
	}
	silofs_caddr_setup(caddr, &hash, size, ctype);
	return 0;
}

static int caddr_from_strview(struct silofs_caddr *caddr,
                              const struct silofs_strview *sv)
{
	struct silofs_strview sv2;
	int ret = -SILOFS_EILLSTR;

	silofs_strview_strip_ws(sv, &sv2);
	if (silofs_strview_isascii(&sv2)) {
		ret = caddr_from_str(caddr, sv2.str, sv2.len);
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
                           char s[SILOFS_NAME_MAX + 1])
{
	const size_t n = SILOFS_NAME_MAX;
	size_t k;

	k = caddr_to_str(caddr, s, n);
	if (k >= n) {
		s[n] = '\0';
	}
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

uint32_t silofs_caddr_to_u32(const struct silofs_caddr *caddr)
{
	struct silofs_caddr64b caddr64b;

	silofs_caddr64b_htox(&caddr64b, caddr);
	return silofs_squash_to_u32(&caddr64b, sizeof(caddr64b));
}

void silofs_caddr64b_htox(struct silofs_caddr64b *caddr64b,
                          const struct silofs_caddr *caddr)
{
	silofs_hash256_assign(&caddr64b->hash, &caddr->hash);
	caddr64b->size = silofs_cpu_to_le32(caddr->size);
	caddr64b->ctype = (uint8_t)caddr->ctype;
	memset(caddr64b->reserved, 0, sizeof(caddr64b->reserved));
}

void silofs_caddr64b_xtoh(const struct silofs_caddr64b *caddr64b,
                          struct silofs_caddr *caddr)
{
	const uint32_t size = silofs_le32_to_cpu(caddr64b->size);

	silofs_caddr_setup(caddr, &caddr64b->hash, size, caddr64b->ctype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_calc_caddr_of(const struct iovec *iov, size_t cnt,
                          enum silofs_ctype ctype,
                          const struct silofs_mdigest *md,
                          struct silofs_caddr *out_caddr)
{
	struct silofs_hash256 hash;
	const uint32_t size = (uint32_t)silofs_iov_length(iov, cnt);

	silofs_sha256_ofv(md, iov, cnt, &hash);
	silofs_caddr_setup(out_caddr, &hash, size, ctype);
}
