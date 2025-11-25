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
#include "str.h"
#include "crypt.h"
#include "htox.h"
#include "uuid.h"
#include "hash.h"
#include "blobid.h"

static void xor_prandom(uint8_t *p, size_t n)
{
	uint8_t d[64];
	size_t r = n;
	size_t k;

	while (r > 0) {
		k = silofs_min(r, sizeof(d));
		silofs_prandom(d, k);
		for (size_t i = 0; i < k; ++i) {
			p[i] ^= d[i];
		}
		p += k;
		r -= k;
	}
}

static void generate_random(uint8_t *p, size_t n)
{
	silofs_gcrypt_random(p, n);
	xor_prandom(p, n);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* semantic "view" into blobid */
struct silofs_blobidv {
	struct silofs_svolid svolid;
	struct silofs_uniqid uniqid;
	uint8_t mtype;
	uint8_t btype;
	/* XXX REMOVE ME */
	uint8_t vspace;
	uint8_t height;
	uint8_t reserved[12];

} silofs_attr_aligned64;

static void blobid_to_view(const struct silofs_blobid *blobid,
                           struct silofs_blobidv *out_blobidv)
{
	STATICASSERT_LE(sizeof(*blobid), sizeof(*out_blobidv));

	memset(out_blobidv, 0, sizeof(*out_blobidv));
	memcpy(out_blobidv, blobid, sizeof(*blobid));
}

static void blobid_from_view(struct silofs_blobid *blobid,
                             const struct silofs_blobidv *blobidv)
{
	STATICASSERT_EQ(sizeof(*blobid), 56);
	STATICASSERT_EQ(sizeof(*blobidv), 64);
	STATICASSERT_LE(sizeof(*blobid), sizeof(*blobidv));

	memcpy(blobid, blobidv, sizeof(*blobid));
}

static void
blobidv_setup_raw(struct silofs_blobidv *blobidv,
                  const struct silofs_svolid *svolid, enum silofs_mtype mtype)
{
	memset(blobidv, 0, sizeof(*blobidv));
	silofs_svolid_copyto(svolid, &blobidv->svolid);
	blobidv->mtype = (uint8_t)mtype;
	blobidv->btype = (uint8_t)SILOFS_BTYPE_RAW;
	generate_random(blobidv->uniqid.u.raw, sizeof(blobidv->uniqid.u.raw));
}

static void
blobidv_setup_uniq(struct silofs_blobidv *blobidv,
                   const struct silofs_svolid *svolid,
                   const struct silofs_uniqid *uniq, enum silofs_mtype mtype)
{
	memset(blobidv, 0, sizeof(*blobidv));
	silofs_svolid_copyto(svolid, &blobidv->svolid);
	blobidv->mtype = (uint8_t)mtype;
	blobidv->btype = (uint8_t)SILOFS_BTYPE_RAW;
	memcpy(&blobidv->uniqid, uniq, sizeof(blobidv->uniqid));
}

static void
blobidv_setup_cas(struct silofs_blobidv *blobidv,
                  const struct silofs_svolid *svolid,
                  const struct silofs_hash256 *hash, enum silofs_mtype mtype)
{
	memset(blobidv, 0, sizeof(*blobidv));
	silofs_svolid_copyto(svolid, &blobidv->svolid);
	blobidv->mtype = (uint8_t)mtype;
	blobidv->btype = (uint8_t)SILOFS_BTYPE_CAS;
	silofs_hash256_copyto(hash, &blobidv->uniqid.u.hash);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_blobid s_silofs_blobid_none;

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_silofs_blobid_none;
}

void silofs_blobid_setup_raw(struct silofs_blobid *blobid,
                             const struct silofs_svolid *svolid,
                             enum silofs_mtype mtype)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_raw(&blobidv, svolid, mtype);
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_setup_raw2(struct silofs_blobid *blobid,
                              const struct silofs_svolid *svolid,
                              enum silofs_mtype mtype,
                              enum silofs_mtype vspace,
                              enum silofs_height height)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_raw(&blobidv, svolid, mtype);
	blobidv.vspace = (uint8_t)vspace;
	blobidv.height = (uint8_t)height;
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_setup_raw3(struct silofs_blobid *blobid,
                              const struct silofs_svolid *svolid,
                              const struct silofs_uniqid *uniq,
                              enum silofs_mtype mtype)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_uniq(&blobidv, svolid, uniq, mtype);
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_setup_cas(struct silofs_blobid *blobid,
                             const struct silofs_svolid *svolid,
                             const struct silofs_hash256 *hash,
                             enum silofs_mtype mtype)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_cas(&blobidv, svolid, hash, mtype);
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_get_svolid(const struct silofs_blobid *blobid,
                              struct silofs_svolid *out_svolid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	silofs_svolid_copyto(&blobidv.svolid, out_svolid);
}

enum silofs_height silofs_blobid_get_height(const struct silofs_blobid *blobid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	return blobidv.height;
}

enum silofs_btype silofs_blobid_get_btype(const struct silofs_blobid *blobid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	return blobidv.btype;
}

enum silofs_mtype silofs_blobid_get_mtype(const struct silofs_blobid *blobid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	return blobidv.mtype;
}

enum silofs_mtype silofs_blobid_get_vspace(const struct silofs_blobid *blobid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	return blobidv.vspace;
}

void silofs_blobid_copyto(const struct silofs_blobid *blobid,
                          struct silofs_blobid *other)
{
	memcpy(other->id, blobid->id, sizeof(other->id));
}

void silofs_blobid_reset(struct silofs_blobid *blobid)
{
	memset(blobid->id, 0, sizeof(blobid->id));
}

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other)
{
	return memcmp(blobid->id, other->id, sizeof(blobid->id));
}

bool silofs_blobid_isequal(const struct silofs_blobid *blobid1,
                           const struct silofs_blobid *blobid2)
{
	return (silofs_blobid_compare(blobid1, blobid2) == 0);
}

bool silofs_blobid_isnone(const struct silofs_blobid *blobid)
{
	return silofs_blobid_isequal(blobid, &s_silofs_blobid_none);
}

int silofs_blobid_to_ascii(const struct silofs_blobid *blobid, char *s,
                           size_t n)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid->id, sizeof(blobid->id), s, n, &cnt);

	if (cnt >= n) {
		return -1;
	}
	s[cnt] = '\0';
	return 0;
}

int silofs_blobid_from_ascii(struct silofs_blobid *blobid, const char *s,
                             size_t n)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->id, sizeof(blobid->id), s, n, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->id)) {
		return -1;
	}
	return 0;
}

void silofs_blobid_to_sbuf(const struct silofs_blobid *blobid,
                           struct silofs_strbuf *sbuf)
{
	silofs_strbuf_reset(sbuf);
	silofs_blobid_to_ascii(blobid, sbuf->str, sizeof(sbuf->str) - 1);
}

int silofs_blobid_to_str(const struct silofs_blobid *blobid,
                         struct silofs_strspan *ss)
{
	struct silofs_strbuf sbuf;
	size_t n;

	silofs_strbuf_reset(&sbuf);
	silofs_blobid_to_sbuf(blobid, &sbuf);
	n = silofs_strspan_assign(ss, sbuf.str);
	return (n < ss->n) ? 0 : -SILOFS_EINVAL;
}

int silofs_blobid_from_str(struct silofs_blobid *blobid,
                           const struct silofs_strview *sv)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(blobid->id, sizeof(blobid->id), sv->str,
	                          sv->len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(blobid->id)) {
		return -1;
	}
	return 0;
}

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed)
{
	return silofs_xxh64(blobid->id, sizeof(blobid->id), seed);
}
