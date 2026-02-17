/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "uuid.h"
#include "hash.h"
#include "blobid.h"

static void generate_random(uint8_t *p, size_t n)
{
	silofs_gcrypt_random(p, n);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* semantic "view" into blobid */
struct silofs_blobidv {
	uint16_t vers;
	uint8_t mtype;
	/* XXX REMOVE ME */
	uint8_t vspace;
	uint8_t height;
	uint8_t reserved[11];
	struct silofs_layerid layerid;
	struct silofs_uniqid uniqid;

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

static void blobidv_pre_setup(struct silofs_blobidv *blobidv)
{
	memset(blobidv, 0, sizeof(*blobidv));
	blobidv->vers = silofs_cpu_to_le16(SILOFS_FMT_VERSION);
}

static void blobidv_setup_raw(struct silofs_blobidv *blobidv,
                              const struct silofs_layerid *layerid,
                              enum silofs_mtype mtype)
{
	blobidv_pre_setup(blobidv);
	silofs_layerid_copyto(layerid, &blobidv->layerid);
	blobidv->mtype = (uint8_t)mtype;
	generate_random(blobidv->uniqid.u.raw, sizeof(blobidv->uniqid.u.raw));
}

static void
blobidv_setup_uniq(struct silofs_blobidv *blobidv,
                   const struct silofs_layerid *layerid,
                   const struct silofs_uniqid *uniq, enum silofs_mtype mtype)
{
	blobidv_pre_setup(blobidv);
	silofs_layerid_copyto(layerid, &blobidv->layerid);
	blobidv->mtype = (uint8_t)mtype;
	memcpy(&blobidv->uniqid, uniq, sizeof(blobidv->uniqid));
}

static void
blobidv_setup_cas(struct silofs_blobidv *blobidv,
                  const struct silofs_layerid *layerid,
                  const struct silofs_hash256 *hash, enum silofs_mtype mtype)
{
	blobidv_pre_setup(blobidv);
	silofs_layerid_copyto(layerid, &blobidv->layerid);
	blobidv->mtype = (uint8_t)mtype;
	silofs_hash256_copyto(hash, &blobidv->uniqid.u.hash);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_blobid s_silofs_blobid_none;

const struct silofs_blobid *silofs_blobid_none(void)
{
	return &s_silofs_blobid_none;
}

void silofs_blobid_setup_raw2(struct silofs_blobid *blobid,
                              const struct silofs_layerid *layerid,
                              enum silofs_mtype mtype,
                              enum silofs_mtype vspace,
                              enum silofs_height height)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_raw(&blobidv, layerid, mtype);
	blobidv.vspace = (uint8_t)vspace;
	blobidv.height = (uint8_t)height;
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_setup_raw3(struct silofs_blobid *blobid,
                              const struct silofs_layerid *layerid,
                              const struct silofs_uniqid *uniq,
                              enum silofs_mtype mtype)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_uniq(&blobidv, layerid, uniq, mtype);
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_setup_cas(struct silofs_blobid *blobid,
                             const struct silofs_layerid *layerid,
                             const struct silofs_hash256 *hash,
                             enum silofs_mtype mtype)
{
	struct silofs_blobidv blobidv;

	blobidv_setup_cas(&blobidv, layerid, hash, mtype);
	blobid_from_view(blobid, &blobidv);
}

void silofs_blobid_get_layerid(const struct silofs_blobid *blobid,
                               struct silofs_layerid *out_layerid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	silofs_layerid_copyto(&blobidv.layerid, out_layerid);
}

enum silofs_height silofs_blobid_get_height(const struct silofs_blobid *blobid)
{
	struct silofs_blobidv blobidv;

	blobid_to_view(blobid, &blobidv);
	return blobidv.height;
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

void silofs_blobid_assign(struct silofs_blobid *blobid,
                          const struct silofs_blobid *other)
{
	silofs_blobid_copyto(other, blobid);
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

static int
blobid_to_ascii(const struct silofs_blobid *blobid, char *s, size_t n)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid->id, sizeof(blobid->id), s, n, &cnt);

	if (cnt >= n) {
		return -1;
	}
	s[cnt] = '\0';
	return 0;
}

void silofs_blobid_to_sbuf(const struct silofs_blobid *blobid,
                           struct silofs_strbuf *sbuf)
{
	silofs_strbuf_reset(sbuf);
	blobid_to_ascii(blobid, sbuf->str, sizeof(sbuf->str) - 1);
}

uint64_t
silofs_blobid_hash64(const struct silofs_blobid *blobid, uint64_t seed)
{
	return silofs_xxh64(blobid->id, sizeof(blobid->id), seed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobidx_setup(struct silofs_blobidx *blobidx,
                          const struct silofs_hash256 *h)
{
	silofs_hash256_assign(&blobidx->idx, h);
}

void silofs_blobidx_assign(struct silofs_blobidx *blobidx,
                           const struct silofs_blobidx *other)
{
	silofs_blobidx_setup(blobidx, &other->idx);
}

void silofs_blobidx_derive(struct silofs_blobidx *blobidx,
                           const struct silofs_mdigest_hd *md_hd,
                           const struct silofs_blobid *blobid)
{
	struct silofs_hash256 hash;

	silofs_sha3_256_of(md_hd, blobid->id, sizeof(blobid->id), &hash);
	silofs_blobidx_setup(blobidx, &hash);
}

bool silofs_blobidx_isequal(const struct silofs_blobidx *blobidx,
                            const struct silofs_blobidx *other)
{
	return silofs_hash256_isequal(&blobidx->idx, &other->idx);
}

int silofs_blobidx_to_str(const struct silofs_blobidx *blobidx, char *str,
                          size_t len)
{
	return silofs_hash256_to_str(&blobidx->idx, str, len);
}

int silofs_blobidx_from_str(struct silofs_blobidx *blobidx, const char *str,
                            size_t len)
{
	return silofs_hash256_from_str(&blobidx->idx, str, len);
}
