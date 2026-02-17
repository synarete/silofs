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
#include "hash.h"
#include "blobid.h"

/* semantic "view" into blobid56b */
struct silofs_blobid56bv {
	uint16_t vers;
	uint16_t flags;
	uint8_t stype;
	uint8_t vspace;
	/* XXX REMOVE ME */
	uint8_t height;
	uint8_t reserved[9];
	struct silofs_layerid layerid;
	struct silofs_uniqid uniqid;

} silofs_attr_aligned64;

static void blobid56b_to_view(const struct silofs_blobid56b *blobid56b,
                              struct silofs_blobid56bv *out_blobid56bv)
{
	STATICASSERT_LE(sizeof(*blobid56b), sizeof(*out_blobid56bv));

	memset(out_blobid56bv, 0, sizeof(*out_blobid56bv));
	memcpy(out_blobid56bv, blobid56b, sizeof(*blobid56b));
}

static void blobid56b_from_view(struct silofs_blobid56b *blobid56b,
                                const struct silofs_blobid56bv *blobid56bv)
{
	STATICASSERT_EQ(sizeof(*blobid56b), 56);
	STATICASSERT_EQ(sizeof(*blobid56bv), 64);
	STATICASSERT_LE(sizeof(*blobid56b), sizeof(*blobid56bv));

	memcpy(blobid56b, blobid56bv, sizeof(*blobid56b));
}

static void blobid56bv_pre_setup(struct silofs_blobid56bv *blobid56bv)
{
	memset(blobid56bv, 0, sizeof(*blobid56bv));
	blobid56bv->vers = silofs_cpu_to_le16(SILOFS_FMT_VERSION);
}

static void blobid56bv_setup_uniq(struct silofs_blobid56bv *blobid56bv,
                                  const struct silofs_layerid *layerid,
                                  const struct silofs_uniqid *uniq,
                                  enum silofs_mtype mtype)
{
	blobid56bv_pre_setup(blobid56bv);
	silofs_layerid_copyto(layerid, &blobid56bv->layerid);
	blobid56bv->stype = (uint8_t)mtype;
	memcpy(&blobid56bv->uniqid, uniq, sizeof(blobid56bv->uniqid));
}

static void blobid56bv_setup_cas(struct silofs_blobid56bv *blobid56bv,
                                 const struct silofs_layerid *layerid,
                                 const struct silofs_hash256 *hash,
                                 enum silofs_mtype mtype)
{
	blobid56bv_pre_setup(blobid56bv);
	silofs_layerid_copyto(layerid, &blobid56bv->layerid);
	blobid56bv->stype = (uint8_t)mtype;
	silofs_hash256_copyto(hash, &blobid56bv->uniqid.u.hash);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_blobid56b s_silofs_blobid56b_none;

const struct silofs_blobid56b *silofs_blobid56b_none(void)
{
	return &s_silofs_blobid56b_none;
}

void silofs_blobid56b_setup_raw2(struct silofs_blobid56b *blobid56b,
                                 const struct silofs_layerid *layerid,
                                 const struct silofs_uniqid *uniq,
                                 enum silofs_mtype mtype,
                                 enum silofs_mtype vspace,
                                 enum silofs_height height)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56bv_setup_uniq(&blobid56bv, layerid, uniq, mtype);
	blobid56bv.vspace = (uint8_t)vspace;
	blobid56bv.height = (uint8_t)height;
	blobid56b_from_view(blobid56b, &blobid56bv);
}

void silofs_blobid56b_setup_raw3(struct silofs_blobid56b *blobid56b,
                                 const struct silofs_layerid *layerid,
                                 const struct silofs_uniqid *uniq,
                                 enum silofs_mtype mtype)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56bv_setup_uniq(&blobid56bv, layerid, uniq, mtype);
	blobid56b_from_view(blobid56b, &blobid56bv);
}

void silofs_blobid56b_setup_cas(struct silofs_blobid56b *blobid56b,
                                const struct silofs_layerid *layerid,
                                const struct silofs_hash256 *hash,
                                enum silofs_mtype mtype)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56bv_setup_cas(&blobid56bv, layerid, hash, mtype);
	blobid56b_from_view(blobid56b, &blobid56bv);
}

void silofs_blobid56b_get_layerid(const struct silofs_blobid56b *blobid56b,
                                  struct silofs_layerid *out_layerid)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56b_to_view(blobid56b, &blobid56bv);
	silofs_layerid_copyto(&blobid56bv.layerid, out_layerid);
}

enum silofs_height
silofs_blobid56b_get_height(const struct silofs_blobid56b *blobid56b)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56b_to_view(blobid56b, &blobid56bv);
	return blobid56bv.height;
}

enum silofs_mtype
silofs_blobid56b_get_mtype(const struct silofs_blobid56b *blobid56b)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56b_to_view(blobid56b, &blobid56bv);
	return blobid56bv.stype;
}

enum silofs_mtype
silofs_blobid56b_get_vspace(const struct silofs_blobid56b *blobid56b)
{
	struct silofs_blobid56bv blobid56bv;

	blobid56b_to_view(blobid56b, &blobid56bv);
	return blobid56bv.vspace;
}

void silofs_blobid56b_assign(struct silofs_blobid56b *blobid56b,
                             const struct silofs_blobid56b *other)
{
	silofs_blobid56b_copyto(other, blobid56b);
}

void silofs_blobid56b_copyto(const struct silofs_blobid56b *blobid56b,
                             struct silofs_blobid56b *other)
{
	memcpy(other->id, blobid56b->id, sizeof(other->id));
}

void silofs_blobid56b_reset(struct silofs_blobid56b *blobid56b)
{
	memset(blobid56b->id, 0, sizeof(blobid56b->id));
}

long silofs_blobid56b_compare(const struct silofs_blobid56b *blobid56b,
                              const struct silofs_blobid56b *other)
{
	return memcmp(blobid56b->id, other->id, sizeof(blobid56b->id));
}

bool silofs_blobid56b_isequal(const struct silofs_blobid56b *blobid56b1,
                              const struct silofs_blobid56b *blobid56b2)
{
	return (silofs_blobid56b_compare(blobid56b1, blobid56b2) == 0);
}

bool silofs_blobid56b_isnone(const struct silofs_blobid56b *blobid56b)
{
	return silofs_blobid56b_isequal(blobid56b, &s_silofs_blobid56b_none);
}

static int
blobid56b_to_ascii(const struct silofs_blobid56b *blobid56b, char *s, size_t n)
{
	size_t cnt = 0;

	silofs_mem_to_ascii(blobid56b->id, sizeof(blobid56b->id), s, n, &cnt);

	if (cnt >= n) {
		return -1;
	}
	s[cnt] = '\0';
	return 0;
}

void silofs_blobid56b_to_sbuf(const struct silofs_blobid56b *blobid56b,
                              struct silofs_strbuf *sbuf)
{
	silofs_strbuf_reset(sbuf);
	blobid56b_to_ascii(blobid56b, sbuf->str, sizeof(sbuf->str) - 1);
}

uint64_t silofs_blobid56b_hash64(const struct silofs_blobid56b *blobid56b,
                                 uint64_t seed)
{
	return silofs_xxh64(blobid56b->id, sizeof(blobid56b->id), seed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobid56bx_setup(struct silofs_blobid56bx *blobid56bx,
                             const struct silofs_hash256 *h)
{
	silofs_hash256_assign(&blobid56bx->idx, h);
}

void silofs_blobid56bx_assign(struct silofs_blobid56bx *blobid56bx,
                              const struct silofs_blobid56bx *other)
{
	silofs_blobid56bx_setup(blobid56bx, &other->idx);
}

void silofs_blobid56bx_derive(struct silofs_blobid56bx *blobid56bx,
                              const struct silofs_mdigest_hd *md_hd,
                              const struct silofs_blobid56b *blobid56b)
{
	struct silofs_hash256 hash;

	silofs_sha3_256_of(md_hd, blobid56b->id, sizeof(blobid56b->id), &hash);
	silofs_blobid56bx_setup(blobid56bx, &hash);
}

bool silofs_blobid56bx_isequal(const struct silofs_blobid56bx *blobid56bx,
                               const struct silofs_blobid56bx *other)
{
	return silofs_hash256_isequal(&blobid56bx->idx, &other->idx);
}

int silofs_blobid56bx_to_str(const struct silofs_blobid56bx *blobid56bx,
                             char *str, size_t len)
{
	return silofs_hash256_to_str(&blobid56bx->idx, str, len);
}

int silofs_blobid56bx_from_str(struct silofs_blobid56bx *blobid56bx,
                               const char *str, size_t len)
{
	return silofs_hash256_from_str(&blobid56bx->idx, str, len);
}
