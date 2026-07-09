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
#include <silofs/types.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/pstor.h>

static void take_grandom(void *p, size_t n)
{
	silofs_gcrypt_random(p, n);
}

static void take_prandom(struct silofs_prandgen *prng, void *p, size_t n)
{
	silofs_prandgen_take(prng, p, n);
}

static void feed_prandom(struct silofs_prandgen *prng, void *p, size_t n)
{
	silofs_prandgen_feed(prng, p, n);
}

static void
generate_civ(struct silofs_prandgen *prng, struct silofs_civ *out_civ)
{
	take_prandom(prng, out_civ->iv, sizeof(out_civ->iv));
}

static void
generate_ckey(struct silofs_prandgen *prng, struct silofs_ckey *out_ckey)
{
	constexpr size_t n = sizeof(out_ckey->key);
	uint8_t *p         = out_ckey->key;

	STATICASSERT_GT(sizeof(out_ckey->key), 16);

	take_grandom(p, 16);
	take_prandom(prng, p + 16, n - 16);
	feed_prandom(prng, p, 16);
}

static void
generate_uniqid(struct silofs_prandgen *prng, struct silofs_uniqid *out_uniqid)
{
	take_prandom(prng, out_uniqid->id, sizeof(out_uniqid->id));
}

static void generate_layerid(struct silofs_layerid *out_layerid)
{
	silofs_layerid_generate(out_layerid);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_layerid *
top_layerid(const struct silofs_pexec_ctx *pexec)
{
	const struct silofs_uber_info *ubi = pexec->ubref->ubi;

	silofs_assert_not_null(ubi);
	return silofs_ubi_layerid(ubi);
}

static void gen_layerid(const struct silofs_pexec_ctx *pexec,
                        struct silofs_layerid *out_layerid)
{
	generate_layerid(out_layerid);
	silofs_unused(pexec);
}

static void gen_uniqid(const struct silofs_pexec_ctx *pexec,
                       struct silofs_uniqid *out_uniqid)
{
	generate_uniqid(pexec->prng, out_uniqid);
}

static void gen_civkey(const struct silofs_pexec_ctx *pexec,
                       struct silofs_civkey *out_civkey)
{
	generate_ckey(pexec->prng, &out_civkey->key);
	generate_civ(pexec->prng, &out_civkey->iv);
}

static int
gen_pnptr_at(const struct silofs_pexec_ctx *pexec,
             const struct silofs_paddr *paddr, struct silofs_pnptr *out_pnptr)
{
	struct silofs_civkey civkey;

	gen_civkey(pexec, &civkey);
	silofs_pnptr_setup(out_pnptr, paddr, &civkey);

	return 0;
}

int silofs_carve_base_ubspace(const struct silofs_pexec_ctx *pexec,
                              struct silofs_pnptr *out_pnptr)
{
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_UBER,
		.ltype = SILOFS_LTYPE_NONE,
	};

	silofs_blobid_init(&blobid, &stype, nullptr, nullptr);
	gen_layerid(pexec, &blobid.layerid);
	gen_uniqid(pexec, &blobid.uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);
	return gen_pnptr_at(pexec, &paddr, out_pnptr);
}

int silofs_carve_base_btspace(const struct silofs_pexec_ctx *pexec,
                              enum silofs_ltype ltype,
                              struct silofs_pnptr *out_pnptr)
{
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.ltype = ltype,
	};

	silofs_blobid_init(&blobid, &stype, top_layerid(pexec), nullptr);
	gen_uniqid(pexec, &blobid.uniqid);
	silofs_paddr_init(&paddr, &blobid, 0);

	return gen_pnptr_at(pexec, &paddr, out_pnptr);
}

int silofs_carve_base_lspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_ltype ltype,
                             struct silofs_paddr *out_paddr)
{
	struct silofs_blobid blobid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_LNODE,
		.ltype = ltype,
	};

	silofs_blobid_init(&blobid, &stype, top_layerid(pexec), nullptr);
	gen_uniqid(pexec, &blobid.uniqid);
	silofs_paddr_init(out_paddr, &blobid, 0);

	return 0;
}

static void carve_next_space_of(const struct silofs_pexec_ctx *pexec,
                                const struct silofs_stype *stype,
                                struct silofs_paddr *out_paddr)
{
	struct silofs_spdesc spdesc_cur, spdesc_nxt;
	struct silofs_paddr paddr_nxt;

	silofs_ubi_spdesc_of(pexec->ubref->ubi, stype, &spdesc_cur);

	silofs_paddr_assign(out_paddr, &spdesc_cur.end);
	silofs_paddr_next(&spdesc_cur.end, &paddr_nxt);

	silofs_spdesc_setup(&spdesc_nxt, &spdesc_cur.beg, &paddr_nxt);
	silofs_ubi_update_spdesc(pexec->ubref->ubi, &spdesc_nxt);
}

static bool try_carve_free_space_of(const struct silofs_pexec_ctx *pexec,
                                    const struct silofs_stype *stype,
                                    struct silofs_paddr *out_paddr)
{
	int err;

	err = silofs_pspools_pull(pexec->pspools, stype, out_paddr);
	return (err == 0);
}

static int carve_pnptr_of(const struct silofs_pexec_ctx *pexec,
                          const struct silofs_stype *stype,
                          struct silofs_pnptr *out_pnptr)
{
	struct silofs_paddr paddr;

	if (!try_carve_free_space_of(pexec, stype, &paddr)) {
		carve_next_space_of(pexec, stype, &paddr);
	}
	return gen_pnptr_at(pexec, &paddr, out_pnptr);
}

int silofs_carve_btspace_pnptr(const struct silofs_pexec_ctx *pexec,
                               enum silofs_ltype ltype,
                               struct silofs_pnptr *out_pnptr)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.ltype = ltype,
	};

	return carve_pnptr_of(pexec, &stype, out_pnptr);
}

int silofs_carve_lspace_pnptr(const struct silofs_pexec_ctx *pexec,
                              enum silofs_ltype ltype,
                              struct silofs_pnptr *out_pnptr)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_LNODE,
		.ltype = ltype,
	};

	return carve_pnptr_of(pexec, &stype, out_pnptr);
}
