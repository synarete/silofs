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
top_layerid(const struct silofs_core_refs *corefs)
{
	const struct silofs_uber_info *ubi = corefs->fsroot->ubi;

	silofs_assert_not_null(ubi);
	return silofs_ubi_layerid(ubi);
}

static void gen_layerid(const struct silofs_core_refs *corefs,
                        struct silofs_layerid *out_layerid)
{
	generate_layerid(out_layerid);
	silofs_unused(corefs);
}

static void gen_uniqid(const struct silofs_core_refs *corefs,
                       struct silofs_uniqid *out_uniqid)
{
	generate_uniqid(corefs->prng, out_uniqid);
}

static void gen_civkey(const struct silofs_core_refs *corefs,
                       struct silofs_civkey *out_civkey)
{
	generate_ckey(corefs->prng, &out_civkey->key);
	generate_civ(corefs->prng, &out_civkey->iv);
}

static int
gen_pnptr_at(const struct silofs_core_refs *corefs,
             const struct silofs_paddr *paddr, struct silofs_pnptr *out_pnptr)
{
	struct silofs_civkey civkey;

	gen_civkey(corefs, &civkey);
	silofs_pnptr_setup(out_pnptr, paddr, &civkey);

	return 0;
}

int silofs_carve_base_ubspace(const struct silofs_core_refs *corefs,
                              struct silofs_pnptr *out_pnptr)
{
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_UBER,
		.ltype = SILOFS_LTYPE_NONE,
	};

	silofs_blobid_init(&blobid, &stype, nullptr, nullptr);
	gen_layerid(corefs, &blobid.layerid);
	gen_uniqid(corefs, &blobid.uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);

	return gen_pnptr_at(corefs, &paddr, out_pnptr);
}

int silofs_carve_base_btspace(const struct silofs_core_refs *corefs,
                              enum silofs_ltype ltype,
                              struct silofs_pnptr *out_pnptr)
{
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.ltype = ltype,
	};

	silofs_blobid_init(&blobid, &stype, top_layerid(corefs), nullptr);
	gen_uniqid(corefs, &blobid.uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);
	silofs_ubi_set_nextfree(corefs->fsroot->ubi, &paddr);

	return gen_pnptr_at(corefs, &paddr, out_pnptr);
}

int silofs_carve_base_lspace(const struct silofs_core_refs *corefs,
                             enum silofs_ltype ltype,
                             struct silofs_paddr *out_paddr)
{
	struct silofs_blobid blobid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_LNODE,
		.ltype = ltype,
	};

	silofs_blobid_init(&blobid, &stype, top_layerid(corefs), nullptr);
	gen_uniqid(corefs, &blobid.uniqid);

	silofs_paddr_init(out_paddr, &blobid, 0);
	silofs_ubi_set_nextfree(corefs->fsroot->ubi, out_paddr);

	return 0;
}

static void carve_next_space_of(const struct silofs_core_refs *corefs,
                                const struct silofs_stype *stype,
                                struct silofs_paddr *out_paddr)
{
	silofs_ubi_consume_nextfree(corefs->fsroot->ubi, stype, out_paddr);
}

static bool try_carve_free_space_of(const struct silofs_core_refs *corefs,
                                    const struct silofs_stype *stype,
                                    struct silofs_paddr *out_paddr)
{
	int err;

	err = silofs_pspools_pull(corefs->pspools, stype, out_paddr);
	return (err == 0);
}

static int carve_pnptr_of(const struct silofs_core_refs *corefs,
                          const struct silofs_stype *stype,
                          struct silofs_pnptr *out_pnptr)
{
	struct silofs_paddr paddr;

	if (!try_carve_free_space_of(corefs, stype, &paddr)) {
		carve_next_space_of(corefs, stype, &paddr);
	}
	return gen_pnptr_at(corefs, &paddr, out_pnptr);
}

int silofs_carve_btspace_pnptr(const struct silofs_core_refs *corefs,
                               enum silofs_ltype ltype,
                               struct silofs_pnptr *out_pnptr)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.ltype = ltype,
	};

	return carve_pnptr_of(corefs, &stype, out_pnptr);
}

int silofs_carve_lspace_pnptr(const struct silofs_core_refs *corefs,
                              enum silofs_ltype ltype,
                              struct silofs_pnptr *out_pnptr)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_LNODE,
		.ltype = ltype,
	};

	return carve_pnptr_of(corefs, &stype, out_pnptr);
}
