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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/crypto.h>
#include <silofs/nodes.h>
#include <silofs/pv/uber.h>
#include <silofs/pv/carve.h>
#include <silofs/run.h>

static const struct silofs_layerid *
top_layerid(const struct silofs_pexec_ctx *pexec)
{
	const struct silofs_uber_info *ubi = pexec->ubi;

	silofs_assert_not_null(ubi);
	return silofs_ubi_layerid(ubi);
}

static void gen_layerid(const struct silofs_pexec_ctx *pexec,
                        struct silofs_layerid *out_layerid)
{
	silofs_generate_layerid(pexec->prng, out_layerid);
}

static void gen_uniqid(const struct silofs_pexec_ctx *pexec,
                       struct silofs_uniqid *out_uniqid)
{
	silofs_generate_uniqid(pexec->prng, out_uniqid);
}

static void gen_civkey(const struct silofs_pexec_ctx *pexec,
                       struct silofs_civkey *out_civkey)
{
	silofs_generate_civkey(pexec->prng, out_civkey);
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
		.vtype = SILOFS_VTYPE_NONE,
	};

	silofs_blobid_init(&blobid, &stype, nullptr, nullptr);
	gen_layerid(pexec, &blobid.layerid);
	gen_uniqid(pexec, &blobid.uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);
	return gen_pnptr_at(pexec, &paddr, out_pnptr);
}

int silofs_carve_base_btspace(const struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype vtype,
                              struct silofs_pnptr *out_pnptr)
{
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.vtype = vtype,
	};

	silofs_blobid_init(&blobid, &stype, top_layerid(pexec), nullptr);
	gen_uniqid(pexec, &blobid.uniqid);
	silofs_paddr_init(&paddr, &blobid, 0);

	return gen_pnptr_at(pexec, &paddr, out_pnptr);
}

int silofs_carve_base_vspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_vtype vtype,
                             struct silofs_paddr *out_paddr)
{
	struct silofs_blobid blobid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_VNODE,
		.vtype = vtype,
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
	struct silofs_spdesc spdesc[2];
	struct silofs_uber_info *ubi = pexec->ubi;

	silofs_ubi_spdesc_of(ubi, stype, &spdesc[0]);
	silofs_paddr_next(&spdesc[0].end, out_paddr);

	silofs_spdesc_setup(&spdesc[1], &spdesc[0].beg, out_paddr);
	silofs_ubi_update_spdesc(ubi, &spdesc[1]);
}

static int carve_next_pnptr_of(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_stype *stype,
                               struct silofs_pnptr *out_pnptr)
{
	struct silofs_paddr paddr;

	carve_next_space_of(pexec, stype, &paddr);
	return gen_pnptr_at(pexec, &paddr, out_pnptr);
}

int silofs_carve_next_btspace(const struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype vtype,
                              struct silofs_pnptr *out_pnptr)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.vtype = vtype,
	};

	return carve_next_pnptr_of(pexec, &stype, out_pnptr);
}

int silofs_carve_next_vspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_vtype vtype,
                             struct silofs_pnptr *out_pnptr)
{
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_VNODE,
		.vtype = vtype,
	};

	return carve_next_pnptr_of(pexec, &stype, out_pnptr);
}
