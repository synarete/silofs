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
#include <silofs/pv.h>

struct silofs_vspace_ctx {
	struct silofs_pexec_ctx *pexec;
	struct silofs_vcache *vcache;
	struct silofs_uber_info *ubi;
	enum silofs_vtype vtype;
};

static void vsc_init(struct silofs_vspace_ctx *vs_ctx,
                     struct silofs_pexec_ctx *pexec, enum silofs_vtype vtype)
{
	vs_ctx->pexec  = pexec;
	vs_ctx->vcache = pexec->vcache;
	vs_ctx->ubi    = pexec->ubref->ubi;
	vs_ctx->vtype  = vtype;

	silofs_assert_ne(vtype, SILOFS_VTYPE_SPNODE2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vsc_apex_ref_vaddr(const struct silofs_vspace_ctx *vs_ctx,
                               struct silofs_vaddr *out_ref_vaddr)
{
	struct silofs_uber_stat ust;
	ssize_t vsz, tip;

	silofs_ubi_stat_of(vs_ctx->ubi, vs_ctx->vtype, &ust);
	vsz = silofs_vtype_ssize(vs_ctx->vtype);
	tip = vsz * (ssize_t)ust.vn;

	silofs_vaddr_setup(out_ref_vaddr, vs_ctx->vtype, tip);
}

static int vsc_require_spnode_of(const struct silofs_vspace_ctx *vs_ctx,
                                 const struct silofs_vaddr *ref_vaddr,
                                 struct silofs_space_info **out_spi)
{
	return silofs_require_spnode2_of(vs_ctx->pexec, ref_vaddr, out_spi);
}

static int vsc_consume_free_vspace(struct silofs_vspace_ctx *vs_ctx,
                                   struct silofs_vaddr *out_vaddr)
{
	struct silofs_space_info *spi = nullptr;
	struct silofs_vaddr ref_vaddr;
	int err;

	vsc_apex_ref_vaddr(vs_ctx, &ref_vaddr);
	err = vsc_require_spnode_of(vs_ctx, &ref_vaddr, &spi);
	silofs_assert_ok(err);
	if (err) {
		return err;
	}
	err = silofs_spi_find_free(spi, out_vaddr);
	silofs_assert_ok(err);
	if (err) {
		return err;
	}
	silofs_spi_inc_allocated(spi, out_vaddr);
	return 0;
}

int silofs_consume_free_vspace(struct silofs_pexec_ctx *pexec,
                               enum silofs_vtype vtype,
                               struct silofs_vaddr *out_vaddr)
{
	struct silofs_vspace_ctx vs_ctx;

	vsc_init(&vs_ctx, pexec, vtype);
	return vsc_consume_free_vspace(&vs_ctx, out_vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vsc_stage_spnode_of(const struct silofs_vspace_ctx *vs_ctx,
                               const struct silofs_vaddr *ref_vaddr,
                               struct silofs_space_info **out_spi)
{
	return silofs_stage_spnode2_of(vs_ctx->pexec, ref_vaddr, out_spi);
}

static int vsc_reclaim_free_vspace(struct silofs_vspace_ctx *vs_ctx,
                                   const struct silofs_vaddr *vaddr)
{
	struct silofs_space_info *spi = nullptr;
	int err;

	err = vsc_stage_spnode_of(vs_ctx, vaddr, &spi);
	silofs_assert_ok(err);
	if (err) {
		return err;
	}
	silofs_spi_dec_allocated(spi, vaddr);
	return 0;
}

int silofs_reclaim_free_vspace(struct silofs_pexec_ctx *pexec,
                               const struct silofs_vaddr *vaddr)
{
	struct silofs_vspace_ctx vs_ctx;

	vsc_init(&vs_ctx, pexec, vaddr->vtype);
	return vsc_reclaim_free_vspace(&vs_ctx, vaddr);
}
