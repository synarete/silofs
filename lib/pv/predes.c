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
#include <silofs/nodes.h>
#include <silofs/pv.h>

struct silofs_predes_ctx {
	struct silofs_pexec_ctx *pexec;
	struct silofs_alloc *alloc;
	struct silofs_mdigest_hd *md_hd;
	struct silofs_cipher_hd *enc_ci_hd;
	const struct silofs_dirtyq *drq;
	struct silofs_destageq *dsq;
	struct silofs_uber_info *ubi;
	bool cleardirty;
};

static void
pdc_init(struct silofs_predes_ctx *pd_ctx, struct silofs_pexec_ctx *pexec,
         struct silofs_destageq *dsq, bool cleardirty)
{
	pd_ctx->pexec      = pexec;
	pd_ctx->alloc      = pexec->alloc;
	pd_ctx->md_hd      = pexec->md_hd;
	pd_ctx->enc_ci_hd  = pexec->enc_ci_hd;
	pd_ctx->drq        = &pexec->pcache->pc_dirtyq;
	pd_ctx->dsq        = dsq;
	pd_ctx->ubi        = pexec->ubref->ubi;
	pd_ctx->cleardirty = cleardirty;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pnode_info *pni_of(const struct silofs_dq_elem *dqe)
{
	return silofs_pni_from_dqe(dqe);
}

static const struct silofs_paddr *paddr_of(const struct silofs_dq_elem *dqe)
{
	const struct silofs_pnode_info *pni = pni_of(dqe);

	return silofs_pni_paddr(pni);
}

static bool ptype_is_uber(enum silofs_ptype ptype)
{
	return (ptype == SILOFS_PTYPE_UBER);
}

static bool pni_is_uber(const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = silofs_pni_paddr(pni);

	return ptype_is_uber(paddr->ptype);
}

static bool pni_is_parent_uber(const struct silofs_pnode_info *pni)
{
	const struct silofs_pnptr *parent = silofs_pni_parent(pni);

	return ptype_is_uber(parent->paddr.ptype);
}

static bool pni_has_pviewx(const struct silofs_pnode_info *pni)
{
	return (silofs_pni_pviewx(pni) != nullptr);
}

static size_t pni_pviewx_size(const struct silofs_pnode_info *pni)
{
	return silofs_pni_pview_size(pni);
}

static void pni_get_self(const struct silofs_pnode_info *pni,
                         struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr_assign(out_pnptr, silofs_pni_self(pni));
}

static void pni_update_ctag_by(struct silofs_pnode_info *pni,
                               const struct silofs_pnptr *pnptr)
{
	silofs_pni_update_ctag(pni, &pnptr->nmeta.ctag);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pdc_stage_btnode(const struct silofs_predes_ctx *pd_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_btnode_info **out_bti)
{
	return silofs_stage_btnode(pd_ctx->pexec, pnptr, out_bti);
}

static void pdc_populate_dsq(struct silofs_predes_ctx *pd_ctx)
{
	silofs_destageq_populate(pd_ctx->dsq, pd_ctx->drq);
}

static void pdc_depopulate_dsq(struct silofs_predes_ctx *pd_ctx)
{
	silofs_destageq_depopulate(pd_ctx->dsq);
}

static int pdc_attach_pviewx(const struct silofs_predes_ctx *pd_ctx,
                             struct silofs_pnode_info *pni)
{
	return silofs_ni_attach_viewx(&pni->pn_base, pd_ctx->alloc);
}

static void pdc_detach_pviewx(const struct silofs_predes_ctx *pd_ctx,
                              struct silofs_pnode_info *pni)
{
	silofs_ni_detach_viewx(&pni->pn_base, pd_ctx->alloc);
}

static int
pdc_encrypt_pviewx(const struct silofs_predes_ctx *pd_ctx,
                   struct silofs_pnode_info *pni, struct silofs_pnptr *pnptr)
{
	struct silofs_caad aad;
	const struct silofs_caad *caad = nullptr;
	struct silofs_ctag *ctag       = nullptr;

	if (!pni_is_uber(pni)) {
		silofs_calc_aad_by_paddr(pd_ctx->md_hd, &pnptr->paddr, &aad);
		caad = &aad;
		ctag = &pnptr->nmeta.ctag;
	}
	return silofs_encrypt_pview(pd_ctx->enc_ci_hd,      //
	                            &pnptr->nmeta.civkey,   //
	                            caad,                   //
	                            silofs_pni_pview(pni),  //
	                            silofs_pni_pviewx(pni), //
	                            ctag,                   //
	                            pni_pviewx_size(pni));
}

static int pdc_update_parent_uber(const struct silofs_predes_ctx *pd_ctx,
                                  const struct silofs_pnptr *pnptr)
{
	silofs_ubi_set_btroot(pd_ctx->ubi, pnptr);
	return 0;
}

static int pdc_update_parent_btnode(const struct silofs_predes_ctx *pd_ctx,
                                    const struct silofs_pnptr *parent,
                                    const struct silofs_pnptr *cur,
                                    const struct silofs_pnptr *alt)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = pdc_stage_btnode(pd_ctx, parent, &bti);
	if (err) {
		return err;
	}
	err = silofs_bti_relink(bti, cur, alt);
	if (err) {
		return err;
	}
	return 0;
}

static int pdc_update_parent(const struct silofs_predes_ctx *pd_ctx,
                             const struct silofs_pnode_info *pni,
                             const struct silofs_pnptr *alt)
{
	const struct silofs_pnptr *parent = silofs_pni_parent(pni);
	const struct silofs_pnptr *cur    = silofs_pni_parent(pni);
	int err;

	if (pni_is_parent_uber(pni)) {
		err = pdc_update_parent_uber(pd_ctx, alt);
	} else {
		err = pdc_update_parent_btnode(pd_ctx, parent, cur, alt);
	}
	return err;
}

static int pdc_prepare_pnode(const struct silofs_predes_ctx *pd_ctx,
                             struct silofs_pnode_info *pni)
{
	struct silofs_pnptr pnptr;
	int err = 0;

	if (pni_has_pviewx(pni)) {
		goto out; /* OK -- already set */
	}
	err = pdc_attach_pviewx(pd_ctx, pni);
	if (err) {
		goto out;
	}
	pni_get_self(pni, &pnptr);
	err = pdc_encrypt_pviewx(pd_ctx, pni, &pnptr);
	if (err) {
		goto out;
	}
	if (pni_is_uber(pni)) {
		goto out; /* OK */
	}
	err = pdc_update_parent(pd_ctx, pni, &pnptr);
	if (err) {
		goto out;
	}
	pni_update_ctag_by(pni, &pnptr);
out:
	return err;
}

static int pdc_cleanup_pnode(const struct silofs_predes_ctx *pd_ctx,
                             struct silofs_pnode_info *pni)
{
	if (pni_has_pviewx(pni)) {
		pdc_detach_pviewx(pd_ctx, pni);
	}
	if (pd_ctx->cleardirty) {
		silofs_pni_cleardirty(pni);
	}
	return 0;
}

static int prepare_by(struct silofs_dq_elem *dqe, void *userp)
{
	return pdc_prepare_pnode(userp, pni_of(dqe));
}

static int pdc_prepare_dsq(struct silofs_predes_ctx *pd_ctx)
{
	return silofs_destageq_foreach(pd_ctx->dsq, prepare_by, pd_ctx);
}

static int cleanup_by(struct silofs_dq_elem *dqe, void *userp)
{
	return pdc_cleanup_pnode(userp, pni_of(dqe));
}

static void pdc_cleanup_dsq(struct silofs_predes_ctx *pd_ctx)
{
	silofs_destageq_foreach(pd_ctx->dsq, cleanup_by, pd_ctx);
}

static void pdc_cleanup_depopulate_dsq(struct silofs_predes_ctx *pd_ctx)
{
	pdc_cleanup_dsq(pd_ctx);
	pdc_depopulate_dsq(pd_ctx);
}

static int compare_paddrs_of(const struct silofs_dq_elem *dqe1,
                             const struct silofs_dq_elem *dqe2)
{
	const struct silofs_paddr *paddr1 = paddr_of(dqe1);
	const struct silofs_paddr *paddr2 = paddr_of(dqe2);
	long cmp;

	cmp = silofs_paddr_compare(paddr1, paddr2);
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
}

static void pdc_sort_dsq(struct silofs_predes_ctx *pd_ctx)
{
	silofs_destageq_sort(pd_ctx->dsq, compare_paddrs_of);
}

static int pdc_pre_destage(struct silofs_predes_ctx *pd_ctx)
{
	int err;

	pdc_populate_dsq(pd_ctx);
	err = pdc_prepare_dsq(pd_ctx);
	if (err) {
		goto out_err;
	}
	pdc_sort_dsq(pd_ctx);
	return 0;
out_err:
	pdc_cleanup_depopulate_dsq(pd_ctx);
	return err;
}

int silofs_pre_destage(struct silofs_pexec_ctx *pexec,
                       struct silofs_destageq *dsq)
{
	struct silofs_predes_ctx pd_ctx;

	pdc_init(&pd_ctx, pexec, dsq, false);
	return pdc_pre_destage(&pd_ctx);
}

void silofs_post_destage(struct silofs_pexec_ctx *pexec,
                         struct silofs_destageq *dsq, bool cleardirty)
{
	struct silofs_predes_ctx pd_ctx;

	pdc_init(&pd_ctx, pexec, dsq, cleardirty);
	pdc_cleanup_depopulate_dsq(&pd_ctx);
}
