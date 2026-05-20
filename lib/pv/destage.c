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

struct silofs_destage_ctx {
	struct silofs_destageq dsq;
	struct silofs_pexec_ctx *pexec;
	struct silofs_alloc *alloc;
	struct silofs_mdigest_hd *md_hd;
	struct silofs_cipher_hd *enc_ci_hd;
	const struct silofs_dirtyq *drq;
	struct silofs_uber_info *ubi;
	struct silofs_dstor *dstor;
	bool cleardirty;
};

static void
dsc_init(struct silofs_destage_ctx *ds_ctx, struct silofs_pexec_ctx *pexec)
{
	silofs_destageq_init(&ds_ctx->dsq);
	ds_ctx->pexec      = pexec;
	ds_ctx->alloc      = pexec->alloc;
	ds_ctx->md_hd      = pexec->md_hd;
	ds_ctx->enc_ci_hd  = pexec->enc_ci_hd;
	ds_ctx->drq        = &pexec->pcache->pc_dirtyq;
	ds_ctx->ubi        = pexec->ubref->ubi;
	ds_ctx->dstor      = pexec->dstor;
	ds_ctx->cleardirty = false;
}

static void dsc_fini(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_fini(&ds_ctx->dsq);
	ds_ctx->pexec     = nullptr;
	ds_ctx->alloc     = nullptr;
	ds_ctx->md_hd     = nullptr;
	ds_ctx->enc_ci_hd = nullptr;
	ds_ctx->drq       = nullptr;
	ds_ctx->ubi       = nullptr;
	ds_ctx->dstor     = nullptr;
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

static const struct silofs_pview * //
pni_pview(const struct silofs_pnode_info *pni)
{
	return silofs_pni_pview(pni);
}

static const struct silofs_pview * //
pni_pviewx(const struct silofs_pnode_info *pni)
{
	return silofs_pni_pviewx(pni);
}

static struct silofs_pview * //
pni_mut_pviewx(const struct silofs_pnode_info *pni)
{
	return silofs_pni_pviewx(pni);
}

static bool pni_has_pviewx(const struct silofs_pnode_info *pni)
{
	return (pni_pviewx(pni) != nullptr);
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

static int dsc_stage_btnode(const struct silofs_destage_ctx *ds_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_btnode_info **out_bti)
{
	return silofs_stage_btnode(ds_ctx->pexec, pnptr, out_bti);
}

static void dsc_populate_dsq(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_populate(&ds_ctx->dsq, ds_ctx->drq);
}

static void dsc_depopulate_dsq(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_depopulate(&ds_ctx->dsq);
}

static int dsc_attach_pviewx(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_pnode_info *pni)
{
	return silofs_ni_attach_viewx(&pni->pn_base, ds_ctx->alloc);
}

static void dsc_detach_pviewx(const struct silofs_destage_ctx *ds_ctx,
                              struct silofs_pnode_info *pni)
{
	silofs_ni_detach_viewx(&pni->pn_base, ds_ctx->alloc);
}

static int
dsc_encrypt_pviewx(const struct silofs_destage_ctx *ds_ctx,
                   struct silofs_pnode_info *pni, struct silofs_pnptr *pnptr)
{
	struct silofs_caad aad;
	const struct silofs_caad *caad = nullptr;
	struct silofs_ctag *ctag       = nullptr;

	if (!pni_is_uber(pni)) {
		silofs_calc_aad_by_paddr(ds_ctx->md_hd, &pnptr->paddr, &aad);
		caad = &aad;
		ctag = &pnptr->nmeta.ctag;
	}
	return silofs_encrypt_pview(ds_ctx->enc_ci_hd,    //
	                            &pnptr->nmeta.civkey, //
	                            caad,                 //
	                            pni_pview(pni),       //
	                            pni_mut_pviewx(pni),  //
	                            ctag,                 //
	                            pni_pviewx_size(pni));
}

static int dsc_seal_encrypt_pviewx(const struct silofs_destage_ctx *ds_ctx,
                                   struct silofs_pnode_info *pni,
                                   struct silofs_pnptr *pnptr)
{
	silofs_seal_pnode(pni);
	return dsc_encrypt_pviewx(ds_ctx, pni, pnptr);
}

static int dsc_update_parent_uber(const struct silofs_destage_ctx *ds_ctx,
                                  const struct silofs_pnptr *pnptr)
{
	silofs_ubi_set_btroot(ds_ctx->ubi, pnptr);
	return 0;
}

static int dsc_update_parent_btnode(const struct silofs_destage_ctx *ds_ctx,
                                    const struct silofs_pnptr *parent,
                                    const struct silofs_pnptr *cur,
                                    const struct silofs_pnptr *alt)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = dsc_stage_btnode(ds_ctx, parent, &bti);
	if (err) {
		return err;
	}
	err = silofs_bti_relink(bti, cur, alt);
	if (err) {
		return err;
	}
	return 0;
}

static int dsc_update_parent(const struct silofs_destage_ctx *ds_ctx,
                             const struct silofs_pnode_info *pni,
                             const struct silofs_pnptr *alt)
{
	const struct silofs_pnptr *parent = silofs_pni_parent(pni);
	const struct silofs_pnptr *cur    = silofs_pni_parent(pni);
	int err;

	if (pni_is_parent_uber(pni)) {
		err = dsc_update_parent_uber(ds_ctx, alt);
	} else {
		err = dsc_update_parent_btnode(ds_ctx, parent, cur, alt);
	}
	return err;
}

static int dsc_prepare_pnode(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_pnode_info *pni)
{
	struct silofs_pnptr pnptr;
	int err = 0;

	if (pni_has_pviewx(pni)) {
		goto out; /* OK -- already set */
	}
	pni_get_self(pni, &pnptr);

	err = dsc_attach_pviewx(ds_ctx, pni);
	if (err) {
		goto out;
	}
	err = dsc_seal_encrypt_pviewx(ds_ctx, pni, &pnptr);
	if (err) {
		goto out;
	}
	if (pni_is_uber(pni)) {
		goto out; /* OK */
	}
	err = dsc_update_parent(ds_ctx, pni, &pnptr);
	if (err) {
		goto out;
	}
	pni_update_ctag_by(pni, &pnptr);
out:
	return err;
}

static int dsc_cleanup_pnode(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_pnode_info *pni)
{
	if (pni_has_pviewx(pni)) {
		dsc_detach_pviewx(ds_ctx, pni);
	}
	if (ds_ctx->cleardirty) {
		silofs_pni_cleardirty(pni);
	}
	return 0;
}

static int prepare_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_prepare_pnode(userp, pni_of(dqe));
}

static int dsc_prepare_dsq(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, prepare_by, ds_ctx);
}

static int dsc_populate_prepare_dsq(struct silofs_destage_ctx *ds_ctx)
{
	dsc_populate_dsq(ds_ctx);
	return dsc_prepare_dsq(ds_ctx);
}

static int cleanup_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_cleanup_pnode(userp, pni_of(dqe));
}

static void dsc_cleanup_dsq(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_foreach(&ds_ctx->dsq, cleanup_by, ds_ctx);
}

static void dsc_cleanup_depopulate_dsq(struct silofs_destage_ctx *ds_ctx)
{
	dsc_cleanup_dsq(ds_ctx);
	dsc_depopulate_dsq(ds_ctx);
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

static void dsc_sort_dsq(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_sort(&ds_ctx->dsq, compare_paddrs_of);
}

static int dsc_pre_destage(struct silofs_destage_ctx *ds_ctx)
{
	int err;

	/* Inject de-stage queue */
	err = dsc_populate_prepare_dsq(ds_ctx);
	if (err) {
		goto out_err;
	}
	/* Add newly introduced dirty btnodes */
	err = dsc_populate_prepare_dsq(ds_ctx);
	if (err) {
		goto out_err;
	}
	/* Finally, sort */
	dsc_sort_dsq(ds_ctx);
	return 0;
out_err:
	dsc_cleanup_depopulate_dsq(ds_ctx);
	return err;
}

static int dsc_commit_pnode(const struct silofs_destage_ctx *ds_ctx,
                            const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = silofs_pni_paddr(pni);

	return silofs_dstor_write_blob_at(ds_ctx->dstor,   //
	                                  &paddr->blobid,  //
	                                  paddr->pos,      //
	                                  pni_pviewx(pni), //
	                                  pni_pviewx_size(pni));
}

static int commit_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_commit_pnode(userp, pni_of(dqe));
}

static int dsc_commit_dsq(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, commit_by, ds_ctx);
}

int silofs_destage_pnodes(struct silofs_pexec_ctx *pexec)
{
	struct silofs_destage_ctx ds_ctx;
	int err;

	dsc_init(&ds_ctx, pexec);
	err = dsc_pre_destage(&ds_ctx);
	if (err) {
		goto out;
	}
	err = dsc_commit_dsq(&ds_ctx);
	if (err) {
		goto out;
	}
	ds_ctx.cleardirty = true;
out:
	dsc_cleanup_depopulate_dsq(&ds_ctx);
	dsc_fini(&ds_ctx);
	return err;
}
