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
#include <silofs/pstor.h>

struct silofs_vspace_ctx {
	const struct silofs_pexec_ctx *pexec;
	struct silofs_freevsqs *fvsqs;
	struct silofs_lcache *lcache;
	struct silofs_uber_info *ubi;
	enum silofs_ltype ltype;
};

static void
vsc_init(struct silofs_vspace_ctx *vs_ctx,
         const struct silofs_pexec_ctx *pexec, enum silofs_ltype ltype)
{
	vs_ctx->pexec  = pexec;
	vs_ctx->fvsqs  = pexec->fvsqs;
	vs_ctx->lcache = pexec->lcache;
	vs_ctx->ubi    = pexec->ubref->ubi;
	vs_ctx->ltype  = ltype;

	silofs_assert_ne(ltype, SILOFS_LTYPE_SPNODE);
}

static void vsc_init_by(struct silofs_vspace_ctx *vs_ctx,
                        const struct silofs_pexec_ctx *pexec,
                        const struct silofs_laddr *laddr)
{
	vsc_init(vs_ctx, pexec, laddr->ltype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vsc_apex_laddr(const struct silofs_vspace_ctx *vs_ctx,
                           struct silofs_laddr *out_laddr)
{
	struct silofs_uber_stat ust;
	ssize_t vsz, tip;

	silofs_ubi_stat_of(vs_ctx->ubi, vs_ctx->ltype, &ust);
	vsz = silofs_ltype_ssize(vs_ctx->ltype);
	tip = vsz * (ssize_t)ust.vn;

	silofs_laddr_setup(out_laddr, vs_ctx->ltype, tip);
}

static int vsc_stage_spnode_by(const struct silofs_vspace_ctx *vs_ctx,
                               const struct silofs_laddr *ref_laddr,
                               struct silofs_spnode_info **out_spi)
{
	int err;

	err = silofs_stage_spnode_by(vs_ctx->pexec, ref_laddr, out_spi);
	if (err) {
		log_err("failed to stage spnode of: ltype=%d off=%ld err=%d",
		        (int)ref_laddr->ltype, ref_laddr->off, err);
	}
	return err;
}

static int vsc_require_spnode2_of(const struct silofs_vspace_ctx *vs_ctx,
                                  const struct silofs_laddr *ref_laddr,
                                  struct silofs_spnode_info **out_spi)
{
	return silofs_require_spnode2_by(vs_ctx->pexec, ref_laddr, out_spi);
}

static int vsc_claim_free_vspace_by_fvsqs(struct silofs_vspace_ctx *vs_ctx,
                                          struct silofs_laddr *out_laddr)
{
	struct silofs_lspace_ref vspref;
	struct silofs_spnode_info *spi = nullptr;
	struct silofs_freevsqs *fvsqs  = vs_ctx->pexec->fvsqs;
	int err;

	err = silofs_freevsqs_pull(fvsqs, vs_ctx->ltype, out_laddr);
	return_if_err(err);

	err = vsc_stage_spnode_by(vs_ctx, out_laddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, out_laddr, &vspref);
	if (vspref.refcnt > 0) {
		log_err("cached free-vspace has active ref-count: "
		        "ltype=%d off=%ld refcnt=%zu",
		        (int)out_laddr->ltype, out_laddr->off, vspref.refcnt);
		return -SILOFS_EBUG;
	}
	silofs_spi_inc_allocated(spi, out_laddr);
	return 0;
}

static int vsc_claim_free_vspace_at(struct silofs_vspace_ctx *vs_ctx,
                                    const struct silofs_laddr *ref_laddr,
                                    struct silofs_laddr *out_laddr)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = vsc_require_spnode2_of(vs_ctx, ref_laddr, &spi);
	silofs_assert_ok(err); /* XXX RM */
	return_if_err(err);

	err = silofs_spi_find_free(spi, out_laddr);
	return_if_err(err);

	silofs_spi_inc_allocated(spi, out_laddr);
	return 0;
}

/*
 * TODO-0065: Define niter limit based on available space.
 *
 * Try to consume free space based of actual usage and total file-system size.
 * Define proper formula and derive 'niter' accordingly.
 */
static int vsc_claim_free_vspace_by_spnodes(struct silofs_vspace_ctx *vs_ctx,
                                            struct silofs_laddr *out_laddr)
{
	constexpr size_t niter = 1024;
	constexpr size_t nrefs = SILOFS_SPNODE_NREFS;
	struct silofs_laddr ref_laddr;
	int err;

	vsc_apex_laddr(vs_ctx, &ref_laddr);
	for (size_t i = 0; i < niter; ++i) {
		err = vsc_claim_free_vspace_at(vs_ctx, &ref_laddr, out_laddr);
		if (!err) {
			return 0;
		}
		if (err != -SILOFS_ENOSPC) {
			break;
		}
		silofs_laddr_advance(&ref_laddr, nrefs, &ref_laddr);
	}

	log_err("failed to calim free vspace: ltype=%d ref-off=%zd err=%d",
	        ref_laddr.ltype, ref_laddr.off, err);
	return err;
}

static int vsc_claim_free_vspace(struct silofs_vspace_ctx *vs_ctx,
                                 struct silofs_laddr *out_laddr)
{
	int ret;

	/* fast: try to allocated from in-memory pool of free vspace */
	ret = vsc_claim_free_vspace_by_fvsqs(vs_ctx, out_laddr);
	if (ret != 0) {
		/* slow: try to allocate using space-mapping nodes */
		ret = vsc_claim_free_vspace_by_spnodes(vs_ctx, out_laddr);
	}
	return ret;
}

int silofs_claim_free_vspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_ltype ltype,
                             struct silofs_laddr *out_laddr)
{
	struct silofs_vspace_ctx vs_ctx;

	vsc_init(&vs_ctx, pexec, ltype);
	return vsc_claim_free_vspace(&vs_ctx, out_laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vsc_decref_used_vspace(struct silofs_vspace_ctx *vs_ctx,
                                  const struct silofs_laddr *laddr)
{
	struct silofs_lspace_ref vspref;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = vsc_stage_spnode_by(vs_ctx, laddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, laddr, &vspref);
	if (vspref.refcnt == 0) {
		log_err("can not reclaim unused vspace: ltype=%d off=%ld",
		        laddr->ltype, laddr->off);
		return -SILOFS_EBUG;
	}
	silofs_spi_dec_allocated(spi, laddr);
	return 0;
}

static int vsc_incref_used_vspace(struct silofs_vspace_ctx *vs_ctx,
                                  const struct silofs_laddr *laddr)
{
	struct silofs_lspace_ref vspref;
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = vsc_stage_spnode_by(vs_ctx, laddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, laddr, &vspref);
	if (vspref.refcnt == 0) {
		log_err("can not incref unused vspace: ltype=%d off=%ld",
		        laddr->ltype, laddr->off);
		return -SILOFS_EBUG;
	}
	silofs_spi_inc_allocated(spi, laddr);
	return 0;
}

static int
vsc_update_used_vspace(struct silofs_vspace_ctx *vs_ctx,
                       const struct silofs_laddr *laddr, bool incref)
{
	int ret;

	if (incref) {
		ret = vsc_incref_used_vspace(vs_ctx, laddr);
	} else {
		ret = vsc_decref_used_vspace(vs_ctx, laddr);
	}
	return ret;
}

int silofs_update_used_vspace(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr *laddr, bool incref)
{
	struct silofs_vspace_ctx vs_ctx;

	vsc_init_by(&vs_ctx, pexec, laddr);
	return vsc_update_used_vspace(&vs_ctx, laddr, incref);
}

static int vsc_probe_vspace_ref(struct silofs_vspace_ctx *vs_ctx,
                                const struct silofs_laddr *laddr,
                                struct silofs_lspace_ref *out_vspref)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = vsc_stage_spnode_by(vs_ctx, laddr, &spi);
	return_if_err(err);

	silofs_spi_vspace_ref(spi, laddr, out_vspref);
	return 0;
}

int silofs_probe_lspace_ref(const struct silofs_pexec_ctx *pexec,
                            const struct silofs_laddr *laddr,
                            struct silofs_lspace_ref *out_vspref)
{
	struct silofs_vspace_ctx vs_ctx;

	vsc_init_by(&vs_ctx, pexec, laddr);
	return vsc_probe_vspace_ref(&vs_ctx, laddr, out_vspref);
}
