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
#include <silofs/ondisk.h>
#include <silofs/pstor.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ptype_isuber(enum silofs_ptype ptype)
{
	return (ptype == SILOFS_PTYPE_UBER);
}

static bool ptype_isbtnode(enum silofs_ptype ptype)
{
	return (ptype == SILOFS_PTYPE_BTNODE);
}

static bool pni_staged_ok(const struct silofs_pnode_info *pni)
{
	return (pni->pn_flags & SILOFS_PNODEF_STAGED_OK) > 0;
}

static void pni_set_staged_ok(struct silofs_pnode_info *pni)
{
	pni->pn_flags |= SILOFS_PNODEF_STAGED_OK;
}

static struct silofs_pnode_info * //
pni_of(const struct silofs_dq_elem *dqe)
{
	return silofs_pni_from_dqe(dqe);
}

static const struct silofs_paddr * //
pni_paddr(const struct silofs_pnode_info *pni)
{
	return silofs_pni_paddr(pni);
}

static bool pni_isuber(const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = pni_paddr(pni);

	return ptype_isuber(paddr->ptype);
}

static bool pni_isbtnode(const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = pni_paddr(pni);

	return ptype_isbtnode(paddr->ptype);
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

static size_t pni_pview_size(const struct silofs_pnode_info *pni)
{
	return silofs_ni_view_size(&pni->pn_ni);
}

static const struct silofs_pnptr * //
pni_self(const struct silofs_pnode_info *pni)
{
	return silofs_pni_self(pni);
}

static void pni_next_self(const struct silofs_pnode_info *pni,
                          struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr_assign(out_pnptr, pni_self(pni));
	silofs_ctag_assign(&out_pnptr->nmeta.ctag, &pni->pn_ctag);
}

static void
pni_update_ctag(struct silofs_pnode_info *pni, const struct silofs_ctag *ctag)
{
	silofs_pni_update_ctag(pni, ctag);
}

static void pni_apply_ctag(struct silofs_pnode_info *pni)
{
	silofs_pni_apply_ctag(pni);
}

static int
pni_attach_viewx(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	return silofs_ni_attach_viewx(&pni->pn_ni, alloc);
}

static void
pni_detach_viewx(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	silofs_ni_detach_viewx(&pni->pn_ni, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_btnode_info * //
bti_of(const struct silofs_pnode_info *pni)
{
	silofs_assert_not_null(pni);
	silofs_assert_eq(pni->pn_self.paddr.ptype, SILOFS_PTYPE_BTNODE);

	return silofs_bti_from_pni(pni);
}

static const struct silofs_pnptr * //
bti_self(const struct silofs_btnode_info *bti)
{
	return silofs_bti_self(bti);
}

static const struct silofs_blobid *bti_blobid(struct silofs_btnode_info *bti)
{
	return silofs_pni_blobid(&bti->btn_pni);
}

static uint32_t bti_height(const struct silofs_btnode_info *bti)
{
	const size_t height = silofs_bti_height(bti);

	silofs_assert_gt(height, 0);
	silofs_assert_le(height, SILOFS_BTREE_HEIGHT_MAX);
	return (uint32_t)height;
}

static const struct silofs_paddr * //
bti_paddr(const struct silofs_btnode_info *bti)
{
	return pni_paddr(&bti->btn_pni);
}

static void bti_base_laddr(const struct silofs_btnode_info *bti,
                           struct silofs_laddr *out_laddr)
{
	const uint64_t minkey   = silofs_bti_minkey(bti);
	enum silofs_ltype ltype = silofs_bti_vspace(bti);

	silofs_assert_lt(minkey, (UINT64_MAX / 2));
	silofs_laddr_setup(out_laddr, ltype, (off_t)minkey);
}

static bool bti_isroot(const struct silofs_btnode_info *bti)
{
	return silofs_bti_marked_root(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info * //
lni_of(const struct silofs_dq_elem *dqe)
{
	return silofs_lni_from_dqe(dqe);
}

static const struct silofs_laddr * //
lni_laddr(const struct silofs_lnode_info *lni)
{
	return silofs_lni_laddr(lni);
}

static const struct silofs_lview * //
lni_lviewx(const struct silofs_lnode_info *lni)
{
	return silofs_lni_lviewx(lni);
}

static struct silofs_lview * //
lni_mut_lviewx(const struct silofs_lnode_info *lni)
{
	return silofs_lni_lviewx(lni);
}

static bool lni_has_lviewx(const struct silofs_lnode_info *lni)
{
	return (lni_lviewx(lni) != nullptr);
}

static size_t lni_lview_size(const struct silofs_lnode_info *lni)
{
	return silofs_ni_view_size(&lni->ln_ni);
}

static const struct silofs_paddr *
lni_curr_paddr(const struct silofs_lnode_info *lni)
{
	return &lni->ln_curr_paddr;
}

static void lni_update_curr_paddr(struct silofs_lnode_info *lni,
                                  const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&lni->ln_curr_paddr, paddr);
}

static int
lni_attach_viewx(struct silofs_lnode_info *lni, struct silofs_alloc *alloc)
{
	return silofs_ni_attach_viewx(&lni->ln_ni, alloc);
}

static void
lni_detach_viewx(struct silofs_lnode_info *lni, struct silofs_alloc *alloc)
{
	silofs_ni_detach_viewx(&lni->ln_ni, alloc);
}

static bool lni_has_asyncwr(const struct silofs_lnode_info *lni)
{
	const int asyncwr = silofs_atomic_sqc_get(&lni->ln_asyncwr);

	return (asyncwr > 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_stage_ctx {
	const struct silofs_core_refs *corefs;
	struct silofs_alloc *alloc;
	struct silofs_dstor *dstor;
	struct silofs_pcache *pcache;
	struct silofs_lcache *lcache;
	enum silofs_lspacef lspf;
};

static void stc_init(struct silofs_stage_ctx *st_ctx,
                     const struct silofs_core_refs *corefs)
{
	st_ctx->corefs = corefs;
	st_ctx->alloc  = corefs->alloc;
	st_ctx->dstor  = corefs->dstor;
	st_ctx->pcache = corefs->pcache;
	st_ctx->lcache = corefs->lcache;
	st_ctx->lspf   = SILOFS_LSPACEF_NONE;
}

static void
stc_init2(struct silofs_stage_ctx *st_ctx,
          const struct silofs_core_refs *corefs, enum silofs_lspacef lspf)
{
	stc_init(st_ctx, corefs);
	st_ctx->lspf = lspf;
}

static void stc_fini(struct silofs_stage_ctx *st_ctx)
{
	st_ctx->corefs = nullptr;
}

static int stc_attach_pviewx(const struct silofs_stage_ctx *st_ctx,
                             struct silofs_pnode_info *pni)
{
	return pni_attach_viewx(pni, st_ctx->alloc);
}

static void stc_detach_pviewx(const struct silofs_stage_ctx *st_ctx,
                              struct silofs_pnode_info *pni)
{
	pni_detach_viewx(pni, st_ctx->alloc);
}

static int stc_attach_lviewx(const struct silofs_stage_ctx *st_ctx,
                             struct silofs_lnode_info *lni)
{
	return lni_attach_viewx(lni, st_ctx->alloc);
}

static void stc_detach_lviewx(const struct silofs_stage_ctx *st_ctx,
                              struct silofs_lnode_info *lni)
{
	lni_detach_viewx(lni, st_ctx->alloc);
}

static int stc_require_paddr(const struct silofs_stage_ctx *st_ctx,
                             const struct silofs_paddr *paddr)
{
	struct silofs_paddr next;

	silofs_paddr_next(paddr, &next);
	return silofs_dstor_require_blob_at(st_ctx->dstor, //
	                                    &next.blobid, next.pos);
}

static int stc_require_paddr_of(const struct silofs_stage_ctx *st_ctx,
                                const struct silofs_pnptr *pnptr)
{
	return stc_require_paddr(st_ctx, &pnptr->paddr);
}

static int stc_access_blob_at(const struct silofs_stage_ctx *st_ctx,
                              const struct silofs_blobid *blobid, off_t pos)
{
	return silofs_dstor_access_blob_at(st_ctx->dstor, blobid, pos);
}

static int stc_access_blob(const struct silofs_stage_ctx *st_ctx,
                           const struct silofs_blobid *blobid)
{
	return stc_access_blob_at(st_ctx, blobid, 0);
}

static int stc_access_pnode(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_paddr *paddr)
{
	struct silofs_paddr next;

	silofs_paddr_next(paddr, &next);
	return stc_access_blob_at(st_ctx, &next.blobid, next.pos);
}

static int stc_access_pnode_of(const struct silofs_stage_ctx *st_ctx,
                               const struct silofs_pnptr *pnptr)
{
	return stc_access_pnode(st_ctx, &pnptr->paddr);
}

static int stc_access_blob_of(const struct silofs_stage_ctx *st_ctx,
                              const struct silofs_pnptr *pnptr)
{
	return stc_access_blob(st_ctx, &pnptr->paddr.blobid);
}

static int
stc_fetch_node_at(const struct silofs_stage_ctx *st_ctx,
                  const struct silofs_paddr *paddr, void *buf, size_t bufsz)
{
	return silofs_dstor_read_blob_at(st_ctx->dstor, &paddr->blobid,
	                                 paddr->pos, buf, bufsz);
}

static int
stc_fetch_pnode(struct silofs_stage_ctx *st_ctx, struct silofs_pnode_info *pni)
{
	return stc_fetch_node_at(st_ctx, pni_paddr(pni), pni_mut_pviewx(pni),
	                         pni_pview_size(pni));
}

static int stc_decrypt_pnode(struct silofs_stage_ctx *st_ctx,
                             const struct silofs_pnode_info *pni)
{
	const struct silofs_pnptr *pnptr = pni_self(pni);
	const struct silofs_ctag *ctag   = //
		pni_isuber(pni) ? nullptr : &pnptr->nmeta.ctag;

	return silofs_decrypt_pnode(st_ctx->corefs, pni, ctag);
}

static int stc_decrypt_verify_pnode(struct silofs_stage_ctx *st_ctx,
                                    struct silofs_pnode_info *pni)
{
	int err;

	err = stc_decrypt_pnode(st_ctx, pni);
	return_if_err(err);

	err = silofs_verify_pview_of(pni);
	return_if_err(err);

	return 0;
}

static int stc_fetch_decrypt_pnode(struct silofs_stage_ctx *st_ctx,
                                   struct silofs_pnode_info *pni)
{
	int err;

	err = stc_attach_pviewx(st_ctx, pni);
	goto_out_if_err(err);

	err = stc_fetch_pnode(st_ctx, pni);
	goto_out_if_err(err);

	err = stc_decrypt_verify_pnode(st_ctx, pni);
	goto_out_if_err(err);
out:
	stc_detach_pviewx(st_ctx, pni);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_create_cached_pnode(const struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_pnptr *pnptr,
                                   struct silofs_pnode_info **out_pni)
{
	*out_pni = silofs_pcache_create_pnode(st_ctx->pcache, pnptr);

	return (*out_pni == nullptr) ? -SILOFS_ENOMEM : 0;
}

static int stc_lookup_cached_pnode(const struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_pnode_info **out_pni)
{
	*out_pni = silofs_pcache_lookup_pnode(st_ctx->pcache, paddr);

	return (*out_pni == nullptr) ? -SILOFS_ENOENT : 0;
}

static void stc_forget_cached_pnode(const struct silofs_stage_ctx *st_ctx,
                                    struct silofs_pnode_info *pni)
{
	silofs_pcache_delete_pnode(st_ctx->pcache, pni);
}

static int stc_spawn_pnode(const struct silofs_stage_ctx *st_ctx,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_pnode_info **out_pni)
{
	int err;

	err = stc_require_paddr_of(st_ctx, pnptr);
	return_if_err(err);

	err = stc_create_cached_pnode(st_ctx, pnptr, out_pni);
	return_if_err(err);

	return 0;
}

static int stc_stage_pnode_at(struct silofs_stage_ctx *st_ctx,
                              const struct silofs_pnptr *pnptr,
                              struct silofs_pnode_info **out_pni)
{
	int err;

	err = stc_access_pnode_of(st_ctx, pnptr);
	return_if_err(err);

	err = stc_create_cached_pnode(st_ctx, pnptr, out_pni);
	return_if_err(err);

	err = stc_fetch_decrypt_pnode(st_ctx, *out_pni);
	return_if_err(err);

	return 0;
}

static int stc_stage_pnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_pnode_info **out_pni)
{
	int err;

	err = stc_lookup_cached_pnode(st_ctx, &pnptr->paddr, out_pni);
	if (err) { /* cache miss */
		err = stc_stage_pnode_at(st_ctx, pnptr, out_pni);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_validate_staged_uber(struct silofs_stage_ctx *st_ctx,
                                    struct silofs_uber_info *ubi)
{
	struct silofs_pnode_info *pni = &ubi->ub_pni;
	int err;

	if (pni_staged_ok(pni)) {
		return 0;
	}
	err = silofs_validate_uber(ubi);
	if (err) {
		stc_forget_cached_pnode(st_ctx, pni);
		return err;
	}
	pni_set_staged_ok(pni);
	return 0;
}

static void stc_update_spawned_uber(const struct silofs_stage_ctx *st_ctx,
                                    struct silofs_uber_info *ubi)
{
	silofs_ubi_update_spawned(ubi);
	silofs_unused(st_ctx);
}

static int stc_spawn_uber(const struct silofs_stage_ctx *st_ctx,
                          const struct silofs_pnptr *pnptr,
                          struct silofs_uber_info **out_ubi)
{
	struct silofs_pnode_info *pni;
	int err;

	err = stc_spawn_pnode(st_ctx, pnptr, &pni);
	return_if_err(err);

	*out_ubi = silofs_ubi_from_pni(pni);
	stc_update_spawned_uber(st_ctx, *out_ubi);
	return 0;
}

int silofs_spawn_uber(const struct silofs_core_refs *corefs,
                      const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_spawn_uber(&st_ctx, pnptr, out_ubi);
	stc_fini(&st_ctx);
	return err;
}

static int stc_stage_uber(struct silofs_stage_ctx *st_ctx,
                          const struct silofs_pnptr *pnptr,
                          struct silofs_uber_info **out_ubi)
{
	struct silofs_pnode_info *pni = nullptr;
	int err;

	silofs_assert_eq(pnptr->paddr.ptype, SILOFS_PTYPE_UBER);
	err = stc_stage_pnode(st_ctx, pnptr, &pni);
	return_if_err(err);

	*out_ubi = silofs_ubi_from_pni(pni);

	err = stc_validate_staged_uber(st_ctx, *out_ubi);
	return_if_err(err);

	return 0;
}

int silofs_stage_uber(const struct silofs_core_refs *corefs,
                      const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_stage_uber(&st_ctx, pnptr, out_ubi);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_validate_staged_bldesc(struct silofs_stage_ctx *st_ctx,
                                      struct silofs_bldesc_info *bdi)
{
	struct silofs_pnode_info *pni = &bdi->bld_pni;
	int err;

	if (pni_staged_ok(pni)) {
		return 0;
	}
	err = silofs_validate_bldesc(bdi);
	if (err) {
		stc_forget_cached_pnode(st_ctx, pni);
		return err;
	}
	pni_set_staged_ok(pni);
	return 0;
}

static void stc_update_spawned_bldesc(const struct silofs_stage_ctx *st_ctx,
                                      struct silofs_bldesc_info *bdi)
{
	silofs_bdi_ignite(bdi);
	silofs_unused(st_ctx);
}

static int stc_spawn_bldesc(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_bldesc_info **out_bdi)
{
	struct silofs_pnode_info *pni = nullptr;
	int err;

	err = stc_spawn_pnode(st_ctx, pnptr, &pni);
	return_if_err(err);

	*out_bdi = silofs_bdi_from_pni(pni);
	stc_update_spawned_bldesc(st_ctx, *out_bdi);
	return 0;
}

int silofs_spawn_bldesc(const struct silofs_core_refs *corefs,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_bldesc_info **out_bdi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_spawn_bldesc(&st_ctx, pnptr, out_bdi);
	stc_fini(&st_ctx);
	return err;
}

static int stc_stage_bldesc(struct silofs_stage_ctx *st_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_bldesc_info **out_bdi)
{
	struct silofs_pnode_info *pni = nullptr;
	int err;

	silofs_assert_eq(pnptr->paddr.ptype, SILOFS_PTYPE_BLDESC);
	err = stc_stage_pnode(st_ctx, pnptr, &pni);
	return_if_err(err);

	*out_bdi = silofs_bdi_from_pni(pni);

	err = stc_validate_staged_bldesc(st_ctx, *out_bdi);
	return_if_err(err);

	return 0;
}

int silofs_stage_bldesc(const struct silofs_core_refs *corefs,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_bldesc_info **out_bdi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_stage_bldesc(&st_ctx, pnptr, out_bdi);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_validate_staged_btnode(struct silofs_stage_ctx *st_ctx,
                                      struct silofs_btnode_info *bti)
{
	struct silofs_pnode_info *pni = &bti->btn_pni;
	int err;

	if (pni_staged_ok(pni)) {
		return 0;
	}
	err = silofs_validate_btnode(bti);
	if (err) {
		stc_forget_cached_pnode(st_ctx, pni);
		return err;
	}
	pni_set_staged_ok(pni);
	return 0;
}

static struct silofs_uber_info *stc_ubi(const struct silofs_stage_ctx *st_ctx)
{
	silofs_assert_not_null(st_ctx->corefs->fsroot->ubi);

	return st_ctx->corefs->fsroot->ubi;
}

static void stc_update_spawned_btnode(const struct silofs_stage_ctx *st_ctx,
                                      struct silofs_btnode_info *bti)
{
	silofs_bti_update_spawned(bti);
	silofs_ubi_inc_count_by(stc_ubi(st_ctx), bti_blobid(bti));
}

static int stc_spawn_btnode(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_pnode_info *pni = nullptr;
	int err;

	err = stc_spawn_pnode(st_ctx, pnptr, &pni);
	return_if_err(err);

	*out_bti = silofs_bti_from_pni(pni);
	stc_update_spawned_btnode(st_ctx, *out_bti);
	return 0;
}

int silofs_spawn_btnode(const struct silofs_core_refs *corefs,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_btnode_info **out_bti)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_spawn_btnode(&st_ctx, pnptr, out_bti);
	stc_fini(&st_ctx);
	return err;
}

static int stc_stage_btnode(struct silofs_stage_ctx *st_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_pnode_info *pni = nullptr;
	int err;

	err = stc_stage_pnode(st_ctx, pnptr, &pni);
	return_if_err(err);

	*out_bti = silofs_bti_from_pni(pni);

	err = stc_validate_staged_btnode(st_ctx, *out_bti);
	return_if_err(err);

	return 0;
}

int silofs_stage_btnode(const struct silofs_core_refs *corefs,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_btnode_info **out_bti)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_stage_btnode(&st_ctx, pnptr, out_bti);
	stc_fini(&st_ctx);
	return err;
}

int silofs_require_paddr(const struct silofs_core_refs *corefs,
                         const struct silofs_paddr *paddr)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_require_paddr(&st_ctx, paddr);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_lookup_cached_lnode(const struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_laddr *laddr,
                                   struct silofs_lnode_info **out_lni)
{
	*out_lni = silofs_lcache_lookup_lnode(st_ctx->lcache, laddr);

	return (*out_lni == nullptr) ? -SILOFS_ENOENT : 0;
}

static int stc_create_cached_lnode(const struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_laddr *laddr,
                                   struct silofs_lnode_info **out_lni)
{
	*out_lni = silofs_lcache_create_lnode(st_ctx->lcache, laddr);

	return (*out_lni == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void stc_update_claimed_lnode(const struct silofs_stage_ctx *st_ctx,
                                     const struct silofs_laddr *laddr,
                                     const struct silofs_pnptr *pnptr)
{
	silofs_unused(laddr);
	silofs_ubi_inc_count_by(stc_ubi(st_ctx), &pnptr->paddr.blobid);
}

static void stc_update_spawned_lnode(const struct silofs_stage_ctx *st_ctx,
                                     struct silofs_lnode_info *lni,
                                     const struct silofs_pnptr *pnptr)
{
	stc_update_claimed_lnode(st_ctx, lni_laddr(lni), pnptr);
}

static int stc_spawn_lnode(const struct silofs_stage_ctx *st_ctx,
                           const struct silofs_laddr *laddr,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_lnode_info **out_lni)
{
	int err;

	err = stc_require_paddr_of(st_ctx, pnptr);
	return_if_err(err);

	err = stc_create_cached_lnode(st_ctx, laddr, out_lni);
	return_if_err(err);

	stc_update_spawned_lnode(st_ctx, *out_lni, pnptr);
	return 0;
}

int silofs_spawn_lnode_with(const struct silofs_core_refs *corefs,
                            const struct silofs_laddr *laddr,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_lnode_info **out_lni)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_spawn_lnode(&st_ctx, laddr, pnptr, out_lni);
	stc_fini(&st_ctx);
	return err;
}

static int stc_claim_lnode_pspace(const struct silofs_stage_ctx *st_ctx,
                                  const struct silofs_laddr *laddr,
                                  const struct silofs_pnptr *pnptr)
{
	int err;

	err = stc_require_paddr_of(st_ctx, pnptr);
	return_if_err(err);

	stc_update_claimed_lnode(st_ctx, laddr, pnptr);
	return 0;
}

int silofs_claim_lnode_pspace(const struct silofs_core_refs *corefs,
                              const struct silofs_laddr *laddr,
                              const struct silofs_pnptr *pnptr)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_claim_lnode_pspace(&st_ctx, laddr, pnptr);
	stc_fini(&st_ctx);
	return err;
}

static int stc_fetch_lnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_lnode_info *lni,
                           const struct silofs_paddr *paddr)
{
	return stc_fetch_node_at(st_ctx, paddr, lni_mut_lviewx(lni),
	                         lni_lview_size(lni));
}

static int stc_decrypt_lnode(struct silofs_stage_ctx *st_ctx,
                             const struct silofs_pnptr *pnptr,
                             const struct silofs_lnode_info *lni)
{
	const struct silofs_ctag *ctag = &pnptr->nmeta.ctag;

	return silofs_decrypt_lnode(st_ctx->corefs, lni, pnptr, ctag);
}

static int stc_decrypt_verify_lnode(struct silofs_stage_ctx *st_ctx,
                                    const struct silofs_pnptr *pnptr,
                                    struct silofs_lnode_info *lni)
{
	int err;

	err = stc_decrypt_lnode(st_ctx, pnptr, lni);
	return_if_err(err);

	err = silofs_verify_lview_of(lni);
	return_if_err(err);

	return 0;
}

static int stc_fetch_decrypt_lnode(struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_pnptr *pnptr,
                                   struct silofs_lnode_info *lni)
{
	int err;

	err = stc_attach_lviewx(st_ctx, lni);
	goto_out_if_err(err);

	err = stc_fetch_lnode(st_ctx, lni, &pnptr->paddr);
	goto_out_if_err(err);

	err = stc_decrypt_verify_lnode(st_ctx, pnptr, lni);
	goto_out_if_err(err);
out:
	stc_detach_lviewx(st_ctx, lni);
	return err;
}

static int stc_stage_lnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_laddr *laddr,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_lnode_info **out_lni)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = stc_lookup_cached_lnode(st_ctx, laddr, &lni);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}

	err = stc_access_pnode_of(st_ctx, pnptr);
	return_if_err(err);

	err = stc_create_cached_lnode(st_ctx, laddr, &lni);
	return_if_err(err);

	if (st_ctx->lspf & SILOFS_LSPACEF_UNWRITTEN) {
		goto out_ok;
	}

	err = stc_fetch_decrypt_lnode(st_ctx, pnptr, lni);
	return_if_err(err);

out_ok:
	*out_lni = lni;
	return 0;
}

int silofs_stage_lnode_with(const struct silofs_core_refs *corefs,
                            const struct silofs_laddr *laddr,
                            const struct silofs_pnptr *pnptr,
                            enum silofs_lspacef lspf,
                            struct silofs_lnode_info **out_lni)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init2(&st_ctx, corefs, lspf);
	err = stc_stage_lnode(&st_ctx, laddr, pnptr, out_lni);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stc_cleardirty_cached_lnode(struct silofs_stage_ctx *st_ctx,
                                        const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = stc_lookup_cached_lnode(st_ctx, laddr, &lni);
	if (!err) {
		silofs_lni_cleardirty(lni);
	}
}

static void stc_detach_lspace(struct silofs_stage_ctx *st_ctx,
                              const struct silofs_pnptr *pnptr)
{
	const struct silofs_blobid *blobid = &pnptr->paddr.blobid;

	silofs_assert_eq(blobid->stype.ptype, SILOFS_PTYPE_LNODE);

	silofs_ubi_dec_count_by(stc_ubi(st_ctx), blobid);
}

static int stc_detach_lnode(struct silofs_stage_ctx *st_ctx,
                            const struct silofs_laddr *laddr,
                            const struct silofs_pnptr *pnptr)
{
	int err;

	err = stc_access_blob_of(st_ctx, pnptr);
	return_if_err(err);

	stc_detach_lspace(st_ctx, pnptr);
	stc_cleardirty_cached_lnode(st_ctx, laddr);
	return 0;
}

int silofs_detach_lnode_at(const struct silofs_core_refs *corefs,
                           const struct silofs_laddr *laddr,
                           const struct silofs_pnptr *pnptr)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, corefs);
	err = stc_detach_lnode(&st_ctx, laddr, pnptr);
	stc_fini(&st_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
mkalt_pnptr(const struct silofs_pnptr *pnptr_cur,
            const struct silofs_ctag *ctag, struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr_assign(out_pnptr, pnptr_cur);
	if (ctag != nullptr) {
		silofs_nmeta_update(&out_pnptr->nmeta, ctag);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_destage_ctx {
	struct silofs_destageq dsq;
	const struct silofs_core_refs *corefs;
	struct silofs_alloc *alloc;
	struct silofs_dirtyq *drq;
	struct silofs_uber_info *ubi;
	struct silofs_dstor *dstor;
	bool cleardirty;
};

static void dsc_init(struct silofs_destage_ctx *ds_ctx,
                     const struct silofs_core_refs *corefs)
{
	silofs_destageq_init(&ds_ctx->dsq);
	ds_ctx->corefs     = corefs;
	ds_ctx->alloc      = corefs->alloc;
	ds_ctx->drq        = nullptr;
	ds_ctx->ubi        = corefs->fsroot->ubi;
	ds_ctx->dstor      = corefs->dstor;
	ds_ctx->cleardirty = false;
}

static void dsc_initp(struct silofs_destage_ctx *ds_ctx,
                      const struct silofs_core_refs *corefs)
{
	dsc_init(ds_ctx, corefs);
	ds_ctx->drq = &corefs->pcache->nc.nc_dirtyq;
}

static void dsc_initv(struct silofs_destage_ctx *ds_ctx,
                      const struct silofs_core_refs *corefs)
{
	dsc_init(ds_ctx, corefs);
	ds_ctx->drq = &corefs->lcache->nc.nc_dirtyq;
}

static void dsc_fini(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_fini(&ds_ctx->dsq);
	ds_ctx->corefs = nullptr;
	ds_ctx->alloc  = nullptr;
	ds_ctx->drq    = nullptr;
	ds_ctx->ubi    = nullptr;
	ds_ctx->dstor  = nullptr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dsc_stage_btnode(const struct silofs_destage_ctx *ds_ctx,
                            const struct silofs_pnptr *pnptr,
                            struct silofs_btnode_info **out_bti)
{
	silofs_assert_eq(pnptr->paddr.ptype, SILOFS_PTYPE_BTNODE);
	return silofs_stage_btnode(ds_ctx->corefs, pnptr, out_bti);
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
	int ret = 0;

	if (!pni_has_pviewx(pni)) {
		ret = pni_attach_viewx(pni, ds_ctx->alloc);
	}
	return ret;
}

static void dsc_detach_pviewx(const struct silofs_destage_ctx *ds_ctx,
                              struct silofs_pnode_info *pni)
{
	if (pni_has_pviewx(pni)) {
		pni_detach_viewx(pni, ds_ctx->alloc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dsc_prepare_pnode(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_pnode_info *pni)
{
	return dsc_attach_pviewx(ds_ctx, pni);
}

static int prepare_pnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_prepare_pnode(userp, pni_of(dqe));
}

static int dsc_prepare_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, prepare_pnode_by, ds_ctx);
}

static int dsc_encrypt_pnode(const struct silofs_destage_ctx *ds_ctx,
                             const struct silofs_pnode_info *pni,
                             struct silofs_ctag *out_ctag)
{
	int err;

	if (pni_isuber(pni)) {
		err = silofs_encrypt_pnode(ds_ctx->corefs, pni, nullptr);
	} else {
		err = silofs_encrypt_pnode(ds_ctx->corefs, pni, out_ctag);
	}
	return err;
}

static int dsc_seal_encrypt_pnode(const struct silofs_destage_ctx *ds_ctx,
                                  const struct silofs_pnode_info *pni,
                                  struct silofs_ctag *out_ctag)
{
	silofs_seal_pview_of(pni);
	return dsc_encrypt_pnode(ds_ctx, pni, out_ctag);
}

static int dsc_update_parent_uber(const struct silofs_destage_ctx *ds_ctx,
                                  const struct silofs_pnode_info *pni)
{
	struct silofs_pnptr alt;
	struct silofs_uber_info *ubi = ds_ctx->ubi;

	if (!silofs_ubi_has_btroot(ubi, pni_self(pni))) {
		return -SILOFS_ENOENT;
	}
	pni_next_self(pni, &alt);
	silofs_ubi_set_btroot(ubi, &alt);
	return 0;
}

static int dsc_update_parent_btnode_at(const struct silofs_destage_ctx *ds_ctx,
                                       const struct silofs_pnptr *parent,
                                       const struct silofs_pnptr *cur,
                                       const struct silofs_pnptr *alt)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = dsc_stage_btnode(ds_ctx, parent, &bti);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	err = silofs_bti_relink(bti, cur, alt);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	return 0;
}

static int dsc_resolve_btnode_parent(const struct silofs_destage_ctx *ds_ctx,
                                     const struct silofs_btnode_info *bti,
                                     struct silofs_pnptr *out_pnptr)
{
	struct silofs_laddr laddr;

	bti_base_laddr(bti, &laddr);
	return silofs_resolve_ltop_parent(ds_ctx->corefs, &laddr, //
	                                  bti_paddr(bti), out_pnptr);
}

static int dsc_update_parent_of_btnode(const struct silofs_destage_ctx *ds_ctx,
                                       const struct silofs_btnode_info *bti)
{
	const struct silofs_pnptr *cur = bti_self(bti);
	struct silofs_pnptr parent, alt;
	int err;

	pni_next_self(&bti->btn_pni, &alt);
	err = dsc_resolve_btnode_parent(ds_ctx, bti, &parent);
	return_if_err(err);

	err = dsc_update_parent_btnode_at(ds_ctx, &parent, cur, &alt);
	return_if_err(err);

	return 0;
}

static int dsc_update_btnode_parent(const struct silofs_destage_ctx *ds_ctx,
                                    const struct silofs_btnode_info *bti)
{
	int err;

	if (bti_isroot(bti)) {
		err = dsc_update_parent_uber(ds_ctx, &bti->btn_pni);
		silofs_assert_ok(err);
	} else {
		err = dsc_update_parent_of_btnode(ds_ctx, bti);
		silofs_assert_ok(err);
	}
	return err;
}

static int dsc_secure_pnode(const struct silofs_destage_ctx *ds_ctx,
                            struct silofs_pnode_info *pni)
{
	struct silofs_ctag ctag;
	int err;

	err = dsc_seal_encrypt_pnode(ds_ctx, pni, &ctag);
	return_if_err(err);

	if (pni_isuber(pni)) {
		return 0;
	}

	pni_update_ctag(pni, &ctag);
	err = dsc_update_btnode_parent(ds_ctx, bti_of(pni));
	return_if_err(err);

	pni_apply_ctag(pni);

	return 0;
}

static int secure_pnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_secure_pnode(userp, pni_of(dqe));
}

static int dsc_secure_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, secure_pnode_by, ds_ctx);
}

static int compare_paddrs(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2)
{
	long cmp;

	silofs_assume_not_null(paddr1);
	silofs_assume_not_null(paddr2);

	if (paddr1->ptype != paddr2->ptype) {
		/* Invert ordering by ptype: btnode come before uber */
		cmp = (long)paddr2->ptype - (long)paddr1->ptype;
	} else {
		cmp = silofs_paddr_compare(paddr1, paddr2);
	}
	return silofs_signof(cmp);
}

static int compare_btnodes(const struct silofs_btnode_info *bti1,
                           const struct silofs_btnode_info *bti2)
{
	const uint32_t h1 = bti_height(bti1);
	const uint32_t h2 = bti_height(bti2);
	int ret;

	if (h1 < h2) {
		ret = -1;
	} else if (h1 > h2) {
		ret = 1;
	} else {
		ret = compare_paddrs(bti_paddr(bti1), bti_paddr(bti2));
	}
	return ret;
}

static int compare_pnodes(const struct silofs_dq_elem *dqe1,
                          const struct silofs_dq_elem *dqe2)
{
	const struct silofs_pnode_info *pni1 = pni_of(dqe1);
	const struct silofs_pnode_info *pni2 = pni_of(dqe2);
	int ret;

	if (pni_isbtnode(pni1) && pni_isbtnode(pni2)) {
		ret = compare_btnodes(bti_of(pni1), bti_of(pni2));
	} else {
		ret = compare_paddrs(pni_paddr(pni1), pni_paddr(pni2));
	}
	return ret;
}

static void dsc_sort_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_sort(&ds_ctx->dsq, compare_pnodes);
}

static int dsc_commit_node_at(const struct silofs_destage_ctx *ds_ctx,
                              const struct silofs_paddr *paddr,
                              const void *buf, size_t bufsz)
{
	return silofs_dstor_write_blob_at(ds_ctx->dstor, &paddr->blobid,
	                                  paddr->pos, buf, bufsz);
}

static int dsc_commit_pnode(const struct silofs_destage_ctx *ds_ctx,
                            const struct silofs_pnode_info *pni)
{
	return dsc_commit_node_at(ds_ctx, pni_paddr(pni), pni_pviewx(pni),
	                          pni_pview_size(pni));
}

static int commit_pnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_commit_pnode(userp, pni_of(dqe));
}

static int dsc_commit_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, commit_pnode_by, ds_ctx);
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
	pni->pn_flags &= ~(unsigned)SILOFS_PNODEF_STAINED;
	return 0;
}

static int cleanup_pnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_cleanup_pnode(userp, pni_of(dqe));
}

static void dsc_cleanup_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_foreach(&ds_ctx->dsq, cleanup_pnode_by, ds_ctx);
}

static void dsc_cleanup_depopulate_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	dsc_cleanup_pnodes(ds_ctx);
	dsc_depopulate_dsq(ds_ctx);
}

static int dsc_destage_pnodes(struct silofs_destage_ctx *ds_ctx)
{
	int err;

	/* Populate de-stage queue. */
	dsc_populate_dsq(ds_ctx);

	/* Prepare each node. */
	err = dsc_prepare_pnodes(ds_ctx);
	goto_out_if_err(err);

	/* Sort for destage. */
	dsc_sort_pnodes(ds_ctx);

	/* For-each node: seal, encrypt and update parents */
	err = dsc_secure_pnodes(ds_ctx);
	goto_out_if_err(err);

	err = dsc_commit_pnodes(ds_ctx);
	goto_out_if_err(err);

	ds_ctx->cleardirty = true;
out:
	dsc_cleanup_depopulate_pnodes(ds_ctx);
	return err;
}

static int destage_pnodes(const struct silofs_core_refs *corefs)
{
	struct silofs_destage_ctx ds_ctx;
	int err;

	dsc_initp(&ds_ctx, corefs);
	err = dsc_destage_pnodes(&ds_ctx);
	dsc_fini(&ds_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int dsc_attach_lviewx(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_lnode_info *lni)
{
	int ret = 0;

	if (!lni_has_lviewx(lni)) {
		ret = lni_attach_viewx(lni, ds_ctx->alloc);
	}
	return ret;
}

static void dsc_detach_lviewx(const struct silofs_destage_ctx *ds_ctx,
                              struct silofs_lnode_info *lni)
{
	if (lni_has_lviewx(lni)) {
		lni_detach_viewx(lni, ds_ctx->alloc);
	}
}

static int dsc_resolve_lnode(const struct silofs_destage_ctx *ds_ctx,
                             const struct silofs_lnode_info *lni,
                             struct silofs_pnptr *out_pnptr)
{
	return silofs_resolve_ltop_mapping(ds_ctx->corefs, lni_laddr(lni),
	                                   out_pnptr);
}

static int dsc_resolve_lnode_parent(const struct silofs_destage_ctx *ds_ctx,
                                    const struct silofs_lnode_info *lni,
                                    struct silofs_pnptr *out_pnptr)
{
	const struct silofs_laddr *laddr = silofs_lni_laddr(lni);

	return silofs_resolve_ltop_btleaf(ds_ctx->corefs, laddr, out_pnptr);
}

static int dsc_encrypt_lnode(const struct silofs_destage_ctx *ds_ctx,
                             const struct silofs_lnode_info *lni,
                             const struct silofs_pnptr *pnptr_cur,
                             struct silofs_pnptr *out_pnptr)
{
	struct silofs_ctag ctag = {};
	int err;

	err = silofs_encrypt_lnode(ds_ctx->corefs, lni, pnptr_cur, &ctag);
	return_if_err(err);

	mkalt_pnptr(pnptr_cur, &ctag, out_pnptr);
	return 0;
}

static int dsc_seal_encrypt_lnode(const struct silofs_destage_ctx *ds_ctx,
                                  const struct silofs_lnode_info *lni,
                                  const struct silofs_pnptr *pnptr,
                                  struct silofs_pnptr *out_pnptr)
{
	silofs_seal_lnode(lni);
	return dsc_encrypt_lnode(ds_ctx, lni, pnptr, out_pnptr);
}

static int dsc_update_lnode_parent(const struct silofs_destage_ctx *ds_ctx,
                                   const struct silofs_lnode_info *lni,
                                   const struct silofs_pnptr *cur,
                                   const struct silofs_pnptr *alt)
{
	struct silofs_pnptr parent;
	int err;

	err = dsc_resolve_lnode_parent(ds_ctx, lni, &parent);
	return_if_err(err);

	err = dsc_update_parent_btnode_at(ds_ctx, &parent, cur, alt);
	return_if_err(err);

	return 0;
}

static int dsc_prepare_lnode(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_lnode_info *lni)
{
	struct silofs_pnptr pnptr_cur, pnptr_alt;
	int asyncwr, err = 0;

	/* XXX TODO: FIXME: handle case of async-write when try to destage */
	asyncwr = lni_has_asyncwr(lni);
	silofs_assert(!asyncwr);

	err = dsc_resolve_lnode(ds_ctx, lni, &pnptr_cur);
	return_if_err(err);

	err = dsc_attach_lviewx(ds_ctx, lni);
	return_if_err(err);

	err = dsc_seal_encrypt_lnode(ds_ctx, lni, &pnptr_cur, &pnptr_alt);
	return_if_err(err);

	err = dsc_update_lnode_parent(ds_ctx, lni, &pnptr_cur, &pnptr_alt);
	return_if_err(err);

	lni_update_curr_paddr(lni, &pnptr_alt.paddr);
	return 0;
}

static int prepare_lnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_prepare_lnode(userp, lni_of(dqe));
}

static int dsc_prepare_lnodes(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, prepare_lnode_by, ds_ctx);
}

static int compare_lnodes(const struct silofs_dq_elem *dqe1,
                          const struct silofs_dq_elem *dqe2)
{
	const struct silofs_lnode_info *lni1 = lni_of(dqe1);
	const struct silofs_lnode_info *lni2 = lni_of(dqe2);

	return compare_paddrs(lni_curr_paddr(lni1), lni_curr_paddr(lni2));
}

static void dsc_sort_lnodes(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_sort(&ds_ctx->dsq, compare_lnodes);
}

static int dsc_stain_lnode_parents(const struct silofs_destage_ctx *ds_ctx,
                                   const struct silofs_lnode_info *lni)
{
	struct silofs_btree_path bpath = { .cnt = 0 };
	int err;

	err = silofs_resolve_ltop_bpath(ds_ctx->corefs, lni_laddr(lni),
	                                &bpath);
	return_if_err(err);

	for (size_t i = 0; i < bpath.cnt; ++i) {
		struct silofs_btnode_info *bti = bpath.bti[i];

		if (bti->btn_pni.pn_flags & SILOFS_PNODEF_STAINED) {
			break;
		}
		silofs_bti_setdirty(bti);
		bti->btn_pni.pn_flags |= SILOFS_PNODEF_STAINED;
	}
	return 0;
}

static int stain_lnode_parents_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_stain_lnode_parents(userp, lni_of(dqe));
}

static int dsc_stain_lnodes_parents(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, //
	                               stain_lnode_parents_by, ds_ctx);
}

static int dsc_commit_lnode(const struct silofs_destage_ctx *ds_ctx,
                            const struct silofs_lnode_info *lni)
{
	return dsc_commit_node_at(ds_ctx, lni_curr_paddr(lni), lni_lviewx(lni),
	                          lni_lview_size(lni));
}

static int commit_lnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_commit_lnode(userp, lni_of(dqe));
}

static int dsc_commit_lnodes(struct silofs_destage_ctx *ds_ctx)
{
	return silofs_destageq_foreach(&ds_ctx->dsq, commit_lnode_by, ds_ctx);
}

static int dsc_cleanup_lnode(const struct silofs_destage_ctx *ds_ctx,
                             struct silofs_lnode_info *lni)
{
	if (lni_has_lviewx(lni)) {
		dsc_detach_lviewx(ds_ctx, lni);
	}
	if (ds_ctx->cleardirty) {
		silofs_lni_cleardirty(lni);
	}
	return 0;
}

static int cleanup_lnode_by(struct silofs_dq_elem *dqe, void *userp)
{
	return dsc_cleanup_lnode(userp, lni_of(dqe));
}

static void dsc_cleanup_lnodes(struct silofs_destage_ctx *ds_ctx)
{
	silofs_destageq_foreach(&ds_ctx->dsq, cleanup_lnode_by, ds_ctx);
}

static void dsc_cleanup_depopulate_lnodes(struct silofs_destage_ctx *ds_ctx)
{
	dsc_cleanup_lnodes(ds_ctx);
	dsc_depopulate_dsq(ds_ctx);
}

static int dsc_destage_lnodes(struct silofs_destage_ctx *ds_ctx)
{
	int err;

	/* Populate de-stage queue. */
	dsc_populate_dsq(ds_ctx);

	/* Prepare each lnode. */
	err = dsc_prepare_lnodes(ds_ctx);
	goto_out_if_err(err);

	/* Sort by latest (updated) paddr. */
	dsc_sort_lnodes(ds_ctx);

	/* Stage parents and mark dirty. */
	err = dsc_stain_lnodes_parents(ds_ctx);
	goto_out_if_err(err);

	/* Commit lnodes to stable blob. */
	err = dsc_commit_lnodes(ds_ctx);
	goto_out_if_err(err);

	ds_ctx->cleardirty = true;
out:
	dsc_cleanup_depopulate_lnodes(ds_ctx);
	return err;
}

static int destage_lnodes(const struct silofs_core_refs *corefs)
{
	struct silofs_destage_ctx ds_ctx;
	int err;

	dsc_initv(&ds_ctx, corefs);
	err = dsc_destage_lnodes(&ds_ctx);
	dsc_fini(&ds_ctx);
	return err;
}

static void dsc_postop_cleanup(struct silofs_destage_ctx *ds_ctx)
{
	/* Populate de-stage queue. */
	dsc_populate_dsq(ds_ctx);

	/* Safety cleanups: remove STAINED flag. */
	dsc_cleanup_depopulate_pnodes(ds_ctx);
}

static void postop_cleanup(const struct silofs_core_refs *corefs)
{
	struct silofs_destage_ctx ds_ctx;

	dsc_initp(&ds_ctx, corefs);
	dsc_postop_cleanup(&ds_ctx);
	dsc_fini(&ds_ctx);
}

static void postop_report(const struct silofs_core_refs *corefs, int status)
{
	if (status != 0) {
		log_err("destage failure: status=%d", status);
	}
	unused(corefs);
}

int silofs_destage_dirty_nodes(const struct silofs_core_refs *corefs)
{
	int err;

	/* Leaf nodes. */
	err = destage_lnodes(corefs);
	goto_out_if_err(err);

	/* Internal mapping nodes */
	err = destage_pnodes(corefs);
	goto_out_if_err(err);

out:
	postop_cleanup(corefs);
	postop_report(corefs, err);
	return err;
}
