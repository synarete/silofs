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

struct silofs_stage_ctx {
	struct silofs_pexec_ctx *pexec;
	struct silofs_alloc *alloc;
	struct silofs_dstor *dstor;
	struct silofs_pcache *pcache;
	struct silofs_vcache *vcache;
	struct silofs_mdigest_hd *md_hd;
	struct silofs_cipher_hd *enc_ci_hd;
	struct silofs_cipher_hd *dec_ci_hd;
	struct silofs_pview *pview;
	struct silofs_lview *lview;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t paddr_len(const struct silofs_paddr *paddr)
{
	return silofs_ptype_size(paddr->ptype);
}

static size_t vaddr_len(const struct silofs_vaddr *vaddr)
{
	return silofs_vaddr_len(vaddr);
}

static size_t pni_len(const struct silofs_pnode_info *pni)
{
	return paddr_len(&pni->pn_self.paddr);
}

static const struct silofs_civkey *
pni_civkey(const struct silofs_pnode_info *pni)
{
	return silofs_pni_civkey(pni);
}

static bool pni_staged_ok(const struct silofs_pnode_info *pni)
{
	return (pni->pn_flags & SILOFS_PNODEF_STAGED_OK) > 0;
}

static void pni_set_staged_ok(struct silofs_pnode_info *pni)
{
	pni->pn_flags |= SILOFS_PNODEF_STAGED_OK;
}

static const struct silofs_blobid *bti_blobid(struct silofs_btnode_info *bti)
{
	return silofs_pni_blobid(&bti->btn_pni);
}

static size_t vni_len(const struct silofs_vnode_info *vni)
{
	return vaddr_len(silofs_vni_vaddr(vni));
}

static const struct silofs_civkey *
vni_civkey(const struct silofs_vnode_info *vni)
{
	silofs_assert(vni->vn_has_pn);

	return &vni->vn_pnptr.nmeta.civkey;
}

static const struct silofs_blobid *vni_blobid(struct silofs_vnode_info *vni)
{
	silofs_assert(vni->vn_has_pn);

	return &vni->vn_pnptr.paddr.blobid;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *stc_memalloc(struct silofs_stage_ctx *st_ctx, size_t n)
{
	return silofs_memalloc(st_ctx->alloc, n, SILOFS_ALLOCF_BZERO);
}

static void stc_memfree(struct silofs_stage_ctx *st_ctx, void *p, size_t n)
{
	silofs_memfree(st_ctx->alloc, p, n, 0);
}

static void
stc_init(struct silofs_stage_ctx *st_ctx, struct silofs_pexec_ctx *pexec)
{
	st_ctx->pexec     = pexec;
	st_ctx->alloc     = pexec->alloc;
	st_ctx->dstor     = pexec->dstor;
	st_ctx->pcache    = pexec->pcache;
	st_ctx->vcache    = pexec->vcache;
	st_ctx->md_hd     = pexec->md_hd;
	st_ctx->enc_ci_hd = pexec->enc_ci_hd;
	st_ctx->dec_ci_hd = pexec->dec_ci_hd;
	st_ctx->pview     = nullptr;
	st_ctx->lview     = nullptr;
}

static void stc_fini(struct silofs_stage_ctx *st_ctx)
{
	if (st_ctx->pview != nullptr) {
		stc_memfree(st_ctx, st_ctx->pview, sizeof(*st_ctx->pview));
		st_ctx->pview = nullptr;
	}
	if (st_ctx->lview != nullptr) {
		stc_memfree(st_ctx, st_ctx->lview, sizeof(*st_ctx->lview));
		st_ctx->lview = nullptr;
	}
}

static int stc_require_pview(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_pview *pview = nullptr;

	if (st_ctx->pview != nullptr) {
		return 0;
	}
	pview = stc_memalloc(st_ctx, sizeof(*pview));
	if (pview == nullptr) {
		return -SILOFS_ENOENT;
	}
	st_ctx->pview = pview;
	return 0;
}

static int stc_require_lview(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_lview *lview = nullptr;

	if (st_ctx->lview != nullptr) {
		return 0;
	}
	lview = stc_memalloc(st_ctx, sizeof(*lview));
	if (lview == nullptr) {
		return -SILOFS_ENOENT;
	}
	st_ctx->lview = lview;
	return 0;
}

static int stc_require_paddr(const struct silofs_stage_ctx *st_ctx,
                             const struct silofs_paddr *paddr)
{
	return silofs_dstor_require_blob_at(st_ctx->dstor, &paddr->blobid,
	                                    paddr->pos);
}

static int stc_require_paddr_of(const struct silofs_stage_ctx *st_ctx,
                                const struct silofs_pnptr *pnptr)
{
	return stc_require_paddr(st_ctx, &pnptr->paddr);
}

static int stc_access_pnode(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_paddr *paddr)
{
	struct silofs_paddr next;

	silofs_paddr_next(paddr, &next);
	return silofs_dstor_access_blob_at(st_ctx->dstor, &next.blobid,
	                                   next.pos);
}

static int stc_access_pnode_of(const struct silofs_stage_ctx *st_ctx,
                               const struct silofs_pnptr *pnptr)
{
	return stc_access_pnode(st_ctx, &pnptr->paddr);
}

static int stc_read_pview_at(struct silofs_stage_ctx *st_ctx,
                             const struct silofs_paddr *paddr, size_t len)
{
	return silofs_dstor_read_blob_at(st_ctx->dstor, &paddr->blobid,
	                                 paddr->pos, st_ctx->pview, len);
}

static int
stc_read_pnode(struct silofs_stage_ctx *st_ctx, struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = &pni->pn_self.paddr;

	return stc_read_pview_at(st_ctx, paddr, pni_len(pni));
}

static int stc_decrypt_pview_of(struct silofs_stage_ctx *st_ctx,
                                struct silofs_pnode_info *pni)
{
	return silofs_decrypt_pview(st_ctx->dec_ci_hd, pni_civkey(pni),
	                            st_ctx->pview, pni->pn_pview,
	                            pni_len(pni));
}

static int stc_decrypt_verify_pnode(struct silofs_stage_ctx *st_ctx,
                                    struct silofs_pnode_info *pni)
{
	int err;

	err = stc_decrypt_pview_of(st_ctx, pni);
	if (err) {
		return err;
	}
	err = silofs_verify_pnode(pni);
	if (err) {
		return err;
	}
	return 0;
}

static int stc_stage_decrypt_pnode(struct silofs_stage_ctx *st_ctx,
                                   struct silofs_pnode_info *pni)
{
	int err;

	err = stc_require_pview(st_ctx);
	if (err) {
		return err;
	}
	err = stc_read_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	err = stc_decrypt_verify_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	return 0;
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
	if (err) {
		return err;
	}
	err = stc_create_cached_pnode(st_ctx, pnptr, out_pni);
	if (err) {
		return err;
	}
	return 0;
}

static int stc_stage_pnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_pnode_info **out_pni)
{
	struct silofs_pnode_info *pni = nullptr;
	int err;

	err = stc_lookup_cached_pnode(st_ctx, &pnptr->paddr, &pni);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}
	err = stc_access_pnode_of(st_ctx, pnptr);
	if (err) {
		return err;
	}
	err = stc_create_cached_pnode(st_ctx, pnptr, &pni);
	if (err) {
		return err;
	}
	err = stc_stage_decrypt_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
out_ok:
	*out_pni = pni;
	return 0;
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
	if (err) {
		return err;
	}
	*out_ubi = silofs_ubi_from_pni(pni);
	stc_update_spawned_uber(st_ctx, *out_ubi);
	return 0;
}

int silofs_spawn_uber(struct silofs_pexec_ctx *pexec,
                      const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
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
	if (err) {
		return err;
	}
	*out_ubi = silofs_ubi_from_pni(pni);

	err = stc_validate_staged_uber(st_ctx, *out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_uber(struct silofs_pexec_ctx *pexec,
                      const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
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
	if (err) {
		return err;
	}
	*out_bdi = silofs_bdi_from_pni(pni);
	stc_update_spawned_bldesc(st_ctx, *out_bdi);
	return 0;
}

int silofs_spawn_bldesc(struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_bldesc_info **out_bdi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
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
	if (err) {
		return err;
	}
	*out_bdi = silofs_bdi_from_pni(pni);

	err = stc_validate_staged_bldesc(st_ctx, *out_bdi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_bldesc(struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_bldesc_info **out_bdi)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
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
	silofs_assert_not_null(st_ctx->pexec->ubref->ubi);

	return st_ctx->pexec->ubref->ubi;
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
	if (err) {
		return err;
	}
	*out_bti = silofs_bti_from_pni(pni);
	stc_update_spawned_btnode(st_ctx, *out_bti);
	return 0;
}

int silofs_spawn_btnode(struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_btnode_info **out_bti)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
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
	if (err) {
		return err;
	}
	*out_bti = silofs_bti_from_pni(pni);

	err = stc_validate_staged_btnode(st_ctx, *out_bti);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_btnode(struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_btnode_info **out_bti)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
	err = stc_stage_btnode(&st_ctx, pnptr, out_bti);
	stc_fini(&st_ctx);
	return err;
}

int silofs_require_paddr(struct silofs_pexec_ctx *pexec,
                         const struct silofs_paddr *paddr)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
	err = stc_require_paddr(&st_ctx, paddr);
	stc_fini(&st_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stc_write_lview_at(struct silofs_stage_ctx *st_ctx,
                              const struct silofs_paddr *paddr, size_t len)
{
	return silofs_dstor_write_blob_at(st_ctx->dstor, &paddr->blobid,
	                                  paddr->pos, st_ctx->lview, len);
}

static int stc_write_vnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_vnode_info *vni)
{
	const struct silofs_paddr *paddr = &vni->vn_pnptr.paddr;

	silofs_assert(vni->vn_has_pn);

	return stc_write_lview_at(st_ctx, paddr, vni_len(vni));
}

static int stc_encrypt_lview_of(struct silofs_stage_ctx *st_ctx,
                                const struct silofs_vnode_info *vni)
{
	return silofs_encrypt_lview2(st_ctx->enc_ci_hd, vni_civkey(vni),
	                             vni->vn_lni.ln_view, st_ctx->lview,
	                             vni_len(vni));
}

static int stc_seal_encrypt_vnode(struct silofs_stage_ctx *st_ctx,
                                  struct silofs_vnode_info *vni)
{
	silofs_seal_vnode(vni);
	return stc_encrypt_lview_of(st_ctx, vni);
}

static int stc_destage_dirty_vnode(struct silofs_stage_ctx *st_ctx,
                                   struct silofs_vnode_info *vni)
{
	int err;

	err = stc_require_lview(st_ctx);
	if (err) {
		return err;
	}
	err = stc_seal_encrypt_vnode(st_ctx, vni);
	if (err) {
		return err;
	}
	err = stc_write_vnode(st_ctx, vni);
	if (err) {
		return err;
	}
	return 0;
}

static struct silofs_vnode_info *
stc_vcache_dqfront(struct silofs_stage_ctx *st_ctx)
{
	return silofs_vcache_dq_front(st_ctx->vcache);
}

static int stc_destage_dirty_vnodes(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_vnode_info *vni;
	int err;

	vni = stc_vcache_dqfront(st_ctx);
	while (vni != nullptr) {
		err = stc_destage_dirty_vnode(st_ctx, vni);
		if (err) {
			return err;
		}
		silofs_vni_undirtify(vni);
		vni = stc_vcache_dqfront(st_ctx);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_write_pview_at(struct silofs_stage_ctx *st_ctx,
                              const struct silofs_paddr *paddr, size_t len)
{
	return silofs_dstor_write_blob_at(st_ctx->dstor, &paddr->blobid,
	                                  paddr->pos, st_ctx->pview, len);
}

static int stc_write_pnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = &pni->pn_self.paddr;

	return stc_write_pview_at(st_ctx, paddr, pni_len(pni));
}

static int stc_encrypt_pview_of(struct silofs_stage_ctx *st_ctx,
                                const struct silofs_pnode_info *pni)
{
	return silofs_encrypt_pview(st_ctx->enc_ci_hd, pni_civkey(pni),
	                            pni->pn_pview, st_ctx->pview,
	                            pni_len(pni));
}

static int stc_seal_encrypt_pnode(struct silofs_stage_ctx *st_ctx,
                                  struct silofs_pnode_info *pni)
{
	silofs_seal_pnode(pni);
	return stc_encrypt_pview_of(st_ctx, pni);
}

static int stc_destage_dirty_pnode(struct silofs_stage_ctx *st_ctx,
                                   struct silofs_pnode_info *pni)
{
	int err;

	err = stc_require_pview(st_ctx);
	if (err) {
		return err;
	}
	err = stc_seal_encrypt_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	err = stc_write_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	return 0;
}

static struct silofs_pnode_info *
stc_pcache_dqfront(struct silofs_stage_ctx *st_ctx)
{
	return silofs_pcache_dq_front(st_ctx->pcache);
}

static int stc_destage_dirty_pnodes(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_pnode_info *pni;
	int err;

	pni = stc_pcache_dqfront(st_ctx);
	while (pni != nullptr) {
		err = stc_destage_dirty_pnode(st_ctx, pni);
		if (err) {
			return err;
		}
		silofs_pni_undirtify(pni);
		pni = stc_pcache_dqfront(st_ctx);
	}
	return 0;
}

static int stc_destage_dirty(struct silofs_stage_ctx *st_ctx)
{
	int err;

	err = stc_destage_dirty_vnodes(st_ctx);
	if (err) {
		return err;
	}
	err = stc_destage_dirty_pnodes(st_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_destage_dirty(struct silofs_pexec_ctx *pexec)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
	err = stc_destage_dirty(&st_ctx);
	stc_fini(&st_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stc_lookup_cached_vnode(const struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_vnode_info **out_vni)
{
	*out_vni = silofs_vcache_lookup_vnode(st_ctx->vcache, vaddr);

	return (*out_vni == nullptr) ? -SILOFS_ENOENT : 0;
}

static int stc_create_cached_vnode(const struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_vaddr *vaddr,
                                   struct silofs_vnode_info **out_vni)
{
	*out_vni = silofs_vcache_create_vnode(st_ctx->vcache, vaddr);

	return (*out_vni == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void stc_update_vnode_with(const struct silofs_stage_ctx *st_ctx,
                                  struct silofs_vnode_info *vni,
                                  const struct silofs_pnptr *pnptr)
{
	silofs_pnptr_assign(&vni->vn_pnptr, pnptr);
	vni->vn_has_pn = true;

	silofs_vcache_rebind_vnode(st_ctx->vcache, vni);
}

static void stc_update_spawned_vnode(const struct silofs_stage_ctx *st_ctx,
                                     struct silofs_vnode_info *vni,
                                     const struct silofs_pnptr *pnptr)
{
	stc_update_vnode_with(st_ctx, vni, pnptr);
	silofs_ubi_inc_count_by(stc_ubi(st_ctx), vni_blobid(vni));
}

static int stc_spawn_vnode(const struct silofs_stage_ctx *st_ctx,
                           const struct silofs_vaddr *vaddr,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_vnode_info **out_vni)
{
	int err;

	err = stc_require_paddr_of(st_ctx, pnptr);
	if (err) {
		return err;
	}
	err = stc_create_cached_vnode(st_ctx, vaddr, out_vni);
	if (err) {
		return err;
	}
	stc_update_spawned_vnode(st_ctx, *out_vni, pnptr);
	return 0;
}

int silofs_spawn_vnode2(struct silofs_pexec_ctx *pexec,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_vnode_info **out_vni)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
	err = stc_spawn_vnode(&st_ctx, vaddr, pnptr, out_vni);
	stc_fini(&st_ctx);
	return err;
}

static int stc_read_lview_at(struct silofs_stage_ctx *st_ctx,
                             const struct silofs_paddr *paddr, size_t len)
{
	return silofs_dstor_read_blob_at(st_ctx->dstor, &paddr->blobid,
	                                 paddr->pos, st_ctx->lview, len);
}

static int stc_read_vnode(struct silofs_stage_ctx *st_ctx,
                          const struct silofs_vnode_info *vni,
                          const struct silofs_paddr *paddr)
{
	const struct silofs_vaddr *vaddr = silofs_vni_vaddr(vni);

	return stc_read_lview_at(st_ctx, paddr, vaddr_len(vaddr));
}

static int stc_decrypt_lview_of(struct silofs_stage_ctx *st_ctx,
                                const struct silofs_pnptr *pnptr,
                                struct silofs_vnode_info *vni)
{
	return silofs_decrypt_lview2(st_ctx->dec_ci_hd, &pnptr->nmeta.civkey,
	                             st_ctx->lview, vni->vn_lni.ln_view,
	                             vni_len(vni));
}

static int stc_decrypt_verify_vnode(struct silofs_stage_ctx *st_ctx,
                                    const struct silofs_pnptr *pnptr,
                                    struct silofs_vnode_info *vni)
{
	int err;

	err = stc_decrypt_lview_of(st_ctx, pnptr, vni);
	if (err) {
		return err;
	}
	err = silofs_verify_lnode(&vni->vn_lni);
	if (err) {
		return err;
	}
	return 0;
}

static int stc_stage_decrypt_vnode(struct silofs_stage_ctx *st_ctx,
                                   const struct silofs_pnptr *pnptr,
                                   struct silofs_vnode_info *vni)
{
	int err;

	err = stc_require_lview(st_ctx);
	if (err) {
		return err;
	}
	err = stc_read_vnode(st_ctx, vni, &pnptr->paddr);
	if (err) {
		return err;
	}
	err = stc_decrypt_verify_vnode(st_ctx, pnptr, vni);
	if (err) {
		return err;
	}
	return 0;
}

static int stc_stage_vnode(struct silofs_stage_ctx *st_ctx,
                           const struct silofs_vaddr *vaddr,
                           const struct silofs_pnptr *pnptr,
                           struct silofs_vnode_info **out_vni)
{
	struct silofs_vnode_info *vni = nullptr;
	int err;

	err = stc_lookup_cached_vnode(st_ctx, vaddr, &vni);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}
	err = stc_access_pnode_of(st_ctx, pnptr);
	if (err) {
		return err;
	}
	err = stc_create_cached_vnode(st_ctx, vaddr, &vni);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	err = stc_stage_decrypt_vnode(st_ctx, pnptr, vni);
	if (err) {
		silofs_assert_ok(err);
		return err;
	}
	stc_update_vnode_with(st_ctx, vni, pnptr);
out_ok:
	*out_vni = vni;
	return 0;
}

int silofs_stage_vnode2(struct silofs_pexec_ctx *pexec,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_vnode_info **out_vni)
{
	struct silofs_stage_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, pexec);
	err = stc_stage_vnode(&st_ctx, vaddr, pnptr, out_vni);
	stc_fini(&st_ctx);
	return err;
}
