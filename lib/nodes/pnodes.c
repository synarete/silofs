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
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *memalloc_pni(struct silofs_alloc *alloc, size_t n)
{
	return silofs_memalloc(alloc, n, SILOFS_ALLOCF_BZERO);
}

static void memfree_pni(struct silofs_alloc *alloc, void *p, size_t n)
{
	silofs_memfree(alloc, p, n, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_ptype pnptr_ptype(const struct silofs_pnptr *pnptr)
{
	return pnptr->paddr.ptype;
}

static size_t pnptr_size(const struct silofs_pnptr *pnptr)
{
	return silofs_ptype_size(pnptr_ptype(pnptr));
}

static void
pni_init(struct silofs_pnode_info *pni, const struct silofs_pnptr *pnptr)
{
	const size_t psize = pnptr_size(pnptr);

	silofs_ni_init(&pni->pn_base, psize);
	silofs_pnptr_assign(&pni->pn_self, pnptr);
	silofs_pnptr_reset(&pni->pn_parent);
	silofs_ctag_reset(&pni->pn_ctag);
	silofs_list_head_init(&pni->pn_dsq_lh);
	silofs_hkey_by_paddr(&pni->pn_base.hmqe.hme_key, &pni->pn_self.paddr);
	pni->pn_flags = SILOFS_PNODEF_NONE;
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	silofs_pnptr_reset(&pni->pn_self);
	silofs_pnptr_reset(&pni->pn_parent);
	silofs_ctag_reset(&pni->pn_ctag);
	silofs_list_head_fini(&pni->pn_dsq_lh);
	silofs_ni_fini(&pni->pn_base);
}

static struct silofs_pview *pni_pview(const struct silofs_pnode_info *pni)
{
	return pni->pn_base.view.pview;
}

struct silofs_pview *silofs_pni_pview(const struct silofs_pnode_info *pni)
{
	silofs_assume_not_null(pni);
	return pni_pview(pni);
}

struct silofs_pview *silofs_pni_pviewx(const struct silofs_pnode_info *pni)
{
	silofs_assume_not_null(pni);
	return pni->pn_base.viewx.pview;
}

static enum silofs_ptype pni_ptype(const struct silofs_pnode_info *pni)
{
	return pni->pn_self.paddr.ptype;
}

enum silofs_ptype silofs_pni_ptype(const struct silofs_pnode_info *pni)
{
	return pni_ptype(pni);
}

static struct silofs_dq_elem *pni_dqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_base.dqe;
}

void silofs_pni_set_dq(struct silofs_pnode_info *pni, struct silofs_dirtyq *dq)
{
	silofs_dqe_set_dirtyq(pni_dqe(pni), dq);
}

const struct silofs_paddr *
silofs_pni_paddr(const struct silofs_pnode_info *pni)
{
	return &pni->pn_self.paddr;
}

const struct silofs_blobid *
silofs_pni_blobid(const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = silofs_pni_paddr(pni);

	return &paddr->blobid;
}

const struct silofs_layerid *
silofs_pni_layerid(const struct silofs_pnode_info *pni)
{
	const struct silofs_blobid *blobid = silofs_pni_blobid(pni);

	return &blobid->layerid;
}

const struct silofs_nmeta *
silofs_pni_nmeta(const struct silofs_pnode_info *pni)
{
	return &pni->pn_self.nmeta;
}

const struct silofs_civkey *
silofs_pni_civkey(const struct silofs_pnode_info *pni)
{
	return &pni->pn_self.nmeta.civkey;
}

void silofs_pni_markdirty(struct silofs_pnode_info *pni)
{
	silofs_dqe_markdirty(pni_dqe(pni));
}

void silofs_pni_cleardirty(struct silofs_pnode_info *pni)
{
	silofs_dqe_cleardirty(pni_dqe(pni));
}

void silofs_pni_incref(struct silofs_pnode_info *pni)
{
	silofs_ni_incref(&pni->pn_base);
}

void silofs_pni_decref(struct silofs_pnode_info *pni)
{
	silofs_ni_decref(&pni->pn_base);
}

static int
pni_attach_pview(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	int err;

	err = silofs_ni_attach_view(&pni->pn_base, alloc, true);
	if (!err) {
		silofs_pview_setup(pni_pview(pni), pni_ptype(pni));
	}
	return err;
}

static void
pni_detach_pview(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	silofs_ni_detach_view(&pni->pn_base, alloc, true);
}

const struct silofs_pnptr *silofs_pni_self(const struct silofs_pnode_info *pni)
{
	return &pni->pn_self;
}

const struct silofs_pnptr *
silofs_pni_parent(const struct silofs_pnode_info *pni)
{
	return &pni->pn_parent;
}

void silofs_pni_set_parent(struct silofs_pnode_info *pni,
                           const struct silofs_pnptr *paddr)
{
	if (paddr != nullptr) {
		silofs_pnptr_assign(&pni->pn_parent, paddr);
	} else {
		silofs_pnptr_reset(&pni->pn_parent);
	}
}

void silofs_pni_update_ctag(struct silofs_pnode_info *pni,
                            const struct silofs_ctag *ctag)
{
	silofs_ctag_assign(&pni->pn_ctag, ctag);
}

void silofs_pni_apply_ctag(struct silofs_pnode_info *pni)
{
	silofs_nmeta_update(&pni->pn_self.nmeta, &pni->pn_ctag);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_uber_info *ubi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_uber_info *ubi = nullptr;

	ubi = memalloc_pni(alloc, sizeof(*ubi));
	return ubi;
}

static void ubi_free(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	memfree_pni(alloc, ubi, sizeof(*ubi));
}

static void
ubi_init(struct silofs_uber_info *ubi, const struct silofs_pnptr *pnptr)
{
	pni_init(&ubi->ub_pni, pnptr);
	ubi->ubn = nullptr;
}

static void ubi_fini(struct silofs_uber_info *ubi)
{
	pni_fini(&ubi->ub_pni);
	ubi->ubn = nullptr;
}

static struct silofs_uber_info *
ubi_malloc_init(struct silofs_alloc *alloc, const struct silofs_pnptr *pnptr)
{
	struct silofs_uber_info *ubi;

	ubi = ubi_malloc(alloc);
	if (ubi != nullptr) {
		ubi_init(ubi, pnptr);
	}
	return ubi;
}

static void
ubi_fini_free(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	ubi_fini(ubi);
	ubi_free(ubi, alloc);
}

static int
ubi_attach_pview(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	struct silofs_pview *pview = nullptr;
	int err;

	err = pni_attach_pview(&ubi->ub_pni, alloc);
	if (!err) {
		pview    = silofs_pni_pview(&ubi->ub_pni);
		ubi->ubn = &pview->pv.ub;
	}
	return err;
}

static void
ubi_detach_pview(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	pni_detach_pview(&ubi->ub_pni, alloc);
	ubi->ubn = nullptr;
}

static struct silofs_uber_info *
ubi_new(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	ubi = ubi_malloc_init(alloc, pnptr);
	if (ubi == nullptr) {
		return nullptr;
	}
	err = ubi_attach_pview(ubi, alloc);
	if (err) {
		ubi_fini_free(ubi, alloc);
		return nullptr;
	}
	return ubi;
}

static void ubi_del(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	if (ubi != nullptr) {
		ubi_detach_pview(ubi, alloc);
		ubi_fini_free(ubi, alloc);
	}
}

static struct silofs_pnode_info *ubi_to_pni(struct silofs_uber_info *ubi)
{
	struct silofs_pnode_info *pni = nullptr;

	if (ubi != nullptr) {
		pni = &ubi->ub_pni;
	}
	return pni;
}

static struct silofs_uber_info *ubi_from_pni(struct silofs_pnode_info *pni)
{
	struct silofs_uber_info *ubi = nullptr;

	if (pni != nullptr) {
		ubi = mut_container_of(pni, struct silofs_uber_info, ub_pni);
	}
	return ubi;
}

static struct silofs_uber_info *ubi_unconst(const struct silofs_uber_info *ubi)
{
	return silofs_unconst(ubi);
}

struct silofs_uber_info *
silofs_ubi_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_uber_info *ubi = nullptr;

	if (pni != nullptr) {
		ubi = container_of(pni, struct silofs_uber_info, ub_pni);
	}
	return ubi_unconst(ubi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bldesc_info *bdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_bldesc_info *bdi = nullptr;

	bdi = memalloc_pni(alloc, sizeof(*bdi));
	return bdi;
}

static void
bdi_free(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	memfree_pni(alloc, bdi, sizeof(*bdi));
}

static void
bdi_init(struct silofs_bldesc_info *bdi, const struct silofs_pnptr *pnptr)
{
	pni_init(&bdi->bld_pni, pnptr);
	bdi->bld = nullptr;
}

static void bdi_fini(struct silofs_bldesc_info *bdi)
{
	pni_fini(&bdi->bld_pni);
	bdi->bld = nullptr;
}

static struct silofs_bldesc_info *
bdi_malloc_init(struct silofs_alloc *alloc, const struct silofs_pnptr *pnptr)
{
	struct silofs_bldesc_info *bdi;

	bdi = bdi_malloc(alloc);
	if (bdi != nullptr) {
		bdi_init(bdi, pnptr);
	}
	return bdi;
}

static void
bdi_fini_free(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	bdi_fini(bdi);
	bdi_free(bdi, alloc);
}

static int
bdi_attach_pview(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	struct silofs_pview *pview = nullptr;
	int err;

	err = pni_attach_pview(&bdi->bld_pni, alloc);
	if (!err) {
		pview    = silofs_pni_pview(&bdi->bld_pni);
		bdi->bld = &pview->pv.bd;
	}
	return err;
}

static void
bdi_detach_pview(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	pni_detach_pview(&bdi->bld_pni, alloc);
	bdi->bld = nullptr;
}

static struct silofs_bldesc_info *
bdi_new(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_bldesc_info *bdi = nullptr;
	int err;

	bdi = bdi_malloc_init(alloc, pnptr);
	if (bdi == nullptr) {
		return nullptr;
	}
	err = bdi_attach_pview(bdi, alloc);
	if (err) {
		bdi_fini_free(bdi, alloc);
		return nullptr;
	}
	return bdi;
}

static void bdi_del(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	if (bdi != nullptr) {
		bdi_detach_pview(bdi, alloc);
		bdi_fini_free(bdi, alloc);
	}
}

static struct silofs_pnode_info *bdi_to_pni(struct silofs_bldesc_info *bdi)
{
	struct silofs_pnode_info *pni = nullptr;

	if (bdi != nullptr) {
		pni = &bdi->bld_pni;
	}
	return pni;
}

static struct silofs_bldesc_info *bdi_from_pni(struct silofs_pnode_info *pni)
{
	struct silofs_bldesc_info *bdi = nullptr;

	if (pni != nullptr) {
		bdi = mut_container_of(pni, struct silofs_bldesc_info,
		                       bld_pni);
	}
	return bdi;
}

static struct silofs_bldesc_info *
bdi_unconst(const struct silofs_bldesc_info *bdi)
{
	return silofs_unconst(bdi);
}

struct silofs_bldesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_bldesc_info *bdi = nullptr;

	if (pni != nullptr) {
		bdi = container_of(pni, struct silofs_bldesc_info, bld_pni);
	}
	return bdi_unconst(bdi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *bti_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = nullptr;

	bti = memalloc_pni(alloc, sizeof(*bti));
	return bti;
}

static void
bti_free(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	memfree_pni(alloc, bti, sizeof(*bti));
}

static void
bti_init(struct silofs_btnode_info *bti, const struct silofs_pnptr *pnptr)
{
	pni_init(&bti->btn_pni, pnptr);
	bti->btn              = nullptr;
	bti->btn_nsub_vobjs   = 0;
	bti->btn_nsub_btnodes = 0;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	pni_fini(&bti->btn_pni);
}

static struct silofs_btnode_info *
bti_malloc_init(struct silofs_alloc *alloc, const struct silofs_pnptr *pnptr)
{
	struct silofs_btnode_info *bti;

	bti = bti_malloc(alloc);
	if (bti != nullptr) {
		bti_init(bti, pnptr);
	}
	return bti;
}

static void
bti_fini_free(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	bti_fini(bti);
	bti_free(bti, alloc);
}

static int
bti_attach_pview(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	struct silofs_pview *pview = nullptr;
	int err;

	err = pni_attach_pview(&bti->btn_pni, alloc);
	if (!err) {
		pview    = silofs_pni_pview(&bti->btn_pni);
		bti->btn = &pview->pv.btn;
	}
	return err;
}

static void
bti_detach_pview(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	pni_detach_pview(&bti->btn_pni, alloc);
	bti->btn = nullptr;
}

static struct silofs_btnode_info *
bti_new(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	bti = bti_malloc_init(alloc, pnptr);
	if (bti == nullptr) {
		return nullptr;
	}
	err = bti_attach_pview(bti, alloc);
	if (err) {
		bti_fini_free(bti, alloc);
		return nullptr;
	}
	return bti;
}

static void bti_del(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	if (bti != nullptr) {
		bti_detach_pview(bti, alloc);
		bti_fini_free(bti, alloc);
	}
}

static struct silofs_pnode_info *bti_to_pni(struct silofs_btnode_info *bti)
{
	struct silofs_pnode_info *pni = nullptr;

	if (bti != nullptr) {
		pni = &bti->btn_pni;
	}
	return pni;
}

static struct silofs_btnode_info *bti_from_pni(struct silofs_pnode_info *pni)
{
	struct silofs_btnode_info *bti = nullptr;

	if (pni != nullptr) {
		bti = mut_container_of(pni, struct silofs_btnode_info,
		                       btn_pni);
	}
	return bti;
}

static struct silofs_btnode_info *
bti_unconst(const struct silofs_btnode_info *bti)
{
	return silofs_unconst(bti);
}

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btnode_info *bti = nullptr;

	if (pni != nullptr) {
		bti = container_of(pni, struct silofs_btnode_info, btn_pni);
	}
	return bti_unconst(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *
silofs_new_pnode(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_pnode_info *pni = nullptr;
	const enum silofs_ptype ptype = pnptr_ptype(pnptr);

	switch (ptype) {
	case SILOFS_PTYPE_UBER:
		pni = ubi_to_pni(ubi_new(pnptr, alloc));
		break;
	case SILOFS_PTYPE_BLDESC:
		pni = bdi_to_pni(bdi_new(pnptr, alloc));
		break;
	case SILOFS_PTYPE_BTNODE:
		pni = bti_to_pni(bti_new(pnptr, alloc));
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_MBR:
	case SILOFS_PTYPE_VNODE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("can not create pnode: ptype=%d", (int)ptype);
		break;
	}
	return pni;
}

void silofs_del_pnode(struct silofs_pnode_info *pni,
                      struct silofs_alloc *alloc)
{
	const enum silofs_ptype ptype = pni_ptype(pni);

	switch (ptype) {
	case SILOFS_PTYPE_UBER:
		ubi_del(ubi_from_pni(pni), alloc);
		break;
	case SILOFS_PTYPE_BLDESC:
		bdi_del(bdi_from_pni(pni), alloc);
		break;
	case SILOFS_PTYPE_BTNODE:
		bti_del(bti_from_pni(pni), alloc);
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_MBR:
	case SILOFS_PTYPE_VNODE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("can not delete pnode: ptype=%d", (int)ptype);
		break;
	}
}

void silofs_seal_pnode(const struct silofs_pnode_info *pni)
{
	struct silofs_pview *pview = silofs_pni_pview(pni);

	silofs_pview_seal(pview);
}

int silofs_verify_pnode(const struct silofs_pnode_info *pni)
{
	struct silofs_pview *pview = silofs_pni_pview(pni);

	// TODO: verify sub-components
	return silofs_pview_verify(pview, pni_ptype(pni));
}
