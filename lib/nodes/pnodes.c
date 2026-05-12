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

static struct silofs_pview *
new_pview_of(struct silofs_alloc *alloc, enum silofs_ptype ptype)
{
	return silofs_pview_new(alloc, ptype);
}

static void del_pview_of(struct silofs_pview *pview,
                         struct silofs_alloc *alloc, enum silofs_ptype ptype)
{
	silofs_pview_del(pview, alloc, ptype);
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

	silofs_ni_init(&pni->pn, psize);
	silofs_pnptr_assign(&pni->pn_self, pnptr);
	silofs_paddr_reset(&pni->pn_parent);
	silofs_list_head_init(&pni->pn_dsq_lh);
	silofs_hkey_by_paddr(&pni->pn.hmqe.hme_key, &pni->pn_self.paddr);
	pni->pn_pview = nullptr;
	pni->pn_flags = SILOFS_PNODEF_NONE;
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	silofs_pnptr_reset(&pni->pn_self);
	silofs_paddr_reset(&pni->pn_parent);
	silofs_list_head_fini(&pni->pn_dsq_lh);
	silofs_ni_fini(&pni->pn);
	pni->pn_pview = nullptr;
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
	return &pni->pn.dqe;
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
	silofs_ni_incref(&pni->pn);
}

void silofs_pni_decref(struct silofs_pnode_info *pni)
{
	silofs_ni_decref(&pni->pn);
}

static int
pni_new_pview(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	silofs_assert_null(pni->pn_pview);
	pni->pn_pview = new_pview_of(alloc, pni_ptype(pni));
	return (pni->pn_pview == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void
pni_del_view(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	if (pni->pn_pview != nullptr) {
		del_pview_of(pni->pn_pview, alloc, pni_ptype(pni));
		pni->pn_pview = nullptr;
	}
}

const struct silofs_pnptr *silofs_pni_self(const struct silofs_pnode_info *pni)
{
	return &pni->pn_self;
}

const struct silofs_paddr *
silofs_pni_parent(const struct silofs_pnode_info *pni)
{
	return &pni->pn_parent;
}

void silofs_pni_set_parent(struct silofs_pnode_info *pni,
                           const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&pni->pn_parent, paddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_uber_info *ubi_malloc(struct silofs_alloc *alloc)
{
	return silofs_memalloc(alloc, sizeof(struct silofs_uber_info), 0);
}

static void ubi_free(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ubi, sizeof(*ubi), 0);
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

static int
ubi_new_view(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	int err;

	err = pni_new_pview(&ubi->ub_pni, alloc);
	if (!err) {
		ubi->ubn = &ubi->ub_pni.pn_pview->pv.ub;
	}
	return err;
}

static struct silofs_uber_info *
ubi_new(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	ubi = ubi_malloc(alloc);
	if (ubi == nullptr) {
		return nullptr;
	}
	ubi_init(ubi, pnptr);

	err = ubi_new_view(ubi, alloc);
	if (err) {
		ubi_fini(ubi);
		ubi_free(ubi, alloc);
		return nullptr;
	}
	return ubi;
}

static void
ubi_del_view(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	pni_del_view(&ubi->ub_pni, alloc);
	ubi->ubn = nullptr;
}

static void ubi_del(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	if (ubi != nullptr) {
		ubi_del_view(ubi, alloc);
		ubi_fini(ubi);
		ubi_free(ubi, alloc);
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

static struct silofs_uber_info *ubi_unconst(const struct silofs_uber_info *p)
{
	union {
		const struct silofs_uber_info *p;
		struct silofs_uber_info *q;
	} u = { .p = p };

	return u.q;
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
	return silofs_memalloc(alloc, sizeof(struct silofs_bldesc_info), 0);
}

static void
bdi_free(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bdi, sizeof(*bdi), 0);
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

static int
bdi_new_view(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	int err;

	err = pni_new_pview(&bdi->bld_pni, alloc);
	if (!err) {
		bdi->bld = &bdi->bld_pni.pn_pview->pv.bd;
	}
	return err;
}

static struct silofs_bldesc_info *
bdi_new(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_bldesc_info *bdi = nullptr;
	int err;

	bdi = bdi_malloc(alloc);
	if (bdi == nullptr) {
		return nullptr;
	}
	bdi_init(bdi, pnptr);

	err = bdi_new_view(bdi, alloc);
	if (err) {
		bdi_fini(bdi);
		bdi_free(bdi, alloc);
		return nullptr;
	}
	return bdi;
}

static void
bdi_del_view(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	pni_del_view(&bdi->bld_pni, alloc);
	bdi->bld = nullptr;
}

static void bdi_del(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	if (bdi != nullptr) {
		bdi_del_view(bdi, alloc);
		bdi_fini(bdi);
		bdi_free(bdi, alloc);
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
bdi_unconst(const struct silofs_bldesc_info *p)
{
	union {
		const struct silofs_bldesc_info *p;
		struct silofs_bldesc_info *q;
	} u = { .p = p };

	return u.q;
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
	return silofs_memalloc(alloc, sizeof(struct silofs_btnode_info), 0);
}

static void
bti_free(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bti, sizeof(*bti), 0);
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
	bti->btn = nullptr;
}

static int
bti_new_view(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	int err;

	err = pni_new_pview(&bti->btn_pni, alloc);
	if (!err) {
		bti->btn = &bti->btn_pni.pn_pview->pv.btn;
	}
	return err;
}

static struct silofs_btnode_info *
bti_new(const struct silofs_pnptr *pnptr, struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	bti = bti_malloc(alloc);
	if (bti == nullptr) {
		return nullptr;
	}
	bti_init(bti, pnptr);

	err = bti_new_view(bti, alloc);
	if (err) {
		bti_fini(bti);
		bti_free(bti, alloc);
		return nullptr;
	}
	return bti;
}

static void
bti_del_view(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	pni_del_view(&bti->btn_pni, alloc);
	bti->btn = nullptr;
}

static void bti_del(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	if (bti != nullptr) {
		bti_del_view(bti, alloc);
		bti_fini(bti);
		bti_free(bti, alloc);
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
bti_unconst(const struct silofs_btnode_info *p)
{
	union {
		const struct silofs_btnode_info *p;
		struct silofs_btnode_info *q;
	} u = { .p = p };

	return u.q;
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

void silofs_seal_pnode(struct silofs_pnode_info *pni)
{
	silofs_seal_pview(pni->pn_pview);
}

int silofs_verify_pnode(const struct silofs_pnode_info *pni)
{
	// TODO: verify sub-components
	return silofs_verify_pview(pni->pn_pview, pni_ptype(pni));
}
