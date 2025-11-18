/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include "infra.h"
#include "addr.h"
#include "pnodes.h"

static struct silofs_view *
new_view_of(struct silofs_alloc *alloc, enum silofs_mtype mtype)
{
	return silofs_view_new(alloc, mtype, 0);
}

static void del_view_of(struct silofs_view *view, struct silofs_alloc *alloc,
                        enum silofs_mtype mtype)
{
	silofs_view_del(view, alloc, mtype, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_mtype pmeta_mtype(const struct silofs_pmeta *pmeta)
{
	return pmeta->paddr.mtype;
}

static size_t pmeta_size(const struct silofs_pmeta *pmeta)
{
	return silofs_mtype_size(pmeta_mtype(pmeta));
}

static void
pni_init(struct silofs_pnode_info *pni, const struct silofs_pmeta *pmeta)
{
	silofs_pmeta_assign(&pni->pn_meta, pmeta);
	silofs_hmqe_init(&pni->pn_hmqe, pmeta_size(pmeta));
	silofs_hkey_by_paddr(&pni->pn_hmqe.hme_key, &pni->pn_meta.paddr);
	pni->pn_view = NULL;
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	silofs_pmeta_reset(&pni->pn_meta);
	silofs_hmqe_fini(&pni->pn_hmqe);
	pni->pn_view = NULL;
}

static enum silofs_mtype pni_mtype(const struct silofs_pnode_info *pni)
{
	return pni->pn_meta.paddr.mtype;
}

enum silofs_mtype silofs_pni_mtype(const struct silofs_pnode_info *pni)
{
	return pni_mtype(pni);
}

static struct silofs_dq_elem *pni_dqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
pni_dqe2(const struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe.hme_dqe;
}

void silofs_pni_set_dq(struct silofs_pnode_info *pni, struct silofs_dirtyq *dq)
{
	silofs_dqe_setq(pni_dqe(pni), dq);
}

static bool pni_isdirty(const struct silofs_pnode_info *pni)
{
	return silofs_dqe_is_dirty(pni_dqe2(pni));
}

void silofs_pni_dirtify(struct silofs_pnode_info *pni)
{
	if (!pni_isdirty(pni)) {
		silofs_dqe_enqueue(pni_dqe(pni));
	}
}

void silofs_pni_undirtify(struct silofs_pnode_info *pni)
{
	if (pni_isdirty(pni)) {
		silofs_dqe_dequeue(pni_dqe(pni));
	}
}

void silofs_pni_incref(struct silofs_pnode_info *pni)
{
	silofs_hmqe_incref(&pni->pn_hmqe);
}

void silofs_pni_decref(struct silofs_pnode_info *pni)
{
	silofs_hmqe_decref(&pni->pn_hmqe);
}

static int
pni_new_view(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	silofs_assert_null(pni->pn_view);
	pni->pn_view = new_view_of(alloc, pni_mtype(pni));
	return (pni->pn_view == NULL) ? -SILOFS_ENOMEM : 0;
}

static void
pni_del_view(struct silofs_pnode_info *pni, struct silofs_alloc *alloc)
{
	if (pni->pn_view != NULL) {
		del_view_of(pni->pn_view, alloc, pni_mtype(pni));
		pni->pn_view = NULL;
	}
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
ubi_init(struct silofs_uber_info *ubi, const struct silofs_pmeta *pmeta)
{
	pni_init(&ubi->ub_pni, pmeta);
	ubi->ub = NULL;
}

static void ubi_fini(struct silofs_uber_info *ubi)
{
	pni_fini(&ubi->ub_pni);
	ubi->ub = NULL;
}

static int
ubi_new_view(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	int err;

	err = pni_new_view(&ubi->ub_pni, alloc);
	if (!err) {
		ubi->ub = &ubi->ub_pni.pn_view->u.ub;
	}
	return err;
}

static struct silofs_uber_info *
ubi_new(const struct silofs_pmeta *pmeta, struct silofs_alloc *alloc)
{
	struct silofs_uber_info *ubi = NULL;
	int                      err;

	ubi = ubi_malloc(alloc);
	if (ubi == NULL) {
		return NULL;
	}
	ubi_init(ubi, pmeta);

	err = ubi_new_view(ubi, alloc);
	if (err) {
		ubi_fini(ubi);
		ubi_free(ubi, alloc);
		return NULL;
	}
	return ubi;
}

static void
ubi_del_view(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	pni_del_view(&ubi->ub_pni, alloc);
	ubi->ub = NULL;
}

static void ubi_del(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	if (ubi != NULL) {
		ubi_del_view(ubi, alloc);
		ubi_fini(ubi);
		ubi_free(ubi, alloc);
	}
}

static struct silofs_pnode_info *ubi_to_pni(struct silofs_uber_info *ubi)
{
	struct silofs_pnode_info *pni = NULL;

	if (ubi != NULL) {
		pni = &ubi->ub_pni;
	}
	return pni;
}

static struct silofs_uber_info *ubi_from_pni(struct silofs_pnode_info *pni)
{
	struct silofs_uber_info *ubi = NULL;

	if (pni != NULL) {
		ubi = container_of(pni, struct silofs_uber_info, ub_pni);
	}
	return ubi;
}

static struct silofs_uber_info *ubi_unconst(const struct silofs_uber_info *p)
{
	union {
		const struct silofs_uber_info *p;
		struct silofs_uber_info       *q;
	} u = { .p = p };

	return u.q;
}

struct silofs_uber_info *
silofs_ubi_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_uber_info *ubi = NULL;

	if (pni != NULL) {
		ubi = container_of2(pni, struct silofs_uber_info, ub_pni);
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
bdi_init(struct silofs_bldesc_info *bdi, const struct silofs_pmeta *pmeta)
{
	pni_init(&bdi->bld_pni, pmeta);
	bdi->bld = NULL;
}

static void bdi_fini(struct silofs_bldesc_info *bdi)
{
	pni_fini(&bdi->bld_pni);
	bdi->bld = NULL;
}

static int
bdi_new_view(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	int err;

	err = pni_new_view(&bdi->bld_pni, alloc);
	if (!err) {
		bdi->bld = &bdi->bld_pni.pn_view->u.bd;
	}
	return err;
}

static struct silofs_bldesc_info *
bdi_new(const struct silofs_pmeta *pmeta, struct silofs_alloc *alloc)
{
	struct silofs_bldesc_info *bdi = NULL;
	int                        err;

	bdi = bdi_malloc(alloc);
	if (bdi == NULL) {
		return NULL;
	}
	bdi_init(bdi, pmeta);

	err = bdi_new_view(bdi, alloc);
	if (err) {
		bdi_fini(bdi);
		bdi_free(bdi, alloc);
		return NULL;
	}
	return bdi;
}

static void
bdi_del_view(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	pni_del_view(&bdi->bld_pni, alloc);
	bdi->bld = NULL;
}

static void bdi_del(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	if (bdi != NULL) {
		bdi_del_view(bdi, alloc);
		bdi_fini(bdi);
		bdi_free(bdi, alloc);
	}
}

static struct silofs_pnode_info *bdi_to_pni(struct silofs_bldesc_info *bdi)
{
	struct silofs_pnode_info *pni = NULL;

	if (bdi != NULL) {
		pni = &bdi->bld_pni;
	}
	return pni;
}

static struct silofs_bldesc_info *bdi_from_pni(struct silofs_pnode_info *pni)
{
	struct silofs_bldesc_info *bdi = NULL;

	if (pni != NULL) {
		bdi = container_of(pni, struct silofs_bldesc_info, bld_pni);
	}
	return bdi;
}

static struct silofs_bldesc_info *
bdi_unconst(const struct silofs_bldesc_info *p)
{
	union {
		const struct silofs_bldesc_info *p;
		struct silofs_bldesc_info       *q;
	} u = { .p = p };

	return u.q;
}

struct silofs_bldesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_bldesc_info *bdi = NULL;

	if (pni != NULL) {
		bdi = container_of2(pni, struct silofs_bldesc_info, bld_pni);
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
bti_init(struct silofs_btnode_info *bti, const struct silofs_pmeta *pmeta)
{
	pni_init(&bti->btn_pni, pmeta);
	bti->btn        = NULL;
	bti->btn_rdonly = false;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	pni_fini(&bti->btn_pni);
	bti->btn = NULL;
}

static int
bti_new_view(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	int err;

	err = pni_new_view(&bti->btn_pni, alloc);
	if (!err) {
		bti->btn = &bti->btn_pni.pn_view->u.btn;
	}
	return err;
}

static struct silofs_btnode_info *
bti_new(const struct silofs_pmeta *pmeta, struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = NULL;
	int                        err;

	bti = bti_malloc(alloc);
	if (bti == NULL) {
		return NULL;
	}
	bti_init(bti, pmeta);

	err = bti_new_view(bti, alloc);
	if (err) {
		bti_fini(bti);
		bti_free(bti, alloc);
		return NULL;
	}
	return bti;
}

static void
bti_del_view(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	pni_del_view(&bti->btn_pni, alloc);
	bti->btn = NULL;
}

static void bti_del(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	if (bti != NULL) {
		bti_del_view(bti, alloc);
		bti_fini(bti);
		bti_free(bti, alloc);
	}
}

static struct silofs_pnode_info *bti_to_pni(struct silofs_btnode_info *bti)
{
	struct silofs_pnode_info *pni = NULL;

	if (bti != NULL) {
		pni = &bti->btn_pni;
	}
	return pni;
}

static struct silofs_btnode_info *bti_from_pni(struct silofs_pnode_info *pni)
{
	struct silofs_btnode_info *bti = NULL;

	if (bti != NULL) {
		bti = container_of(pni, struct silofs_btnode_info, btn_pni);
	}
	return bti;
}

static struct silofs_btnode_info *
bti_unconst(const struct silofs_btnode_info *p)
{
	union {
		const struct silofs_btnode_info *p;
		struct silofs_btnode_info       *q;
	} u = { .p = p };

	return u.q;
}

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_btnode_info *bti = NULL;

	if (pni != NULL) {
		bti = container_of2(pni, struct silofs_btnode_info, btn_pni);
	}
	return bti_unconst(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *
silofs_new_pnode(const struct silofs_pmeta *pmeta, struct silofs_alloc *alloc)
{
	struct silofs_pnode_info *pni   = NULL;
	const enum silofs_mtype   mtype = pmeta_mtype(pmeta);

	switch (mtype) {
	case SILOFS_MTYPE_UBER:
		pni = ubi_to_pni(ubi_new(pmeta, alloc));
		break;
	case SILOFS_MTYPE_BLDESC:
		pni = bdi_to_pni(bdi_new(pmeta, alloc));
		break;
	case SILOFS_MTYPE_BTNODE:
		pni = bti_to_pni(bti_new(pmeta, alloc));
		break;
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_MBR:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("can not create pnode: mtype=%d", (int)mtype);
		break;
	}
	return pni;
}

void silofs_del_pnode(struct silofs_pnode_info *pni,
                      struct silofs_alloc      *alloc)
{
	const enum silofs_mtype mtype = pni_mtype(pni);

	switch (mtype) {
	case SILOFS_MTYPE_UBER:
		ubi_del(ubi_from_pni(pni), alloc);
		break;
	case SILOFS_MTYPE_BLDESC:
		bdi_del(bdi_from_pni(pni), alloc);
		break;
	case SILOFS_MTYPE_BTNODE:
		bti_del(bti_from_pni(pni), alloc);
		break;
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_MBR:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("can not create pnode: mtype=%d", (int)mtype);
		break;
	}
}

static const struct silofs_civkey *
pni_civkey(const struct silofs_pnode_info *pni)
{
	return &pni->pn_meta.nmeta.civkey;
}

int silofs_encrypt_pnode(const struct silofs_pnode_info *pni,
                         const struct silofs_cipher     *cipher,
                         struct silofs_view             *enc_view)
{
	return silofs_encrypt_view(cipher,          //
	                           pni_civkey(pni), //
	                           pni->pn_view,    //
	                           pni_mtype(pni),  //
	                           enc_view);
}

int silofs_decrypt_pnode(struct silofs_pnode_info   *pni,
                         const struct silofs_cipher *cipher,
                         const struct silofs_view   *enc_view)
{
	return silofs_decrypt_view(cipher,          //
	                           pni_civkey(pni), //
	                           enc_view,        //
	                           pni_mtype(pni),  //
	                           pni->pn_view);
}

int silofs_verify_pnode(const struct silofs_pnode_info *pni)
{
	// TODO: verify sub-components
	return silofs_view_verify(pni->pn_view, pni_mtype(pni));
}

void silofs_seal_pnode(struct silofs_pnode_info *pni)
{
	silofs_view_seal(pni->pn_view);
}
