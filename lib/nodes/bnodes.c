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
#include "bnodes.h"

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

static size_t baddr_size(const struct silofs_baddr *baddr)
{
	return silofs_mtype_size(baddr->mtype);
}

void silofs_bni_init(struct silofs_bnode_info *bni,
                     const struct silofs_baddr *baddr)
{
	silofs_ivkey_reset(&bni->bn_ivkey);
	silofs_baddr_assign(&bni->bn_baddr, baddr);
	silofs_hmqe_init(&bni->bn_hmqe, baddr_size(baddr));
	silofs_hkey_by_baddr(&bni->bn_hmqe.hme_key, &bni->bn_baddr);
	bni->bn_view = nullptr;
}

void silofs_bni_fini(struct silofs_bnode_info *bni)
{
	silofs_ivkey_reset(&bni->bn_ivkey);
	silofs_baddr_fini(&bni->bn_baddr);
	silofs_hmqe_fini(&bni->bn_hmqe);
	bni->bn_view = nullptr;
}

static enum silofs_mtype bni_mtype(const struct silofs_bnode_info *bni)
{
	return bni->bn_baddr.mtype;
}

enum silofs_mtype silofs_bni_mtype(const struct silofs_bnode_info *bni)
{
	return bni_mtype(bni);
}

static struct silofs_dq_elem *bni_dqe(struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
bni_dqe2(const struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe.hme_dqe;
}

void silofs_bni_set_dq(struct silofs_bnode_info *bni, struct silofs_dirtyq *dq)
{
	silofs_dqe_setq(bni_dqe(bni), dq);
}

static bool bni_isdirty(const struct silofs_bnode_info *bni)
{
	return silofs_dqe_is_dirty(bni_dqe2(bni));
}

void silofs_bni_dirtify(struct silofs_bnode_info *bni)
{
	if (!bni_isdirty(bni)) {
		silofs_dqe_enqueue(bni_dqe(bni));
	}
}

void silofs_bni_undirtify(struct silofs_bnode_info *bni)
{
	if (bni_isdirty(bni)) {
		silofs_dqe_dequeue(bni_dqe(bni));
	}
}

void silofs_bni_incref(struct silofs_bnode_info *bni)
{
	silofs_hmqe_incref(&bni->bn_hmqe);
}

void silofs_bni_decref(struct silofs_bnode_info *bni)
{
	silofs_hmqe_decref(&bni->bn_hmqe);
}

void silofs_bni_setup_ivkey(struct silofs_bnode_info *bni,
                            const struct silofs_mdigest *md,
                            const struct silofs_key *key)
{
	struct silofs_iv iv;

	silofs_derive_iv_by_baddr(md, &bni->bn_baddr, &iv);
	silofs_ivkey_setup(&bni->bn_ivkey, key, &iv);
}

static int
bni_new_view(struct silofs_bnode_info *bni, struct silofs_alloc *alloc)
{
	silofs_assert_null(bni->bn_view);
	bni->bn_view = new_view_of(alloc, bni_mtype(bni));
	return (bni->bn_view == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void
bni_del_view(struct silofs_bnode_info *bni, struct silofs_alloc *alloc)
{
	if (bni->bn_view != nullptr) {
		del_view_of(bni->bn_view, alloc, bni_mtype(bni));
		bni->bn_view = nullptr;
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
ubi_init(struct silofs_uber_info *ubi, const struct silofs_baddr *baddr)
{
	silofs_bni_init(&ubi->ub_bni, baddr);
	ubi->ub = nullptr;
}

static void ubi_fini(struct silofs_uber_info *ubi)
{
	silofs_bni_fini(&ubi->ub_bni);
	ubi->ub = nullptr;
}

static int
ubi_new_view(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	int err;

	err = bni_new_view(&ubi->ub_bni, alloc);
	if (!err) {
		ubi->ub = &ubi->ub_bni.bn_view->u.ub;
	}
	return err;
}

static struct silofs_uber_info *
ubi_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	ubi = ubi_malloc(alloc);
	if (ubi == nullptr) {
		return nullptr;
	}
	ubi_init(ubi, baddr);

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
	bni_del_view(&ubi->ub_bni, alloc);
	ubi->ub = nullptr;
}

static void ubi_del(struct silofs_uber_info *ubi, struct silofs_alloc *alloc)
{
	if (ubi != nullptr) {
		ubi_del_view(ubi, alloc);
		ubi_fini(ubi);
		ubi_free(ubi, alloc);
	}
}

static struct silofs_bnode_info *ubi_to_bni(struct silofs_uber_info *ubi)
{
	struct silofs_bnode_info *bni = nullptr;

	if (ubi != nullptr) {
		bni = &ubi->ub_bni;
	}
	return bni;
}

static struct silofs_uber_info *ubi_from_bni(struct silofs_bnode_info *bni)
{
	struct silofs_uber_info *ubi = nullptr;

	if (bni != nullptr) {
		ubi = container_of(bni, struct silofs_uber_info, ub_bni);
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
silofs_ubi_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_uber_info *ubi = nullptr;

	if (bni != nullptr) {
		ubi = container_of2(bni, struct silofs_uber_info, ub_bni);
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
bdi_init(struct silofs_bldesc_info *bdi, const struct silofs_baddr *baddr)
{
	silofs_bni_init(&bdi->bd_bni, baddr);
	bdi->bd = nullptr;
}

static void bdi_fini(struct silofs_bldesc_info *bdi)
{
	silofs_bni_fini(&bdi->bd_bni);
	bdi->bd = nullptr;
}

static int
bdi_new_view(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	int err;

	err = bni_new_view(&bdi->bd_bni, alloc);
	if (!err) {
		bdi->bd = &bdi->bd_bni.bn_view->u.bd;
	}
	return err;
}

static struct silofs_bldesc_info *
bdi_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc)
{
	struct silofs_bldesc_info *bdi = nullptr;
	int err;

	bdi = bdi_malloc(alloc);
	if (bdi == nullptr) {
		return nullptr;
	}
	bdi_init(bdi, baddr);

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
	bni_del_view(&bdi->bd_bni, alloc);
	bdi->bd = nullptr;
}

static void bdi_del(struct silofs_bldesc_info *bdi, struct silofs_alloc *alloc)
{
	if (bdi != nullptr) {
		bdi_del_view(bdi, alloc);
		bdi_fini(bdi);
		bdi_free(bdi, alloc);
	}
}

static struct silofs_bnode_info *bdi_to_bni(struct silofs_bldesc_info *bdi)
{
	struct silofs_bnode_info *bni = nullptr;

	if (bdi != nullptr) {
		bni = &bdi->bd_bni;
	}
	return bni;
}

static struct silofs_bldesc_info *bdi_from_bni(struct silofs_bnode_info *bni)
{
	struct silofs_bldesc_info *bdi = nullptr;

	if (bni != nullptr) {
		bdi = container_of(bni, struct silofs_bldesc_info, bd_bni);
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
silofs_bdi_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_bldesc_info *bdi = nullptr;

	if (bni != nullptr) {
		bdi = container_of2(bni, struct silofs_bldesc_info, bd_bni);
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
bti_init(struct silofs_btnode_info *bti, const struct silofs_baddr *baddr)
{
	silofs_bni_init(&bti->btn_bni, baddr);
	bti->btn = nullptr;
	bti->btn_rdonly = false;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	silofs_bni_fini(&bti->btn_bni);
	bti->btn = nullptr;
}

static int
bti_new_view(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	int err;

	err = bni_new_view(&bti->btn_bni, alloc);
	if (!err) {
		bti->btn = &bti->btn_bni.bn_view->u.btn;
	}
	return err;
}

static struct silofs_btnode_info *
bti_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	bti = bti_malloc(alloc);
	if (bti == nullptr) {
		return nullptr;
	}
	bti_init(bti, baddr);

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
	bni_del_view(&bti->btn_bni, alloc);
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

static struct silofs_bnode_info *bti_to_bni(struct silofs_btnode_info *bti)
{
	struct silofs_bnode_info *bni = nullptr;

	if (bti != nullptr) {
		bni = &bti->btn_bni;
	}
	return bni;
}

static struct silofs_btnode_info *bti_from_bni(struct silofs_bnode_info *bni)
{
	struct silofs_btnode_info *bti = nullptr;

	if (bti != nullptr) {
		bti = container_of(bni, struct silofs_btnode_info, btn_bni);
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
silofs_bti_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_btnode_info *bti = nullptr;

	if (bni != nullptr) {
		bti = container_of2(bni, struct silofs_btnode_info, btn_bni);
	}
	return bti_unconst(bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_bnode_info *
silofs_new_bnode(const struct silofs_baddr *baddr, struct silofs_alloc *alloc)
{
	struct silofs_bnode_info *bni = nullptr;
	const enum silofs_mtype mtype = baddr->mtype;

	switch (mtype) {
	case SILOFS_MTYPE_UBER:
		bni = ubi_to_bni(ubi_new(baddr, alloc));
		break;
	case SILOFS_MTYPE_BDESC:
		bni = bdi_to_bni(bdi_new(baddr, alloc));
		break;
	case SILOFS_MTYPE_BTNODE:
		bni = bti_to_bni(bti_new(baddr, alloc));
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
		silofs_panic("can not create bnode: mtype=%d", (int)mtype);
		break;
	}
	return bni;
}

void silofs_del_bnode(struct silofs_bnode_info *bni,
                      struct silofs_alloc *alloc)
{
	const enum silofs_mtype mtype = bni_mtype(bni);

	switch (mtype) {
	case SILOFS_MTYPE_UBER:
		ubi_del(ubi_from_bni(bni), alloc);
		break;
	case SILOFS_MTYPE_BDESC:
		bdi_del(bdi_from_bni(bni), alloc);
		break;
	case SILOFS_MTYPE_BTNODE:
		bti_del(bti_from_bni(bni), alloc);
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
		silofs_panic("can not create bnode: mtype=%d", (int)mtype);
		break;
	}
}
