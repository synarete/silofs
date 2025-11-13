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
#include <limits.h>
#include "infra.h"
#include "fs.h"
#include "env.h"

enum {
	SILOFS_UI_MAGIC = 0xCAFEBEB,
	SILOFS_VI_MAGIC = 0xDEDFACE,
};

/* local functions forward declarations */
static int
verify_view_by(const struct silofs_view *view, const enum silofs_mtype mtype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_view *
view_new_by_uaddr(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	return silofs_view_new(alloc, silofs_uaddr_mtype(uaddr), 0);
}

static struct silofs_view *
view_new_by_vaddr(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	return silofs_view_new(alloc, vaddr->mtype, 0);
}

static void
view_del_by_uaddr(struct silofs_view *view, const struct silofs_uaddr *uaddr,
                  struct silofs_alloc *alloc, int flags)
{
	silofs_view_del(view, alloc, silofs_uaddr_mtype(uaddr), flags);
}

static void
view_del_by_vaddr(struct silofs_view *view, const struct silofs_vaddr *vaddr,
                  struct silofs_alloc *alloc, int flags)
{
	silofs_view_del(view, alloc, vaddr->mtype, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *
lni_unconst(const struct silofs_lnode_info *lni)
{
	union {
		const struct silofs_lnode_info *p;
		struct silofs_lnode_info *q;
	} u = { .p = lni };
	return u.q;
}

static void lni_init(struct silofs_lnode_info *lni, enum silofs_mtype mtype,
                     struct silofs_view *view)
{
	silofs_hmqe_init(&lni->ln_hmqe, silofs_mtype_size(mtype));
	silofs_avl_node_init(&lni->ln_ds_avl_node);
	lni->ln_mtype = mtype;
	lni->ln_ds_next = nullptr;
	lni->ln_view = view;
	lni->ln_flags = 0;
}

static void lni_fini(struct silofs_lnode_info *lni)
{
	silofs_hmqe_fini(&lni->ln_hmqe);
	silofs_avl_node_fini(&lni->ln_ds_avl_node);
	lni->ln_ds_next = nullptr;
	lni->ln_view = nullptr;
}

int silofs_lni_verify_view(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni->ln_view);
	return verify_view_by(lni->ln_view, lni->ln_mtype);
}

struct silofs_lnode_info *
silofs_lni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_lnode_info *lni = nullptr;

	if (likely(hmqe != nullptr)) {
		lni = container_of2(hmqe, struct silofs_lnode_info, ln_hmqe);
	}
	return lni_unconst(lni);
}

struct silofs_lnode_info *silofs_lni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmqe_from_dqe(dqe);
	return silofs_lni_from_hmqe(hmqe);
}

struct silofs_hmapq_elem *silofs_lni_to_hmqe(struct silofs_lnode_info *lni)
{
	return &lni->ln_hmqe;
}

static bool lni_ispinned(const struct silofs_lnode_info *lni)
{
	const enum silofs_lnflags mask = SILOFS_LNF_PINNED;

	return (lni->ln_flags & mask) == mask;
}

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni)
{
	bool ret = false;

	if (!lni_ispinned(lni)) {
		ret = silofs_hmqe_is_evictable(&lni->ln_hmqe);
	}
	return ret;
}

static void lni_incref(struct silofs_lnode_info *lni)
{
	silofs_hmqe_incref(&lni->ln_hmqe);
}

static void lni_decref(struct silofs_lnode_info *lni)
{
	silofs_hmqe_decref(&lni->ln_hmqe);
}

static int lni_refcnt(const struct silofs_lnode_info *lni)
{
	return silofs_hmqe_refcnt(&lni->ln_hmqe);
}

int silofs_lni_refcnt(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	return lni_refcnt(lni);
}

void silofs_lni_incref(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	lni_incref(lni);
}

void silofs_lni_decref(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	lni_decref(lni);
}

void silofs_lni_remove_from(struct silofs_lnode_info *lni,
                            struct silofs_hmapq *hmapq)
{
	silofs_hmapq_remove(hmapq, silofs_lni_to_hmqe(lni));
}

static struct silofs_dq_elem *lni_dqe(struct silofs_lnode_info *lni)
{
	return &lni->ln_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
lni_dqe2(const struct silofs_lnode_info *lni)
{
	return &lni->ln_hmqe.hme_dqe;
}

static void lni_set_dq(struct silofs_lnode_info *lni, struct silofs_dirtyq *dq)
{
	silofs_dqe_setq(lni_dqe(lni), dq);
}

bool silofs_lni_isdirty(const struct silofs_lnode_info *lni)
{
	return silofs_dqe_is_dirty(lni_dqe2(lni));
}

void silofs_lni_dirtify(struct silofs_lnode_info *lni)
{
	if (!silofs_lni_isdirty(lni)) {
		silofs_dqe_enqueue(lni_dqe(lni));
	}
}

void silofs_lni_undirtify(struct silofs_lnode_info *lni)
{
	if (silofs_lni_isdirty(lni)) {
		silofs_dqe_dequeue(lni_dqe(lni));
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *
uni_unconst(const struct silofs_unode_info *uni)
{
	union {
		const struct silofs_unode_info *p;
		struct silofs_unode_info *q;
	} u = { .p = uni };
	return u.q;
}

static void uni_verify(const struct silofs_unode_info *uni)
{
	silofs_assert_not_null(uni);
	silofs_assert_not_null(uni->un_lni.ln_view);

	if (unlikely(uni->un_magic != SILOFS_UI_MAGIC)) {
		silofs_panic("bad unode: uni=%p magic=%lx", (const void *)uni,
		             uni->un_magic);
	}
}

static void
uni_init(struct silofs_unode_info *uni, const struct silofs_uaddr *uaddr,
         struct silofs_view *view)
{
	lni_init(&uni->un_lni, silofs_uaddr_mtype(uaddr), view);
	silofs_uaddr_assign(&uni->un_uaddr, uaddr);
	uni->un_magic = SILOFS_UI_MAGIC;
}

static void uni_fini(struct silofs_unode_info *uni)
{
	silofs_uaddr_reset(&uni->un_uaddr);
	lni_fini(&uni->un_lni);
	uni->un_magic = UINT64_MAX;
}

void silofs_uni_incref(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_lni_incref(&uni->un_lni);
}

void silofs_uni_decref(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_lni_decref(&uni->un_lni);
}

struct silofs_unode_info *
silofs_uni_from_lni(const struct silofs_lnode_info *lni)
{
	const struct silofs_unode_info *uni;

	silofs_assert_not_null(lni);

	uni = container_of2(lni, struct silofs_unode_info, un_lni);
	uni_verify(uni);

	return uni_unconst(uni);
}

void silofs_uni_seal_view(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_hdr_seal(&uni->un_lni.ln_view->u.hdr[0]);
}

static void uni_del_view(struct silofs_unode_info *uni,
                         struct silofs_alloc *alloc, int flags)
{
	struct silofs_view *view = uni->un_lni.ln_view;

	view_del_by_uaddr(view, silofs_uni_uaddr(uni), alloc, flags);
	uni->un_lni.ln_view = nullptr;
}

bool silofs_uni_isactive(const struct silofs_unode_info *uni)
{
	uni_verify(uni);

	return (uni->un_lni.ln_flags & SILOFS_LNF_ACTIVE) > 0;
}

void silofs_uni_set_active(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	uni->un_lni.ln_flags |= SILOFS_LNF_ACTIVE;
}

void silofs_uni_dirtify(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_lni_dirtify(&uni->un_lni);
}

void silofs_uni_undirtify(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_lni_undirtify(&uni->un_lni);
}

bool silofs_uni_isevictable(const struct silofs_unode_info *uni)
{
	uni_verify(uni);

	return silofs_lni_isevictable(&uni->un_lni);
}

enum silofs_mtype silofs_uni_mtype(const struct silofs_unode_info *uni)
{
	uni_verify(uni);

	return silofs_uaddr_mtype(&uni->un_uaddr);
}

void silofs_uni_set_dq(struct silofs_unode_info *uni, struct silofs_dirtyq *dq)
{
	lni_set_dq(&uni->un_lni, dq);
}

const struct silofs_uaddr *
silofs_uni_uaddr(const struct silofs_unode_info *uni)
{
	return &uni->un_uaddr;
}

const struct silofs_laddr *
silofs_uni_laddr(const struct silofs_unode_info *uni)
{
	return &uni->un_uaddr.laddr;
}

const struct silofs_blobid *
silofs_uni_lvid(const struct silofs_unode_info *uni)
{
	return &uni->un_uaddr.laddr.lsid.blobid;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
vni_unconst(const struct silofs_vnode_info *vni)
{
	union {
		const struct silofs_vnode_info *p;
		struct silofs_vnode_info *q;
	} u = { .p = vni };
	return u.q;
}

static void vni_verify(const struct silofs_vnode_info *vni)
{
	if (unlikely(vni->vn_magic != SILOFS_VI_MAGIC)) {
		silofs_panic("bad vnode: vni=%p magic=%lx", (const void *)vni,
		             vni->vn_magic);
	}
}

static void
vni_init(struct silofs_vnode_info *vni, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	lni_init(&vni->vn_lni, vaddr->mtype, view);
	silofs_vaddr_assign(&vni->vn_vaddr, vaddr);
	silofs_llink_reset(&vni->vn_llink);
	vni->vn_asyncwr = 0;
	vni->vn_magic = SILOFS_VI_MAGIC;
}

static void vni_fini(struct silofs_vnode_info *vni)
{
	vni_verify(vni);
	silofs_assert_eq(vni->vn_asyncwr, 0);

	lni_fini(&vni->vn_lni);
	silofs_vaddr_reset(&vni->vn_vaddr);
	vni->vn_magic = UINT64_MAX;
}

int silofs_vni_refcnt(const struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	return silofs_lni_refcnt(&vni->vn_lni);
}

void silofs_vni_incref(struct silofs_vnode_info *vni)
{
	if (likely(vni != nullptr)) {
		silofs_lni_incref(&vni->vn_lni);
	}
}

void silofs_vni_decref(struct silofs_vnode_info *vni)
{
	if (likely(vni != nullptr)) {
		silofs_lni_decref(&vni->vn_lni);
	}
}

void silofs_vni_set_dq(struct silofs_vnode_info *vni, struct silofs_dirtyq *dq)
{
	lni_set_dq(&vni->vn_lni, dq);
}

bool silofs_vni_isdirty(const struct silofs_vnode_info *vni)
{
	return silofs_lni_isdirty(&vni->vn_lni);
}

static void
vni_update_dq_by(struct silofs_vnode_info *vni, struct silofs_inode_info *ii)
{
	if (ii != nullptr) {
		silofs_vni_set_dq(vni, &ii->i_dq_vnis);
	}
}

void silofs_vni_dirtify(struct silofs_vnode_info *vni,
                        struct silofs_inode_info *ii)
{
	silofs_assert_not_null(vni);

	if (!silofs_vni_isdirty(vni)) {
		vni_update_dq_by(vni, ii);
		silofs_lni_dirtify(&vni->vn_lni);
	}
}

void silofs_vni_undirtify(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	if (silofs_vni_isdirty(vni)) {
		silofs_lni_undirtify(&vni->vn_lni);
	}
}

struct silofs_vnode_info *
silofs_vni_from_lni(const struct silofs_lnode_info *lni)
{
	const struct silofs_vnode_info *vni = nullptr;

	if (lni != nullptr) {
		vni = container_of2(lni, struct silofs_vnode_info, vn_lni);
		vni_verify(vni);
	}
	return vni_unconst(vni);
}

struct silofs_vnode_info *silofs_vni_from_dqe(struct silofs_dq_elem *dqe)
{
	return silofs_vni_from_lni(silofs_lni_from_dqe(dqe));
}

void silofs_vni_seal_view(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni->vn_lni.ln_view);
	silofs_hdr_seal(&vni->vn_lni.ln_view->u.hdr[0]);
}

static bool
vni_has_mtype(const struct silofs_vnode_info *vni, enum silofs_mtype mtype)
{
	return silofs_vni_mtype(vni) == mtype;
}

static void vni_del_view(struct silofs_vnode_info *vni,
                         struct silofs_alloc *alloc, int flags)
{
	struct silofs_view *view = vni->vn_lni.ln_view;

	view_del_by_vaddr(view, silofs_vni_vaddr(vni), alloc, flags);
	vni->vn_lni.ln_view = nullptr;
}

bool silofs_vni_isevictable(const struct silofs_vnode_info *vni)
{
	return silofs_lni_isevictable(&vni->vn_lni);
}

bool silofs_vni_need_recheck(const struct silofs_vnode_info *vni)
{
	const enum silofs_lnflags flags = vni->vn_lni.ln_flags;
	const enum silofs_lnflags mask = SILOFS_LNF_RECHECK;

	return (flags & mask) != mask;
}

void silofs_vni_set_rechecked(struct silofs_vnode_info *vni)
{
	vni->vn_lni.ln_flags |= SILOFS_LNF_RECHECK;
}

enum silofs_mtype silofs_vni_mtype(const struct silofs_vnode_info *vni)
{
	return vni->vn_vaddr.mtype;
}

const struct silofs_vaddr *
silofs_vni_vaddr(const struct silofs_vnode_info *vni)
{
	return &vni->vn_vaddr;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sbi_to_uni(struct silofs_sb_info *sbi)
{
	return &sbi->sb_uni;
}

static struct silofs_sb_info *sbi_from_uni(struct silofs_unode_info *uni)
{
	return container_of(uni, struct silofs_sb_info, sb_uni);
}

static int sbi_init(struct silofs_sb_info *sbi,
                    const struct silofs_uaddr *uaddr, struct silofs_view *view)
{
	uni_init(&sbi->sb_uni, uaddr, view);
	sbi->sb = &view->u.sb;
	return 0;
}

static void sbi_fini(struct silofs_sb_info *sbi)
{
	uni_fini(&sbi->sb_uni);
	sbi->sb = nullptr;
}

static struct silofs_sb_info *sbi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sb_info *sbi;

	sbi = silofs_memalloc(alloc, sizeof(*sbi), SILOFS_ALLOCF_BZERO);
	return sbi;
}

static void
sbi_free(struct silofs_sb_info *sbi, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, sbi, sizeof(*sbi), flags);
}

static struct silofs_sb_info *
sbi_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_view *view;
	struct silofs_sb_info *sbi;
	int err;

	view = view_new_by_uaddr(alloc, uaddr);
	if (view == nullptr) {
		return nullptr;
	}
	sbi = sbi_malloc(alloc);
	if (sbi == nullptr) {
		view_del_by_uaddr(view, uaddr, alloc, 0);
		return nullptr;
	}
	err = sbi_init(sbi, uaddr, view);
	if (err) {
		sbi_free(sbi, alloc, 0);
		view_del_by_uaddr(view, uaddr, alloc, 0);
		return nullptr;
	}
	return sbi;
}

static void
sbi_del(struct silofs_sb_info *sbi, struct silofs_alloc *alloc, int flags)
{
	uni_del_view(&sbi->sb_uni, alloc, flags);
	sbi_fini(sbi);
	sbi_free(sbi, alloc, flags);
}

struct silofs_sb_info *silofs_sbi_from_uni(struct silofs_unode_info *uni)
{
	silofs_assert_not_null(uni);
	return sbi_from_uni(uni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *sni_to_uni(struct silofs_spnode_info *sni)
{
	return &sni->sn_uni;
}

static struct silofs_spnode_info *sni_from_uni(struct silofs_unode_info *uni)
{
	return container_of(uni, struct silofs_spnode_info, sn_uni);
}

static void
sni_init(struct silofs_spnode_info *sni, const struct silofs_uaddr *uaddr,
         struct silofs_view *view)
{
	uni_init(&sni->sn_uni, uaddr, view);
	sni->sn = &view->u.sn;
	sni->sn_nactive_subs = 0;
}

static void sni_fini(struct silofs_spnode_info *sni)
{
	uni_fini(&sni->sn_uni);
	sni->sn = nullptr;
	sni->sn_nactive_subs = 0;
}

static struct silofs_spnode_info *sni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spnode_info *sni;

	sni = silofs_memalloc(alloc, sizeof(*sni), 0);
	return sni;
}

static void
sni_free(struct silofs_spnode_info *sni, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, sni, sizeof(*sni), flags);
}

static void
sni_del(struct silofs_spnode_info *sni, struct silofs_alloc *alloc, int flags)
{
	uni_verify(&sni->sn_uni);
	uni_del_view(&sni->sn_uni, alloc, flags);
	sni_fini(sni);
	sni_free(sni, alloc, flags);
}

static struct silofs_spnode_info *
sni_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_view *view;
	struct silofs_spnode_info *sni;

	view = view_new_by_uaddr(alloc, uaddr);
	if (view == nullptr) {
		return nullptr;
	}
	sni = sni_malloc(alloc);
	if (sni == nullptr) {
		view_del_by_uaddr(view, uaddr, alloc, 0);
		return nullptr;
	}
	sni_init(sni, uaddr, view);
	return sni;
}

struct silofs_spnode_info *silofs_sni_from_uni(struct silofs_unode_info *uni)
{
	silofs_assert_not_null(uni);
	return sni_from_uni(uni_unconst(uni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *sli_to_uni(struct silofs_spleaf_info *sli)
{
	return &sli->sl_uni;
}

static struct silofs_spleaf_info *sli_from_uni(struct silofs_unode_info *uni)
{
	return container_of(uni, struct silofs_spleaf_info, sl_uni);
}

static void
sli_init(struct silofs_spleaf_info *sli, const struct silofs_uaddr *uaddr,
         struct silofs_view *view)
{
	uni_init(&sli->sl_uni, uaddr, view);
	sli->sl = &view->u.sl;
}

static void sli_fini(struct silofs_spleaf_info *sli)
{
	uni_fini(&sli->sl_uni);
	sli->sl = nullptr;
}

static struct silofs_spleaf_info *sli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spleaf_info *sli;

	sli = silofs_memalloc(alloc, sizeof(*sli), 0);
	return sli;
}

static void
sli_free(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, sli, sizeof(*sli), flags);
}

static struct silofs_spleaf_info *
sli_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_view *view;
	struct silofs_spleaf_info *sli;

	view = view_new_by_uaddr(alloc, uaddr);
	if (view == nullptr) {
		return nullptr;
	}
	sli = sli_malloc(alloc);
	if (sli == nullptr) {
		view_del_by_uaddr(view, uaddr, alloc, 0);
		return nullptr;
	}
	sli_init(sli, uaddr, view);
	return sli;
}

static void
sli_del(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc, int flags)
{
	uni_verify(&sli->sl_uni);
	uni_del_view(&sli->sl_uni, alloc, flags);
	sli_fini(sli);
	sli_free(sli, alloc, flags);
}

struct silofs_spleaf_info *silofs_sli_from_uni(struct silofs_unode_info *uni)
{
	return sli_from_uni(uni_unconst(uni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *lsi_to_vni(struct silofs_lsmap_info *lsi)
{
	return &lsi->ls_vni;
}

struct silofs_lsmap_info *silofs_lsi_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_lsmap_info, ls_vni);
}

static void
lsi_init(struct silofs_lsmap_info *lsi, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	vni_init(&lsi->ls_vni, vaddr, view);
	lsi->lsm = &view->u.lsm;
	lsi->ls_nused_bytes = 0;
	lsi->ls_off_hint = 0;
}

static void lsi_fini(struct silofs_lsmap_info *lsi)
{
	vni_fini(&lsi->ls_vni);
	lsi->ls_nused_bytes = UINT_MAX;
	lsi->ls_off_hint = -1;
}

static struct silofs_lsmap_info *lsi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_lsmap_info *lsi;

	lsi = silofs_memalloc(alloc, sizeof(*lsi), 0);
	return lsi;
}

static void
lsi_free(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, lsi, sizeof(*lsi), flags);
}

static struct silofs_lsmap_info *
lsi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_lsmap_info *lsi;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	lsi = lsi_malloc(alloc);
	if (lsi == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	lsi_init(lsi, vaddr, view);
	return lsi;
}

static void
lsi_del(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&lsi->ls_vni, alloc, flags);
	lsi_fini(lsi);
	lsi_free(lsi, alloc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_info *ii_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_inode_info, i_vni);
}

static void ii_init(struct silofs_inode_info *ii,
                    const struct silofs_vaddr *vaddr, struct silofs_view *view)
{
	vni_init(&ii->i_vni, vaddr, view);
	silofs_dirtyq_init(&ii->i_dq_vnis);
	ii->inode = &view->u.in;
	ii->i_looseq_next = nullptr;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = 0;
	ii->i_nlookup = 0;
	ii->i_in_looseq = false;
}

static void ii_fini(struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vnis.dq.sz, 0);
	silofs_assert_eq(ii->i_dq_vnis.dq_accum, 0);
	silofs_assert(!ii->i_in_looseq);
	silofs_assert_null(ii->i_looseq_next);

	vni_fini(&ii->i_vni);
	silofs_dirtyq_fini(&ii->i_dq_vnis);
	ii->inode = nullptr;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static struct silofs_inode_info *ii_malloc(struct silofs_alloc *alloc)
{
	struct silofs_inode_info *ii;

	ii = silofs_memalloc(alloc, sizeof(*ii), 0);
	return ii;
}

static void
ii_free(struct silofs_inode_info *ii, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, ii, sizeof(*ii), flags);
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_inode_info *ii;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	ii = ii_malloc(alloc);
	if (ii == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	ii_init(ii, vaddr, view);
	return ii;
}

static void
ii_del(struct silofs_inode_info *ii, struct silofs_alloc *alloc, int flags)
{
	silofs_assert_eq(ii->i_dq_vnis.dq.sz, 0);
	silofs_assert_ge(ii->i_nopen, 0);

	vni_del_view(&ii->i_vni, alloc, flags);
	ii_fini(ii);
	ii_free(ii, alloc, flags);
}

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni)
{
	return silofs_ii_from_vni(silofs_vni_from_lni(lni));
}

struct silofs_inode_info *
silofs_ii_from_vni(const struct silofs_vnode_info *vni)
{
	return likely(vni != nullptr) ? ii_from_vni(vni_unconst(vni)) :
	                                nullptr;
}

struct silofs_inode_info *silofs_ii_from_dqe(struct silofs_dq_elem *dqe)
{
	return silofs_ii_from_vni(silofs_vni_from_dqe(dqe));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *xai_to_vni(struct silofs_xanode_info *xai)
{
	return &xai->xan_vni;
}

static struct silofs_xanode_info *xai_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_xanode_info, xan_vni);
}

static void
xai_init(struct silofs_xanode_info *xai, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	vni_init(&xai->xan_vni, vaddr, view);
	xai->xan = &view->u.xan;
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vni_fini(&xai->xan_vni);
	xai->xan = nullptr;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc *alloc)
{
	struct silofs_xanode_info *xai;

	xai = silofs_memalloc(alloc, sizeof(*xai), 0);
	return xai;
}

static void
xai_free(struct silofs_xanode_info *xai, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, xai, sizeof(*xai), flags);
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_xanode_info *xai;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	xai = xai_malloc(alloc);
	if (xai == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	xai_init(xai, vaddr, view);
	return xai;
}

static void
xai_del(struct silofs_xanode_info *xai, struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&xai->xan_vni, alloc, flags);
	xai_fini(xai);
	xai_free(xai, alloc, flags);
}

struct silofs_xanode_info *silofs_xai_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return xai_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *syi_to_vni(struct silofs_symval_info *syi)
{
	return &syi->sy_vni;
}

static struct silofs_symval_info *syi_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_symval_info, sy_vni);
}

static void
syi_init(struct silofs_symval_info *syi, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	vni_init(&syi->sy_vni, vaddr, view);
	syi->syv = &view->u.syv;
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vni_fini(&syi->sy_vni);
	syi->syv = nullptr;
}

static struct silofs_symval_info *syi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_symval_info *syi;

	syi = silofs_memalloc(alloc, sizeof(*syi), 0);
	return syi;
}

static void
syi_free(struct silofs_symval_info *syi, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, syi, sizeof(*syi), flags);
}

static struct silofs_symval_info *
syi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_symval_info *syi;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	syi = syi_malloc(alloc);
	if (syi == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	syi_init(syi, vaddr, view);
	return syi;
}

static void
syi_del(struct silofs_symval_info *syi, struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&syi->sy_vni, alloc, flags);
	syi_fini(syi);
	syi_free(syi, alloc, flags);
}

struct silofs_symval_info *silofs_syi_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_symval_info, sy_vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *dni_to_vni(struct silofs_dnode_info *dni)
{
	return &dni->dn_vni;
}

static struct silofs_dnode_info *dni_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_dnode_info, dn_vni);
}

static void
dni_init(struct silofs_dnode_info *dni, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	vni_init(&dni->dn_vni, vaddr, view);
	dni->dtn = &view->u.dtn;
}

static void dni_fini(struct silofs_dnode_info *dni)
{
	vni_fini(&dni->dn_vni);
	dni->dtn = nullptr;
}

static struct silofs_dnode_info *dni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_dnode_info *dni;

	dni = silofs_memalloc(alloc, sizeof(*dni), 0);
	return dni;
}

static void
dni_free(struct silofs_dnode_info *dni, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, dni, sizeof(*dni), flags);
}

static struct silofs_dnode_info *
dni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_dnode_info *dni;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	dni = dni_malloc(alloc);
	if (dni == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	dni_init(dni, vaddr, view);
	return dni;
}

static void
dni_del(struct silofs_dnode_info *dni, struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&dni->dn_vni, alloc, flags);
	dni_fini(dni);
	dni_free(dni, alloc, flags);
}

struct silofs_dnode_info *silofs_dni_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	silofs_assert(vni_has_mtype(vni, SILOFS_MTYPE_DTNODE));
	return dni_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fni_to_vni(struct silofs_finode_info *fni)
{
	return &fni->fn_vni;
}

static struct silofs_finode_info *fni_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_finode_info, fn_vni);
}

static void
fni_init(struct silofs_finode_info *fni, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	vni_init(&fni->fn_vni, vaddr, view);
	fni->ftn = &view->u.ftn;
}

static void fni_fini(struct silofs_finode_info *fni)
{
	vni_fini(&fni->fn_vni);
	fni->ftn = nullptr;
}

static struct silofs_finode_info *fni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_finode_info *fni;

	fni = silofs_memalloc(alloc, sizeof(*fni), 0);
	return fni;
}

static void
fni_free(struct silofs_finode_info *fni, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, fni, sizeof(*fni), flags);
}

static struct silofs_finode_info *
fni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_finode_info *fni;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	fni = fni_malloc(alloc);
	if (fni == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	fni_init(fni, vaddr, view);
	return fni;
}

static void
fni_del(struct silofs_finode_info *fni, struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&fni->fn_vni, alloc, flags);
	fni_fini(fni);
	fni_free(fni, alloc, flags);
}

struct silofs_finode_info *silofs_fni_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return fni_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fli_to_vni(struct silofs_fileaf_info *fli)
{
	return &fli->fl_vni;
}

static struct silofs_fileaf_info *fli_from_vni(struct silofs_vnode_info *vni)
{
	return container_of(vni, struct silofs_fileaf_info, fl_vni);
}

static void
fli_init(struct silofs_fileaf_info *fli, const struct silofs_vaddr *vaddr,
         struct silofs_view *view)
{
	vni_init(&fli->fl_vni, vaddr, view);

	if (vaddr->mtype == SILOFS_MTYPE_DATA1K) {
		fli->flu.db1 = &view->u.dbk1;
	} else if (vaddr->mtype == SILOFS_MTYPE_DATA4K) {
		fli->flu.db4 = &view->u.dbk4;
	} else if (vaddr->mtype == SILOFS_MTYPE_DATABK) {
		fli->flu.db = &view->u.dbk64;
	} else {
		silofs_panic("not data mtype: %d", (int)vaddr->mtype);
	}
}

static void fli_fini(struct silofs_fileaf_info *fli)
{
	vni_fini(&fli->fl_vni);
	fli->flu.db = nullptr;
}

static struct silofs_fileaf_info *fli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_fileaf_info *fli;

	fli = silofs_memalloc(alloc, sizeof(*fli), 0);
	return fli;
}

static void
fli_free(struct silofs_fileaf_info *fli, struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, fli, sizeof(*fli), flags);
}

static struct silofs_fileaf_info *
fli_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_fileaf_info *fli;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == nullptr) {
		return nullptr;
	}
	fli = fli_malloc(alloc);
	if (fli == nullptr) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return nullptr;
	}
	fli_init(fli, vaddr, view);
	return fli;
}

static void
fli_del(struct silofs_fileaf_info *fli, struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&fli->fl_vni, alloc, flags);
	fli_fini(fli);
	fli_free(fli, alloc, flags);
}

struct silofs_fileaf_info *silofs_fli_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return fli_from_vni(vni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
view_verify_sub(const struct silofs_view *view, enum silofs_mtype mtype)
{
	switch (mtype) {
		// XXX
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BDESC:
	case SILOFS_MTYPE_BTNODE:
		silofs_assert_null(view);
		break;
	case SILOFS_MTYPE_GBR:
		break;
	case SILOFS_MTYPE_SUPER:
		return silofs_verify_super_block(&view->u.sb);
	case SILOFS_MTYPE_SPNODE:
		return silofs_verify_spmap_node(&view->u.sn);
	case SILOFS_MTYPE_SPLEAF:
		return silofs_verify_spmap_leaf(&view->u.sl);
	case SILOFS_MTYPE_LSMAP:
		return silofs_verify_lsmap(&view->u.lsm);
	case SILOFS_MTYPE_INODE:
		return silofs_verify_inode(&view->u.in);
	case SILOFS_MTYPE_XANODE:
		return silofs_verify_xattr_node(&view->u.xan);
	case SILOFS_MTYPE_SYMVAL:
		return silofs_verify_symlnk_value(&view->u.syv);
	case SILOFS_MTYPE_DTNODE:
		return silofs_verify_dtree_node(&view->u.dtn);
	case SILOFS_MTYPE_FTNODE:
		return silofs_verify_ftree_node(&view->u.ftn);
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
		break;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		log_err("illegal sub-type: mtype=%d", (int)mtype);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int
verify_view_by(const struct silofs_view *view, const enum silofs_mtype mtype)
{
	int err;

	if (silofs_mtype_isdata(mtype)) {
		return 0;
	}
	err = silofs_view_verify(view, mtype);
	if (err) {
		return err;
	}
	err = view_verify_sub(view, mtype);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_unode_info *
silofs_new_unode(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni = nullptr;
	const enum silofs_mtype mtype = silofs_uaddr_mtype(uaddr);

	switch (mtype) {
	case SILOFS_MTYPE_SUPER:
		uni = sbi_to_uni(sbi_new(alloc, uaddr));
		break;
	case SILOFS_MTYPE_SPNODE:
		uni = sni_to_uni(sni_new(alloc, uaddr));
		break;
	case SILOFS_MTYPE_SPLEAF:
		uni = sli_to_uni(sli_new(alloc, uaddr));
		break;
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_GBR:
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
		silofs_panic("can not create unode: mtype=%d", (int)mtype);
		break;
	}
	return uni;
}

void silofs_del_unode(struct silofs_unode_info *uni,
                      struct silofs_alloc *alloc, int flags)
{
	const enum silofs_mtype mtype = silofs_uni_mtype(uni);

	switch (mtype) {
	case SILOFS_MTYPE_SUPER:
		sbi_del(sbi_from_uni(uni), alloc, flags);
		break;
	case SILOFS_MTYPE_SPNODE:
		sni_del(sni_from_uni(uni), alloc, flags);
		break;
	case SILOFS_MTYPE_SPLEAF:
		sli_del(sli_from_uni(uni), alloc, flags);
		break;
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_GBR:
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
		silofs_panic("can not destroy unode: mtype=%d", (int)mtype);
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = nullptr;
	const enum silofs_mtype mtype = vaddr->mtype;

	switch (mtype) {
	case SILOFS_MTYPE_LSMAP:
		vni = lsi_to_vni(lsi_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_INODE:
		vni = silofs_ii_to_vni(ii_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_XANODE:
		vni = xai_to_vni(xai_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_SYMVAL:
		vni = syi_to_vni(syi_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_DTNODE:
		vni = dni_to_vni(dni_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_FTNODE:
		vni = fni_to_vni(fni_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
		vni = fli_to_vni(fli_new(alloc, vaddr));
		break;
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_GBR:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("can not create vnode: mtype=%d", (int)mtype);
		break;
	}
	return vni;
}

void silofs_del_vnode(struct silofs_vnode_info *vni,
                      struct silofs_alloc *alloc, int flags)
{
	const enum silofs_mtype mtype = silofs_vni_mtype(vni);

	switch (mtype) {
	case SILOFS_MTYPE_LSMAP:
		lsi_del(silofs_lsi_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_INODE:
		ii_del(ii_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_XANODE:
		xai_del(xai_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_SYMVAL:
		syi_del(syi_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_DTNODE:
		dni_del(dni_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_FTNODE:
		fni_del(fni_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
		fli_del(fli_from_vni(vni), alloc, flags);
		break;
	case SILOFS_MTYPE_UBER:
	case SILOFS_MTYPE_ARIX:
	case SILOFS_MTYPE_BDESC:
	case SILOFS_MTYPE_BTNODE:
	case SILOFS_MTYPE_GBR:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("can not destroy vnode: mtype=%d", (int)mtype);
		break;
	}
}
