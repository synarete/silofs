/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <limits.h>

#define UI_MAGIC (0xCAFEBEBE)
#define VI_MAGIC (0xFEEDFACE)

/* local functions forward declarations */
static int verify_view_by(const struct silofs_view *view,
                          const enum silofs_ltype ltype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_ltype ltype_of(const struct silofs_ulink *ulink)
{
	return uaddr_ltype(&ulink->uaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void view_init_by(struct silofs_view *view, enum silofs_ltype ltype)
{
	size_t size;

	if (!ltype_isdata(ltype)) {
		size = ltype_size(ltype);
		silofs_memzero(view, size);
		silofs_hdr_setup(&view->u.hdr,
		                 (uint8_t)ltype, size, SILOFS_HDRF_LTYPE);
	}
}

static struct silofs_view *
view_new_by(struct silofs_alloc *alloc, enum silofs_ltype ltype)
{
	struct silofs_view *view = NULL;
	const int flags = ltype_issuper(ltype) ? SILOFS_ALLOCF_BZERO : 0;

	view = silofs_memalloc(alloc, ltype_size(ltype), flags);
	if (view != NULL) {
		view_init_by(view, ltype);
	}
	return view;
}

static struct silofs_view *
view_new_by_ulink(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	return view_new_by(alloc, ltype_of(ulink));
}

static struct silofs_view *
view_new_by_vaddr(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	return view_new_by(alloc, vaddr->ltype);
}

static void view_del(struct silofs_view *view, enum silofs_ltype ltype,
                     struct silofs_alloc *alloc, int flags)
{
	const size_t size = ltype_size(ltype);

	if (ltype_issuper(ltype)) {
		flags |= SILOFS_ALLOCF_TRYPUNCH;
	}
	if (!ltype_isdata(ltype)) {
		silofs_memzero(view, min(size, sizeof(struct silofs_header)));
	}
	silofs_memfree(alloc, view, size, flags);
}

static void view_del_by(struct silofs_view *view, enum silofs_ltype ltype,
                        struct silofs_alloc *alloc, int flags)
{
	if (likely(view != NULL)) {
		view_del(view, ltype, alloc, flags);
	}
}

static void view_del_by_ulink(struct silofs_view *view,
                              const struct silofs_ulink *ulink,
                              struct silofs_alloc *alloc, int flags)
{
	view_del_by(view, uaddr_ltype(&ulink->uaddr), alloc, flags);
}

static void view_del_by_vaddr(struct silofs_view *view,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_alloc *alloc, int flags)
{
	view_del_by(view, vaddr->ltype, alloc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *
lni_unconst(const struct silofs_lnode_info *lni)
{
	union {
		const struct silofs_lnode_info *p;
		struct silofs_lnode_info *q;
	} u = {
		.p = lni
	};
	return u.q;
}

static void lni_init(struct silofs_lnode_info *lni,
                     enum silofs_ltype ltype, struct silofs_view *view)
{
	silofs_hmqe_init(&lni->ln_hmqe, ltype_size(ltype));
	silofs_avl_node_init(&lni->ln_ds_avl_node);
	lni->ln_ltype = ltype;
	lni->ln_ds_next = NULL;
	lni->ln_fsenv = NULL;
	lni->ln_view = view;
	lni->ln_flags = 0;
}

static void lni_fini(struct silofs_lnode_info *lni)
{
	silofs_hmqe_fini(&lni->ln_hmqe);
	silofs_avl_node_fini(&lni->ln_ds_avl_node);
	lni->ln_ds_next = NULL;
	lni->ln_fsenv = NULL;
	lni->ln_view = NULL;
}

int silofs_lni_verify_view(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni->ln_view);
	return verify_view_by(lni->ln_view, lni->ln_ltype);
}

struct silofs_lnode_info *
silofs_lni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_lnode_info *lni = NULL;

	if (likely(hmqe != NULL)) {
		lni = container_of2(hmqe, struct silofs_lnode_info, ln_hmqe);
	}
	return lni_unconst(lni);
}

struct silofs_lnode_info *
silofs_lni_from_dqe(const struct silofs_dq_elem *dqe)
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

static struct silofs_dq_elem *
lni_dqe(struct silofs_lnode_info *lni)
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
	} u = {
		.p = uni
	};
	return u.q;
}

static void uni_verify(const struct silofs_unode_info *uni)
{
	silofs_assert_not_null(uni);
	silofs_assert_not_null(uni->un_lni.ln_view);

	if (unlikely(uni->un_magic != UI_MAGIC)) {
		silofs_panic("bad unode: uni=%p magic=%lx",
		             (const void *)uni, uni->un_magic);
	}
}

static void uni_init(struct silofs_unode_info *uni,
                     const struct silofs_ulink *ulink,
                     struct silofs_view *view)
{
	lni_init(&uni->un_lni, ltype_of(ulink), view);
	ulink_assign(&uni->un_ulink, ulink);
	uni->un_magic = UI_MAGIC;
}

static void uni_fini(struct silofs_unode_info *uni)
{
	ulink_reset(&uni->un_ulink);
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

	silofs_hdr_seal(&uni->un_lni.ln_view->u.hdr);
}

static void uni_del_view(struct silofs_unode_info *uni,
                         struct silofs_alloc *alloc, int flags)
{
	view_del_by_ulink(uni->un_lni.ln_view, uni_ulink(uni), alloc, flags);
	uni->un_lni.ln_view = NULL;
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

enum silofs_ltype silofs_uni_ltype(const struct silofs_unode_info *uni)
{
	uni_verify(uni);

	return uaddr_ltype(&uni->un_ulink.uaddr);
}

void silofs_uni_set_dq(struct silofs_unode_info *uni, struct silofs_dirtyq *dq)
{
	lni_set_dq(&uni->un_lni, dq);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
vni_unconst(const struct silofs_vnode_info *vni)
{
	union {
		const struct silofs_vnode_info *p;
		struct silofs_vnode_info *q;
	} u = {
		.p = vni
	};
	return u.q;
}

static void vni_verify(const struct silofs_vnode_info *vni)
{
	if (unlikely(vni->vn_magic != VI_MAGIC)) {
		silofs_panic("bad vnode: vni=%p magic=%lx",
		             (const void *)vni, vni->vn_magic);
	}
}

static void vni_init(struct silofs_vnode_info *vni,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	lni_init(&vni->vn_lni, vaddr->ltype, view);
	vaddr_assign(&vni->vn_vaddr, vaddr);
	silofs_llink_reset(&vni->vn_llink);
	vni->vn_asyncwr = 0;
	vni->vn_magic = VI_MAGIC;
}

static void vni_fini(struct silofs_vnode_info *vni)
{
	vni_verify(vni);
	silofs_assert_eq(vni->vn_asyncwr, 0);

	lni_fini(&vni->vn_lni);
	vaddr_reset(&vni->vn_vaddr);
	vni->vn_magic = UINT64_MAX;
}

int silofs_vni_refcnt(const struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	return silofs_lni_refcnt(&vni->vn_lni);
}

void silofs_vni_incref(struct silofs_vnode_info *vni)
{
	if (likely(vni != NULL)) {
		silofs_lni_incref(&vni->vn_lni);
	}
}

void silofs_vni_decref(struct silofs_vnode_info *vni)
{
	if (likely(vni != NULL)) {
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

static void vni_update_dq_by(struct silofs_vnode_info *vni,
                             struct silofs_inode_info *ii)
{
	if (ii != NULL) {
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
	const struct silofs_vnode_info *vni = NULL;

	if (lni != NULL) {
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
	silofs_assert(!vaddr_isdata(vni_vaddr(vni)));

	silofs_hdr_seal(&vni->vn_lni.ln_view->u.hdr);
}

static bool vni_has_ltype(const struct silofs_vnode_info *vni,
                          enum silofs_ltype ltype)
{
	return vni_ltype(vni) == ltype;
}

static void vni_del_view(struct silofs_vnode_info *vni,
                         struct silofs_alloc *alloc, int flags)
{
	view_del_by_vaddr(vni->vn_lni.ln_view, vni_vaddr(vni), alloc, flags);
	vni->vn_lni.ln_view = NULL;
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sbi_to_uni(struct silofs_sb_info *sbi)
{
	return &sbi->sb_uni;
}

static struct silofs_sb_info *sbi_from_uni(struct silofs_unode_info *uni)
{
	struct silofs_sb_info *sbi = NULL;

	sbi = container_of(uni, struct silofs_sb_info, sb_uni);
	return sbi;
}

static int sbi_init(struct silofs_sb_info *sbi,
                    const struct silofs_ulink *ulink, struct silofs_view *view)
{
	uni_init(&sbi->sb_uni, ulink, view);
	sbi->sb = &view->u.sb;
	return 0;
}

static void sbi_fini(struct silofs_sb_info *sbi)
{
	uni_fini(&sbi->sb_uni);
	sbi->sb = NULL;
}

static struct silofs_sb_info *sbi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sb_info *sbi;

	sbi = silofs_memalloc(alloc, sizeof(*sbi), SILOFS_ALLOCF_BZERO);
	return sbi;
}

static void sbi_free(struct silofs_sb_info *sbi,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, sbi, sizeof(*sbi), flags);
}

static struct silofs_sb_info *
sbi_new(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_view *view;
	struct silofs_sb_info *sbi;
	int err;

	view = view_new_by_ulink(alloc, ulink);
	if (view == NULL) {
		return NULL;
	}
	sbi = sbi_malloc(alloc);
	if (sbi == NULL) {
		view_del_by_ulink(view, ulink, alloc, 0);
		return NULL;
	}
	err = sbi_init(sbi, ulink, view);
	if (err) {
		sbi_free(sbi, alloc, 0);
		view_del_by_ulink(view, ulink, alloc, 0);
		return NULL;
	}
	return sbi;
}

static void sbi_del(struct silofs_sb_info *sbi,
                    struct silofs_alloc *alloc, int flags)
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
	struct silofs_spnode_info *sni = NULL;

	sni = container_of(uni, struct silofs_spnode_info, sn_uni);
	return sni;
}

static void sni_init(struct silofs_spnode_info *sni,
                     const struct silofs_ulink *ulink,
                     struct silofs_view *view)
{
	uni_init(&sni->sn_uni, ulink, view);
	sni->sn = &view->u.sn;
	sni->sn_nactive_subs = 0;
}

static void sni_fini(struct silofs_spnode_info *sni)
{
	uni_fini(&sni->sn_uni);
	sni->sn = NULL;
	sni->sn_nactive_subs = 0;
}

static struct silofs_spnode_info *sni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spnode_info *sni;

	sni = silofs_memalloc(alloc, sizeof(*sni), 0);
	return sni;
}

static void sni_free(struct silofs_spnode_info *sni,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, sni, sizeof(*sni), flags);
}

static void sni_del(struct silofs_spnode_info *sni,
                    struct silofs_alloc *alloc, int flags)
{
	uni_verify(&sni->sn_uni);
	uni_del_view(&sni->sn_uni, alloc, flags);
	sni_fini(sni);
	sni_free(sni, alloc, flags);
}

static struct silofs_spnode_info *
sni_new(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_view *view;
	struct silofs_spnode_info *sni;

	view = view_new_by_ulink(alloc, ulink);
	if (view == NULL) {
		return NULL;
	}
	sni = sni_malloc(alloc);
	if (sni == NULL) {
		view_del_by_ulink(view, ulink, alloc, 0);
		return NULL;
	}
	sni_init(sni, ulink, view);
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
	struct silofs_spleaf_info *sli = NULL;

	sli = container_of(uni, struct silofs_spleaf_info, sl_uni);
	return sli;
}

static void sli_init(struct silofs_spleaf_info *sli,
                     const struct silofs_ulink *ulink,
                     struct silofs_view *view)
{
	uni_init(&sli->sl_uni, ulink, view);
	sli->sl = &view->u.sl;
	sli->sl_nused_bytes = 0;
}

static void sli_fini(struct silofs_spleaf_info *sli)
{
	uni_fini(&sli->sl_uni);
	sli->sl = NULL;
	sli->sl_nused_bytes = UINT_MAX;
}

static struct silofs_spleaf_info *sli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spleaf_info *sli;

	sli = silofs_memalloc(alloc, sizeof(*sli), 0);
	return sli;
}

static void sli_free(struct silofs_spleaf_info *sli,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, sli, sizeof(*sli), flags);
}

static struct silofs_spleaf_info *
sli_new(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_view *view;
	struct silofs_spleaf_info *sli;

	view = view_new_by_ulink(alloc, ulink);
	if (view == NULL) {
		return NULL;
	}
	sli = sli_malloc(alloc);
	if (sli == NULL) {
		view_del_by_ulink(view, ulink, alloc, 0);
		return NULL;
	}
	sli_init(sli, ulink, view);
	return sli;
}

static void sli_del(struct silofs_spleaf_info *sli,
                    struct silofs_alloc *alloc, int flags)
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

static struct silofs_inode_info *ii_from_vni(struct silofs_vnode_info *vni)
{
	struct silofs_inode_info *ii = NULL;

	ii = container_of(vni, struct silofs_inode_info, i_vni);
	return ii;
}

static void ii_init(struct silofs_inode_info *ii,
                    const struct silofs_vaddr *vaddr,
                    struct silofs_view *view)
{
	vni_init(&ii->i_vni, vaddr, view);
	silofs_dirtyq_init(&ii->i_dq_vnis);
	ii->inode = &view->u.in;
	ii->i_looseq_next = NULL;
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
	ii->inode = NULL;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static struct silofs_inode_info *ii_malloc(struct silofs_alloc *alloc)
{
	struct silofs_inode_info *ii;

	ii = silofs_memalloc(alloc, sizeof(*ii), 0);
	return ii;
}

static void ii_free(struct silofs_inode_info *ii,
                    struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, ii, sizeof(*ii), flags);
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_inode_info *ii;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	ii = ii_malloc(alloc);
	if (ii == NULL) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return NULL;
	}
	ii_init(ii, vaddr, view);
	return ii;
}

static void ii_del(struct silofs_inode_info *ii,
                   struct silofs_alloc *alloc, int flags)
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
	return likely(vni != NULL) ? ii_from_vni(vni_unconst(vni)) : NULL;
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
	struct silofs_xanode_info *xai = NULL;

	silofs_assert_not_null(vni);
	xai = container_of(vni, struct silofs_xanode_info, xan_vni);
	return xai;
}

static void xai_init(struct silofs_xanode_info *xai,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vni_init(&xai->xan_vni, vaddr, view);
	xai->xan = &view->u.xan;
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vni_fini(&xai->xan_vni);
	xai->xan = NULL;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc *alloc)
{
	struct silofs_xanode_info *xai;

	xai = silofs_memalloc(alloc, sizeof(*xai), 0);
	return xai;
}

static void xai_free(struct silofs_xanode_info *xai,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, xai, sizeof(*xai), flags);
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_xanode_info *xai;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	xai = xai_malloc(alloc);
	if (xai == NULL) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return NULL;
	}
	xai_init(xai, vaddr, view);
	return xai;
}

static void xai_del(struct silofs_xanode_info *xai,
                    struct silofs_alloc *alloc, int flags)
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
	struct silofs_symval_info *syi = NULL;

	syi = container_of(vni, struct silofs_symval_info, sy_vni);
	return syi;
}

static void syi_init(struct silofs_symval_info *syi,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vni_init(&syi->sy_vni, vaddr, view);
	syi->syv = &view->u.syv;
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vni_fini(&syi->sy_vni);
	syi->syv = NULL;
}

static struct silofs_symval_info *syi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_symval_info *syi;

	syi = silofs_memalloc(alloc, sizeof(*syi), 0);
	return syi;
}

static void syi_free(struct silofs_symval_info *syi,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, syi, sizeof(*syi), flags);
}

static struct silofs_symval_info *
syi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_symval_info *syi;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	syi = syi_malloc(alloc);
	if (syi == NULL) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return NULL;
	}
	syi_init(syi, vaddr, view);
	return syi;
}

static void syi_del(struct silofs_symval_info *syi,
                    struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&syi->sy_vni, alloc, flags);
	syi_fini(syi);
	syi_free(syi, alloc, flags);
}

struct silofs_symval_info *silofs_syi_from_vni(struct silofs_vnode_info *vni)
{
	struct silofs_symval_info *syi = NULL;

	silofs_assert_not_null(vni);
	syi = container_of(vni, struct silofs_symval_info, sy_vni);
	return syi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *dni_to_vni(struct silofs_dnode_info *dni)
{
	return &dni->dn_vni;
}

static struct silofs_dnode_info *dni_from_vni(struct silofs_vnode_info *vni)
{
	struct silofs_dnode_info *dni = NULL;

	dni = container_of(vni, struct silofs_dnode_info, dn_vni);
	return dni;
}

static void dni_init(struct silofs_dnode_info *dni,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vni_init(&dni->dn_vni, vaddr, view);
	dni->dtn = &view->u.dtn;
}

static void dni_fini(struct silofs_dnode_info *dni)
{
	vni_fini(&dni->dn_vni);
	dni->dtn = NULL;
}

static struct silofs_dnode_info *dni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_dnode_info *dni;

	dni = silofs_memalloc(alloc, sizeof(*dni), 0);
	return dni;
}

static void dni_free(struct silofs_dnode_info *dni,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, dni, sizeof(*dni), flags);
}

static struct silofs_dnode_info *
dni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_dnode_info *dni;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	dni = dni_malloc(alloc);
	if (dni == NULL) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return NULL;
	}
	dni_init(dni, vaddr, view);
	return dni;
}

static void dni_del(struct silofs_dnode_info *dni,
                    struct silofs_alloc *alloc, int flags)
{
	vni_del_view(&dni->dn_vni, alloc, flags);
	dni_fini(dni);
	dni_free(dni, alloc, flags);
}

struct silofs_dnode_info *silofs_dni_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	silofs_assert(vni_has_ltype(vni, SILOFS_LTYPE_DTNODE));
	return dni_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fni_to_vni(struct silofs_finode_info *fni)
{
	return &fni->fn_vni;
}

static struct silofs_finode_info *fni_from_vni(struct silofs_vnode_info *vni)
{
	struct silofs_finode_info *fni = NULL;

	fni = container_of(vni, struct silofs_finode_info, fn_vni);
	return fni;
}

static void fni_init(struct silofs_finode_info *fni,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vni_init(&fni->fn_vni, vaddr, view);
	fni->ftn = &view->u.ftn;
}

static void fni_fini(struct silofs_finode_info *fni)
{
	vni_fini(&fni->fn_vni);
	fni->ftn = NULL;
}

static struct silofs_finode_info *fni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_finode_info *fni;

	fni = silofs_memalloc(alloc, sizeof(*fni), 0);
	return fni;
}

static void fni_free(struct silofs_finode_info *fni,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, fni, sizeof(*fni), flags);
}

static struct silofs_finode_info *
fni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_finode_info *fni;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	fni = fni_malloc(alloc);
	if (fni == NULL) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return NULL;
	}
	fni_init(fni, vaddr, view);
	return fni;
}

static void fni_del(struct silofs_finode_info *fni,
                    struct silofs_alloc *alloc, int flags)
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
	struct silofs_fileaf_info *fli = NULL;

	fli = container_of(vni, struct silofs_fileaf_info, fl_vni);
	return fli;
}

static void fli_init(struct silofs_fileaf_info *fli,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vni_init(&fli->fl_vni, vaddr, view);

	if (ltype_isdata1k(vaddr->ltype)) {
		fli->flu.db1 = &view->u.dbk1;
	} else if (ltype_isdata4k(vaddr->ltype)) {
		fli->flu.db4 = &view->u.dbk4;
	} else if (ltype_isdatabk(vaddr->ltype)) {
		fli->flu.db = &view->u.dbk64;
	}
}

static void fli_fini(struct silofs_fileaf_info *fli)
{
	vni_fini(&fli->fl_vni);
	fli->flu.db = NULL;
}

static struct silofs_fileaf_info *fli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_fileaf_info *fli;

	fli = silofs_memalloc(alloc, sizeof(*fli), 0);
	return fli;
}

static void fli_free(struct silofs_fileaf_info *fli,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_memfree(alloc, fli, sizeof(*fli), flags);
}

static struct silofs_fileaf_info *
fli_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_fileaf_info *fli;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	fli = fli_malloc(alloc);
	if (fli == NULL) {
		view_del_by_vaddr(view, vaddr, alloc, 0);
		return NULL;
	}
	fli_init(fli, vaddr, view);
	return fli;
}

static void fli_del(struct silofs_fileaf_info *fli,
                    struct silofs_alloc *alloc, int flags)
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

static int view_verify_by_hdr(const struct silofs_view *view,
                              enum silofs_ltype ltype)
{
	const struct silofs_header *hdr = &view->u.hdr;

	return silofs_hdr_verify(hdr, (uint8_t)ltype, ltype_size(ltype),
	                         SILOFS_HDRF_CSUM | SILOFS_HDRF_LTYPE);
}

static int view_verify_sub(const struct silofs_view *view,
                           enum silofs_ltype ltype)
{
	switch (ltype) {
	case SILOFS_LTYPE_BOOTREC:
		break;
	case SILOFS_LTYPE_SUPER:
		return silofs_verify_super_block(&view->u.sb);
	case SILOFS_LTYPE_SPNODE:
		return silofs_verify_spmap_node(&view->u.sn);
	case SILOFS_LTYPE_SPLEAF:
		return silofs_verify_spmap_leaf(&view->u.sl);
	case SILOFS_LTYPE_INODE:
		return silofs_verify_inode(&view->u.in);
	case SILOFS_LTYPE_XANODE:
		return silofs_verify_xattr_node(&view->u.xan);
	case SILOFS_LTYPE_SYMVAL:
		return silofs_verify_symlnk_value(&view->u.syv);
	case SILOFS_LTYPE_DTNODE:
		return silofs_verify_dtree_node(&view->u.dtn);
	case SILOFS_LTYPE_FTNODE:
		return silofs_verify_ftree_node(&view->u.ftn);
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		log_err("illegal sub-type: ltype=%d", (int)ltype);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_view_by(const struct silofs_view *view,
                          const enum silofs_ltype ltype)
{
	int err;

	if (ltype_isdata(ltype)) {
		return 0;
	}
	err = view_verify_by_hdr(view, ltype);
	if (err) {
		return err;
	}
	err = view_verify_sub(view, ltype);
	if (err) {
		return err;
	}
	return 0;
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_unode_info *
silofs_new_unode(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *uni = NULL;
	const enum silofs_ltype ltype = ltype_of(ulink);

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		uni = sbi_to_uni(sbi_new(alloc, ulink));
		break;
	case SILOFS_LTYPE_SPNODE:
		uni = sni_to_uni(sni_new(alloc, ulink));
		break;
	case SILOFS_LTYPE_SPLEAF:
		uni = sli_to_uni(sli_new(alloc, ulink));
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_INODE:
	case SILOFS_LTYPE_XANODE:
	case SILOFS_LTYPE_SYMVAL:
	case SILOFS_LTYPE_DTNODE:
	case SILOFS_LTYPE_FTNODE:
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("can not create unode: ltype=%d", (int)ltype);
		break;
	}
	return uni;
}

void silofs_del_unode(struct silofs_unode_info *uni,
                      struct silofs_alloc *alloc, int flags)
{
	const enum silofs_ltype ltype = uni_ltype(uni);

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		sbi_del(sbi_from_uni(uni), alloc, flags);
		break;
	case SILOFS_LTYPE_SPNODE:
		sni_del(sni_from_uni(uni), alloc, flags);
		break;
	case SILOFS_LTYPE_SPLEAF:
		sli_del(sli_from_uni(uni), alloc, flags);
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_INODE:
	case SILOFS_LTYPE_XANODE:
	case SILOFS_LTYPE_SYMVAL:
	case SILOFS_LTYPE_DTNODE:
	case SILOFS_LTYPE_FTNODE:
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("can not destroy unode: ltype=%d", (int)ltype);
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = NULL;
	const enum silofs_ltype ltype = vaddr->ltype;

	switch (ltype) {
	case SILOFS_LTYPE_INODE:
		vni = ii_to_vni(ii_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_XANODE:
		vni = xai_to_vni(xai_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_SYMVAL:
		vni = syi_to_vni(syi_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_DTNODE:
		vni = dni_to_vni(dni_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_FTNODE:
		vni = fni_to_vni(fni_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
		vni = fli_to_vni(fli_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("can not create vnode: ltype=%d", (int)ltype);
		break;
	}
	return vni;
}

void silofs_del_vnode(struct silofs_vnode_info *vni,
                      struct silofs_alloc *alloc, int flags)
{
	const enum silofs_ltype ltype = vni_ltype(vni);


	switch (ltype) {
	case SILOFS_LTYPE_INODE:
		ii_del(ii_from_vni(vni), alloc, flags);
		break;
	case SILOFS_LTYPE_XANODE:
		xai_del(xai_from_vni(vni), alloc, flags);
		break;
	case SILOFS_LTYPE_SYMVAL:
		syi_del(syi_from_vni(vni), alloc, flags);
		break;
	case SILOFS_LTYPE_DTNODE:
		dni_del(dni_from_vni(vni), alloc, flags);
		break;
	case SILOFS_LTYPE_FTNODE:
		fni_del(fni_from_vni(vni), alloc, flags);
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
		fli_del(fli_from_vni(vni), alloc, flags);
		break;
	case SILOFS_LTYPE_BOOTREC:
	case SILOFS_LTYPE_SUPER:
	case SILOFS_LTYPE_SPNODE:
	case SILOFS_LTYPE_SPLEAF:
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("can not destroy vnode: ltype=%d", (int)ltype);
		break;
	}
}
