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
	silofs_memzero(view, min(size, sizeof(struct silofs_header)));
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
		silofs_panic("bad unode: uni=%p magic=%x",
		             uni, uni->un_magic);
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
vi_unconst(const struct silofs_vnode_info *vi)
{
	union {
		const struct silofs_vnode_info *p;
		struct silofs_vnode_info *q;
	} u = {
		.p = vi
	};
	return u.q;
}

static void vi_verify(const struct silofs_vnode_info *vi)
{
	if (unlikely(vi->v_magic != VI_MAGIC)) {
		silofs_panic("corrupted: vi=%p v_magic=%x", vi, vi->v_magic);
	}
}

static void vi_init(struct silofs_vnode_info *vi,
                    const struct silofs_vaddr *vaddr, struct silofs_view *view)
{
	lni_init(&vi->v_lni, vaddr->ltype, view);
	vaddr_assign(&vi->v_vaddr, vaddr);
	silofs_llink_reset(&vi->v_llink);
	vi->v_asyncwr = 0;
	vi->v_magic = VI_MAGIC;
}

static void vi_fini(struct silofs_vnode_info *vi)
{
	vi_verify(vi);
	silofs_assert_eq(vi->v_asyncwr, 0);

	lni_fini(&vi->v_lni);
	vaddr_reset(&vi->v_vaddr);
	vi->v_magic = UINT64_MAX;
}

int silofs_vi_refcnt(const struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi);

	return silofs_lni_refcnt(&vi->v_lni);
}

void silofs_vi_incref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		silofs_lni_incref(&vi->v_lni);
	}
}

void silofs_vi_decref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		silofs_lni_decref(&vi->v_lni);
	}
}

void silofs_vi_set_dq(struct silofs_vnode_info *vi, struct silofs_dirtyq *dq)
{
	lni_set_dq(&vi->v_lni, dq);
}

bool silofs_vi_isdirty(const struct silofs_vnode_info *vi)
{
	return silofs_lni_isdirty(&vi->v_lni);
}

static void vi_update_dq_by(struct silofs_vnode_info *vi,
                            struct silofs_inode_info *ii)
{
	if (ii != NULL) {
		silofs_vi_set_dq(vi, &ii->i_dq_vis);
	}
}

void silofs_vi_dirtify(struct silofs_vnode_info *vi,
                       struct silofs_inode_info *ii)
{
	silofs_assert_not_null(vi);

	if (!silofs_vi_isdirty(vi)) {
		vi_update_dq_by(vi, ii);
		silofs_lni_dirtify(&vi->v_lni);
	}
}

void silofs_vi_undirtify(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi);

	if (silofs_vi_isdirty(vi)) {
		silofs_lni_undirtify(&vi->v_lni);
	}
}

struct silofs_vnode_info *
silofs_vi_from_lni(const struct silofs_lnode_info *lni)
{
	const struct silofs_vnode_info *vi = NULL;

	if (lni != NULL) {
		vi = container_of2(lni, struct silofs_vnode_info, v_lni);
		vi_verify(vi);
	}
	return vi_unconst(vi);
}

struct silofs_vnode_info *silofs_vi_from_dqe(struct silofs_dq_elem *dqe)
{
	return silofs_vi_from_lni(silofs_lni_from_dqe(dqe));
}

void silofs_vi_seal_view(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi->v_lni.ln_view);
	silofs_assert(!vaddr_isdata(vi_vaddr(vi)));

	silofs_hdr_seal(&vi->v_lni.ln_view->u.hdr);
}

static bool vi_has_ltype(const struct silofs_vnode_info *vi,
                         enum silofs_ltype ltype)
{
	return vi_ltype(vi) == ltype;
}

static void vi_del_view(struct silofs_vnode_info *vi,
                        struct silofs_alloc *alloc, int flags)
{
	view_del_by_vaddr(vi->v_lni.ln_view, vi_vaddr(vi), alloc, flags);
	vi->v_lni.ln_view = NULL;
}

bool silofs_vi_isevictable(const struct silofs_vnode_info *vi)
{
	return silofs_lni_isevictable(&vi->v_lni);
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

static struct silofs_inode_info *ii_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_inode_info *ii = NULL;

	ii = container_of(vi, struct silofs_inode_info, i_vi);
	return ii;
}

static void ii_init(struct silofs_inode_info *ii,
                    const struct silofs_vaddr *vaddr,
                    struct silofs_view *view)
{
	vi_init(&ii->i_vi, vaddr, view);
	silofs_dirtyq_init(&ii->i_dq_vis);
	ii->inode = &view->u.in;
	ii->i_looseq_next = NULL;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = 0;
	ii->i_nlookup = 0;
	ii->i_in_looseq = false;
}

static void ii_fini(struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vis.dq.sz, 0);
	silofs_assert_eq(ii->i_dq_vis.dq_accum, 0);
	silofs_assert(!ii->i_in_looseq);
	silofs_assert_null(ii->i_looseq_next);

	vi_fini(&ii->i_vi);
	silofs_dirtyq_fini(&ii->i_dq_vis);
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
	silofs_assert_eq(ii->i_dq_vis.dq.sz, 0);
	silofs_assert_ge(ii->i_nopen, 0);

	vi_del_view(&ii->i_vi, alloc, flags);
	ii_fini(ii);
	ii_free(ii, alloc, flags);
}

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni)
{
	return silofs_ii_from_vi(silofs_vi_from_lni(lni));
}

struct silofs_inode_info *silofs_ii_from_vi(const struct silofs_vnode_info *vi)
{
	return likely(vi != NULL) ? ii_from_vi(vi_unconst(vi)) : NULL;
}

struct silofs_inode_info *silofs_ii_from_dqe(struct silofs_dq_elem *dqe)
{
	return silofs_ii_from_vi(silofs_vi_from_dqe(dqe));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *xai_to_vi(struct silofs_xanode_info *xai)
{
	return &xai->xan_vi;
}

static struct silofs_xanode_info *xai_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_xanode_info *xai = NULL;

	silofs_assert_not_null(vi);
	xai = container_of(vi, struct silofs_xanode_info, xan_vi);
	return xai;
}

static void xai_init(struct silofs_xanode_info *xai,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&xai->xan_vi, vaddr, view);
	xai->xan = &view->u.xan;
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vi_fini(&xai->xan_vi);
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
	vi_del_view(&xai->xan_vi, alloc, flags);
	xai_fini(xai);
	xai_free(xai, alloc, flags);
}

struct silofs_xanode_info *silofs_xai_from_vi(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi);
	return xai_from_vi(vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *syi_to_vi(struct silofs_symval_info *syi)
{
	return &syi->sy_vi;
}

static struct silofs_symval_info *syi_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_symval_info *syi = NULL;

	syi = container_of(vi, struct silofs_symval_info, sy_vi);
	return syi;
}

static void syi_init(struct silofs_symval_info *syi,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&syi->sy_vi, vaddr, view);
	syi->syv = &view->u.syv;
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vi_fini(&syi->sy_vi);
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
	vi_del_view(&syi->sy_vi, alloc, flags);
	syi_fini(syi);
	syi_free(syi, alloc, flags);
}

struct silofs_symval_info *silofs_syi_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_symval_info *syi = NULL;

	silofs_assert_not_null(vi);
	syi = container_of(vi, struct silofs_symval_info, sy_vi);
	return syi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *dni_to_vi(struct silofs_dnode_info *dni)
{
	return &dni->dn_vi;
}

static struct silofs_dnode_info *dni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_dnode_info *dni = NULL;

	dni = container_of(vi, struct silofs_dnode_info, dn_vi);
	return dni;
}

static void dni_init(struct silofs_dnode_info *dni,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&dni->dn_vi, vaddr, view);
	dni->dtn = &view->u.dtn;
}

static void dni_fini(struct silofs_dnode_info *dni)
{
	vi_fini(&dni->dn_vi);
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
	vi_del_view(&dni->dn_vi, alloc, flags);
	dni_fini(dni);
	dni_free(dni, alloc, flags);
}

struct silofs_dnode_info *silofs_dni_from_vi(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi);
	silofs_assert(vi_has_ltype(vi, SILOFS_LTYPE_DTNODE));
	return dni_from_vi(vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fni_to_vi(struct silofs_finode_info *fni)
{
	return &fni->fn_vi;
}

static struct silofs_finode_info *fni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_finode_info *fni = NULL;

	fni = container_of(vi, struct silofs_finode_info, fn_vi);
	return fni;
}

static void fni_init(struct silofs_finode_info *fni,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&fni->fn_vi, vaddr, view);
	fni->ftn = &view->u.ftn;
}

static void fni_fini(struct silofs_finode_info *fni)
{
	vi_fini(&fni->fn_vi);
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
	vi_del_view(&fni->fn_vi, alloc, flags);
	fni_fini(fni);
	fni_free(fni, alloc, flags);
}

struct silofs_finode_info *silofs_fni_from_vi(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi);
	return fni_from_vi(vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fli_to_vi(struct silofs_fileaf_info *fli)
{
	return &fli->fl_vi;
}

static struct silofs_fileaf_info *fli_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_fileaf_info *fli = NULL;

	fli = container_of(vi, struct silofs_fileaf_info, fl_vi);
	return fli;
}

static void fli_init(struct silofs_fileaf_info *fli,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&fli->fl_vi, vaddr, view);

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
	vi_fini(&fli->fl_vi);
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
	vi_del_view(&fli->fl_vi, alloc, flags);
	fli_fini(fli);
	fli_free(fli, alloc, flags);
}

struct silofs_fileaf_info *silofs_fli_from_vi(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi);
	return fli_from_vi(vi);
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
	struct silofs_vnode_info *vi = NULL;
	const enum silofs_ltype ltype = vaddr->ltype;

	switch (ltype) {
	case SILOFS_LTYPE_INODE:
		vi = ii_to_vi(ii_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_XANODE:
		vi = xai_to_vi(xai_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_SYMVAL:
		vi = syi_to_vi(syi_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_DTNODE:
		vi = dni_to_vi(dni_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_FTNODE:
		vi = fni_to_vi(fni_new(alloc, vaddr));
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
		vi = fli_to_vi(fli_new(alloc, vaddr));
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
	return vi;
}

void silofs_del_vnode(struct silofs_vnode_info *vi,
                      struct silofs_alloc *alloc, int flags)
{
	const enum silofs_ltype ltype = vi_ltype(vi);


	switch (ltype) {
	case SILOFS_LTYPE_INODE:
		ii_del(ii_from_vi(vi), alloc, flags);
		break;
	case SILOFS_LTYPE_XANODE:
		xai_del(xai_from_vi(vi), alloc, flags);
		break;
	case SILOFS_LTYPE_SYMVAL:
		syi_del(syi_from_vi(vi), alloc, flags);
		break;
	case SILOFS_LTYPE_DTNODE:
		dni_del(dni_from_vi(vi), alloc, flags);
		break;
	case SILOFS_LTYPE_FTNODE:
		fni_del(fni_from_vi(vi), alloc, flags);
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATABK:
		fli_del(fli_from_vi(vi), alloc, flags);
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
