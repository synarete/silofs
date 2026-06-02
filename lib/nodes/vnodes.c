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
#include <limits.h>

#include <silofs/base.h>
#include <silofs/nodes.h>

enum {
	SILOFS_UI_MAGIC = 0xCAFEBEB,
	SILOFS_VI_MAGIC = 0xDEDFACE,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *memalloc_lni(struct silofs_alloc *alloc, size_t n)
{
	return silofs_memalloc(alloc, n, SILOFS_ALLOCF_BZERO);
}

static void memfree_lni(struct silofs_alloc *alloc, void *p, size_t n)
{
	silofs_memfree(alloc, p, n, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *
lni_unconst(const struct silofs_lnode_info *lni)
{
	return silofs_unconst(lni);
}

static void lni_init(struct silofs_lnode_info *lni, enum silofs_vtype vtype)
{
	const size_t vsize = silofs_vtype_size(vtype);

	silofs_ni_init(&lni->ln_base, vsize);
	silofs_avl_node_init(&lni->ln_ds_avl_node);
	lni->ln_vtype   = vtype;
	lni->ln_ds_next = nullptr;
	lni->ln_flags   = 0;
}

static void lni_fini(struct silofs_lnode_info *lni)
{
	silofs_ni_fini(&lni->ln_base);
	silofs_avl_node_fini(&lni->ln_ds_avl_node);
	lni->ln_ds_next = nullptr;
}

struct silofs_lview *silofs_lni_lview(const struct silofs_lnode_info *lni)
{
	return lni->ln_base.view.lview;
}

static struct silofs_lnode_info *lni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_lnode_info *lni = nullptr;

	if (likely(ni != nullptr)) {
		lni = container_of(ni, struct silofs_lnode_info, ln_base);
	}
	return lni_unconst(lni);
}

struct silofs_lnode_info *
silofs_lni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	return lni_from_ni(silofs_ni_from_hmqe(hmqe));
}

struct silofs_lnode_info *silofs_lni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_node_info *ni;

	ni = silofs_ni_from_dqe(dqe);
	return lni_from_ni(ni);
}

struct silofs_hmapq_elem *silofs_lni_to_hmqe(struct silofs_lnode_info *lni)
{
	return &lni->ln_base.hmqe;
}

static bool lni_hasflags(const struct silofs_lnode_info *lni,
                         const enum silofs_lnflags mask)
{
	return ((lni->ln_flags & mask) == mask);
}

static bool lni_ispinned(const struct silofs_lnode_info *lni)
{
	return lni_hasflags(lni, SILOFS_LNF_PINNED) ||
	       silofs_ni_ispinned(&lni->ln_base);
}

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni)
{
	return !lni_ispinned(lni);
}

size_t silofs_lni_refcnt(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	return silofs_ni_refcnt(&lni->ln_base);
}

void silofs_lni_incref(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	silofs_ni_incref(&lni->ln_base);
}

void silofs_lni_decref(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	silofs_ni_decref(&lni->ln_base);
}

static enum silofs_vtype lni_vtype(const struct silofs_lnode_info *lni)
{
	return lni->ln_vtype;
}

static bool lni_isdata(const struct silofs_lnode_info *lni)
{
	return silofs_vtype_isdata(lni_vtype(lni));
}

static int
lni_attach_lview(struct silofs_lnode_info *lni, struct silofs_alloc *alloc)
{
	int err;

	err = silofs_ni_attach_view(&lni->ln_base, alloc, !lni_isdata(lni));
	if (!err) {
		silofs_lview_setup(lni->ln_base.view.lview, lni_vtype(lni));
	}
	return err;
}

static void
lni_detach_lview(struct silofs_lnode_info *lni, struct silofs_alloc *alloc)
{
	silofs_ni_detach_view(&lni->ln_base, alloc, false);
}

void silofs_lni_remove_from(struct silofs_lnode_info *lni,
                            struct silofs_hmapq *hmapq)
{
	silofs_hmapq_remove(hmapq, silofs_lni_to_hmqe(lni));
}

static struct silofs_dq_elem *lni_mut_dqe(struct silofs_lnode_info *lni)
{
	return &lni->ln_base.dqe;
}

static const struct silofs_dq_elem *
lni_dqe(const struct silofs_lnode_info *lni)
{
	return &lni->ln_base.dqe;
}

static void lni_set_dq(struct silofs_lnode_info *lni, struct silofs_dirtyq *dq)
{
	silofs_dqe_set_dirtyq(lni_mut_dqe(lni), dq);
}

bool silofs_lni_isdirty(const struct silofs_lnode_info *lni)
{
	return silofs_dqe_isdirty(lni_dqe(lni));
}

void silofs_lni_markdirty(struct silofs_lnode_info *lni)
{
	if (!silofs_lni_isdirty(lni)) {
		silofs_dqe_markdirty(lni_mut_dqe(lni));
	}
}

void silofs_lni_cleardirty(struct silofs_lnode_info *lni)
{
	if (silofs_lni_isdirty(lni)) {
		silofs_dqe_cleardirty(lni_mut_dqe(lni));
	}
}

int silofs_verify_lnode(const struct silofs_lnode_info *lni)
{
	const struct silofs_lview *lview = silofs_lni_lview(lni);

	return silofs_lview_verify(lview, lni->ln_vtype);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *
uni_unconst(const struct silofs_unode_info *uni)
{
	return silofs_unconst(uni);
}

static void uni_verify(const struct silofs_unode_info *uni)
{
	silofs_assume_not_null(uni);
	silofs_assert_eq(uni->un_magic, SILOFS_UI_MAGIC);
}

static void
uni_init(struct silofs_unode_info *uni, const struct silofs_uaddr *uaddr)
{
	lni_init(&uni->un_lni, silofs_uaddr_vtype(uaddr));
	silofs_uaddr_assign(&uni->un_uaddr, uaddr);
	uni->un_magic = SILOFS_UI_MAGIC;
}

static void uni_fini(struct silofs_unode_info *uni)
{
	silofs_uaddr_reset(&uni->un_uaddr);
	lni_fini(&uni->un_lni);
	uni->un_magic = UINT64_MAX;
}

struct silofs_lview *silofs_uni_lview(const struct silofs_unode_info *uni)
{
	return silofs_lni_lview(&uni->un_lni);
}

static int
uni_attach_lview(struct silofs_unode_info *uni, struct silofs_alloc *alloc)
{
	return lni_attach_lview(&uni->un_lni, alloc);
}

static void
uni_detach_lview(struct silofs_unode_info *uni, struct silofs_alloc *alloc)
{
	lni_detach_lview(&uni->un_lni, alloc);
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

	uni = container_of(lni, struct silofs_unode_info, un_lni);
	uni_verify(uni);

	return uni_unconst(uni);
}

void silofs_uni_seal_view(struct silofs_unode_info *uni)
{
	uni_verify(uni);
	silofs_lview_seal(silofs_uni_lview(uni));
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

void silofs_uni_markdirty(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_lni_markdirty(&uni->un_lni);
}

void silofs_uni_cleardirty(struct silofs_unode_info *uni)
{
	uni_verify(uni);

	silofs_lni_cleardirty(&uni->un_lni);
}

bool silofs_uni_isevictable(const struct silofs_unode_info *uni)
{
	uni_verify(uni);

	return silofs_lni_isevictable(&uni->un_lni);
}

enum silofs_vtype silofs_uni_vtype(const struct silofs_unode_info *uni)
{
	uni_verify(uni);

	return silofs_uaddr_vtype(&uni->un_uaddr);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
vni_unconst(const struct silofs_vnode_info *vni)
{
	return silofs_unconst(vni);
}

static void vni_verify(const struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	silofs_assert_eq(vni->vn_magic, SILOFS_VI_MAGIC);
}

static void
vni_init(struct silofs_vnode_info *vni, const struct silofs_vaddr *vaddr)
{
	lni_init(&vni->vn_lni, vaddr->vtype);
	silofs_vaddr_assign(&vni->vn_vaddr, vaddr);
	silofs_llink_reset(&vni->vn_llink);
	silofs_paddr_reset(&vni->vn_curr_paddr);
	vni->vn_asyncwr = 0;
	vni->vn_has_pn  = false;
	vni->vn_magic   = SILOFS_VI_MAGIC;

	vni->isevictable_fn = silofs_vni_isevictable;
}

static void vni_fini(struct silofs_vnode_info *vni)
{
	vni_verify(vni);
	silofs_assert_eq(vni->vn_asyncwr, 0);

	lni_fini(&vni->vn_lni);
	silofs_vaddr_reset(&vni->vn_vaddr);
	silofs_paddr_reset(&vni->vn_curr_paddr);
	vni->vn_magic = UINT64_MAX;
}

struct silofs_lview *silofs_vni_lview(const struct silofs_vnode_info *vni)
{
	return silofs_lni_lview(&vni->vn_lni);
}

struct silofs_lview *silofs_vni_lviewx(const struct silofs_vnode_info *vni)
{
	silofs_assume_not_null(vni);
	return vni->vn_lni.ln_base.viewx.lview;
}

static int
vni_attach_lview(struct silofs_vnode_info *vni, struct silofs_alloc *alloc)
{
	return lni_attach_lview(&vni->vn_lni, alloc);
}

static void
vni_detach_lview(struct silofs_vnode_info *vni, struct silofs_alloc *alloc)
{
	lni_detach_lview(&vni->vn_lni, alloc);
}

size_t silofs_vni_refcnt(const struct silofs_vnode_info *vni)
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
	if (ii != nullptr && !vni->vn_has_pn) {
		silofs_vni_set_dq(vni, &ii->i_dq_vnis);
	}
}

void silofs_vni_markdirty(struct silofs_vnode_info *vni,
                          struct silofs_inode_info *ii)
{
	silofs_assert_not_null(vni);

	if (!silofs_vni_isdirty(vni)) {
		vni_update_dq_by(vni, ii);
		silofs_lni_markdirty(&vni->vn_lni);
	}
}

void silofs_vni_cleardirty(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	if (silofs_vni_isdirty(vni)) {
		silofs_lni_cleardirty(&vni->vn_lni);
	}
}

struct silofs_vnode_info *
silofs_vni_from_lni(const struct silofs_lnode_info *lni)
{
	const struct silofs_vnode_info *vni = nullptr;

	if (lni != nullptr) {
		vni = container_of(lni, struct silofs_vnode_info, vn_lni);
		vni_verify(vni);
	}
	return vni_unconst(vni);
}

struct silofs_vnode_info *silofs_vni_from_dqe(const struct silofs_dq_elem *dqe)
{
	return silofs_vni_from_lni(silofs_lni_from_dqe(dqe));
}

static bool
vni_has_vtype(const struct silofs_vnode_info *vni, enum silofs_vtype vtype)
{
	return silofs_vni_vtype(vni) == vtype;
}

bool silofs_vni_isevictable(const struct silofs_vnode_info *vni)
{
	return silofs_lni_isevictable(&vni->vn_lni);
}

bool silofs_vni_need_recheck(const struct silofs_vnode_info *vni)
{
	const enum silofs_lnflags flags = vni->vn_lni.ln_flags;
	const enum silofs_lnflags mask  = SILOFS_LNF_RECHECK;

	return (flags & mask) != mask;
}

void silofs_vni_set_rechecked(struct silofs_vnode_info *vni)
{
	vni->vn_lni.ln_flags |= SILOFS_LNF_RECHECK;
}

const struct silofs_vaddr *
silofs_vni_vaddr(const struct silofs_vnode_info *vni)
{
	return &vni->vn_vaddr;
}

static enum silofs_vtype vni_vtype(const struct silofs_vnode_info *vni)
{
	const struct silofs_vaddr *vaddr = silofs_vni_vaddr(vni);

	return vaddr->vtype;
}

enum silofs_vtype silofs_vni_vtype(const struct silofs_vnode_info *vni)
{
	silofs_assume_not_null(vni);
	return vni_vtype(vni);
}

static bool vni_isdata(const struct silofs_vnode_info *vni)
{
	enum silofs_vtype vtype = silofs_vni_vtype(vni);

	return silofs_vtype_isdata(vtype);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_unode_info *sbi_to_uni(struct silofs_sb_info *sbi)
{
	return &sbi->sb_uni;
}

static struct silofs_sb_info *sbi_from_uni(struct silofs_unode_info *uni)
{
	return mut_container_of(uni, struct silofs_sb_info, sb_uni);
}

static void
sbi_init(struct silofs_sb_info *sbi, const struct silofs_uaddr *uaddr)
{
	uni_init(&sbi->sb_uni, uaddr);
}

static void sbi_fini(struct silofs_sb_info *sbi)
{
	uni_fini(&sbi->sb_uni);
	sbi->sb = nullptr;
}

static struct silofs_sb_info *sbi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sb_info *sbi;

	sbi = memalloc_lni(alloc, sizeof(*sbi));
	return sbi;
}

static void sbi_free(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, sbi, sizeof(*sbi));
}

static struct silofs_sb_info *
sbi_malloc_init(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_sb_info *sbi;

	sbi = sbi_malloc(alloc);
	if (sbi != nullptr) {
		sbi_init(sbi, uaddr);
	}
	return sbi;
}

static void
sbi_fini_free(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	sbi_fini(sbi);
	sbi_free(sbi, alloc);
}

static int
sbi_attach_lview(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = uni_attach_lview(&sbi->sb_uni, alloc);
	if (!err) {
		lview   = silofs_uni_lview(&sbi->sb_uni);
		sbi->sb = &lview->u.sb;
	}
	return err;
}

static void
sbi_detach_lview(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	uni_detach_lview(&sbi->sb_uni, alloc);
	sbi->sb = nullptr;
}

static struct silofs_sb_info *
sbi_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_sb_info *sbi;
	int err;

	sbi = sbi_malloc_init(alloc, uaddr);
	if (sbi == nullptr) {
		return nullptr;
	}
	err = sbi_attach_lview(sbi, alloc);
	if (err) {
		sbi_fini_free(sbi, alloc);
		return nullptr;
	}
	return sbi;
}

static void sbi_del(struct silofs_sb_info *sbi, struct silofs_alloc *alloc)
{
	sbi_detach_lview(sbi, alloc);
	sbi_fini_free(sbi, alloc);
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
	return mut_container_of(uni, struct silofs_spnode_info, sn_uni);
}

static void
sni_init(struct silofs_spnode_info *sni, const struct silofs_uaddr *uaddr)
{
	uni_init(&sni->sn_uni, uaddr);
	sni->sn_nactive_subs = 0;
}

static void sni_fini(struct silofs_spnode_info *sni)
{
	uni_fini(&sni->sn_uni);
	sni->sn_nactive_subs = 0;
}

static struct silofs_spnode_info *sni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spnode_info *sni;

	sni = memalloc_lni(alloc, sizeof(*sni));
	return sni;
}

static void
sni_free(struct silofs_spnode_info *sni, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, sni, sizeof(*sni));
}

static struct silofs_spnode_info *
sni_malloc_init(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_spnode_info *sni;

	sni = sni_malloc(alloc);
	if (sni != nullptr) {
		sni_init(sni, uaddr);
	}
	return sni;
}

static void
sni_fini_free(struct silofs_spnode_info *sni, struct silofs_alloc *alloc)
{
	sni_fini(sni);
	sni_free(sni, alloc);
}

static int
sni_attach_lview(struct silofs_spnode_info *sni, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = uni_attach_lview(&sni->sn_uni, alloc);
	if (!err) {
		lview   = silofs_uni_lview(&sni->sn_uni);
		sni->sn = &lview->u.sn;
	}
	return err;
}

static void
sni_detach_lview(struct silofs_spnode_info *sni, struct silofs_alloc *alloc)
{
	uni_detach_lview(&sni->sn_uni, alloc);
	sni->sn = nullptr;
}

static struct silofs_spnode_info *
sni_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_spnode_info *sni;
	int err;

	sni = sni_malloc_init(alloc, uaddr);
	if (sni == nullptr) {
		return nullptr;
	}
	err = sni_attach_lview(sni, alloc);
	if (err) {
		sni_fini_free(sni, alloc);
		return nullptr;
	}
	return sni;
}

static void sni_del(struct silofs_spnode_info *sni, struct silofs_alloc *alloc)
{
	sni_detach_lview(sni, alloc);
	sni_fini_free(sni, alloc);
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
	return mut_container_of(uni, struct silofs_spleaf_info, sl_uni);
}

static void
sli_init(struct silofs_spleaf_info *sli, const struct silofs_uaddr *uaddr)
{
	uni_init(&sli->sl_uni, uaddr);
}

static void sli_fini(struct silofs_spleaf_info *sli)
{
	uni_fini(&sli->sl_uni);
}

static struct silofs_spleaf_info *sli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spleaf_info *sli;

	sli = memalloc_lni(alloc, sizeof(*sli));
	return sli;
}

static struct silofs_spleaf_info *
sli_malloc_init(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_spleaf_info *sli;

	sli = sli_malloc(alloc);
	if (sli != nullptr) {
		sli_init(sli, uaddr);
	}
	return sli;
}

static void
sli_free(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, sli, sizeof(*sli));
}

static void
sli_fini_free(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc)
{
	sli_fini(sli);
	sli_free(sli, alloc);
}

static int
sli_attach_lview(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = uni_attach_lview(&sli->sl_uni, alloc);
	if (!err) {
		lview   = silofs_uni_lview(&sli->sl_uni);
		sli->sl = &lview->u.sl;
	}
	return err;
}

static void
sli_detach_lview(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc)
{
	uni_detach_lview(&sli->sl_uni, alloc);
	sli->sl = nullptr;
}

static struct silofs_spleaf_info *
sli_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_spleaf_info *sli;
	int err;

	sli = sli_malloc_init(alloc, uaddr);
	if (sli == nullptr) {
		return nullptr;
	}
	err = sli_attach_lview(sli, alloc);
	if (err) {
		sli_fini_free(sli, alloc);
		return nullptr;
	}
	return sli;
}

static void sli_del(struct silofs_spleaf_info *sli, struct silofs_alloc *alloc)
{
	sli_detach_lview(sli, alloc);
	sli_fini_free(sli, alloc);
}

struct silofs_spleaf_info *silofs_sli_from_uni(struct silofs_unode_info *uni)
{
	return sli_from_uni(uni_unconst(uni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *spi_to_vni(struct silofs_space_info *spi)
{
	return likely(spi != nullptr) ? &spi->spn_vni : nullptr;
}

static struct silofs_space_info *spi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_space_info, spn_vni);
}

static void
spi_init(struct silofs_space_info *spi, const struct silofs_vaddr *vaddr)
{
	vni_init(&spi->spn_vni, vaddr);
	spi->spn_nused_ref = 0;
}

static void spi_fini(struct silofs_space_info *spi)
{
	vni_fini(&spi->spn_vni);
	spi->spn_nused_ref = UINT_MAX;
}

static struct silofs_space_info *spi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_space_info *spi;

	spi = memalloc_lni(alloc, sizeof(*spi));
	return spi;
}

static void spi_free(struct silofs_space_info *spi, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, spi, sizeof(*spi));
}

static struct silofs_space_info *
spi_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_space_info *spi;

	spi = spi_malloc(alloc);
	if (spi != nullptr) {
		spi_init(spi, vaddr);
	}
	return spi;
}

static void
spi_fini_free(struct silofs_space_info *spi, struct silofs_alloc *alloc)
{
	spi_fini(spi);
	spi_free(spi, alloc);
}

static int
spi_attach_lview(struct silofs_space_info *spi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&spi->spn_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&spi->spn_vni);
		spi->spn = &lview->u.spn;
	}
	return err;
}

static void
spi_detach_lview(struct silofs_space_info *spi, struct silofs_alloc *alloc)
{
	vni_detach_lview(&spi->spn_vni, alloc);
	spi->spn = nullptr;
}

static struct silofs_space_info *
spi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_space_info *spi;
	int err;

	spi = spi_malloc_init(alloc, vaddr);
	if (spi == nullptr) {
		return nullptr;
	}
	err = spi_attach_lview(spi, alloc);
	if (err) {
		spi_fini_free(spi, alloc);
		return nullptr;
	}
	return spi;
}

static void spi_del(struct silofs_space_info *spi, struct silofs_alloc *alloc)
{
	spi_detach_lview(spi, alloc);
	spi_fini_free(spi, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *lsi_to_vni(struct silofs_lsmap_info *lsi)
{
	return likely(lsi != nullptr) ? &lsi->ls_vni : nullptr;
}

static struct silofs_lsmap_info *lsi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_lsmap_info, ls_vni);
}

static void
lsi_init(struct silofs_lsmap_info *lsi, const struct silofs_vaddr *vaddr)
{
	vni_init(&lsi->ls_vni, vaddr);
	lsi->ls_nused_bytes = 0;
	lsi->ls_off_hint    = 0;
}

static void lsi_fini(struct silofs_lsmap_info *lsi)
{
	vni_fini(&lsi->ls_vni);
	lsi->ls_nused_bytes = UINT_MAX;
	lsi->ls_off_hint    = -1;
}

static struct silofs_lsmap_info *lsi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_lsmap_info *lsi;

	lsi = memalloc_lni(alloc, sizeof(*lsi));
	return lsi;
}

static void lsi_free(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, lsi, sizeof(*lsi));
}

static struct silofs_lsmap_info *
lsi_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_lsmap_info *lsi;

	lsi = lsi_malloc(alloc);
	if (lsi != nullptr) {
		lsi_init(lsi, vaddr);
	}
	return lsi;
}

static void
lsi_fini_free(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc)
{
	lsi_fini(lsi);
	lsi_free(lsi, alloc);
}

static int
lsi_attach_lview(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&lsi->ls_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&lsi->ls_vni);
		lsi->lsm = &lview->u.lsm;
	}
	return err;
}

static void
lsi_detach_lview(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc)
{
	vni_detach_lview(&lsi->ls_vni, alloc);
	lsi->lsm = nullptr;
}

static struct silofs_lsmap_info *
lsi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_lsmap_info *lsi;
	int err;

	lsi = lsi_malloc_init(alloc, vaddr);
	if (lsi == nullptr) {
		return nullptr;
	}
	err = lsi_attach_lview(lsi, alloc);
	if (err) {
		lsi_fini_free(lsi, alloc);
		return nullptr;
	}
	return lsi;
}

static void lsi_del(struct silofs_lsmap_info *lsi, struct silofs_alloc *alloc)
{
	lsi_detach_lview(lsi, alloc);
	lsi_fini_free(lsi, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *ii_to_vni(struct silofs_inode_info *ii)
{
	return likely(ii != nullptr) ? &ii->i_vni : nullptr;
}

static struct silofs_inode_info *ii_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_inode_info, i_vni);
}

static void
ii_init(struct silofs_inode_info *ii, const struct silofs_vaddr *vaddr)
{
	vni_init(&ii->i_vni, vaddr);
	silofs_dirtyq_init(&ii->i_dq_vnis);
	ii->inode         = nullptr;
	ii->i_looseq_next = nullptr;
	ii->i_ino         = SILOFS_INO_NULL;
	ii->i_nopen       = 0;
	ii->i_nlookup     = 0;
	ii->i_in_looseq   = false;
}

static void ii_fini(struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vnis.drq.sz, 0);
	silofs_assert(!ii->i_in_looseq);
	silofs_assert_null(ii->i_looseq_next);

	vni_fini(&ii->i_vni);
	silofs_dirtyq_fini(&ii->i_dq_vnis);
	ii->inode   = nullptr;
	ii->i_ino   = SILOFS_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static struct silofs_inode_info *ii_malloc(struct silofs_alloc *alloc)
{
	struct silofs_inode_info *ii;

	ii = memalloc_lni(alloc, sizeof(*ii));
	return ii;
}

static void ii_free(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, ii, sizeof(*ii));
}

static struct silofs_inode_info *
ii_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_info *ii;

	ii = ii_malloc(alloc);
	if (ii != nullptr) {
		ii_init(ii, vaddr);
	}
	return ii;
}

static void
ii_fini_free(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	ii_fini(ii);
	ii_free(ii, alloc);
}

static int
ii_attach_lview(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&ii->i_vni, alloc);
	if (!err) {
		lview     = silofs_vni_lview(&ii->i_vni);
		ii->inode = &lview->u.in;
	}
	return err;
}

static void
ii_detach_lview(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	vni_detach_lview(&ii->i_vni, alloc);
	ii->inode = nullptr;
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_info *ii;
	int err;

	ii = ii_malloc_init(alloc, vaddr);
	if (ii == nullptr) {
		return nullptr;
	}
	err = ii_attach_lview(ii, alloc);
	if (err) {
		ii_fini_free(ii, alloc);
		return nullptr;
	}
	return ii;
}

static void ii_del(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	silofs_assert_eq(ii->i_dq_vnis.drq.sz, 0);
	silofs_assert_ge(ii->i_nopen, 0);

	vni_detach_lview(&ii->i_vni, alloc);
	ii_detach_lview(ii, alloc);
	ii_fini_free(ii, alloc);
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
	return likely(xai != nullptr) ? &xai->xan_vni : nullptr;
}

static struct silofs_xanode_info *xai_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_xanode_info, xan_vni);
}

static void
xai_init(struct silofs_xanode_info *xai, const struct silofs_vaddr *vaddr)
{
	vni_init(&xai->xan_vni, vaddr);
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vni_fini(&xai->xan_vni);
	xai->xan = nullptr;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc *alloc)
{
	struct silofs_xanode_info *xai;

	xai = memalloc_lni(alloc, sizeof(*xai));
	return xai;
}

static struct silofs_xanode_info *
xai_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_xanode_info *xai;

	xai = xai_malloc(alloc);
	if (xai != nullptr) {
		xai_init(xai, vaddr);
	}
	return xai;
}

static void
xai_free(struct silofs_xanode_info *xai, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, xai, sizeof(*xai));
}

static void
xai_fini_free(struct silofs_xanode_info *xai, struct silofs_alloc *alloc)
{
	xai_fini(xai);
	xai_free(xai, alloc);
}

static int
xai_bind_lview(struct silofs_xanode_info *xai, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&xai->xan_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&xai->xan_vni);
		xai->xan = &lview->u.xan;
	}
	return err;
}

static void
xai_unbind_lview(struct silofs_xanode_info *xai, struct silofs_alloc *alloc)
{
	vni_detach_lview(&xai->xan_vni, alloc);
	xai->xan = nullptr;
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_xanode_info *xai;
	int err;

	xai = xai_malloc_init(alloc, vaddr);
	if (xai == nullptr) {
		return nullptr;
	}
	err = xai_bind_lview(xai, alloc);
	if (err) {
		xai_fini_free(xai, alloc);
		return nullptr;
	}
	return xai;
}

static void xai_del(struct silofs_xanode_info *xai, struct silofs_alloc *alloc)
{
	xai_unbind_lview(xai, alloc);
	xai_fini(xai);
	xai_free(xai, alloc);
}

struct silofs_xanode_info *silofs_xai_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return xai_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *syi_to_vni(struct silofs_symval_info *syi)
{
	return likely(syi != nullptr) ? &syi->syv_vni : nullptr;
}

static struct silofs_symval_info *syi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_symval_info, syv_vni);
}

static void
syi_init(struct silofs_symval_info *syi, const struct silofs_vaddr *vaddr)
{
	vni_init(&syi->syv_vni, vaddr);
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vni_fini(&syi->syv_vni);
	syi->syv = nullptr;
}

static struct silofs_symval_info *syi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_symval_info *syi;

	syi = memalloc_lni(alloc, sizeof(*syi));
	return syi;
}

static void
syi_free(struct silofs_symval_info *syi, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, syi, sizeof(*syi));
}

static void
syi_fini_free(struct silofs_symval_info *syi, struct silofs_alloc *alloc)
{
	syi_fini(syi);
	syi_free(syi, alloc);
}

static struct silofs_symval_info *
syi_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_symval_info *syi;

	syi = syi_malloc(alloc);
	if (syi != nullptr) {
		syi_init(syi, vaddr);
	}
	return syi;
}

static int
syi_attach_lview(struct silofs_symval_info *syi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&syi->syv_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&syi->syv_vni);
		syi->syv = &lview->u.syv;
	}
	return err;
}

static void
syi_detach_lview(struct silofs_symval_info *syi, struct silofs_alloc *alloc)
{
	vni_detach_lview(&syi->syv_vni, alloc);
	syi->syv = nullptr;
}

static struct silofs_symval_info *
syi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_symval_info *syi;
	int err;

	syi = syi_malloc_init(alloc, vaddr);
	if (syi == nullptr) {
		return nullptr;
	}
	err = syi_attach_lview(syi, alloc);
	if (err) {
		syi_fini_free(syi, alloc);
		return nullptr;
	}
	return syi;
}

static void syi_del(struct silofs_symval_info *syi, struct silofs_alloc *alloc)
{
	syi_detach_lview(syi, alloc);
	syi_fini_free(syi, alloc);
}

struct silofs_symval_info *silofs_syi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_symval_info, syv_vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *dni_to_vni(struct silofs_dtnode_info *dni)
{
	return likely(dni != nullptr) ? &dni->dtn_vni : nullptr;
}

static struct silofs_dtnode_info *dni_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_dtnode_info, dtn_vni);
}

static void
dni_init(struct silofs_dtnode_info *dni, const struct silofs_vaddr *vaddr)
{
	vni_init(&dni->dtn_vni, vaddr);
}

static void dni_fini(struct silofs_dtnode_info *dni)
{
	vni_fini(&dni->dtn_vni);
	dni->dtn = nullptr;
}

static struct silofs_dtnode_info *dni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_dtnode_info *dni;

	dni = memalloc_lni(alloc, sizeof(*dni));
	return dni;
}

static void
dni_free(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, dni, sizeof(*dni));
}

static struct silofs_dtnode_info *
dni_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_dtnode_info *dni;

	dni = dni_malloc(alloc);
	if (dni != nullptr) {
		dni_init(dni, vaddr);
	}
	return dni;
}

static void
dni_fini_free(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	dni_fini(dni);
	dni_free(dni, alloc);
}

static int
dni_attach_lview(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&dni->dtn_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&dni->dtn_vni);
		dni->dtn = &lview->u.dtn;
	}
	return err;
}

static void
dni_detach_lview(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	vni_detach_lview(&dni->dtn_vni, alloc);
	dni->dtn = nullptr;
}

static struct silofs_dtnode_info *
dni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_dtnode_info *dni;
	int err;

	dni = dni_malloc_init(alloc, vaddr);
	if (dni == nullptr) {
		return nullptr;
	}
	err = dni_attach_lview(dni, alloc);
	if (err) {
		dni_fini_free(dni, alloc);
		return nullptr;
	}
	return dni;
}

static void dni_del(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	dni_detach_lview(dni, alloc);
	dni_fini_free(dni, alloc);
}

struct silofs_dtnode_info *silofs_dni_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	silofs_assert(vni_has_vtype(vni, SILOFS_VTYPE_DTNODE));
	return dni_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fni_to_vni(struct silofs_ftnode_info *fni)
{
	return likely(fni != nullptr) ? &fni->ftn_vni : nullptr;
}

static struct silofs_ftnode_info *fni_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_ftnode_info, ftn_vni);
}

static void
fni_init(struct silofs_ftnode_info *fni, const struct silofs_vaddr *vaddr)
{
	vni_init(&fni->ftn_vni, vaddr);
}

static void fni_fini(struct silofs_ftnode_info *fni)
{
	vni_fini(&fni->ftn_vni);
	fni->ftn = nullptr;
}

static struct silofs_ftnode_info *fni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ftnode_info *fni;

	fni = memalloc_lni(alloc, sizeof(*fni));
	return fni;
}

static void
fni_free(struct silofs_ftnode_info *fni, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, fni, sizeof(*fni));
}

static struct silofs_ftnode_info *
fni_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_ftnode_info *fni;

	fni = fni_malloc(alloc);
	if (fni != nullptr) {
		fni_init(fni, vaddr);
	}
	return fni;
}

static void
fni_fini_free(struct silofs_ftnode_info *fni, struct silofs_alloc *alloc)
{
	fni_fini(fni);
	fni_free(fni, alloc);
}

static int
fni_attach_lview(struct silofs_ftnode_info *fni, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&fni->ftn_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&fni->ftn_vni);
		fni->ftn = &lview->u.ftn;
	}
	return err;
}

static void
fni_detach_lview(struct silofs_ftnode_info *fni, struct silofs_alloc *alloc)
{
	vni_detach_lview(&fni->ftn_vni, alloc);
	fni->ftn = nullptr;
}

static struct silofs_ftnode_info *
fni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_ftnode_info *fni;
	int err;

	fni = fni_malloc_init(alloc, vaddr);
	if (fni == nullptr) {
		return nullptr;
	}
	err = fni_attach_lview(fni, alloc);
	if (err) {
		fni_fini_free(fni, alloc);
		return nullptr;
	}
	return fni;
}

static void fni_del(struct silofs_ftnode_info *fni, struct silofs_alloc *alloc)
{
	fni_detach_lview(fni, alloc);
	fni_fini(fni);
	fni_free(fni, alloc);
}

struct silofs_ftnode_info *silofs_fni_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return fni_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fli_to_vni(struct silofs_ftleaf_info *fli)
{
	return likely(fli != nullptr) ? &fli->ftl_vni : nullptr;
}

static struct silofs_ftleaf_info *fli_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_ftleaf_info, ftl_vni);
}

static void
fli_init(struct silofs_ftleaf_info *fli, const struct silofs_vaddr *vaddr)
{
	vni_init(&fli->ftl_vni, vaddr);
}

static void fli_fini(struct silofs_ftleaf_info *fli)
{
	vni_fini(&fli->ftl_vni);
	fli->ftl.db = nullptr;
}

static struct silofs_ftleaf_info *fli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ftleaf_info *fli;

	fli = memalloc_lni(alloc, sizeof(*fli));
	return fli;
}

static void
fli_free(struct silofs_ftleaf_info *fli, struct silofs_alloc *alloc)
{
	memfree_lni(alloc, fli, sizeof(*fli));
}

static struct silofs_ftleaf_info *
fli_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_ftleaf_info *fli;

	fli = fli_malloc(alloc);
	if (fli != nullptr) {
		fli_init(fli, vaddr);
	}
	return fli;
}

static void
fli_fini_free(struct silofs_ftleaf_info *fli, struct silofs_alloc *alloc)
{
	fli_fini(fli);
	fli_free(fli, alloc);
}

static int
fli_attach_lview(struct silofs_ftleaf_info *fli, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview = nullptr;
	int err;

	err = vni_attach_lview(&fli->ftl_vni, alloc);
	if (!err) {
		const enum silofs_vtype vtype = vni_vtype(&fli->ftl_vni);

		lview = silofs_vni_lview(&fli->ftl_vni);
		if (vtype == SILOFS_VTYPE_DATA1K) {
			fli->ftl.db1 = &lview->u.dbk1;
		} else if (vtype == SILOFS_VTYPE_DATA4K) {
			fli->ftl.db4 = &lview->u.dbk4;
		} else if (vtype == SILOFS_VTYPE_DATA64K) {
			fli->ftl.db = &lview->u.dbk64;
		} else {
			silofs_panic("not a data vtype: %d", (int)vtype);
		}
	}
	return err;
}

static void
fli_detach_lview(struct silofs_ftleaf_info *fli, struct silofs_alloc *alloc)
{
	vni_detach_lview(&fli->ftl_vni, alloc);
}

static struct silofs_ftleaf_info *
fli_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_ftleaf_info *fli;
	int err;

	fli = fli_malloc_init(alloc, vaddr);
	if (fli == nullptr) {
		return nullptr;
	}
	err = fli_attach_lview(fli, alloc);
	if (err) {
		fli_fini_free(fli, alloc);
		return nullptr;
	}
	return fli;
}

static void fli_del(struct silofs_ftleaf_info *fli, struct silofs_alloc *alloc)
{
	fli_detach_lview(fli, alloc);
	fli_fini_free(fli, alloc);
}

struct silofs_ftleaf_info *silofs_fli_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return fli_from_vni(vni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_unode_info *
silofs_new_unode(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *uni = nullptr;
	const enum silofs_vtype vtype = silofs_uaddr_vtype(uaddr);

	switch (vtype) {
	case SILOFS_VTYPE_SUPER:
		uni = sbi_to_uni(sbi_new(alloc, uaddr));
		break;
	case SILOFS_VTYPE_SPNODE:
		uni = sni_to_uni(sni_new(alloc, uaddr));
		break;
	case SILOFS_VTYPE_SPLEAF:
		uni = sli_to_uni(sli_new(alloc, uaddr));
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_LSMAP:
	case SILOFS_VTYPE_INODE:
	case SILOFS_VTYPE_XANODE:
	case SILOFS_VTYPE_SYMVAL:
	case SILOFS_VTYPE_DTNODE:
	case SILOFS_VTYPE_FTNODE:
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
	case SILOFS_VTYPE_SPNODE2:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		silofs_panic("can not create unode: vtype=%d", (int)vtype);
		break;
	}
	return uni;
}

void silofs_del_unode(struct silofs_unode_info *uni,
                      struct silofs_alloc *alloc)
{
	const enum silofs_vtype vtype = silofs_uni_vtype(uni);

	switch (vtype) {
	case SILOFS_VTYPE_SUPER:
		sbi_del(sbi_from_uni(uni), alloc);
		break;
	case SILOFS_VTYPE_SPNODE:
		sni_del(sni_from_uni(uni), alloc);
		break;
	case SILOFS_VTYPE_SPLEAF:
		sli_del(sli_from_uni(uni), alloc);
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_LSMAP:
	case SILOFS_VTYPE_INODE:
	case SILOFS_VTYPE_XANODE:
	case SILOFS_VTYPE_SYMVAL:
	case SILOFS_VTYPE_DTNODE:
	case SILOFS_VTYPE_FTNODE:
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
	case SILOFS_VTYPE_SPNODE2:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		silofs_panic("can not destroy unode: vtype=%d", (int)vtype);
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = nullptr;
	const enum silofs_vtype vtype = vaddr->vtype;

	switch (vtype) {
	case SILOFS_VTYPE_SPNODE2:
		vni = spi_to_vni(spi_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_LSMAP:
		vni = lsi_to_vni(lsi_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_INODE:
		vni = ii_to_vni(ii_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_XANODE:
		vni = xai_to_vni(xai_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_SYMVAL:
		vni = syi_to_vni(syi_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_DTNODE:
		vni = dni_to_vni(dni_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_FTNODE:
		vni = fni_to_vni(fni_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		vni = fli_to_vni(fli_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		silofs_panic("can not create vnode: vtype=%d", (int)vtype);
		break;
	}
	return vni;
}

void silofs_del_vnode(struct silofs_vnode_info *vni,
                      struct silofs_alloc *alloc)
{
	const enum silofs_vtype vtype = silofs_vni_vtype(vni);

	switch (vtype) {
	case SILOFS_VTYPE_SPNODE2:
		spi_del(spi_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_LSMAP:
		lsi_del(lsi_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_INODE:
		ii_del(ii_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_XANODE:
		xai_del(xai_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_SYMVAL:
		syi_del(syi_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_DTNODE:
		dni_del(dni_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_FTNODE:
		fni_del(fni_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		fli_del(fli_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_ARIX:
	case SILOFS_VTYPE_SUPER:
	case SILOFS_VTYPE_SPNODE:
	case SILOFS_VTYPE_SPLEAF:
	case SILOFS_VTYPE_NONE:
	case SILOFS_VTYPE_LAST:
	default:
		silofs_panic("can not destroy vnode: vtype=%d", (int)vtype);
		break;
	}
}

void silofs_seal_vnode(const struct silofs_vnode_info *vni)
{
	if (!vni_isdata(vni)) {
		silofs_lview_seal(silofs_vni_lview(vni));
	}
}
