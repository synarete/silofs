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
	SILOFS_VI_MAGIC = 0xDEDFACE,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *malloc_node_info(struct silofs_alloc *alloc, size_t n)
{
	return silofs_memalloc(alloc, n, SILOFS_ALLOCF_BZERO);
}

static void mfree_node_info(struct silofs_alloc *alloc, void *p, size_t n)
{
	silofs_memfree(alloc, p, n, 0);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t vsize_of(const struct silofs_vaddr *vaddr)
{
	return silofs_vtype_size(vaddr->vtype);
}

static struct silofs_vnode_info *
vni_unconst(const struct silofs_vnode_info *vni)
{
	return silofs_unconst(vni);
}

static void vni_debug_check(const struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	silofs_assert_eq(vni->vn_magic, SILOFS_VI_MAGIC);
}

static void
vni_init(struct silofs_vnode_info *vni, const struct silofs_vaddr *vaddr)
{
	silofs_ni_init(&vni->vn_ni, vsize_of(vaddr));
	vni->vn_flags = 0;

	silofs_vaddr_assign(&vni->vn_vaddr, vaddr);
	silofs_paddr_reset(&vni->vn_curr_paddr);
	vni->vn_asyncwr        = 0;
	vni->vn_use_pn_vnis_dq = false;
	vni->vn_magic          = SILOFS_VI_MAGIC;

	vni->isevictable_fn = silofs_vni_isevictable;
}

static void vni_fini(struct silofs_vnode_info *vni)
{
	vni_debug_check(vni);
	silofs_assert_eq(vni->vn_asyncwr, 0);

	silofs_ni_fini(&vni->vn_ni);
	silofs_vaddr_reset(&vni->vn_vaddr);
	silofs_paddr_reset(&vni->vn_curr_paddr);
	vni->vn_magic = UINT64_MAX;
}

static struct silofs_vnode_info *vni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_vnode_info *vni = nullptr;

	if (likely(ni != nullptr)) {
		vni = container_of(ni, struct silofs_vnode_info, vn_ni);
	}
	return vni_unconst(vni);
}

static struct silofs_vnode_info *
vni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	return vni_from_ni(silofs_ni_from_hmqe(hmqe));
}

static struct silofs_vnode_info *vni_from_dqe(const struct silofs_dq_elem *dqe)
{
	return vni_from_ni(silofs_ni_from_dqe(dqe));
}

struct silofs_vnode_info *silofs_vni_from_dqe(const struct silofs_dq_elem *dqe)
{
	return vni_from_dqe(dqe);
}

struct silofs_vnode_info * //
silofs_vni_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	return vni_from_hmqe(hmqe);
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
	return silofs_vtype_isdata(vni_vtype(vni));
}

struct silofs_lview *silofs_vni_lview(const struct silofs_vnode_info *vni)
{
	return vni->vn_ni.view.lview;
}

struct silofs_lview *silofs_vni_lviewx(const struct silofs_vnode_info *vni)
{
	silofs_assume_not_null(vni);
	return vni->vn_ni.viewx.lview;
}

static int
vni_attach_lview(struct silofs_vnode_info *vni, struct silofs_alloc *alloc)
{
	int err;

	err = silofs_ni_attach_view(&vni->vn_ni, alloc, !vni_isdata(vni));
	return_if_err(err);

	silofs_lview_setup(vni->vn_ni.view.lview, vni_vtype(vni));
	return 0;
}

static void
vni_detach_lview(struct silofs_vnode_info *vni, struct silofs_alloc *alloc)
{
	silofs_ni_detach_view(&vni->vn_ni, alloc, false);
}

size_t silofs_vni_refcnt(const struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	return silofs_ni_refcnt(&vni->vn_ni);
}

void silofs_vni_incref(struct silofs_vnode_info *vni)
{
	if (likely(vni != nullptr)) {
		silofs_ni_incref(&vni->vn_ni);
	}
}

void silofs_vni_decref(struct silofs_vnode_info *vni)
{
	if (likely(vni != nullptr)) {
		silofs_ni_decref(&vni->vn_ni);
	}
}

static const struct silofs_dq_elem *
vni_dqe(const struct silofs_vnode_info *vni)
{
	return &vni->vn_ni.dqe;
}

static struct silofs_dq_elem *vni_mut_dqe(struct silofs_vnode_info *vni)
{
	return &vni->vn_ni.dqe;
}

static bool vni_isdirty(const struct silofs_vnode_info *vni)
{
	return silofs_dqe_isdirty(vni_dqe(vni));
}

static void vni_setdirty(struct silofs_vnode_info *vni)
{
	if (!vni_isdirty(vni)) {
		silofs_dqe_setdirty(vni_mut_dqe(vni));
	}
}

static void vni_cleardirty(struct silofs_vnode_info *vni)
{
	if (vni_isdirty(vni)) {
		silofs_dqe_cleardirty(vni_mut_dqe(vni));
	}
}

static void vni_set_dq(struct silofs_vnode_info *vni, struct silofs_dirtyq *dq)
{
	struct silofs_dq_elem *dqe = vni_mut_dqe(vni);

	silofs_dqe_set_dirtyq(dqe, dq);
}

void silofs_vni_set_dq(struct silofs_vnode_info *vni, struct silofs_dirtyq *dq)
{
	vni_set_dq(vni, dq);
}

bool silofs_vni_isdirty(const struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	return vni_isdirty(vni);
}

void silofs_vni_setdirty(struct silofs_vnode_info *vni,
                         struct silofs_inode_info *ii)
{
	silofs_assert_not_null(vni);
	silofs_unused(ii);

	vni_setdirty(vni);
}

void silofs_vni_cleardirty(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);

	vni_cleardirty(vni);
}

static bool
vni_has_vtype(const struct silofs_vnode_info *vni, enum silofs_vtype vtype)
{
	return silofs_vni_vtype(vni) == vtype;
}

static bool vni_hasflags(const struct silofs_vnode_info *vni,
                         const enum silofs_vni_flags mask)
{
	return ((vni->vn_flags & mask) == mask);
}

static bool vni_ispinned(const struct silofs_vnode_info *vni)
{
	return vni_hasflags(vni, SILOFS_VNF_PINNED) ||
	       silofs_ni_ispinned(&vni->vn_ni);
}

bool silofs_vni_isevictable(const struct silofs_vnode_info *vni)
{
	return !vni_ispinned(vni);
}

bool silofs_vni_need_recheck(const struct silofs_vnode_info *vni)
{
	const enum silofs_vni_flags flags = vni->vn_flags;
	const enum silofs_vni_flags mask  = SILOFS_VNF_RECHECK;

	return (flags & mask) != mask;
}

void silofs_vni_set_rechecked(struct silofs_vnode_info *vni)
{
	vni->vn_flags |= SILOFS_VNF_RECHECK;
}

void silofs_vni_remove_from(struct silofs_vnode_info *vni,
                            struct silofs_hmapq *hmapq)
{
	silofs_hmapq_remove(hmapq, &vni->vn_ni.hmqe);
}

int silofs_verify_lview_of(const struct silofs_vnode_info *vni)
{
	const struct silofs_lview *lview = silofs_vni_lview(vni);

	return silofs_lview_verify(lview, vni_vtype(vni));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_vnode_info *sbi2_to_vni(struct silofs_sbnode_info2 *sui)
{
	return likely(sui != nullptr) ? &sui->sbn_vni : nullptr;
}

static struct silofs_sbnode_info2 *sbi2_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_sbnode_info2, sbn_vni);
}

static void
sbi2_init(struct silofs_sbnode_info2 *sui, const struct silofs_vaddr *vaddr)
{
	vni_init(&sui->sbn_vni, vaddr);
}

static void sbi2_fini(struct silofs_sbnode_info2 *sui)
{
	vni_fini(&sui->sbn_vni);
}

static struct silofs_sbnode_info2 *sbi2_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sbnode_info2 *sui;

	sui = malloc_node_info(alloc, sizeof(*sui));
	return sui;
}

static void
sbi2_free(struct silofs_sbnode_info2 *sui, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, sui, sizeof(*sui));
}

static struct silofs_sbnode_info2 *
sbi2_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_sbnode_info2 *sui;

	sui = sbi2_malloc(alloc);
	if (sui != nullptr) {
		sbi2_init(sui, vaddr);
	}
	return sui;
}

static void
sbi2_fini_free(struct silofs_sbnode_info2 *sui, struct silofs_alloc *alloc)
{
	sbi2_fini(sui);
	sbi2_free(sui, alloc);
}

static int
sbi2_attach_lview(struct silofs_sbnode_info2 *sui, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&sui->sbn_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&sui->sbn_vni);
		sui->sbn = &lview->u.sbn;
	}
	return err;
}

static void
sbi2_detach_lview(struct silofs_sbnode_info2 *sui, struct silofs_alloc *alloc)
{
	vni_detach_lview(&sui->sbn_vni, alloc);
	sui->sbn = nullptr;
}

static struct silofs_sbnode_info2 *
sbi2_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_sbnode_info2 *sui;
	int err;

	sui = sbi2_malloc_init(alloc, vaddr);
	if (sui == nullptr) {
		return nullptr;
	}
	err = sbi2_attach_lview(sui, alloc);
	if (err) {
		sbi2_fini_free(sui, alloc);
		return nullptr;
	}
	return sui;
}

static void
sbi2_del(struct silofs_sbnode_info2 *sui, struct silofs_alloc *alloc)
{
	sbi2_detach_lview(sui, alloc);
	sbi2_fini_free(sui, alloc);
}

struct silofs_sbnode_info2 * //
silofs_sbi2_from_vni(struct silofs_vnode_info *vni)
{
	return sbi2_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *spi_to_vni(struct silofs_spnode_info2 *spi)
{
	return likely(spi != nullptr) ? &spi->spn_vni : nullptr;
}

static struct silofs_spnode_info2 *spi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_spnode_info2, spn_vni);
}

static void
spi_init(struct silofs_spnode_info2 *spi, const struct silofs_vaddr *vaddr)
{
	vni_init(&spi->spn_vni, vaddr);
	spi->spn_nused_ref = 0;
}

static void spi_fini(struct silofs_spnode_info2 *spi)
{
	vni_fini(&spi->spn_vni);
	spi->spn_nused_ref = UINT_MAX;
}

static struct silofs_spnode_info2 *spi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spnode_info2 *spi;

	spi = malloc_node_info(alloc, sizeof(*spi));
	return spi;
}

static void
spi_free(struct silofs_spnode_info2 *spi, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, spi, sizeof(*spi));
}

static struct silofs_spnode_info2 *
spi_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_spnode_info2 *spi;

	spi = spi_malloc(alloc);
	if (spi != nullptr) {
		spi_init(spi, vaddr);
	}
	return spi;
}

static void
spi_fini_free(struct silofs_spnode_info2 *spi, struct silofs_alloc *alloc)
{
	spi_fini(spi);
	spi_free(spi, alloc);
}

static int
spi_attach_lview(struct silofs_spnode_info2 *spi, struct silofs_alloc *alloc)
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
spi_detach_lview(struct silofs_spnode_info2 *spi, struct silofs_alloc *alloc)
{
	vni_detach_lview(&spi->spn_vni, alloc);
	spi->spn = nullptr;
}

static struct silofs_spnode_info2 *
spi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_spnode_info2 *spi;
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

static void
spi_del(struct silofs_spnode_info2 *spi, struct silofs_alloc *alloc)
{
	spi_detach_lview(spi, alloc);
	spi_fini_free(spi, alloc);
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

	ii = malloc_node_info(alloc, sizeof(*ii));
	return ii;
}

static void ii_free(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, ii, sizeof(*ii));
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
silofs_ii_from_vni(const struct silofs_vnode_info *vni)
{
	struct silofs_inode_info *ii = nullptr;

	if (likely(vni != nullptr)) {
		ii = ii_from_vni(vni_unconst(vni));
	}
	return ii;
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

	xai = malloc_node_info(alloc, sizeof(*xai));
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
	mfree_node_info(alloc, xai, sizeof(*xai));
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

static struct silofs_vnode_info *svi_to_vni(struct silofs_symval_info *svi)
{
	return likely(svi != nullptr) ? &svi->svn_vni : nullptr;
}

static struct silofs_symval_info *svi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_symval_info, svn_vni);
}

static void
svi_init(struct silofs_symval_info *svi, const struct silofs_vaddr *vaddr)
{
	vni_init(&svi->svn_vni, vaddr);
}

static void svi_fini(struct silofs_symval_info *svi)
{
	vni_fini(&svi->svn_vni);
	svi->svn = nullptr;
}

static struct silofs_symval_info *svi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_symval_info *syi;

	syi = malloc_node_info(alloc, sizeof(*syi));
	return syi;
}

static void
svi_free(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, svi, sizeof(*svi));
}

static void
svi_fini_free(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	svi_fini(svi);
	svi_free(svi, alloc);
}

static struct silofs_symval_info *
svi_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_symval_info *svi;

	svi = svi_malloc(alloc);
	if (svi != nullptr) {
		svi_init(svi, vaddr);
	}
	return svi;
}

static int
svi_attach_lview(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&svi->svn_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&svi->svn_vni);
		svi->svn = &lview->u.svn;
	}
	return err;
}

static void
svi_detach_lview(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	vni_detach_lview(&svi->svn_vni, alloc);
	svi->svn = nullptr;
}

static struct silofs_symval_info *
svi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_symval_info *svi;
	int err;

	svi = svi_malloc_init(alloc, vaddr);
	if (svi == nullptr) {
		return nullptr;
	}
	err = svi_attach_lview(svi, alloc);
	if (err) {
		svi_fini_free(svi, alloc);
		return nullptr;
	}
	return svi;
}

static void svi_del(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	svi_detach_lview(svi, alloc);
	svi_fini_free(svi, alloc);
}

struct silofs_symval_info *silofs_svi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_symval_info, svn_vni);
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

	dni = malloc_node_info(alloc, sizeof(*dni));
	return dni;
}

static void
dni_free(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, dni, sizeof(*dni));
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

struct silofs_dtnode_info *silofs_dti_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	silofs_assert(vni_has_vtype(vni, SILOFS_VTYPE_DTNODE));
	return dni_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fti_to_vni(struct silofs_ftnode_info *fti)
{
	return likely(fti != nullptr) ? &fti->ftn_vni : nullptr;
}

static struct silofs_ftnode_info *fti_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_ftnode_info, ftn_vni);
}

static void
fti_init(struct silofs_ftnode_info *fti, const struct silofs_vaddr *vaddr)
{
	vni_init(&fti->ftn_vni, vaddr);
}

static void fti_fini(struct silofs_ftnode_info *fti)
{
	vni_fini(&fti->ftn_vni);
	fti->ftn = nullptr;
}

static struct silofs_ftnode_info *fti_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ftnode_info *fti;

	fti = malloc_node_info(alloc, sizeof(*fti));
	return fti;
}

static void
fti_free(struct silofs_ftnode_info *fti, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, fti, sizeof(*fti));
}

static struct silofs_ftnode_info *
fti_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_ftnode_info *fti;

	fti = fti_malloc(alloc);
	if (fti != nullptr) {
		fti_init(fti, vaddr);
	}
	return fti;
}

static void
fti_fini_free(struct silofs_ftnode_info *fti, struct silofs_alloc *alloc)
{
	fti_fini(fti);
	fti_free(fti, alloc);
}

static int
fti_attach_lview(struct silofs_ftnode_info *fti, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = vni_attach_lview(&fti->ftn_vni, alloc);
	if (!err) {
		lview    = silofs_vni_lview(&fti->ftn_vni);
		fti->ftn = &lview->u.ftn;
	}
	return err;
}

static void
fti_detach_lview(struct silofs_ftnode_info *fti, struct silofs_alloc *alloc)
{
	vni_detach_lview(&fti->ftn_vni, alloc);
	fti->ftn = nullptr;
}

static struct silofs_ftnode_info *
fti_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_ftnode_info *fti;
	int err;

	fti = fti_malloc_init(alloc, vaddr);
	if (fti == nullptr) {
		return nullptr;
	}
	err = fti_attach_lview(fti, alloc);
	if (err) {
		fti_fini_free(fti, alloc);
		return nullptr;
	}
	return fti;
}

static void fti_del(struct silofs_ftnode_info *fti, struct silofs_alloc *alloc)
{
	fti_detach_lview(fti, alloc);
	fti_fini(fti);
	fti_free(fti, alloc);
}

struct silofs_ftnode_info *silofs_fti_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return fti_from_vni(vni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *fdi_to_vni(struct silofs_fdnode_info *fdi)
{
	return likely(fdi != nullptr) ? &fdi->fdn_vni : nullptr;
}

static struct silofs_fdnode_info *fdi_from_vni(struct silofs_vnode_info *vni)
{
	return mut_container_of(vni, struct silofs_fdnode_info, fdn_vni);
}

static void
fdi_init(struct silofs_fdnode_info *fdi, const struct silofs_vaddr *vaddr)
{
	vni_init(&fdi->fdn_vni, vaddr);
}

static void fdi_fini(struct silofs_fdnode_info *fdi)
{
	vni_fini(&fdi->fdn_vni);
	fdi->fdn.dn64 = nullptr;
}

static struct silofs_fdnode_info *fdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_fdnode_info *fdi;

	fdi = malloc_node_info(alloc, sizeof(*fdi));
	return fdi;
}

static void
fdi_free(struct silofs_fdnode_info *fdi, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, fdi, sizeof(*fdi));
}

static struct silofs_fdnode_info *
fdi_malloc_init(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_fdnode_info *fdi;

	fdi = fdi_malloc(alloc);
	if (fdi != nullptr) {
		fdi_init(fdi, vaddr);
	}
	return fdi;
}

static void
fdi_fini_free(struct silofs_fdnode_info *fdi, struct silofs_alloc *alloc)
{
	fdi_fini(fdi);
	fdi_free(fdi, alloc);
}

static int
fdi_attach_lview(struct silofs_fdnode_info *fdi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview = nullptr;
	int err;

	err = vni_attach_lview(&fdi->fdn_vni, alloc);
	if (!err) {
		const enum silofs_vtype vtype = vni_vtype(&fdi->fdn_vni);

		lview = silofs_vni_lview(&fdi->fdn_vni);
		if (vtype == SILOFS_VTYPE_DATA1K) {
			fdi->fdn.dn1 = &lview->u.dn1;
		} else if (vtype == SILOFS_VTYPE_DATA4K) {
			fdi->fdn.dn4 = &lview->u.dn4;
		} else if (vtype == SILOFS_VTYPE_DATA64K) {
			fdi->fdn.dn64 = &lview->u.dn64;
		} else {
			silofs_panic("not a data vtype: %d", (int)vtype);
		}
	}
	return err;
}

static void
fdi_detach_lview(struct silofs_fdnode_info *fdi, struct silofs_alloc *alloc)
{
	vni_detach_lview(&fdi->fdn_vni, alloc);
}

static struct silofs_fdnode_info *
fdi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_fdnode_info *fdi;
	int err;

	fdi = fdi_malloc_init(alloc, vaddr);
	if (fdi == nullptr) {
		return nullptr;
	}
	err = fdi_attach_lview(fdi, alloc);
	if (err) {
		fdi_fini_free(fdi, alloc);
		return nullptr;
	}
	return fdi;
}

static void fdi_del(struct silofs_fdnode_info *fdi, struct silofs_alloc *alloc)
{
	fdi_detach_lview(fdi, alloc);
	fdi_fini_free(fdi, alloc);
}

struct silofs_fdnode_info *silofs_fdi_from_vni(struct silofs_vnode_info *vni)
{
	silofs_assert_not_null(vni);
	return fdi_from_vni(vni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vni = nullptr;
	const enum silofs_vtype vtype = vaddr->vtype;

	switch (vtype) {
	case SILOFS_VTYPE_SUPER2:
		vni = sbi2_to_vni(sbi2_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_SPNODE2:
		vni = spi_to_vni(spi_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_INODE:
		vni = ii_to_vni(ii_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_XANODE:
		vni = xai_to_vni(xai_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_SYMVAL:
		vni = svi_to_vni(svi_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_DTNODE:
		vni = dni_to_vni(dni_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_FTNODE:
		vni = fti_to_vni(fti_new(alloc, vaddr));
		break;
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		vni = fdi_to_vni(fdi_new(alloc, vaddr));
		break;
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
	case SILOFS_VTYPE_SUPER2:
		sbi2_del(sbi2_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_SPNODE2:
		spi_del(spi_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_INODE:
		ii_del(ii_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_XANODE:
		xai_del(xai_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_SYMVAL:
		svi_del(svi_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_DTNODE:
		dni_del(dni_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_FTNODE:
		fti_del(fti_from_vni(vni), alloc);
		break;
	case SILOFS_VTYPE_DATA1K:
	case SILOFS_VTYPE_DATA4K:
	case SILOFS_VTYPE_DATA64K:
		fdi_del(fdi_from_vni(vni), alloc);
		break;
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
