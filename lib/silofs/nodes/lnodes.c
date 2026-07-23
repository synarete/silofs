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

#include <silofs/infra.h>
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

static size_t vsize_of(const struct silofs_laddr *laddr)
{
	return silofs_ltype_size(laddr->ltype);
}

static struct silofs_lnode_info *
lni_unconst(const struct silofs_lnode_info *lni)
{
	return silofs_unconst(lni);
}

static void lni_debug_check(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);
	silofs_assert_eq(lni->ln_magic, SILOFS_VI_MAGIC);
}

static void
lni_init(struct silofs_lnode_info *lni, const struct silofs_laddr *laddr)
{
	silofs_ni_init(&lni->ln_ni, vsize_of(laddr));
	silofs_laddr_assign(&lni->ln_laddr, laddr);
	silofs_paddr_reset(&lni->ln_curr_paddr);
	lni->ln_asyncwr = 0;
	lni->ln_magic   = SILOFS_VI_MAGIC;
}

static void lni_fini(struct silofs_lnode_info *lni)
{
	lni_debug_check(lni);
	silofs_assert_eq(lni->ln_asyncwr, 0);

	silofs_ni_fini(&lni->ln_ni);
	silofs_laddr_reset(&lni->ln_laddr);
	silofs_paddr_reset(&lni->ln_curr_paddr);
	lni->ln_magic = UINT64_MAX;
}

struct silofs_lnode_info *silofs_lni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_lnode_info *lni = nullptr;

	silofs_assume_not_null(ni);

	lni = container_of(ni, struct silofs_lnode_info, ln_ni);
	return lni_unconst(lni);
}

static struct silofs_lnode_info *
lni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	struct silofs_lnode_info *lni = nullptr;

	if (likely(hmqe != nullptr)) {
		lni = silofs_lni_from_ni(silofs_ni_from_hmqe(hmqe));
	}
	return lni;
}

static struct silofs_lnode_info *lni_from_dqe(const struct silofs_dq_elem *dqe)
{
	struct silofs_lnode_info *lni = nullptr;

	if (likely(dqe != nullptr)) {
		lni = silofs_lni_from_ni(silofs_ni_from_dqe(dqe));
	}
	return lni;
}

struct silofs_lnode_info *silofs_lni_from_dqe(const struct silofs_dq_elem *dqe)
{
	return lni_from_dqe(dqe);
}

struct silofs_lnode_info * //
silofs_lni_from_hmqe(struct silofs_hmapq_elem *hmqe)
{
	return lni_from_hmqe(hmqe);
}

const struct silofs_laddr *
silofs_lni_laddr(const struct silofs_lnode_info *lni)
{
	return &lni->ln_laddr;
}

static enum silofs_ltype lni_ltype(const struct silofs_lnode_info *lni)
{
	const struct silofs_laddr *laddr = silofs_lni_laddr(lni);

	return laddr->ltype;
}

enum silofs_ltype silofs_lni_ltype(const struct silofs_lnode_info *lni)
{
	silofs_assume_not_null(lni);
	return lni_ltype(lni);
}

static bool lni_isdata(const struct silofs_lnode_info *lni)
{
	return silofs_ltype_isdata(lni_ltype(lni));
}

struct silofs_lview *silofs_lni_lview(const struct silofs_lnode_info *lni)
{
	return lni->ln_ni.view.lview;
}

struct silofs_lview *silofs_lni_lviewx(const struct silofs_lnode_info *lni)
{
	silofs_assume_not_null(lni);
	return lni->ln_ni.viewx.lview;
}

static int
lni_attach_lview(struct silofs_lnode_info *lni, struct silofs_alloc *alloc)
{
	int err;

	err = silofs_ni_attach_view(&lni->ln_ni, alloc, !lni_isdata(lni));
	return_if_err(err);

	silofs_lview_setup(lni->ln_ni.view.lview, lni_ltype(lni));
	return 0;
}

static void
lni_detach_lview(struct silofs_lnode_info *lni, struct silofs_alloc *alloc)
{
	silofs_ni_detach_view(&lni->ln_ni, alloc, false);
}

size_t silofs_lni_refcnt(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	return silofs_ni_refcnt(&lni->ln_ni);
}

void silofs_lni_incref(struct silofs_lnode_info *lni)
{
	if (likely(lni != nullptr)) {
		silofs_ni_incref(&lni->ln_ni);
	}
}

void silofs_lni_decref(struct silofs_lnode_info *lni)
{
	if (likely(lni != nullptr)) {
		silofs_ni_decref(&lni->ln_ni);
	}
}

void silofs_lni_set_dq(struct silofs_lnode_info *lni, struct silofs_dirtyq *dq)
{
	silofs_ni_set_dq(&lni->ln_ni, dq);
}

bool silofs_lni_isdirty(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	return silofs_ni_isdirty(&lni->ln_ni);
}

void silofs_lni_setdirty(struct silofs_lnode_info *lni,
                         struct silofs_inode_info *ii)
{
	silofs_assert_not_null(lni);
	silofs_unused(ii);

	silofs_ni_setdirty(&lni->ln_ni);
}

void silofs_lni_cleardirty(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);

	silofs_ni_cleardirty(&lni->ln_ni);
}

static bool
lni_has_ltype(const struct silofs_lnode_info *lni, enum silofs_ltype ltype)
{
	return silofs_lni_ltype(lni) == ltype;
}

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni)
{
	return silofs_ni_isevictable(&lni->ln_ni);
}

bool silofs_lni_need_recheck(const struct silofs_lnode_info *lni)
{
	return !silofs_ni_testf(&lni->ln_ni, SILOFS_NIF_RECHECKED);
}

void silofs_lni_set_rechecked(struct silofs_lnode_info *lni)
{
	silofs_ni_setf(&lni->ln_ni, SILOFS_NIF_RECHECKED);
}

void silofs_lni_remove_from(struct silofs_lnode_info *lni,
                            struct silofs_hmapq *hmapq)
{
	silofs_hmapq_remove(hmapq, &lni->ln_ni.hmqe);
}

int silofs_verify_lview_of(const struct silofs_lnode_info *lni)
{
	const struct silofs_lview *lview = silofs_lni_lview(lni);

	return silofs_lview_verify(lview, lni_ltype(lni));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_lnode_info *sbi_to_lni(struct silofs_sbnode_info *sui)
{
	return likely(sui != nullptr) ? &sui->sbn_lni : nullptr;
}

static struct silofs_sbnode_info *sbi_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_sbnode_info, sbn_lni);
}

static void
sbi_init(struct silofs_sbnode_info *sui, const struct silofs_laddr *laddr)
{
	lni_init(&sui->sbn_lni, laddr);
}

static void sbi_fini(struct silofs_sbnode_info *sui)
{
	lni_fini(&sui->sbn_lni);
}

static struct silofs_sbnode_info *sbi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sbnode_info *sui;

	sui = malloc_node_info(alloc, sizeof(*sui));
	return sui;
}

static void
sbi_free(struct silofs_sbnode_info *sui, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, sui, sizeof(*sui));
}

static struct silofs_sbnode_info *
sbi_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_sbnode_info *sui;

	sui = sbi_malloc(alloc);
	if (sui != nullptr) {
		sbi_init(sui, laddr);
	}
	return sui;
}

static void
sbi_fini_free(struct silofs_sbnode_info *sui, struct silofs_alloc *alloc)
{
	sbi_fini(sui);
	sbi_free(sui, alloc);
}

static int
sbi_attach_lview(struct silofs_sbnode_info *sui, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = lni_attach_lview(&sui->sbn_lni, alloc);
	if (!err) {
		lview    = silofs_lni_lview(&sui->sbn_lni);
		sui->sbn = &lview->u.sbn;
	}
	return err;
}

static void
sbi_detach_lview(struct silofs_sbnode_info *sui, struct silofs_alloc *alloc)
{
	lni_detach_lview(&sui->sbn_lni, alloc);
	sui->sbn = nullptr;
}

static struct silofs_sbnode_info *
sbi_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_sbnode_info *sui;
	int err;

	sui = sbi_malloc_init(alloc, laddr);
	if (sui == nullptr) {
		return nullptr;
	}
	err = sbi_attach_lview(sui, alloc);
	if (err) {
		sbi_fini_free(sui, alloc);
		return nullptr;
	}
	return sui;
}

static void sbi_del(struct silofs_sbnode_info *sui, struct silofs_alloc *alloc)
{
	sbi_detach_lview(sui, alloc);
	sbi_fini_free(sui, alloc);
}

struct silofs_sbnode_info * //
silofs_sbi_from_lni(struct silofs_lnode_info *lni)
{
	return sbi_from_lni(lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *spi_to_lni(struct silofs_spnode_info *spi)
{
	return likely(spi != nullptr) ? &spi->spn_lni : nullptr;
}

static struct silofs_spnode_info *spi_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_spnode_info, spn_lni);
}

static void
spi_init(struct silofs_spnode_info *spi, const struct silofs_laddr *laddr)
{
	lni_init(&spi->spn_lni, laddr);
	spi->spn_nused_ref = 0;
}

static void spi_fini(struct silofs_spnode_info *spi)
{
	lni_fini(&spi->spn_lni);
	spi->spn_nused_ref = UINT_MAX;
}

static struct silofs_spnode_info *spi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spnode_info *spi;

	spi = malloc_node_info(alloc, sizeof(*spi));
	return spi;
}

static void
spi_free(struct silofs_spnode_info *spi, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, spi, sizeof(*spi));
}

static struct silofs_spnode_info *
spi_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_spnode_info *spi;

	spi = spi_malloc(alloc);
	if (spi != nullptr) {
		spi_init(spi, laddr);
	}
	return spi;
}

static void
spi_fini_free(struct silofs_spnode_info *spi, struct silofs_alloc *alloc)
{
	spi_fini(spi);
	spi_free(spi, alloc);
}

static int
spi_attach_lview(struct silofs_spnode_info *spi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = lni_attach_lview(&spi->spn_lni, alloc);
	if (!err) {
		lview    = silofs_lni_lview(&spi->spn_lni);
		spi->spn = &lview->u.spn;
	}
	return err;
}

static void
spi_detach_lview(struct silofs_spnode_info *spi, struct silofs_alloc *alloc)
{
	lni_detach_lview(&spi->spn_lni, alloc);
	spi->spn = nullptr;
}

static struct silofs_spnode_info *
spi_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_spnode_info *spi;
	int err;

	spi = spi_malloc_init(alloc, laddr);
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

static void spi_del(struct silofs_spnode_info *spi, struct silofs_alloc *alloc)
{
	spi_detach_lview(spi, alloc);
	spi_fini_free(spi, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *ii_to_lni(struct silofs_inode_info *ii)
{
	return likely(ii != nullptr) ? &ii->i_lni : nullptr;
}

static struct silofs_inode_info *ii_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_inode_info, i_lni);
}

static void
ii_init(struct silofs_inode_info *ii, const struct silofs_laddr *laddr)
{
	lni_init(&ii->i_lni, laddr);
	ii->inode         = nullptr;
	ii->i_looseq_next = nullptr;
	ii->i_ino         = SILOFS_INO_NULL;
	ii->i_nopen       = 0;
	ii->i_nlookup     = 0;
	ii->i_in_looseq   = false;
}

static void ii_fini(struct silofs_inode_info *ii)
{
	silofs_assert(!ii->i_in_looseq);
	silofs_assert_null(ii->i_looseq_next);

	lni_fini(&ii->i_lni);
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
ii_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_inode_info *ii;

	ii = ii_malloc(alloc);
	if (ii != nullptr) {
		ii_init(ii, laddr);
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

	err = lni_attach_lview(&ii->i_lni, alloc);
	if (!err) {
		lview     = silofs_lni_lview(&ii->i_lni);
		ii->inode = &lview->u.in;
	}
	return err;
}

static void
ii_detach_lview(struct silofs_inode_info *ii, struct silofs_alloc *alloc)
{
	lni_detach_lview(&ii->i_lni, alloc);
	ii->inode = nullptr;
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_inode_info *ii;
	int err;

	ii = ii_malloc_init(alloc, laddr);
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
	silofs_assert_ge(ii->i_nopen, 0);

	lni_detach_lview(&ii->i_lni, alloc);
	ii_detach_lview(ii, alloc);
	ii_fini_free(ii, alloc);
}

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni)
{
	struct silofs_inode_info *ii = nullptr;

	if (likely(lni != nullptr)) {
		ii = ii_from_lni(lni_unconst(lni));
	}
	return ii;
}

struct silofs_inode_info *silofs_ii_from_dqe(struct silofs_dq_elem *dqe)
{
	return silofs_ii_from_lni(silofs_lni_from_dqe(dqe));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *xai_to_lni(struct silofs_xanode_info *xai)
{
	return likely(xai != nullptr) ? &xai->xan_lni : nullptr;
}

static struct silofs_xanode_info *xai_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_xanode_info, xan_lni);
}

static void
xai_init(struct silofs_xanode_info *xai, const struct silofs_laddr *laddr)
{
	lni_init(&xai->xan_lni, laddr);
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	lni_fini(&xai->xan_lni);
	xai->xan = nullptr;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc *alloc)
{
	struct silofs_xanode_info *xai;

	xai = malloc_node_info(alloc, sizeof(*xai));
	return xai;
}

static struct silofs_xanode_info *
xai_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_xanode_info *xai;

	xai = xai_malloc(alloc);
	if (xai != nullptr) {
		xai_init(xai, laddr);
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

	err = lni_attach_lview(&xai->xan_lni, alloc);
	if (!err) {
		lview    = silofs_lni_lview(&xai->xan_lni);
		xai->xan = &lview->u.xan;
	}
	return err;
}

static void
xai_unbind_lview(struct silofs_xanode_info *xai, struct silofs_alloc *alloc)
{
	lni_detach_lview(&xai->xan_lni, alloc);
	xai->xan = nullptr;
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_xanode_info *xai;
	int err;

	xai = xai_malloc_init(alloc, laddr);
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

struct silofs_xanode_info *silofs_xai_from_lni(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);
	return xai_from_lni(lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *svi_to_lni(struct silofs_symval_info *svi)
{
	return likely(svi != nullptr) ? &svi->svn_lni : nullptr;
}

static struct silofs_symval_info *svi_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_symval_info, svn_lni);
}

static void
svi_init(struct silofs_symval_info *svi, const struct silofs_laddr *laddr)
{
	lni_init(&svi->svn_lni, laddr);
}

static void svi_fini(struct silofs_symval_info *svi)
{
	lni_fini(&svi->svn_lni);
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
svi_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_symval_info *svi;

	svi = svi_malloc(alloc);
	if (svi != nullptr) {
		svi_init(svi, laddr);
	}
	return svi;
}

static int
svi_attach_lview(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview;
	int err;

	err = lni_attach_lview(&svi->svn_lni, alloc);
	if (!err) {
		lview    = silofs_lni_lview(&svi->svn_lni);
		svi->svn = &lview->u.svn;
	}
	return err;
}

static void
svi_detach_lview(struct silofs_symval_info *svi, struct silofs_alloc *alloc)
{
	lni_detach_lview(&svi->svn_lni, alloc);
	svi->svn = nullptr;
}

static struct silofs_symval_info *
svi_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_symval_info *svi;
	int err;

	svi = svi_malloc_init(alloc, laddr);
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

struct silofs_symval_info *silofs_svi_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_symval_info, svn_lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *dni_to_lni(struct silofs_dtnode_info *dni)
{
	return likely(dni != nullptr) ? &dni->dtn_lni : nullptr;
}

static struct silofs_dtnode_info *dni_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_dtnode_info, dtn_lni);
}

static void
dni_init(struct silofs_dtnode_info *dni, const struct silofs_laddr *laddr)
{
	lni_init(&dni->dtn_lni, laddr);
}

static void dni_fini(struct silofs_dtnode_info *dni)
{
	lni_fini(&dni->dtn_lni);
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
dni_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_dtnode_info *dni;

	dni = dni_malloc(alloc);
	if (dni != nullptr) {
		dni_init(dni, laddr);
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

	err = lni_attach_lview(&dni->dtn_lni, alloc);
	if (!err) {
		lview    = silofs_lni_lview(&dni->dtn_lni);
		dni->dtn = &lview->u.dtn;
	}
	return err;
}

static void
dni_detach_lview(struct silofs_dtnode_info *dni, struct silofs_alloc *alloc)
{
	lni_detach_lview(&dni->dtn_lni, alloc);
	dni->dtn = nullptr;
}

static struct silofs_dtnode_info *
dni_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_dtnode_info *dni;
	int err;

	dni = dni_malloc_init(alloc, laddr);
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

struct silofs_dtnode_info *silofs_dti_from_lni(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);
	silofs_assert(lni_has_ltype(lni, SILOFS_LTYPE_DTNODE));
	return dni_from_lni(lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *fti_to_lni(struct silofs_ftnode_info *fti)
{
	return likely(fti != nullptr) ? &fti->ftn_lni : nullptr;
}

static struct silofs_ftnode_info *fti_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_ftnode_info, ftn_lni);
}

static void
fti_init(struct silofs_ftnode_info *fti, const struct silofs_laddr *laddr)
{
	lni_init(&fti->ftn_lni, laddr);
}

static void fti_fini(struct silofs_ftnode_info *fti)
{
	lni_fini(&fti->ftn_lni);
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
fti_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_ftnode_info *fti;

	fti = fti_malloc(alloc);
	if (fti != nullptr) {
		fti_init(fti, laddr);
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

	err = lni_attach_lview(&fti->ftn_lni, alloc);
	if (!err) {
		lview    = silofs_lni_lview(&fti->ftn_lni);
		fti->ftn = &lview->u.ftn;
	}
	return err;
}

static void
fti_detach_lview(struct silofs_ftnode_info *fti, struct silofs_alloc *alloc)
{
	lni_detach_lview(&fti->ftn_lni, alloc);
	fti->ftn = nullptr;
}

static struct silofs_ftnode_info *
fti_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_ftnode_info *fti;
	int err;

	fti = fti_malloc_init(alloc, laddr);
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

struct silofs_ftnode_info *silofs_fti_from_lni(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);
	return fti_from_lni(lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lnode_info *fli_to_lni(struct silofs_flnode_info *fli)
{
	return likely(fli != nullptr) ? &fli->fln_lni : nullptr;
}

static struct silofs_flnode_info *fli_from_lni(struct silofs_lnode_info *lni)
{
	return mut_container_of(lni, struct silofs_flnode_info, fln_lni);
}

static void
fli_init(struct silofs_flnode_info *fli, const struct silofs_laddr *laddr)
{
	lni_init(&fli->fln_lni, laddr);
}

static void fli_fini(struct silofs_flnode_info *fli)
{
	lni_fini(&fli->fln_lni);
	fli->fln.dn64 = nullptr;
}

static struct silofs_flnode_info *fli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_flnode_info *fli;

	fli = malloc_node_info(alloc, sizeof(*fli));
	return fli;
}

static void
fli_free(struct silofs_flnode_info *fli, struct silofs_alloc *alloc)
{
	mfree_node_info(alloc, fli, sizeof(*fli));
}

static struct silofs_flnode_info *
fli_malloc_init(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_flnode_info *fli;

	fli = fli_malloc(alloc);
	if (fli != nullptr) {
		fli_init(fli, laddr);
	}
	return fli;
}

static void
fli_fini_free(struct silofs_flnode_info *fli, struct silofs_alloc *alloc)
{
	fli_fini(fli);
	fli_free(fli, alloc);
}

static int
fli_attach_lview(struct silofs_flnode_info *fli, struct silofs_alloc *alloc)
{
	struct silofs_lview *lview = nullptr;
	int err;

	err = lni_attach_lview(&fli->fln_lni, alloc);
	if (!err) {
		const enum silofs_ltype ltype = lni_ltype(&fli->fln_lni);

		lview = silofs_lni_lview(&fli->fln_lni);
		if (ltype == SILOFS_LTYPE_DATA1K) {
			fli->fln.dn1 = &lview->u.dn1;
		} else if (ltype == SILOFS_LTYPE_DATA4K) {
			fli->fln.dn4 = &lview->u.dn4;
		} else if (ltype == SILOFS_LTYPE_DATA64K) {
			fli->fln.dn64 = &lview->u.dn64;
		} else {
			silofs_panic("not a data ltype: %d", (int)ltype);
		}
	}
	return err;
}

static void
fli_detach_lview(struct silofs_flnode_info *fli, struct silofs_alloc *alloc)
{
	lni_detach_lview(&fli->fln_lni, alloc);
}

static struct silofs_flnode_info *
fli_new(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_flnode_info *fli;
	int err;

	fli = fli_malloc_init(alloc, laddr);
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

static void fli_del(struct silofs_flnode_info *fli, struct silofs_alloc *alloc)
{
	fli_detach_lview(fli, alloc);
	fli_fini_free(fli, alloc);
}

struct silofs_flnode_info *silofs_fli_from_lni(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni);
	return fli_from_lni(lni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_lnode_info *
silofs_new_lnode(struct silofs_alloc *alloc, const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;
	const enum silofs_ltype ltype = laddr->ltype;

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		lni = sbi_to_lni(sbi_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_SPNODE:
		lni = spi_to_lni(spi_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_INODE:
		lni = ii_to_lni(ii_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_XANODE:
		lni = xai_to_lni(xai_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_SYMVAL:
		lni = svi_to_lni(svi_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_DTNODE:
		lni = dni_to_lni(dni_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_FTNODE:
		lni = fti_to_lni(fti_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATA64K:
		lni = fli_to_lni(fli_new(alloc, laddr));
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("can not create lnode: ltype=%d", (int)ltype);
		break;
	}
	return lni;
}

void silofs_del_lnode(struct silofs_lnode_info *lni,
                      struct silofs_alloc *alloc)
{
	const enum silofs_ltype ltype = silofs_lni_ltype(lni);

	switch (ltype) {
	case SILOFS_LTYPE_SUPER:
		sbi_del(sbi_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_SPNODE:
		spi_del(spi_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_INODE:
		ii_del(ii_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_XANODE:
		xai_del(xai_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_SYMVAL:
		svi_del(svi_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_DTNODE:
		dni_del(dni_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_FTNODE:
		fti_del(fti_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_DATA1K:
	case SILOFS_LTYPE_DATA4K:
	case SILOFS_LTYPE_DATA64K:
		fli_del(fli_from_lni(lni), alloc);
		break;
	case SILOFS_LTYPE_NONE:
	case SILOFS_LTYPE_LAST:
	default:
		silofs_panic("can not destroy lnode: ltype=%d", (int)ltype);
		break;
	}
}

void silofs_seal_lnode(const struct silofs_lnode_info *lni)
{
	if (!lni_isdata(lni)) {
		silofs_lview_seal(silofs_lni_lview(lni));
	}
}
