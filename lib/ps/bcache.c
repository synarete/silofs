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
#include <silofs/ps.h>

#define RETRY_MAX (4)

/* local functions */
static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pnode_info *pni_unconst(const struct silofs_pnode_info *p)
{
	union {
		const struct silofs_pnode_info *p;
		struct silofs_pnode_info *q;
	} u = { .p = p };
	return u.q;
}

static struct silofs_pnode_info *
pni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_pnode_info *pni = NULL;

	if (hmqe != NULL) {
		pni = container_of2(hmqe, struct silofs_pnode_info, pn_hmqe);
	}
	return pni_unconst(pni);
}

static struct silofs_hmapq_elem *pni_to_hmqe(struct silofs_pnode_info *pni)
{
	return &pni->pn_hmqe;
}

static struct silofs_pnode_info *pni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmqe_from_dqe(dqe);
	return pni_from_hmqe(hmqe);
}

static bool pni_isevictable(const struct silofs_pnode_info *pni)
{
	return silofs_hmqe_is_evictable(&pni->pn_hmqe);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc)
{
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 1);
	int err;

	silofs_memzero(bcache, sizeof(*bcache));
	err = silofs_hmapq_init(&bcache->bc_hmapq, alloc, nslots);
	if (err) {
		return err;
	}
	silofs_dirtyq_init(&bcache->bc_dirtyq);
	bcache->bc_alloc = alloc;
	return 0;
}

void silofs_bcache_fini(struct silofs_bcache *bcache)
{
	silofs_hmapq_fini(&bcache->bc_hmapq, bcache->bc_alloc);
	silofs_dirtyq_fini(&bcache->bc_dirtyq);
	bcache->bc_alloc = NULL;
}

static struct silofs_pnode_info *
bcache_search(const struct silofs_bcache *bcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_paddr(&hkey, paddr);
	hmqe = silofs_hmapq_lookup(&bcache->bc_hmapq, &hkey);
	return pni_from_hmqe(hmqe);
}

static void
bcache_promote(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_promote(&bcache->bc_hmapq, pni_to_hmqe(pni), false);
}

static struct silofs_pnode_info *
bcache_search_and_relru(struct silofs_bcache *bcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = bcache_search(bcache, paddr);
	if (pni != NULL) {
		bcache_promote(bcache, pni);
	}
	return pni;
}

static struct silofs_pnode_info *
bcache_lookup(struct silofs_bcache *bcache, const struct silofs_paddr *paddr)
{
	return bcache_search_and_relru(bcache, paddr);
}

static void
bcache_store(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&bcache->bc_hmapq, pni_to_hmqe(pni));
}

static void
bcache_remove(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&bcache->bc_hmapq, pni_to_hmqe(pni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_chkpt_info *
bcache_new_cpi(const struct silofs_bcache *bcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_CHKPT);
	silofs_assert_eq(paddr->off % SILOFS_PSEG_CHKPT_SIZE, 0);

	return silofs_cpi_new(paddr, bcache->bc_alloc);
}

static void bcache_del_cpi(const struct silofs_bcache *bcache,
                           struct silofs_chkpt_info *cpi)
{
	silofs_cpi_del(cpi, bcache->bc_alloc);
}

struct silofs_chkpt_info *
silofs_bcache_lookup_cpi(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_CHKPT);

	pni = bcache_lookup(bcache, paddr);
	return silofs_cpi_from_pni(pni);
}

static struct silofs_chkpt_info *
bcache_require_cpi(struct silofs_bcache *bcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_chkpt_info *cpi = NULL;

	for (size_t i = 0; i < RETRY_MAX; ++i) {
		cpi = bcache_new_cpi(bcache, paddr);
		if (cpi != NULL) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return cpi;
}

static void
bcache_bind_cpi_dq(struct silofs_bcache *bcache, struct silofs_chkpt_info *cpi)
{
	silofs_cpi_set_dq(cpi, &bcache->bc_dirtyq);
}

static void
bcache_store_cpi(struct silofs_bcache *bcache, struct silofs_chkpt_info *cpi)
{
	bcache_store(bcache, &cpi->ub_pni);
}

struct silofs_chkpt_info *
silofs_bcache_create_cpi(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_chkpt_info *cpi;

	cpi = bcache_require_cpi(bcache, paddr);
	if (cpi != NULL) {
		bcache_bind_cpi_dq(bcache, cpi);
		bcache_store_cpi(bcache, cpi);
	}
	return cpi;
}

static void
bcache_remove_cpi(struct silofs_bcache *bcache, struct silofs_chkpt_info *cpi)
{
	bcache_remove(bcache, &cpi->ub_pni);
}

static void
bcache_forget_cpi(struct silofs_bcache *bcache, struct silofs_chkpt_info *cpi)
{
	cpi_undirtify(cpi);
	bcache_remove_cpi(bcache, cpi);
}

void silofs_bcache_evict_cpi(struct silofs_bcache *bcache,
                             struct silofs_chkpt_info *cpi)
{
	bcache_forget_cpi(bcache, cpi);
	bcache_del_cpi(bcache, cpi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
bcache_new_bti(const struct silofs_bcache *bcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	return silofs_bti_new(paddr, bcache->bc_alloc);
}

static void bcache_del_bti(const struct silofs_bcache *bcache,
                           struct silofs_btnode_info *bti)
{
	silofs_assert_eq(bti->bn_pni.pn_paddr.ptype, SILOFS_PTYPE_BTNODE);

	silofs_bti_del(bti, bcache->bc_alloc);
}

struct silofs_btnode_info *
silofs_bcache_lookup_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	pni = bcache_lookup(bcache, paddr);
	return silofs_bti_from_pni(pni);
}

static struct silofs_btnode_info *
bcache_require_bti(struct silofs_bcache *bcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti = NULL;

	for (size_t i = 0; i < RETRY_MAX; ++i) {
		bti = bcache_new_bti(bcache, paddr);
		if (bti != NULL) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return bti;
}

static void bcache_bind_bti_dq(struct silofs_bcache *bcache,
                               struct silofs_btnode_info *bti)
{
	silofs_bti_set_dq(bti, &bcache->bc_dirtyq);
}

static void
bcache_store_bti(struct silofs_bcache *bcache, struct silofs_btnode_info *bti)
{
	bcache_store(bcache, &bti->bn_pni);
}

struct silofs_btnode_info *
silofs_bcache_create_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti;

	bti = bcache_require_bti(bcache, paddr);
	if (bti != NULL) {
		bcache_bind_bti_dq(bcache, bti);
		bcache_store_bti(bcache, bti);
	}
	return bti;
}

static void
bcache_remove_bti(struct silofs_bcache *bcache, struct silofs_btnode_info *bti)
{
	bcache_remove(bcache, &bti->bn_pni);
}

static void
bcache_forget_bti(struct silofs_bcache *bcache, struct silofs_btnode_info *bti)
{
	bti_undirtify(bti);
	bcache_remove_bti(bcache, bti);
}

void silofs_bcache_evict_bti(struct silofs_bcache *bcache,
                             struct silofs_btnode_info *bti)
{
	bcache_forget_bti(bcache, bti);
	bcache_del_bti(bcache, bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btleaf_info *
bcache_new_bli(const struct silofs_bcache *bcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	return silofs_bli_new(paddr, bcache->bc_alloc);
}

static void bcache_del_bli(const struct silofs_bcache *bcache,
                           struct silofs_btleaf_info *bli)
{
	silofs_assert_eq(bli->bl_pni.pn_paddr.ptype, SILOFS_PTYPE_BTLEAF);

	silofs_bli_del(bli, bcache->bc_alloc);
}

struct silofs_btleaf_info *
silofs_bcache_lookup_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	pni = bcache_lookup(bcache, paddr);
	return silofs_bli_from_pni(pni);
}

static void bcache_bind_bli_dq(struct silofs_bcache *bcache,
                               struct silofs_btleaf_info *bli)
{
	silofs_bli_set_dq(bli, &bcache->bc_dirtyq);
}

static void
bcache_store_bli(struct silofs_bcache *bcache, struct silofs_btleaf_info *bli)
{
	bcache_store(bcache, &bli->bl_pni);
}

static struct silofs_btleaf_info *
bcache_require_bli(struct silofs_bcache *bcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli = NULL;

	for (size_t i = 0; i < RETRY_MAX; ++i) {
		bli = bcache_new_bli(bcache, paddr);
		if (bli != NULL) {
			break;
		}
		bcache_evict_some(bcache, i + 1, false);
	}
	return bli;
}

struct silofs_btleaf_info *
silofs_bcache_create_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli;

	bli = bcache_require_bli(bcache, paddr);
	if (bli != NULL) {
		bcache_bind_bli_dq(bcache, bli);
		bcache_store_bli(bcache, bli);
	}
	return bli;
}

static void
bcache_remove_bli(struct silofs_bcache *bcache, struct silofs_btleaf_info *bli)
{
	bcache_remove(bcache, &bli->bl_pni);
}

static void
bcache_forget_bli(struct silofs_bcache *bcache, struct silofs_btleaf_info *bli)
{
	bli_undirtify(bli);
	bcache_remove_bli(bcache, bli);
}

void silofs_bcache_evict_bli(struct silofs_bcache *bcache,
                             struct silofs_btleaf_info *bli)
{
	bcache_forget_bli(bcache, bli);
	bcache_del_bli(bcache, bli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
bcache_evict_by(struct silofs_bcache *bcache, struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = pni_ptype(pni);

	switch (ptype) {
	case SILOFS_PTYPE_CHKPT:
		silofs_bcache_evict_cpi(bcache, silofs_cpi_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTNODE:
		silofs_bcache_evict_bti(bcache, silofs_bti_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTLEAF:
		silofs_bcache_evict_bli(bcache, silofs_bli_from_pni(pni));
		break;
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("corrupted bcache: ptype=%d", (int)ptype);
		break;
	}
}

static int visit_evictable_pni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_pnode_info *pni = pni_from_hmqe(hmqe);
	struct silofs_pnode_info **out_pni = arg;
	int ret = 0;

	if (pni_isevictable(pni)) {
		*out_pni = pni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static struct silofs_pnode_info *
bcache_find_evictable(struct silofs_bcache *bcache, bool iterall)
{
	struct silofs_pnode_info *pni = NULL;
	const size_t limit = iterall ? SILOFS_HMAPQ_ITERALL : 10;

	silofs_hmapq_riterate(&bcache->bc_hmapq, limit, visit_evictable_pni,
	                      &pni);
	return pni;
}

static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = bcache_find_evictable(bcache, iterall);
		if (pni == NULL) {
			break;
		}
		bcache_evict_by(bcache, pni);
		cnt++;
	}
	return cnt;
}

static size_t bcache_usage(const struct silofs_bcache *bcache)
{
	return silofs_hmapq_usage(&bcache->bc_hmapq);
}

bool silofs_bcache_isempty(const struct silofs_bcache *bcache)
{
	return (bcache_usage(bcache) == 0);
}

void silofs_bcache_drop(struct silofs_bcache *bcache)
{
	size_t cnt;

	cnt = bcache_evict_some(bcache, 1, true);
	while (cnt > 0) {
		cnt = bcache_evict_some(bcache, 1, true);
	}
}

static size_t bcache_memory_pressure(const struct silofs_bcache *bcache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 0;

	silofs_memstat(bcache->bc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres; /* percentage of total available memory */
}

static void bcache_relax_args(const struct silofs_bcache *bcache, int flags,
                              size_t *out_niter, bool *out_iterall)
{
	size_t mem_pres;

	*out_niter = 0;
	*out_iterall = false;
	if (flags & SILOFS_F_NOW) {
		*out_niter += 2;
		*out_iterall = true;
	}
	if (flags & SILOFS_F_IDLE) {
		*out_niter += 1;
		*out_iterall = false;
	}
	mem_pres = bcache_memory_pressure(bcache);
	if (mem_pres > 50) {
		*out_niter += mem_pres / 10;
		*out_iterall = true;
	}
}

void silofs_bcache_relax(struct silofs_bcache *bcache, int flags)
{
	size_t niter = 0;
	bool iterall = false;

	bcache_relax_args(bcache, flags, &niter, &iterall);
	bcache_evict_some(bcache, niter, iterall);
}

struct silofs_pnode_info *
silofs_bcache_dq_front(const struct silofs_bcache *bcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&bcache->bc_dirtyq);
	return pni_from_dqe(dqe);
}
