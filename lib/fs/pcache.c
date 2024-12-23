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
#include <silofs/addr.h>
#include <silofs/fs.h>

#define RETRY_MAX (4)

/* local functions */
static size_t
pcache_evict_some(struct silofs_pcache *pcache, size_t niter, bool iterall);

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

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc *alloc)
{
	const size_t nslots = silofs_hmapq_nslots_by(alloc, 1);
	int err;

	silofs_memzero(pcache, sizeof(*pcache));
	err = silofs_hmapq_init(&pcache->pc_hmapq, alloc, nslots);
	if (err) {
		return err;
	}
	silofs_dirtyq_init(&pcache->pc_dirtyq);
	pcache->pc_alloc = alloc;
	return 0;
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	silofs_hmapq_fini(&pcache->pc_hmapq, pcache->pc_alloc);
	silofs_dirtyq_fini(&pcache->pc_dirtyq);
	pcache->pc_alloc = NULL;
}

static struct silofs_pnode_info *
pcache_search(const struct silofs_pcache *pcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_paddr(&hkey, paddr);
	hmqe = silofs_hmapq_lookup(&pcache->pc_hmapq, &hkey);
	return pni_from_hmqe(hmqe);
}

static void
pcache_promote(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_promote(&pcache->pc_hmapq, pni_to_hmqe(pni), false);
}

static struct silofs_pnode_info *
pcache_search_and_relru(struct silofs_pcache *pcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_search(pcache, paddr);
	if (pni != NULL) {
		pcache_promote(pcache, pni);
	}
	return pni;
}

static struct silofs_pnode_info *
pcache_lookup(struct silofs_pcache *pcache, const struct silofs_paddr *paddr)
{
	return pcache_search_and_relru(pcache, paddr);
}

static void
pcache_store(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&pcache->pc_hmapq, pni_to_hmqe(pni));
}

static void
pcache_remove(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&pcache->pc_hmapq, pni_to_hmqe(pni));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_chkpt_info *
pcache_new_cpi(const struct silofs_pcache *pcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_CHKPT);
	silofs_assert_eq(paddr->off % SILOFS_PSEG_CHKPT_SIZE, 0);

	return silofs_cpi_new(paddr, pcache->pc_alloc);
}

static void pcache_del_cpi(const struct silofs_pcache *pcache,
                           struct silofs_chkpt_info *cpi)
{
	silofs_cpi_del(cpi, pcache->pc_alloc);
}

struct silofs_chkpt_info *
silofs_pcache_lookup_cpi(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_CHKPT);

	pni = pcache_lookup(pcache, paddr);
	return silofs_cpi_from_pni(pni);
}

static struct silofs_chkpt_info *
pcache_require_cpi(struct silofs_pcache *pcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_chkpt_info *cpi = NULL;

	for (size_t i = 0; i < RETRY_MAX; ++i) {
		cpi = pcache_new_cpi(pcache, paddr);
		if (cpi != NULL) {
			break;
		}
		pcache_evict_some(pcache, i + 1, false);
	}
	return cpi;
}

static void
pcache_bind_cpi_dq(struct silofs_pcache *pcache, struct silofs_chkpt_info *cpi)
{
	silofs_cpi_set_dq(cpi, &pcache->pc_dirtyq);
}

static void
pcache_store_cpi(struct silofs_pcache *pcache, struct silofs_chkpt_info *cpi)
{
	pcache_store(pcache, &cpi->cp_pni);
}

struct silofs_chkpt_info *
silofs_pcache_create_cpi(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_chkpt_info *cpi;

	cpi = pcache_require_cpi(pcache, paddr);
	if (cpi != NULL) {
		pcache_bind_cpi_dq(pcache, cpi);
		pcache_store_cpi(pcache, cpi);
	}
	return cpi;
}

static void
pcache_remove_cpi(struct silofs_pcache *pcache, struct silofs_chkpt_info *cpi)
{
	pcache_remove(pcache, &cpi->cp_pni);
}

static void
pcache_forget_cpi(struct silofs_pcache *pcache, struct silofs_chkpt_info *cpi)
{
	silofs_cpi_undirtify(cpi);
	pcache_remove_cpi(pcache, cpi);
}

void silofs_pcache_evict_cpi(struct silofs_pcache *pcache,
                             struct silofs_chkpt_info *cpi)
{
	pcache_forget_cpi(pcache, cpi);
	pcache_del_cpi(pcache, cpi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
pcache_new_bti(const struct silofs_pcache *pcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	return silofs_bti_new(paddr, pcache->pc_alloc);
}

static void pcache_del_bti(const struct silofs_pcache *pcache,
                           struct silofs_btnode_info *bti)
{
	silofs_assert_eq(bti->bn_pni.pn_paddr.ptype, SILOFS_PTYPE_BTNODE);

	silofs_bti_del(bti, pcache->pc_alloc);
}

struct silofs_btnode_info *
silofs_pcache_lookup_bti(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	pni = pcache_lookup(pcache, paddr);
	return silofs_bti_from_pni(pni);
}

static struct silofs_btnode_info *
pcache_require_bti(struct silofs_pcache *pcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti = NULL;

	for (size_t i = 0; i < RETRY_MAX; ++i) {
		bti = pcache_new_bti(pcache, paddr);
		if (bti != NULL) {
			break;
		}
		pcache_evict_some(pcache, i + 1, false);
	}
	return bti;
}

static void pcache_bind_bti_dq(struct silofs_pcache *pcache,
                               struct silofs_btnode_info *bti)
{
	silofs_bti_set_dq(bti, &pcache->pc_dirtyq);
}

static void
pcache_store_bti(struct silofs_pcache *pcache, struct silofs_btnode_info *bti)
{
	pcache_store(pcache, &bti->bn_pni);
}

struct silofs_btnode_info *
silofs_pcache_create_bti(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti;

	bti = pcache_require_bti(pcache, paddr);
	if (bti != NULL) {
		pcache_bind_bti_dq(pcache, bti);
		pcache_store_bti(pcache, bti);
	}
	return bti;
}

static void
pcache_remove_bti(struct silofs_pcache *pcache, struct silofs_btnode_info *bti)
{
	pcache_remove(pcache, &bti->bn_pni);
}

static void
pcache_forget_bti(struct silofs_pcache *pcache, struct silofs_btnode_info *bti)
{
	silofs_bti_undirtify(bti);
	pcache_remove_bti(pcache, bti);
}

void silofs_pcache_evict_bti(struct silofs_pcache *pcache,
                             struct silofs_btnode_info *bti)
{
	pcache_forget_bti(pcache, bti);
	pcache_del_bti(pcache, bti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btleaf_info *
pcache_new_bli(const struct silofs_pcache *pcache,
               const struct silofs_paddr *paddr)
{
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	return silofs_bli_new(paddr, pcache->pc_alloc);
}

static void pcache_del_bli(const struct silofs_pcache *pcache,
                           struct silofs_btleaf_info *bli)
{
	silofs_assert_eq(bli->bl_pni.pn_paddr.ptype, SILOFS_PTYPE_BTLEAF);

	silofs_bli_del(bli, pcache->pc_alloc);
}

struct silofs_btleaf_info *
silofs_pcache_lookup_bli(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	pni = pcache_lookup(pcache, paddr);
	return silofs_bli_from_pni(pni);
}

static void pcache_bind_bli_dq(struct silofs_pcache *pcache,
                               struct silofs_btleaf_info *bli)
{
	silofs_bli_set_dq(bli, &pcache->pc_dirtyq);
}

static void
pcache_store_bli(struct silofs_pcache *pcache, struct silofs_btleaf_info *bli)
{
	pcache_store(pcache, &bli->bl_pni);
}

static struct silofs_btleaf_info *
pcache_require_bli(struct silofs_pcache *pcache,
                   const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli = NULL;

	for (size_t i = 0; i < RETRY_MAX; ++i) {
		bli = pcache_new_bli(pcache, paddr);
		if (bli != NULL) {
			break;
		}
		pcache_evict_some(pcache, i + 1, false);
	}
	return bli;
}

struct silofs_btleaf_info *
silofs_pcache_create_bli(struct silofs_pcache *pcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli;

	bli = pcache_require_bli(pcache, paddr);
	if (bli != NULL) {
		pcache_bind_bli_dq(pcache, bli);
		pcache_store_bli(pcache, bli);
	}
	return bli;
}

static void
pcache_remove_bli(struct silofs_pcache *pcache, struct silofs_btleaf_info *bli)
{
	pcache_remove(pcache, &bli->bl_pni);
}

static void
pcache_forget_bli(struct silofs_pcache *pcache, struct silofs_btleaf_info *bli)
{
	silofs_bli_undirtify(bli);
	pcache_remove_bli(pcache, bli);
}

void silofs_pcache_evict_bli(struct silofs_pcache *pcache,
                             struct silofs_btleaf_info *bli)
{
	pcache_forget_bli(pcache, bli);
	pcache_del_bli(pcache, bli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
pcache_evict_by(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = silofs_pni_ptype(pni);

	switch (ptype) {
	case SILOFS_PTYPE_CHKPT:
		silofs_pcache_evict_cpi(pcache, silofs_cpi_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTNODE:
		silofs_pcache_evict_bti(pcache, silofs_bti_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTLEAF:
		silofs_pcache_evict_bli(pcache, silofs_bli_from_pni(pni));
		break;
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("corrupted pcache: ptype=%d", (int)ptype);
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
pcache_find_evictable(struct silofs_pcache *pcache, bool iterall)
{
	struct silofs_pnode_info *pni = NULL;
	const size_t limit = iterall ? SILOFS_HMAPQ_ITERALL : 10;

	silofs_hmapq_riterate(&pcache->pc_hmapq, limit, visit_evictable_pni,
	                      &pni);
	return pni;
}

static size_t
pcache_evict_some(struct silofs_pcache *pcache, size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = pcache_find_evictable(pcache, iterall);
		if (pni == NULL) {
			break;
		}
		pcache_evict_by(pcache, pni);
		cnt++;
	}
	return cnt;
}

static size_t pcache_usage(const struct silofs_pcache *pcache)
{
	return silofs_hmapq_usage(&pcache->pc_hmapq);
}

bool silofs_pcache_isempty(const struct silofs_pcache *pcache)
{
	return (pcache_usage(pcache) == 0);
}

void silofs_pcache_drop(struct silofs_pcache *pcache)
{
	size_t cnt;

	cnt = pcache_evict_some(pcache, 1, true);
	while (cnt > 0) {
		cnt = pcache_evict_some(pcache, 1, true);
	}
}

static size_t pcache_memory_pressure(const struct silofs_pcache *pcache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 0;

	silofs_memstat(pcache->pc_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres; /* percentage of total available memory */
}

static void pcache_relax_args(const struct silofs_pcache *pcache, int flags,
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
	mem_pres = pcache_memory_pressure(pcache);
	if (mem_pres > 50) {
		*out_niter += mem_pres / 10;
		*out_iterall = true;
	}
}

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags)
{
	size_t niter = 0;
	bool iterall = false;

	pcache_relax_args(pcache, flags, &niter, &iterall);
	pcache_evict_some(pcache, niter, iterall);
}

struct silofs_pnode_info *
silofs_pcache_dq_front(const struct silofs_pcache *pcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&pcache->pc_dirtyq);
	return pni_from_dqe(dqe);
}
