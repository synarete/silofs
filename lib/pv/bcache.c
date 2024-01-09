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
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/pv.h>


static struct silofs_pnode_info *
pni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_pnode_info *pni = NULL;

	if (hmqe != NULL) {
		pni = container_of2(hmqe, struct silofs_pnode_info, p_hmqe);
	}
	return unconst(pni);
}

static struct silofs_hmapq_elem *
pni_to_hmqe(const struct silofs_pnode_info *pni)
{
	const struct silofs_hmapq_elem *hmqe = &pni->p_hmqe;

	return unconst(hmqe);
}

static void pni_do_undirtify(struct silofs_pnode_info *pni)
{
	pni->p_hmqe.hme_dirty = false;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc)
{
	int err;

	silofs_memzero(bcache, sizeof(*bcache));
	err = silofs_hmapq_init(&bcache->bc_hmapq, alloc);
	if (err) {
		return err;
	}
	bcache->bc_alloc = alloc;
	return 0;
}

void silofs_bcache_fini(struct silofs_bcache *bcache)
{
	silofs_hmapq_fini(&bcache->bc_hmapq, bcache->bc_alloc);
	bcache->bc_alloc = NULL;
}

static struct silofs_pnode_info *
bcache_find_pni(const struct silofs_bcache *bcache,
                const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_paddr(&hkey, paddr);
	hmqe = silofs_hmapq_lookup(&bcache->bc_hmapq, &hkey);
	return pni_from_hmqe(hmqe);
}

static void bcache_promote_pni(struct silofs_bcache *bcache,
                               struct silofs_pnode_info *pni, bool now)
{
	silofs_hmapq_promote(&bcache->bc_hmapq, pni_to_hmqe(pni), now);
}


static struct silofs_pnode_info *
bcache_find_relru_pni(struct silofs_bcache *bcache,
                      const struct silofs_paddr *paddr, bool now)
{
	struct silofs_pnode_info *pni;

	pni = bcache_find_pni(bcache, paddr);
	if (pni != NULL) {
		bcache_promote_pni(bcache, pni, now);
	}
	return pni;
}

static struct silofs_pnode_info *
bcache_lookup_pni(struct silofs_bcache *bcache,
                  const struct silofs_paddr *paddr)
{
	return bcache_find_relru_pni(bcache, paddr, false);
}

struct silofs_btnode_info *
silofs_bcache_lookup_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = bcache_lookup_pni(bcache, paddr);
	return silofs_bti_from_pni(pni);
}

struct silofs_btleaf_info *
silofs_bcache_lookup_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = bcache_lookup_pni(bcache, paddr);
	return silofs_bli_from_pni(pni);
}

static struct silofs_pnode_info *
bcache_new_bti_as_pni(const struct silofs_bcache *bcache,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti;

	bti = silofs_bti_new(paddr, bcache->bc_alloc);
	return (bti != NULL) ? &bti->btn_pni : NULL;
}

static void bcache_del_bti_by_pni(const struct silofs_bcache *bcache,
                                  struct silofs_pnode_info *pni)
{
	struct silofs_btnode_info *bti = silofs_bti_from_pni(pni);

	silofs_bti_del(bti, bcache->bc_alloc);
}

static struct silofs_pnode_info *
bcache_new_bli_as_pni(const struct silofs_bcache *bcache,
                      const struct silofs_paddr *paddr)
{
	struct silofs_btleaf_info *bli;

	bli = silofs_bli_new(paddr, bcache->bc_alloc);
	return (bli != NULL) ? &bli->btl_pni : NULL;
}

static void bcache_del_bli_by_pni(const struct silofs_bcache *bcache,
                                  struct silofs_pnode_info *pni)
{
	struct silofs_btleaf_info *bli = silofs_bli_from_pni(pni);

	silofs_bli_del(bli, bcache->bc_alloc);
}

static struct silofs_pnode_info *
bcache_new_pni(const struct silofs_bcache *bcache,
               const struct silofs_paddr *paddr, enum silofs_ptype ptype)
{
	struct silofs_pnode_info *pni = NULL;

	switch (ptype) {
	case SILOFS_PTYPE_BTNODE:
		pni = bcache_new_bti_as_pni(bcache, paddr);
		break;
	case SILOFS_PTYPE_BTLEAF:
		pni = bcache_new_bli_as_pni(bcache, paddr);
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		pni = NULL;
		break;
	}
	return pni;
}

static void bcache_del_pni(const struct silofs_bcache *bcache,
                           struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = pni->p_type;

	switch (ptype) {
	case SILOFS_PTYPE_BTNODE:
		bcache_del_bti_by_pni(bcache, pni);
		break;
	case SILOFS_PTYPE_BTLEAF:
		bcache_del_bli_by_pni(bcache, pni);
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		break;
	}
}

static int visit_evictable_pni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_pnode_info *pni = pni_from_hmqe(hmqe);
	struct silofs_pnode_info **out_pni = arg;
	int ret = 0;

	if (silofs_pni_isevictable(pni)) {
		*out_pni = pni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static void bcache_remove_pni(struct silofs_bcache *bcache,
                              struct silofs_pnode_info *pni)
{
	silofs_hmapq_remove(&bcache->bc_hmapq, pni_to_hmqe(pni));
}

static void bcache_evict_pni(struct silofs_bcache *bcache,
                             struct silofs_pnode_info *pni)
{
	pni_do_undirtify(pni);
	bcache_remove_pni(bcache, pni);
	bcache_del_pni(bcache, pni);
}

static struct silofs_pnode_info *
bcache_find_evictable_pni(struct silofs_bcache *bcache, bool iterall)
{
	struct silofs_pnode_info *pni = NULL;
	const size_t limit = iterall ? SILOFS_HMAPQ_ITERALL : 10;

	silofs_hmapq_riterate(&bcache->bc_hmapq, limit,
	                      visit_evictable_pni, &pni);
	return pni;
}

static size_t bcache_evict_some(struct silofs_bcache *bcache,
                                size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = bcache_find_evictable_pni(bcache, iterall);
		if (pni == NULL) {
			break;
		}
		bcache_evict_pni(bcache, pni);
		cnt++;
	}
	return cnt;
}

static struct silofs_pnode_info *
bcache_require_pni(struct silofs_bcache *bcache,
                   const struct silofs_paddr *paddr, enum silofs_ptype ptype)
{
	struct silofs_pnode_info *pni = NULL;
	int retry = 3;

	while (retry-- > 0) {
		pni = bcache_new_pni(bcache, paddr, ptype);
		if (pni != NULL) {
			break;
		}
		bcache_evict_some(bcache, 2, false);
	}
	return pni;
}

static void bcache_store_pni(struct silofs_bcache *bcache,
                             struct silofs_pnode_info *pni)
{
	silofs_hmapq_store(&bcache->bc_hmapq, pni_to_hmqe(pni));
}

static struct silofs_pnode_info *
bcache_create_pni(struct silofs_bcache *bcache,
                  const struct silofs_paddr *paddr, enum silofs_ptype ptype)
{
	struct silofs_pnode_info *pni;

	pni = bcache_require_pni(bcache, paddr, ptype);
	if (pni != NULL) {
		bcache_store_pni(bcache, pni);
	}
	return pni;
}

struct silofs_btnode_info *
silofs_bcache_create_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = bcache_create_pni(bcache, paddr, SILOFS_PTYPE_BTNODE);
	return silofs_bti_from_pni(pni);
}

struct silofs_btleaf_info *
silofs_bcache_create_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = bcache_create_pni(bcache, paddr, SILOFS_PTYPE_BTLEAF);
	return silofs_bli_from_pni(pni);
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

	silofs_allocstat(bcache->bc_alloc, &st);
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
	if (flags & SILOFS_F_TIMEOUT) {
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

