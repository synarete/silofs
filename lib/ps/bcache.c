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
static size_t bcache_evict_some(struct silofs_bcache *bcache,
                                size_t niter, bool iterall);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bnode_info *bni_unconst(const struct silofs_bnode_info *p)
{
	union {
		const struct silofs_bnode_info *p;
		struct silofs_bnode_info *q;
	} u = {
		.p = p
	};
	return u.q;
}

static struct silofs_bnode_info *
bni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_bnode_info *bni = NULL;

	if (hmqe != NULL) {
		bni = container_of2(hmqe, struct silofs_bnode_info, bn_hmqe);
	}
	return bni_unconst(bni);
}

static struct silofs_dq_elem *bni_to_dqe(struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe.hme_dqe;
}

static const struct silofs_dq_elem *
bni_to_dqe2(const struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe.hme_dqe;
}

static struct silofs_hmapq_elem *bni_to_hmqe(struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe;
}

static enum silofs_ptype bni_ptype(const struct silofs_bnode_info *bni)
{
	return bni->bn_paddr.ptype;
}

static bool bni_is_dirty(const struct silofs_bnode_info *bni)
{
	return silofs_dqe_is_dirty(bni_to_dqe2(bni));
}

static void bni_undirtify(struct silofs_bnode_info *bni)
{
	if (bni_is_dirty(bni)) {
		silofs_dqe_dequeue(bni_to_dqe(bni));
	}
}

static bool bni_isevictable(const struct silofs_bnode_info *bni)
{
	return silofs_hmqe_is_evictable(&bni->bn_hmqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *
bti_unconst(const struct silofs_btnode_info *p)
{
	union {
		const struct silofs_btnode_info *p;
		struct silofs_btnode_info *q;
	} u = {
		.p = p
	};
	return u.q;
}

static struct silofs_btnode_info *
bti_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_btnode_info *bti = NULL;

	if (bni != NULL) {
		silofs_assert_eq(bni->bn_paddr.ptype, SILOFS_PTYPE_BTNODE);
		bti = container_of2(bni, struct silofs_btnode_info, btn_bni);
	}
	return bti_unconst(bti);
}

static void bti_undirtify(struct silofs_btnode_info *bti)
{
	bni_undirtify(&bti->btn_bni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btleaf_info *
bli_unconst(const struct silofs_btleaf_info *p)
{
	union {
		const struct silofs_btleaf_info *p;
		struct silofs_btleaf_info *q;
	} u = {
		.p = p
	};
	return u.q;
}

static struct silofs_btleaf_info *
bli_from_bni(const struct silofs_bnode_info *bni)
{
	const struct silofs_btleaf_info *bli = NULL;

	if (bni != NULL) {
		silofs_assert_eq(bni->bn_paddr.ptype, SILOFS_PTYPE_BTLEAF);
		bli = container_of2(bni, struct silofs_btleaf_info, btl_bni);
	}
	return bli_unconst(bli);
}

static void bli_undirtify(struct silofs_btleaf_info *bli)
{
	bni_undirtify(&bli->btl_bni);
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

static struct silofs_bnode_info *
bcache_search(const struct silofs_bcache *bcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe;

	silofs_hkey_by_paddr(&hkey, paddr);
	hmqe = silofs_hmapq_lookup(&bcache->bc_hmapq, &hkey);
	return bni_from_hmqe(hmqe);
}

static void bcache_promote(struct silofs_bcache *bcache,
                           struct silofs_bnode_info *bni)
{
	silofs_hmapq_promote(&bcache->bc_hmapq, bni_to_hmqe(bni), false);
}


static struct silofs_bnode_info *
bcache_search_and_relru(struct silofs_bcache *bcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_bnode_info *bni;

	bni = bcache_search(bcache, paddr);
	if (bni != NULL) {
		bcache_promote(bcache, bni);
	}
	return bni;
}

static struct silofs_bnode_info *
bcache_lookup(struct silofs_bcache *bcache, const struct silofs_paddr *paddr)
{
	return bcache_search_and_relru(bcache, paddr);
}

static void bcache_store(struct silofs_bcache *bcache,
                         struct silofs_bnode_info *bni)
{
	silofs_hmapq_store(&bcache->bc_hmapq, bni_to_hmqe(bni));
}

static void bcache_remove(struct silofs_bcache *bcache,
                          struct silofs_bnode_info *bni)
{
	silofs_hmapq_remove(&bcache->bc_hmapq, bni_to_hmqe(bni));
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
	silofs_assert_eq(bti->btn_bni.bn_paddr.ptype, SILOFS_PTYPE_BTNODE);

	silofs_bti_del(bti, bcache->bc_alloc);
}

struct silofs_btnode_info *
silofs_bcache_lookup_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_bnode_info *bni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	bni = bcache_lookup(bcache, paddr);
	return bti_from_bni(bni);
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

static void bcache_store_bti(struct silofs_bcache *bcache,
                             struct silofs_btnode_info *bti)
{
	bcache_store(bcache, &bti->btn_bni);
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

static void bcache_remove_bti(struct silofs_bcache *bcache,
                              struct silofs_btnode_info *bti)
{
	bcache_remove(bcache, &bti->btn_bni);
}

static void bcache_forget_bti(struct silofs_bcache *bcache,
                              struct silofs_btnode_info *bti)
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
	silofs_assert_eq(bli->btl_bni.bn_paddr.ptype, SILOFS_PTYPE_BTLEAF);

	silofs_bli_del(bli, bcache->bc_alloc);
}

struct silofs_btleaf_info *
silofs_bcache_lookup_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr)
{
	struct silofs_bnode_info *bni;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTLEAF);

	bni = bcache_lookup(bcache, paddr);
	return bli_from_bni(bni);
}

static void bcache_bind_bli_dq(struct silofs_bcache *bcache,
                               struct silofs_btleaf_info *bli)
{
	silofs_bli_set_dq(bli, &bcache->bc_dirtyq);
}

static void bcache_store_bli(struct silofs_bcache *bcache,
                             struct silofs_btleaf_info *bli)
{
	bcache_store(bcache, &bli->btl_bni);
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

static void bcache_remove_bli(struct silofs_bcache *bcache,
                              struct silofs_btleaf_info *bli)
{
	bcache_remove(bcache, &bli->btl_bni);
}

static void bcache_forget_bli(struct silofs_bcache *bcache,
                              struct silofs_btleaf_info *bli)
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

static void bcache_evict_by(struct silofs_bcache *bcache,
                            struct silofs_bnode_info *bni)
{
	const enum silofs_ptype ptype = bni_ptype(bni);

	switch (ptype) {
	case SILOFS_PTYPE_BTNODE:
		silofs_bcache_evict_bti(bcache, bti_from_bni(bni));
		break;
	case SILOFS_PTYPE_BTLEAF:
		silofs_bcache_evict_bli(bcache, bli_from_bni(bni));
		break;
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("corrupted bcache: ptype=%d", (int)ptype);
		break;
	}
}

static int visit_evictable_bni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_bnode_info *bni = bni_from_hmqe(hmqe);
	struct silofs_bnode_info **out_bni = arg;
	int ret = 0;

	if (bni_isevictable(bni)) {
		*out_bni = bni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static struct silofs_bnode_info *
bcache_find_evictable(struct silofs_bcache *bcache, bool iterall)
{
	struct silofs_bnode_info *bni = NULL;
	const size_t limit = iterall ? SILOFS_HMAPQ_ITERALL : 10;

	silofs_hmapq_riterate(&bcache->bc_hmapq, limit,
	                      visit_evictable_bni, &bni);
	return bni;
}

static size_t bcache_evict_some(struct silofs_bcache *bcache,
                                size_t niter, bool iterall)
{
	struct silofs_bnode_info *bni;
	size_t cnt = 0;

	while (niter-- > 0) {
		bni = bcache_find_evictable(bcache, iterall);
		if (bni == NULL) {
			break;
		}
		bcache_evict_by(bcache, bni);
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
