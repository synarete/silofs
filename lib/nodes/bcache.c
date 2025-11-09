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
#include "infra.h"
#include "addr.h"
#include "flags.h"
#include "nodes.h"
#include "bcache.h"

static struct silofs_bnode_info *bni_unconst(const struct silofs_bnode_info *p)
{
	union {
		const struct silofs_bnode_info *p;
		struct silofs_bnode_info *q;
	} u = { .p = p };
	return u.q;
}

static struct silofs_bnode_info *
bni_from_hmqe(const struct silofs_hmapq_elem *hmqe)
{
	const struct silofs_bnode_info *bni = nullptr;

	if (hmqe != nullptr) {
		bni = container_of2(hmqe, struct silofs_bnode_info, bn_hmqe);
	}
	return bni_unconst(bni);
}

static struct silofs_hmapq_elem *bni_to_hmqe(struct silofs_bnode_info *bni)
{
	return &bni->bn_hmqe;
}

static struct silofs_bnode_info *bni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = silofs_hmqe_from_dqe(dqe);
	return bni_from_hmqe(hmqe);
}

static bool bni_isevictable(const struct silofs_bnode_info *bni)
{
	return silofs_hmqe_is_evictable(&bni->bn_hmqe);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int bcache_init_hmapqs(struct silofs_bcache *bcache)
{
	struct silofs_alloc *alloc = bcache->bc_alloc;
	const size_t nslots = 1024; /* TODO: revisit */
	size_t i = 0, j = 0;
	int err;

	for (i = 0; i < ARRAY_SIZE(bcache->bc_hmapq); ++i) {
		err = silofs_hmapq_init(&bcache->bc_hmapq[i], alloc, nslots);
		if (err) {
			goto out_err;
		}
	}
	return 0;
out_err:
	for (j = 0; j < i; ++j) {
		silofs_hmapq_fini(&bcache->bc_hmapq[j], alloc);
	}
	return err;
}

static void bcache_fini_hmapqs(struct silofs_bcache *bcache)
{
	struct silofs_alloc *alloc = bcache->bc_alloc;

	for (size_t i = 0; i < ARRAY_SIZE(bcache->bc_hmapq); ++i) {
		silofs_hmapq_fini(&bcache->bc_hmapq[i], alloc);
	}
}

int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc)
{
	silofs_memzero(bcache, sizeof(*bcache));
	bcache->bc_alloc = alloc;
	silofs_dirtyq_init(&bcache->bc_dirtyq);
	return bcache_init_hmapqs(bcache);
}

void silofs_bcache_fini(struct silofs_bcache *bcache)
{
	bcache_fini_hmapqs(bcache);
	silofs_dirtyq_fini(&bcache->bc_dirtyq);
	bcache->bc_alloc = nullptr;
}

static const struct silofs_hmapq *
bcache_hmapq_of(const struct silofs_bcache *bcache,
                const struct silofs_baddr *baddr)
{
	const struct silofs_hmapq *hmapq = nullptr;

	switch (baddr->mtype) {
	case SILOFS_MTYPE_UBER:
		hmapq = &bcache->bc_hmapq[0];
		break;
	case SILOFS_MTYPE_ARIX:
		break;
	case SILOFS_MTYPE_BDESC:
		hmapq = &bcache->bc_hmapq[1];
		break;
	case SILOFS_MTYPE_BTNODE:
		hmapq = &bcache->bc_hmapq[2];
		break;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_MBR:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("bad bcache: mtype=%d", (int)baddr->mtype);
		break;
	}
	return hmapq;
}

static struct silofs_hmapq *
bcache_hmapq_of2(const struct silofs_bcache *bcache,
                 const struct silofs_bnode_info *bni)
{
	const struct silofs_hmapq *hmapq;

	hmapq = bcache_hmapq_of(bcache, &bni->bn_baddr);
	return unconst(hmapq);
}

static struct silofs_bnode_info *
bcache_search(const struct silofs_bcache *bcache,
              const struct silofs_baddr *baddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe = nullptr;
	const struct silofs_hmapq *hmapq = nullptr;

	hmapq = bcache_hmapq_of(bcache, baddr);
	if (likely(hmapq != nullptr)) {
		silofs_hkey_by_baddr(&hkey, baddr);
		hmqe = silofs_hmapq_lookup(hmapq, &hkey);
	}
	return bni_from_hmqe(hmqe);
}

static void
bcache_promote(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	struct silofs_hmapq *hmapq = bcache_hmapq_of2(bcache, bni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_promote(hmapq, bni_to_hmqe(bni), false);
	}
}

static struct silofs_bnode_info *
bcache_search_and_relru(struct silofs_bcache *bcache,
                        const struct silofs_baddr *baddr)
{
	struct silofs_bnode_info *bni;

	bni = bcache_search(bcache, baddr);
	if (bni != nullptr) {
		bcache_promote(bcache, bni);
	}
	return bni;
}

static void
bcache_map(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	struct silofs_hmapq *hmapq = bcache_hmapq_of2(bcache, bni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_store(hmapq, bni_to_hmqe(bni));
	}
}

static void
bcache_unmap(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	struct silofs_hmapq *hmapq = bcache_hmapq_of2(bcache, bni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_remove(hmapq, bni_to_hmqe(bni));
	}
}

static void
bcache_bind_dirtyq(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	silofs_bni_set_dq(bni, &bcache->bc_dirtyq);
}

static void bcache_unbind_dirtyq(struct silofs_bcache *bcache,
                                 struct silofs_bnode_info *bni)
{
	silofs_bni_undirtify(bni);
	silofs_bni_set_dq(bni, nullptr);
	unused(bcache);
}

static struct silofs_bnode_info *
bcache_new_bnode(const struct silofs_bcache *bcache,
                 const struct silofs_baddr *baddr)
{
	return silofs_new_bnode(baddr, bcache->bc_alloc);
}

static void bcache_del_bnode(const struct silofs_bcache *bcache,
                             struct silofs_bnode_info *bni)
{
	silofs_del_bnode(bni, bcache->bc_alloc);
}

static void bcache_insert_bnode(struct silofs_bcache *bcache,
                                struct silofs_bnode_info *bni)
{
	bcache_bind_dirtyq(bcache, bni);
	bcache_map(bcache, bni);
}

static void bcache_remove_bnode(struct silofs_bcache *bcache,
                                struct silofs_bnode_info *bni)
{
	bcache_unbind_dirtyq(bcache, bni);
	bcache_unmap(bcache, bni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_bnode_info *
silofs_bcache_lookup_bnode(struct silofs_bcache *bcache,
                           const struct silofs_baddr *baddr)
{
	return bcache_search_and_relru(bcache, baddr);
}

struct silofs_bnode_info *
silofs_bcache_create_bnode(struct silofs_bcache *bcache,
                           const struct silofs_baddr *baddr)
{
	struct silofs_bnode_info *bni = nullptr;

	bni = bcache_new_bnode(bcache, baddr);
	if (bni != nullptr) {
		bcache_insert_bnode(bcache, bni);
	}
	return bni;
}

void silofs_bcache_delete_bnode(struct silofs_bcache *bcache,
                                struct silofs_bnode_info *bni)
{
	bcache_remove_bnode(bcache, bni);
	bcache_del_bnode(bcache, bni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
bcache_evict_by(struct silofs_bcache *bcache, struct silofs_bnode_info *bni)
{
	silofs_bcache_delete_bnode(bcache, bni);
}

static int visit_evictable_bni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_bnode_info *bni = bni_from_hmqe(hmqe);
	struct silofs_bnode_info **out_bni;
	int ret = 0;

	if (bni_isevictable(bni)) {
		out_bni = (struct silofs_bnode_info **)arg;
		*out_bni = bni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

static struct silofs_bnode_info *
bcache_find_evictable(struct silofs_bcache *bcache, bool iterall)
{
	struct silofs_bnode_info *bni = nullptr;
	struct silofs_bnode_info **p_bni = &bni;

	for (size_t i = ARRAY_SIZE(bcache->bc_hmapq); i > 0; --i) {
		silofs_hmapq_riterate(&bcache->bc_hmapq[i - 1],
		                      iterall ? SILOFS_HMAPQ_ITERALL : 10,
		                      visit_evictable_bni, (void *)p_bni);
		if (bni != nullptr) {
			break;
		}
	}
	return bni;
}

static size_t
bcache_evict_some(struct silofs_bcache *bcache, size_t niter, bool iterall)
{
	struct silofs_bnode_info *bni;
	size_t cnt = 0;

	while (niter-- > 0) {
		bni = bcache_find_evictable(bcache, iterall);
		if (bni == nullptr) {
			break;
		}
		bcache_evict_by(bcache, bni);
		cnt++;
	}
	return cnt;
}

static size_t bcache_usage(const struct silofs_bcache *bcache)
{
	size_t usage = 0;

	for (size_t i = 0; i < ARRAY_SIZE(bcache->bc_hmapq); ++i) {
		usage += silofs_hmapq_usage(&bcache->bc_hmapq[i]);
	}
	return usage;
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
	if (flags & SILOFS_CTLF_NOW) {
		*out_niter += 2;
		*out_iterall = true;
	}
	if (flags & SILOFS_CTLF_IDLE) {
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

struct silofs_bnode_info *
silofs_bcache_dq_front(const struct silofs_bcache *bcache)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&bcache->bc_dirtyq);
	return bni_from_dqe(dqe);
}
