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
#include "infra.h"
#include "addr.h"
#include "flags.h"
#include "pnodes.h"
#include "pcache.h"

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
	const struct silofs_pnode_info *pni = nullptr;

	if (hmqe != nullptr) {
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

static int pcache_init_hmapqs(struct silofs_pcache *pcache)
{
	struct silofs_alloc *alloc = pcache->pc_alloc;
	const size_t nslots        = 1024; /* TODO: revisit */
	size_t i = 0, j = 0;
	int err;

	for (i = 0; i < ARRAY_SIZE(pcache->pc_hmapq); ++i) {
		err = silofs_hmapq_init(&pcache->pc_hmapq[i], alloc, nslots);
		if (err) {
			goto out_err;
		}
	}
	return 0;
out_err:
	for (j = 0; j < i; ++j) {
		silofs_hmapq_fini(&pcache->pc_hmapq[j], alloc);
	}
	return err;
}

static void pcache_fini_hmapqs(struct silofs_pcache *pcache)
{
	struct silofs_alloc *alloc = pcache->pc_alloc;

	for (size_t i = 0; i < ARRAY_SIZE(pcache->pc_hmapq); ++i) {
		silofs_hmapq_fini(&pcache->pc_hmapq[i], alloc);
	}
}

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc *alloc)
{
	silofs_memzero(pcache, sizeof(*pcache));
	pcache->pc_alloc = alloc;
	silofs_dirtyq_init(&pcache->pc_dirtyq);
	return pcache_init_hmapqs(pcache);
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	pcache_fini_hmapqs(pcache);
	silofs_dirtyq_fini(&pcache->pc_dirtyq);
	pcache->pc_alloc = nullptr;
}

static const struct silofs_hmapq *
pcache_hmapq_of(const struct silofs_pcache *pcache,
                const struct silofs_paddr *paddr)
{
	const struct silofs_hmapq *hmapq = nullptr;

	switch (paddr->mtype) {
	case SILOFS_MTYPE_UBER:
		hmapq = &pcache->pc_hmapq[0];
		break;
	case SILOFS_MTYPE_ARIX:
		break;
	case SILOFS_MTYPE_BLDESC:
		hmapq = &pcache->pc_hmapq[1];
		break;
	case SILOFS_MTYPE_BTNODE:
		hmapq = &pcache->pc_hmapq[2];
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
		silofs_panic("bad pcache: mtype=%d", (int)paddr->mtype);
		break;
	}
	return hmapq;
}

static struct silofs_hmapq *
pcache_hmapq_of2(const struct silofs_pcache *pcache,
                 const struct silofs_pnode_info *pni)
{
	const struct silofs_hmapq *hmapq;

	hmapq = pcache_hmapq_of(pcache, &pni->pn_meta.paddr);
	return unconst(hmapq);
}

static struct silofs_pnode_info *
pcache_search(const struct silofs_pcache *pcache,
              const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_hmapq_elem *hmqe   = nullptr;
	const struct silofs_hmapq *hmapq = nullptr;

	hmapq = pcache_hmapq_of(pcache, paddr);
	if (likely(hmapq != nullptr)) {
		silofs_hkey_by_paddr(&hkey, paddr);
		hmqe = silofs_hmapq_lookup(hmapq, &hkey);
	}
	return pni_from_hmqe(hmqe);
}

static void
pcache_promote(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_promote(hmapq, pni_to_hmqe(pni), false);
	}
}

static struct silofs_pnode_info *
pcache_search_and_relru(struct silofs_pcache *pcache,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pnode_info *pni;

	pni = pcache_search(pcache, paddr);
	if (pni != nullptr) {
		pcache_promote(pcache, pni);
	}
	return pni;
}

static void
pcache_map(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_store(hmapq, pni_to_hmqe(pni));
	}
}

static void
pcache_unmap(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	struct silofs_hmapq *hmapq = pcache_hmapq_of2(pcache, pni);

	if (likely(hmapq != nullptr)) {
		silofs_hmapq_remove(hmapq, pni_to_hmqe(pni));
	}
}

static void
pcache_bind_dirtyq(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_pni_set_dq(pni, &pcache->pc_dirtyq);
}

static void pcache_unbind_dirtyq(struct silofs_pcache *pcache,
                                 struct silofs_pnode_info *pni)
{
	silofs_pni_undirtify(pni);
	silofs_pni_set_dq(pni, nullptr);
	unused(pcache);
}

static struct silofs_pnode_info *
pcache_new_pnode(const struct silofs_pcache *pcache,
                 const struct silofs_pmeta *pmeta)
{
	return silofs_new_pnode(pmeta, pcache->pc_alloc);
}

static void pcache_del_pnode(const struct silofs_pcache *pcache,
                             struct silofs_pnode_info *pni)
{
	silofs_del_pnode(pni, pcache->pc_alloc);
}

static void pcache_insert_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	pcache_bind_dirtyq(pcache, pni);
	pcache_map(pcache, pni);
}

static void pcache_remove_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	pcache_unbind_dirtyq(pcache, pni);
	pcache_unmap(pcache, pni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache *pcache,
                           const struct silofs_paddr *paddr)
{
	return pcache_search_and_relru(pcache, paddr);
}

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache *pcache,
                           const struct silofs_pmeta *pmeta)
{
	struct silofs_pnode_info *pni = nullptr;

	pni = pcache_new_pnode(pcache, pmeta);
	if (pni != nullptr) {
		pcache_insert_pnode(pcache, pni);
	}
	return pni;
}

void silofs_pcache_delete_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	pcache_remove_pnode(pcache, pni);
	pcache_del_pnode(pcache, pni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
pcache_evict_by(struct silofs_pcache *pcache, struct silofs_pnode_info *pni)
{
	silofs_pcache_delete_pnode(pcache, pni);
}

static int visit_evictable_pni(struct silofs_hmapq_elem *hmqe, void *arg)
{
	struct silofs_pnode_info *pni = pni_from_hmqe(hmqe);
	struct silofs_pnode_info **out_pni;
	int ret = 0;

	if (pni_isevictable(pni)) {
		out_pni  = (struct silofs_pnode_info **)arg;
		*out_pni = pni; /* found candidate for eviction */
		ret      = 1;
	}
	return ret;
}

static struct silofs_pnode_info *
pcache_find_evictable(struct silofs_pcache *pcache, bool iterall)
{
	struct silofs_pnode_info *pni    = nullptr;
	struct silofs_pnode_info **p_pni = &pni;

	for (size_t i = ARRAY_SIZE(pcache->pc_hmapq); i > 0; --i) {
		silofs_hmapq_riterate(&pcache->pc_hmapq[i - 1],
		                      iterall ? SILOFS_HMAPQ_ITERALL : 10,
		                      visit_evictable_pni, (void *)p_pni);
		if (pni != nullptr) {
			break;
		}
	}
	return pni;
}

static size_t
pcache_evict_some(struct silofs_pcache *pcache, size_t niter, bool iterall)
{
	struct silofs_pnode_info *pni;
	size_t cnt = 0;

	while (niter-- > 0) {
		pni = pcache_find_evictable(pcache, iterall);
		if (pni == nullptr) {
			break;
		}
		pcache_evict_by(pcache, pni);
		cnt++;
	}
	return cnt;
}

static size_t pcache_usage(const struct silofs_pcache *pcache)
{
	size_t usage = 0;

	for (size_t i = 0; i < ARRAY_SIZE(pcache->pc_hmapq); ++i) {
		usage += silofs_hmapq_usage(&pcache->pc_hmapq[i]);
	}
	return usage;
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

	*out_niter   = 0;
	*out_iterall = false;
	if (flags & SILOFS_CTLF_NOW) {
		*out_niter += 2;
		*out_iterall = true;
	}
	if (flags & SILOFS_CTLF_IDLE) {
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
