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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

static struct silofs_pnode_info *pni_unconst(const struct silofs_pnode_info *p)
{
	return silofs_unconst(p);
}

static struct silofs_pnode_info *pni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_pnode_info *pni = nullptr;

	if (ni != nullptr) {
		pni = container_of(ni, struct silofs_pnode_info, pn_ni);
	}
	return pni_unconst(pni);
}

struct silofs_pnode_info *silofs_pni_from_dqe(const struct silofs_dq_elem *dqe)
{
	const struct silofs_node_info *ni;

	ni = silofs_ni_from_dqe(dqe);
	return pni_from_ni(ni);
}

struct silofs_pnode_info *silofs_pni_from_mut_ni(struct silofs_node_info *ni)
{
	return mut_container_of(ni, struct silofs_pnode_info, pn_ni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc *alloc)
{
	return silofs_ncache_init(&pcache->nc, alloc);
}

void silofs_pcache_fini(struct silofs_pcache *pcache)
{
	silofs_ncache_fini(&pcache->nc);
}

void silofs_pcache_drop(struct silofs_pcache *pcache)
{
	silofs_ncache_drop(&pcache->nc);
}

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags)
{
	silofs_ncache_relax(&pcache->nc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache *pcache,
                           const struct silofs_paddr *paddr)
{
	struct silofs_hkey hkey;
	struct silofs_node_info *ni;

	silofs_hkey_by_paddr(&hkey, paddr);
	ni = silofs_ncache_lookup_node_by(&pcache->nc, &hkey);
	return pni_from_ni(ni);
}

static void
del_pnode_as(struct silofs_node_info *ni, struct silofs_alloc *alloc)
{
	struct silofs_pnode_info *pni = pni_from_ni(ni);

	silofs_del_pnode(pni, alloc);
}

static struct silofs_pnode_info *
pcache_new_pnode(const struct silofs_pcache *pcache,
                 const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni;

	pni = silofs_new_pnode(pnptr, pcache->nc.nc_alloc);
	if (pni != nullptr) {
		pni->pn_ni.delete_fn = del_pnode_as;
	}
	return pni;
}

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache *pcache,
                           const struct silofs_pnptr *pnptr)
{
	struct silofs_pnode_info *pni = nullptr;

	pni = pcache_new_pnode(pcache, pnptr);
	if (pni != nullptr) {
		silofs_ncache_insert_node(&pcache->nc, &pni->pn_ni);
	}
	return pni;
}

void silofs_pcache_delete_pnode(struct silofs_pcache *pcache,
                                struct silofs_pnode_info *pni)
{
	silofs_ncache_evict_node(&pcache->nc, &pni->pn_ni);
}
