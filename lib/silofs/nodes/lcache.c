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

static struct silofs_lnode_info *
lni_unconst(const struct silofs_lnode_info *lni)
{
	return silofs_unconst(lni);
}

static struct silofs_lnode_info *lni_from_ni(const struct silofs_node_info *ni)
{
	const struct silofs_lnode_info *lni = nullptr;

	if (ni != nullptr) {
		lni = container_of(ni, struct silofs_lnode_info, ln_ni);
	}
	return lni_unconst(lni);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc *alloc)
{
	return silofs_ncache_init(&lcache->nc, alloc);
}

void silofs_lcache_fini(struct silofs_lcache *lcache)
{
	silofs_ncache_fini(&lcache->nc);
}

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags)
{
	silofs_ncache_relax(&lcache->nc, flags);
}

void silofs_lcache_drop(struct silofs_lcache *lcache)
{
	silofs_ncache_drop(&lcache->nc);
}

struct silofs_lnode_info *
silofs_lcache_lookup_lnode(struct silofs_lcache *lcache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_hkey hkey;
	struct silofs_node_info *ni;

	silofs_hkey_by_laddr(&hkey, laddr);
	ni = silofs_ncache_lookup_node_by(&lcache->nc, &hkey);
	return lni_from_ni(ni);
}

static void
del_lnode_as(struct silofs_node_info *ni, struct silofs_alloc *alloc)
{
	struct silofs_lnode_info *lni = silofs_lni_from_ni(ni);

	silofs_del_lnode(lni, alloc);
}

static struct silofs_lnode_info *
lcache_new_lnode(const struct silofs_lcache *lcache,
                 const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni;

	lni = silofs_new_lnode(lcache->nc.nc_alloc, laddr);
	if (lni != nullptr) {
		lni->ln_ni.delete_fn = del_lnode_as;
	}
	return lni;
}

struct silofs_lnode_info *
silofs_lcache_create_lnode(struct silofs_lcache *lcache,
                           const struct silofs_laddr *laddr)
{
	struct silofs_lnode_info *lni = nullptr;

	lni = lcache_new_lnode(lcache, laddr);
	if (lni != nullptr) {
		silofs_ncache_insert_node(&lcache->nc, &lni->ln_ni);
	}
	return lni;
}

void silofs_lcache_forget_lnode(struct silofs_lcache *lcache,
                                struct silofs_lnode_info *lni)
{
	silofs_ncache_forget_node(&lcache->nc, &lni->ln_ni);
}
