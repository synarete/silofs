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
#ifndef SILOFS_NCACHE_H_
#define SILOFS_NCACHE_H_

#include <silofs/infra.h>
#include <silofs/nodes/dirtyq.h>
#include <silofs/nodes/hmapq.h>

/* common base to all nodes' caches */
struct silofs_ncache {
	struct silofs_hmapq  hmapq;
	struct silofs_dirtyq dirtyq;
	struct silofs_alloc *nc_alloc;
};

/* pnodes cache */
struct silofs_pcache {
	struct silofs_ncache nc;
};

/* lnodes cache */
struct silofs_lcache {
	struct silofs_ncache nc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc  *alloc);

void silofs_pcache_fini(struct silofs_pcache *pcache);

void silofs_pcache_drop(struct silofs_pcache *pcache);

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags);

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache      *pcache,
                           const struct silofs_paddr *paddr);

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache      *pcache,
                           const struct silofs_pnptr *pnptr);

void silofs_pcache_delete_pnode(struct silofs_pcache     *pcache,
                                struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc  *alloc);

void silofs_lcache_fini(struct silofs_lcache *lcache);

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags);

void silofs_lcache_drop(struct silofs_lcache *lcache);

struct silofs_lnode_info *
silofs_lcache_lookup_lnode(struct silofs_lcache      *lcache,
                           const struct silofs_laddr *laddr);

struct silofs_lnode_info *
silofs_lcache_create_lnode(struct silofs_lcache      *lcache,
                           const struct silofs_laddr *laddr);

void silofs_lcache_forget_lnode(struct silofs_lcache     *lcache,
                                struct silofs_lnode_info *lni);

size_t silofs_lcache_usage(const struct silofs_lcache *lcache);

#endif /* SILOFS_NCACHE_H_ */
