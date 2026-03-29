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
#ifndef SILOFS_LCACHE_H_
#define SILOFS_LCACHE_H_

#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/fs/spxmap.h>

/* in-memory caching */
struct silofs_lcache {
	struct silofs_alloc *lc_alloc;
	struct silofs_hmapq  lc_uni_hmapq;
	struct silofs_uamap  lc_uamap;
	struct silofs_dirtyq lc_unis_dq;
	struct silofs_vcache lc_vc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc  *alloc);

void silofs_lcache_fini(struct silofs_lcache *lcache);

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags);

void silofs_lcache_drop(struct silofs_lcache *lcache);

struct silofs_unode_info *
silofs_lcache_lookup_uni(struct silofs_lcache      *lcache,
                         const struct silofs_uaddr *uaddr);

struct silofs_unode_info *
silofs_lcache_create_uni(struct silofs_lcache      *lcache,
                         const struct silofs_uaddr *uaddr);

void silofs_lcache_forget_uni(struct silofs_lcache     *lcache,
                              struct silofs_unode_info *uni);

struct silofs_unode_info *
silofs_lcache_find_uni_by(struct silofs_lcache      *lcache,
                          const struct silofs_uakey *uakey);

void silofs_lcache_drop_uamap(struct silofs_lcache *lcache);

struct silofs_vnode_info *
silofs_lcache_lookup_vnode(struct silofs_lcache      *lcache,
                           const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_lcache_create_vnode(struct silofs_lcache      *lcache,
                           const struct silofs_vaddr *vaddr);

void silofs_lcache_forget_vnode(struct silofs_lcache     *lcache,
                                struct silofs_vnode_info *vni);

void silofs_lcache_redirtify_vnode(struct silofs_lcache     *lcache,
                                   struct silofs_vnode_info *vni);

void silofs_lcache_collect_stats(const struct silofs_lcache *lcache,
                                 struct silofs_cache_stats  *out_cstats);

#endif /* SILOFS_LCACHE_H_ */
