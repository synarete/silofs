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
#ifndef SILOFS_VCACHE_H_
#define SILOFS_VCACHE_H_

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

/* in-memory caching */
struct silofs_vcache {
	struct silofs_alloc *vc_alloc;
	struct silofs_hmapq  vc_hmapq;
	struct silofs_dirtyq vc_dirtyq;
};

int silofs_vcache_init(struct silofs_vcache *vcache,
                       struct silofs_alloc  *alloc);

void silofs_vcache_fini(struct silofs_vcache *vcache);

size_t silofs_vcache_relax(struct silofs_vcache *vcache, int flags);

void silofs_vcache_drop(struct silofs_vcache *vcache);

struct silofs_vnode_info *
silofs_vcache_dq_front(const struct silofs_vcache *vcache);

struct silofs_vnode_info *
silofs_vcache_lookup_vnode(struct silofs_vcache      *vcache,
                           const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_vcache_create_vnode(struct silofs_vcache      *vcache,
                           const struct silofs_vaddr *vaddr);

void silofs_vcache_forget_vnode(struct silofs_vcache     *vcache,
                                struct silofs_vnode_info *vni);

void silofs_vcache_collect_stats(const struct silofs_vcache *vcache,
                                 struct silofs_cache_stats  *out_cstats);

#endif /* SILOFS_VCACHE_H_ */
