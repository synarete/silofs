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
#ifndef SILOFS_BCACHE_H_
#define SILOFS_BCACHE_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/hmdq.h>

struct silofs_bcache {
	struct silofs_hmapq     bc_hmapq;
	struct silofs_dirtyq    bc_dirtyq;
	struct silofs_alloc    *bc_alloc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc);

void silofs_bcache_fini(struct silofs_bcache *bcache);

bool silofs_bcache_isempty(const struct silofs_bcache *bcache);

void silofs_bcache_drop(struct silofs_bcache *bcache);

void silofs_bcache_relax(struct silofs_bcache *bcache, int flags);

struct silofs_bnode_info *
silofs_bcache_dq_front(const struct silofs_bcache *bcache);


struct silofs_btnode_info *
silofs_bcache_lookup_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr);

struct silofs_btnode_info *
silofs_bcache_create_bti(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr);

void silofs_bcache_evict_bti(struct silofs_bcache *bcache,
                             struct silofs_btnode_info *bti);

struct silofs_btleaf_info *
silofs_bcache_lookup_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr);

struct silofs_btleaf_info *
silofs_bcache_create_bli(struct silofs_bcache *bcache,
                         const struct silofs_paddr *paddr);

void silofs_bcache_evict_bli(struct silofs_bcache *bcache,
                             struct silofs_btleaf_info *bli);

#endif /* SILOFS_BCACHE_H_ */
