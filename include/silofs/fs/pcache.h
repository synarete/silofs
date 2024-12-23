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
#ifndef SILOFS_PCACHE_H_
#define SILOFS_PCACHE_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/hmdq.h>

struct silofs_pcache {
	struct silofs_hmapq  pc_hmapq;
	struct silofs_dirtyq pc_dirtyq;
	struct silofs_alloc *pc_alloc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc  *alloc);

void silofs_pcache_fini(struct silofs_pcache *pcache);

bool silofs_pcache_isempty(const struct silofs_pcache *pcache);

void silofs_pcache_drop(struct silofs_pcache *pcache);

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags);

struct silofs_pnode_info *
silofs_pcache_dq_front(const struct silofs_pcache *pcache);

struct silofs_chkpt_info *
silofs_pcache_lookup_cpi(struct silofs_pcache      *pcache,
                         const struct silofs_paddr *paddr);

struct silofs_chkpt_info *
silofs_pcache_create_cpi(struct silofs_pcache      *pcache,
                         const struct silofs_paddr *paddr);

void silofs_pcache_evict_cpi(struct silofs_pcache     *pcache,
                             struct silofs_chkpt_info *cpi);

struct silofs_btnode_info *
silofs_pcache_lookup_bti(struct silofs_pcache      *pcache,
                         const struct silofs_paddr *paddr);

struct silofs_btnode_info *
silofs_pcache_create_bti(struct silofs_pcache      *pcache,
                         const struct silofs_paddr *paddr);

void silofs_pcache_evict_bti(struct silofs_pcache      *pcache,
                             struct silofs_btnode_info *bti);

struct silofs_btleaf_info *
silofs_pcache_lookup_bli(struct silofs_pcache      *pcache,
                         const struct silofs_paddr *paddr);

struct silofs_btleaf_info *
silofs_pcache_create_bli(struct silofs_pcache      *pcache,
                         const struct silofs_paddr *paddr);

void silofs_pcache_evict_bli(struct silofs_pcache      *pcache,
                             struct silofs_btleaf_info *bli);

#endif /* SILOFS_PCACHE_H_ */
