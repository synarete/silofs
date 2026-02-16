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
#ifndef SILOFS_PCACHE_H_
#define SILOFS_PCACHE_H_

#include "infra.h"
#include "addr.h"
#include "pnodes.h"

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

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache       *pcache,
                           const struct silofs_pndptr *pndptr);

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache      *pcache,
                           const struct silofs_paddr *paddr);

void silofs_pcache_delete_pnode(struct silofs_pcache     *pcache,
                                struct silofs_pnode_info *pni);

#endif /* SILOFS_PCACHE_H_ */
