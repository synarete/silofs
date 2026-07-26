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

struct silofs_ncache {
	struct silofs_hmapq  nc_hmapq;
	struct silofs_dirtyq nc_dirtyq;
	struct silofs_alloc *nc_alloc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_ncache_init(struct silofs_ncache *ncache,
                       struct silofs_alloc  *alloc);

void silofs_ncache_fini(struct silofs_ncache *ncache);

bool silofs_ncache_isempty(const struct silofs_ncache *ncache);

void silofs_ncache_drop(struct silofs_ncache *ncache);

void silofs_ncache_relax(struct silofs_ncache *ncache, int flags);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_node_info *
silofs_ncache_lookup_node_by(struct silofs_ncache     *ncache,
                             const struct silofs_hkey *hkey);

void silofs_ncache_insert_node(struct silofs_ncache    *ncache,
                               struct silofs_node_info *ni);

void silofs_ncache_evict_node(struct silofs_ncache    *ncache,
                              struct silofs_node_info *ni);

void silofs_ncache_forget_node(struct silofs_ncache    *ncache,
                               struct silofs_node_info *ni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *
silofs_ncache_lookup_pnode(struct silofs_ncache      *ncache,
                           const struct silofs_paddr *paddr);

struct silofs_pnode_info *
silofs_ncache_create_pnode(struct silofs_ncache      *ncache,
                           const struct silofs_pnptr *pnptr);

void silofs_ncache_delete_pnode(struct silofs_ncache     *ncache,
                                struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_lnode_info *
silofs_ncache_lookup_lnode(struct silofs_ncache      *ncache,
                           const struct silofs_laddr *laddr);

struct silofs_lnode_info *
silofs_ncache_create_lnode(struct silofs_ncache      *ncache,
                           const struct silofs_laddr *laddr);

void silofs_ncache_forget_lnode(struct silofs_ncache     *ncache,
                                struct silofs_lnode_info *lni);

#endif /* SILOFS_NCACHE_H_ */
