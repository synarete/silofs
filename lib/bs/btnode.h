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
#ifndef SILOFS_BTNODE_H_
#define SILOFS_BTNODE_H_

#include "infra.h"
#include "addr.h"
#include "nodes.h"

#define SILOFS_BTREE_KEY_NULL (0)

void silofs_bti_self(const struct silofs_btnode_info *bti,
                     struct silofs_btnptr            *out_btnptr);

void silofs_bti_incref(struct silofs_btnode_info *bti);

void silofs_bti_decref(struct silofs_btnode_info *bti);

void silofs_bti_dirtify(struct silofs_btnode_info *bti);

void silofs_bti_undirtify(struct silofs_btnode_info *bti);

void silofs_bti_dup_by(struct silofs_btnode_info       *bti,
                       const struct silofs_btnode_info *bti_other);

enum silofs_vtype silofs_bti_vspace(const struct silofs_btnode_info *bti);

void silofs_bti_set_vspace(struct silofs_btnode_info *bti,
                           enum silofs_vtype          vspace);

void silofs_bti_mark_root(struct silofs_btnode_info *bti);

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti);

size_t silofs_bti_height(const struct silofs_btnode_info *bti);

size_t silofs_bti_nkeys(const struct silofs_btnode_info *bti);

size_t silofs_bti_nchilds(const struct silofs_btnode_info *bti);

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_btnptr *out_btnptr);

int silofs_bti_relink(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr);

int silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr);

bool silofs_bti_isfull(const struct silofs_btnode_info *bti);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_split_btnode(struct silofs_btnode_info *bti,
                        struct silofs_btnode_info *bti_next,
                        uint64_t                  *out_mkey);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btnode_info *
silofs_lookup_cached_btnode(struct silofs_pcache      *pcache,
                            const struct silofs_paddr *paddr);

struct silofs_btnode_info *
silofs_create_cached_btnode(struct silofs_pcache      *pcache,
                            const struct silofs_pnptr *pnptr, bool spawn);

void silofs_forget_cached_btnode(struct silofs_pcache      *pcache,
                                 struct silofs_btnode_info *bti);

#endif /* SILOFS_BTNODE_H_ */
