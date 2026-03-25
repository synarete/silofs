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

#include <limits.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

#define SILOFS_BTREE_KEY_NULL UINT64_MAX

void silofs_bti_self(const struct silofs_btnode_info *bti,
                     struct silofs_btnptr            *out_btnptr);

void silofs_bti_incref(struct silofs_btnode_info *bti);

void silofs_bti_decref(struct silofs_btnode_info *bti);

void silofs_bti_dirtify(struct silofs_btnode_info *bti);

void silofs_bti_undirtify(struct silofs_btnode_info *bti);

bool silofs_bti_isfull(const struct silofs_btnode_info *bti);

void silofs_bti_ignite(struct silofs_btnode_info *bti);

enum silofs_vtype silofs_bti_vspace(const struct silofs_btnode_info *bti);

void silofs_bti_set_vspace(struct silofs_btnode_info *bti,
                           enum silofs_vtype          vspace);

void silofs_bti_mark_root(struct silofs_btnode_info *bti);

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti);

size_t silofs_bti_height(const struct silofs_btnode_info *bti);

void silofs_bti_set_height(struct silofs_btnode_info *bti, size_t height);

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_btnptr *out_btnptr);

int silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr);

int silofs_bti_update(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr);

int silofs_bti_remove(struct silofs_btnode_info *bti, uint64_t key);

int silofs_bti_relink(struct silofs_btnode_info  *bti,
                      const struct silofs_btnptr *cur,
                      const struct silofs_btnptr *alt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_validate_btnode(const struct silofs_btnode_info *bti);

uint64_t silofs_split_btnode(struct silofs_btnode_info *curr,
                             struct silofs_btnode_info *next);

void silofs_rebind_btchilds(struct silofs_btnode_info  *parent,
                            const struct silofs_btnptr *left,
                            const struct silofs_btnptr *right, uint64_t key);

void silofs_clone_btnode(const struct silofs_btnode_info *bti,
                         struct silofs_btnode_info       *bti_other);

#endif /* SILOFS_BTNODE_H_ */
