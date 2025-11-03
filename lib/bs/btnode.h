/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "bnode.h"

/* btree-node */
struct silofs_btnode_info {
	struct silofs_bnode_info  btn_bni;
	struct silofs_btree_node *btn;
	bool                      btn_rdonly;
};

struct silofs_btnode_info *
silofs_bti_from_bni(const struct silofs_bnode_info *bni);

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc);

void silofs_bti_del(struct silofs_btnode_info *bti,
                    struct silofs_alloc       *alloc);

void silofs_bti_set_dq(struct silofs_btnode_info *bti,
                       struct silofs_dirtyq      *dq);

void silofs_bti_dirtify(struct silofs_btnode_info *bti);

void silofs_bti_undirtify(struct silofs_btnode_info *bti);

void silofs_bti_dup_by(struct silofs_btnode_info       *bti,
                       const struct silofs_btnode_info *bti_other);

bool silofs_bti_isfull(const struct silofs_btnode_info *bti);

void silofs_bti_mark_root(struct silofs_btnode_info *bti);

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti);

size_t silofs_bti_height(const struct silofs_btnode_info *bti);

size_t silofs_bti_nkeys(const struct silofs_btnode_info *bti);

uint64_t silofs_bti_median_key(const struct silofs_btnode_info *bti);

size_t silofs_bti_nchilds(const struct silofs_btnode_info *bti);

void silofs_bti_child_at(const struct silofs_btnode_info *bti, size_t slot,
                         struct silofs_baddr *out_baddr);

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_baddr *out_baddr);

int silofs_bti_update_child(struct silofs_btnode_info *bti, uint64_t key,
                            const struct silofs_baddr *baddr);

int silofs_bti_expand(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_baddr *baddr);

void silofs_bti_set_final(struct silofs_btnode_info *bti,
                          const struct silofs_baddr *baddr);

#endif /* SILOFS_BTNODE_H_ */
