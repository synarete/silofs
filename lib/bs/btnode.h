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
#include "pnode.h"

/* btree-node */
struct silofs_btnode_info {
	struct silofs_pnode_info  bn_pni;
	struct silofs_btree_node *bn;
	bool                      bn_rdonly;
};

struct silofs_btnode_info *
silofs_bni_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_bni_del(struct silofs_btnode_info *bni,
                    struct silofs_alloc       *alloc);

void silofs_bni_set_dq(struct silofs_btnode_info *bni,
                       struct silofs_dirtyq      *dq);

void silofs_bni_dirtify(struct silofs_btnode_info *bni);

void silofs_bni_undirtify(struct silofs_btnode_info *bni);

void silofs_bni_dup_by(struct silofs_btnode_info       *bni,
                       const struct silofs_btnode_info *bni_other);

bool silofs_bni_isfull(const struct silofs_btnode_info *bni);

void silofs_bni_mark_root(struct silofs_btnode_info *bni);

bool silofs_bni_marked_root(const struct silofs_btnode_info *bni);

size_t silofs_bni_height(const struct silofs_btnode_info *bni);

size_t silofs_bni_nkeys(const struct silofs_btnode_info *bni);

uint64_t silofs_bni_median_key(const struct silofs_btnode_info *bni);

size_t silofs_bni_nchilds(const struct silofs_btnode_info *bni);

void silofs_bni_child_at(const struct silofs_btnode_info *bni, size_t slot,
                         struct silofs_paddr *out_paddr);

int silofs_bni_resolve(const struct silofs_btnode_info *bni, uint64_t key,
                       struct silofs_paddr *out_paddr);

int silofs_bni_update_child(struct silofs_btnode_info *bni, uint64_t key,
                            const struct silofs_paddr *paddr);

int silofs_bni_expand(struct silofs_btnode_info *bni, uint64_t key,
                      const struct silofs_paddr *paddr);

void silofs_bni_set_final(struct silofs_btnode_info *bni,
                          const struct silofs_paddr *paddr);

struct silofs_btnode_info *
silofs_bni_from_pni(const struct silofs_pnode_info *pni);

#endif /* SILOFS_BTNODE_H_ */
