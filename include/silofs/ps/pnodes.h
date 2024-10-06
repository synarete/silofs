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
#ifndef SILOFS_PNODES_H_
#define SILOFS_PNODES_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/hmdq.h>

struct silofs_pstore;


/* bnode: base of all btree-mapping nodes */
struct silofs_bnode_info {
	struct silofs_paddr             bn_paddr;
	struct silofs_hmapq_elem        bn_hmqe;
	struct silofs_pstore           *bn_pstore;
};

/* btree-node */
struct silofs_btnode_info {
	struct silofs_bnode_info        btn_bni;
	struct silofs_btree_node       *btn;
};

/* btree-leaf */
struct silofs_btleaf_info {
	struct silofs_bnode_info        btl_bni;
	struct silofs_btree_leaf       *btl;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum silofs_ptype silofs_bni_ptype(const struct silofs_bnode_info *bni);

void silofs_bni_undirtify(struct silofs_bnode_info *bni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_paddr *paddr,
               struct silofs_alloc *alloc);

void silofs_bti_del(struct silofs_btnode_info *bti,
                    struct silofs_alloc *alloc);

void silofs_bti_set_dq(struct silofs_btnode_info *bti,
                       struct silofs_dirtyq *dq);

void silofs_bti_mark_root(struct silofs_btnode_info *bti);

int silofs_bti_resolve(const struct silofs_btnode_info *bti,
                       const struct silofs_laddr *laddr,
                       struct silofs_paddr *out_paddr);

int silofs_bti_expand(struct silofs_btnode_info *bti,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr);

void silofs_bti_setapex(struct silofs_btnode_info *bti,
                        const struct silofs_paddr *paddr);

void silofs_bti_dirtify(struct silofs_btnode_info *bti);

void silofs_bti_undirtify(struct silofs_btnode_info *bti);

struct silofs_btnode_info *
silofs_bti_from_bni(const struct silofs_bnode_info *bni);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btleaf_info *
silofs_bli_new(const struct silofs_paddr *paddr,
               struct silofs_alloc *alloc);

void silofs_bli_del(struct silofs_btleaf_info *bli,
                    struct silofs_alloc *alloc);

void silofs_bli_set_dq(struct silofs_btleaf_info *bli,
                       struct silofs_dirtyq *dq);

void silofs_bli_dirtify(struct silofs_btleaf_info *bli);

void silofs_bli_undirtify(struct silofs_btleaf_info *bli);

int silofs_bli_resolve(const struct silofs_btleaf_info *bli,
                       const struct silofs_laddr *laddr,
                       struct silofs_paddr *out_paddr);

int silofs_bli_extend(struct silofs_btleaf_info *bli,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr);

struct silofs_btleaf_info *
silofs_bli_from_bni(const struct silofs_bnode_info *bni);

#endif /* SILOFS_PNODES_H_ */
