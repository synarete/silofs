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

struct silofs_psenv;


/* pnode: base of all physical-mapping nodes */
struct silofs_pnode_info {
	struct silofs_paddr             p_paddr;
	struct silofs_hmapq_elem        p_hmqe;
	struct silofs_psenv            *p_psenv;
	enum silofs_ptype               p_type;
};

/* btree-node */
struct silofs_btnode_info {
	struct silofs_pnode_info        btn_pni;
	struct silofs_btree_node       *btn;
};

/* btree-leaf */
struct silofs_btleaf_info {
	struct silofs_pnode_info        btl_pni;
	struct silofs_btree_leaf       *btl;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_paddr *paddr,
               struct silofs_alloc *alloc);

void silofs_bti_del(struct silofs_btnode_info *bti,
                    struct silofs_alloc *alloc);

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pi);

int silofs_bti_resolve(const struct silofs_btnode_info *bti,
                       const struct silofs_laddr *laddr,
                       struct silofs_paddr *out_paddr);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btleaf_info *
silofs_bli_new(const struct silofs_paddr *paddr,
               struct silofs_alloc *alloc);

void silofs_bli_del(struct silofs_btleaf_info *bli,
                    struct silofs_alloc *alloc);

struct silofs_btleaf_info *
silofs_bli_from_pni(const struct silofs_pnode_info *pni);

#endif /* SILOFS_PNODES_H_ */
