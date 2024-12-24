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
#ifndef SILOFS_PNODES_H_
#define SILOFS_PNODES_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/hmdq.h>

struct silofs_bstore;

/* base of all persistent-segment nodes */
struct silofs_pnode_info {
	struct silofs_paddr      pn_paddr;
	struct silofs_hmapq_elem pn_hmqe;
	struct silofs_bstore    *pn_bstore;
};

/* check-point node */
struct silofs_chkpt_info {
	struct silofs_pnode_info  cp_pni;
	struct silofs_chkpt_node *cp;
};

/* btree-node */
struct silofs_btnode_info {
	struct silofs_pnode_info  bn_pni;
	struct silofs_btree_node *bn;
};

/* btree-leaf */
struct silofs_btleaf_info {
	struct silofs_pnode_info  bl_pni;
	struct silofs_btree_leaf *bl;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum silofs_ptype silofs_pni_ptype(const struct silofs_pnode_info *pni);

void silofs_pni_undirtify(struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_chkpt_info *
silofs_cpi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_cpi_del(struct silofs_chkpt_info *cpi, struct silofs_alloc *alloc);

struct silofs_chkpt_info *
silofs_cpi_from_pni(const struct silofs_pnode_info *pni);

void silofs_cpi_set_dq(struct silofs_chkpt_info *cpi,
                       struct silofs_dirtyq     *dq);

void silofs_cpi_dirtify(struct silofs_chkpt_info *cpi);

void silofs_cpi_undirtify(struct silofs_chkpt_info *cpi);

void silofs_cpi_btree_root(const struct silofs_chkpt_info *cpi,
                           struct silofs_paddr            *out_paddr);

void silofs_cpi_set_btree_root(struct silofs_chkpt_info  *cpi,
                               const struct silofs_paddr *paddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_bti_del(struct silofs_btnode_info *bti,
                    struct silofs_alloc       *alloc);

void silofs_bti_set_dq(struct silofs_btnode_info *bti,
                       struct silofs_dirtyq      *dq);

void silofs_bti_mark_root(struct silofs_btnode_info *bti);

size_t silofs_bti_nkeys(const struct silofs_btnode_info *bti);

size_t silofs_bti_nchilds(const struct silofs_btnode_info *bti);

void silofs_bti_child_at(const struct silofs_btnode_info *bti, size_t slot,
                         struct silofs_paddr *out_paddr);

int silofs_bti_resolve(const struct silofs_btnode_info *bti,
                       const struct silofs_laddr       *laddr,
                       struct silofs_paddr             *out_paddr);

int silofs_bti_expand(struct silofs_btnode_info *bti,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr);

void silofs_bti_setapex(struct silofs_btnode_info *bti,
                        const struct silofs_paddr *paddr);

void silofs_bti_dirtify(struct silofs_btnode_info *bti);

void silofs_bti_undirtify(struct silofs_btnode_info *bti);

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_btleaf_info *
silofs_bli_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_bli_del(struct silofs_btleaf_info *bli,
                    struct silofs_alloc       *alloc);

void silofs_bli_set_dq(struct silofs_btleaf_info *bli,
                       struct silofs_dirtyq      *dq);

void silofs_bli_dirtify(struct silofs_btleaf_info *bli);

void silofs_bli_undirtify(struct silofs_btleaf_info *bli);

int silofs_bli_resolve(const struct silofs_btleaf_info *bli,
                       const struct silofs_laddr       *laddr,
                       struct silofs_paddr             *out_paddr);

int silofs_bli_extend(struct silofs_btleaf_info *bli,
                      const struct silofs_laddr *laddr,
                      const struct silofs_paddr *paddr);

struct silofs_btleaf_info *
silofs_bli_from_pni(const struct silofs_pnode_info *pni);

#endif /* SILOFS_PNODES_H_ */
