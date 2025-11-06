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
#ifndef SILOFS_BNODES_H_
#define SILOFS_BNODES_H_

#include "addr.h"
#include "crypt.h"
#include "dirtyq.h"
#include "hmapq.h"
#include "view.h"

/* base of all blob-store nodes */
struct silofs_bnode_info {
	struct silofs_ivkey      bn_ivkey;
	struct silofs_baddr      bn_baddr;
	struct silofs_hmapq_elem bn_hmqe;
	struct silofs_view      *bn_view;
};

/* uber-block in-memory state */
struct silofs_ub_info {
	struct silofs_bnode_info  ub_bni;
	struct silofs_uber_block *ub;
};

/* blob-descriptor node */
struct silofs_bldesc_info {
	struct silofs_bnode_info bd_bni;
	struct silofs_blob_desc *bd;
};

/* btree-node */
struct silofs_btnode_info {
	struct silofs_bnode_info  btn_bni;
	struct silofs_btree_node *btn;
	bool                      btn_rdonly;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bni_init(struct silofs_bnode_info  *bni,
                     const struct silofs_baddr *baddr);

void silofs_bni_fini(struct silofs_bnode_info *bni);

enum silofs_mtype silofs_bni_mtype(const struct silofs_bnode_info *bni);

void silofs_bni_dirtify(struct silofs_bnode_info *bni);

void silofs_bni_undirtify(struct silofs_bnode_info *bni);

void silofs_bni_incref(struct silofs_bnode_info *bni);

void silofs_bni_decref(struct silofs_bnode_info *bni);

void silofs_bni_set_dq(struct silofs_bnode_info *bni,
                       struct silofs_dirtyq     *dq);

void silofs_bni_setup_ivkey(struct silofs_bnode_info    *bni,
                            const struct silofs_mdigest *md,
                            const struct silofs_key     *key);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_ub_info *
silofs_ubi_from_bni(const struct silofs_bnode_info *bni);

struct silofs_bldesc_info *
silofs_bdi_from_bni(const struct silofs_bnode_info *bni);

struct silofs_btnode_info *
silofs_bti_from_bni(const struct silofs_bnode_info *bni);

struct silofs_bnode_info *
silofs_new_bnode(const struct silofs_baddr *baddr, struct silofs_alloc *alloc);

void silofs_del_bnode(struct silofs_bnode_info *bni,
                      struct silofs_alloc      *alloc);

#endif /* SILOFS_BNODES_H_ */
