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
#ifndef SILOFS_PNODES_H_
#define SILOFS_PNODES_H_

#include "addr.h"
#include "dirtyq.h"
#include "hmapq.h"
#include "view.h"

/* base of all persistent nodes */
struct silofs_pnode_info {
	struct silofs_pnptr      pn_self;
	struct silofs_hmapq_elem pn_hmqe;
	struct silofs_pview     *pn_pview;
};

/* uber-node in-memory state */
struct silofs_uber_info {
	struct silofs_pnode_info ub_pni;
	struct silofs_uber_node *ubn;
};

/* blob-descriptor node */
struct silofs_bldesc_info {
	struct silofs_pnode_info bld_pni;
	struct silofs_blob_desc *bld;
};

/* btree-node */
struct silofs_btnode_info {
	struct silofs_pnode_info  btn_pni;
	struct silofs_btree_node *btn;
	size_t                    btp_nsub_vobjs;
	size_t                    btp_nsub_btnodes;
	bool                      btn_rdonly;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_pnptr *
silofs_pni_self(const struct silofs_pnode_info *pni);

enum silofs_ptype silofs_pni_ptype(const struct silofs_pnode_info *pni);

void silofs_pni_dirtify(struct silofs_pnode_info *pni);

void silofs_pni_undirtify(struct silofs_pnode_info *pni);

void silofs_pni_incref(struct silofs_pnode_info *pni);

void silofs_pni_decref(struct silofs_pnode_info *pni);

void silofs_pni_set_dq(struct silofs_pnode_info *pni,
                       struct silofs_dirtyq     *dq);

const struct silofs_paddr *
silofs_pni_paddr(const struct silofs_pnode_info *pni);

const struct silofs_layerid *
silofs_pni_layerid(const struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_info *
silofs_ubi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_bldesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *silofs_new_pnode(const struct silofs_pnptr *pnptr, //
                                           struct silofs_alloc       *alloc);

void silofs_del_pnode(struct silofs_pnode_info *pni,
                      struct silofs_alloc      *alloc);

int silofs_encrypt_pnode(const struct silofs_pnode_info *pni,
                         const struct silofs_cipher_hd  *ci_hd,
                         struct silofs_pview            *enc_pview);

int silofs_decrypt_pnode(struct silofs_pnode_info      *pni,
                         const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_pview     *enc_pview);

int silofs_verify_pnode(const struct silofs_pnode_info *pni);

void silofs_seal_pnode(struct silofs_pnode_info *pni);

#endif /* SILOFS_PNODES_H_ */
