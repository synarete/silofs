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

enum silofs_pnodef {
	SILOFS_PNODEF_NONE      = 0x00,
	SILOFS_PNODEF_STAGED_OK = 0x01,
	SILOFS_PNODEF_RDONLY    = 0x02,
	SILOFS_PNODEF_STAINED   = 0x04,
};

/* base of all persistent nodes */
struct silofs_pnode_info {
	struct silofs_node_info pn_ni;
	struct silofs_pnptr     pn_self;
	struct silofs_ctag      pn_ctag;
	struct silofs_list_head pn_dsq_lh;
	unsigned int            pn_flags;
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
	bool                      btn_stained;
};

const struct silofs_pnptr *
silofs_pni_self(const struct silofs_pnode_info *pni);

void silofs_pni_setdirty(struct silofs_pnode_info *pni);

void silofs_pni_cleardirty(struct silofs_pnode_info *pni);

void silofs_pni_incref(struct silofs_pnode_info *pni);

void silofs_pni_decref(struct silofs_pnode_info *pni);

void silofs_pni_set_dq(struct silofs_pnode_info *pni,
                       struct silofs_dirtyq     *dq);

struct silofs_pview *       //
silofs_pni_pview(const struct silofs_pnode_info *pni);

struct silofs_pview *       //
silofs_pni_pviewx(const struct silofs_pnode_info *pni);

enum silofs_ptype           //
silofs_pni_ptype(const struct silofs_pnode_info *pni);

const struct silofs_stype * //
silofs_pni_stype(const struct silofs_pnode_info *pni);

const struct silofs_paddr *
silofs_pni_paddr(const struct silofs_pnode_info *pni);

const struct silofs_blobid *
silofs_pni_blobid(const struct silofs_pnode_info *pni);

const struct silofs_layerid *
silofs_pni_layerid(const struct silofs_pnode_info *pni);

const struct silofs_nmeta *
silofs_pni_nmeta(const struct silofs_pnode_info *pni);

const struct silofs_civkey *
silofs_pni_civkey(const struct silofs_pnode_info *pni);

struct silofs_pnode_info *
silofs_pni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_pnode_info *       //
silofs_pni_from_mut_ni(struct silofs_node_info *ni);

const struct silofs_pnode_info * //
silofs_pni_from_ni(const struct silofs_node_info *ni);

void silofs_pni_update_ctag(struct silofs_pnode_info *pni,
                            const struct silofs_ctag *ctag);

void silofs_pni_apply_ctag(struct silofs_pnode_info *pni);

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

int silofs_verify_pview_of(const struct silofs_pnode_info *pni);

void silofs_seal_pview_of(const struct silofs_pnode_info *pni);

#endif /* SILOFS_PNODES_H_ */
