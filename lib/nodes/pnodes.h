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

#include "addr.h"
#include "crypt.h"
#include "dirtyq.h"
#include "hmapq.h"
#include "view.h"

/* persistent nodes meta params */
struct silofs_pmeta {
	struct silofs_paddr  paddr;
	struct silofs_ivkey  ivkey;
	struct silofs_ciargs ciargs;
};

/* base of all persistent nodes */
struct silofs_pnode_info {
	struct silofs_pmeta      pn_meta;
	struct silofs_hmapq_elem pn_hmqe;
	struct silofs_view      *pn_view;
};

/* uber-block in-memory state */
struct silofs_uber_info {
	struct silofs_pnode_info  ub_pni;
	struct silofs_uber_block *ub;
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
	bool                      btn_rdonly;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_derive_iv_by(const struct silofs_mdigest *mdigest,
                         const struct silofs_paddr   *paddr,
                         struct silofs_iv            *out_iv);

void silofs_derive_key_by(const struct silofs_mdigest *mdigest,
                          const struct silofs_paddr   *paddr,
                          struct silofs_key           *out_key);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_pmeta *silofs_pmeta_none(void);

void silofs_pmeta_reset(struct silofs_pmeta *pmeta);

void silofs_pmeta_assign(struct silofs_pmeta       *pmeta,
                         const struct silofs_pmeta *other);

bool silofs_pmeta_isnull(const struct silofs_pmeta *pmeta);

void silofs_pmeta192b_htox(struct silofs_pmeta192b   *pmeta192,
                           const struct silofs_pmeta *pmeta);

void silofs_pmeta192b_xtoh(const struct silofs_pmeta192b *pmeta192,
                           struct silofs_pmeta           *pmeta);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum silofs_mtype silofs_pni_mtype(const struct silofs_pnode_info *pni);

void silofs_pni_dirtify(struct silofs_pnode_info *pni);

void silofs_pni_undirtify(struct silofs_pnode_info *pni);

void silofs_pni_incref(struct silofs_pnode_info *pni);

void silofs_pni_decref(struct silofs_pnode_info *pni);

void silofs_pni_set_dq(struct silofs_pnode_info *pni,
                       struct silofs_dirtyq     *dq);

void silofs_pni_setup_ivkey(struct silofs_pnode_info    *pni,
                            const struct silofs_mdigest *md,
                            const struct silofs_key     *key);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_info *
silofs_ubi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_bldesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni);

struct silofs_pnode_info *
silofs_new_pnode(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_del_pnode(struct silofs_pnode_info *pni,
                      struct silofs_alloc      *alloc);

int silofs_encrypt_pnode(const struct silofs_pnode_info *pni,
                         const struct silofs_cipher     *cipher,
                         struct silofs_view             *enc_view);

int silofs_decrypt_pnode(struct silofs_pnode_info   *pni,
                         const struct silofs_cipher *cipher,
                         const struct silofs_view   *enc_view);

int silofs_verify_pnode(const struct silofs_pnode_info *pni);

void silofs_seal_pnode(struct silofs_pnode_info *pni);

#endif /* SILOFS_PNODES_H_ */
