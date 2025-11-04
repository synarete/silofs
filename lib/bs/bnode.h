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
#ifndef SILOFS_BNODE_H_
#define SILOFS_BNODE_H_

#include "addr.h"
#include "crypt.h"
#include "cache.h"

#define SILOFS_BTREE_KEY_NULL (0)

/* base of all blob-store nodes */
struct silofs_bnode_info {
	struct silofs_ivkey      bn_ivkey;
	struct silofs_baddr      bn_baddr;
	struct silofs_hmapq_elem bn_hmqe;
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

#endif /* SILOFS_BNODE_H_ */
