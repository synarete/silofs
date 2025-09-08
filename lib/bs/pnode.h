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
#ifndef SILOFS_PNODE_H_
#define SILOFS_PNODE_H_

#include "addr.h"
#include "hmdq.h"

#define SILOFS_BTREE_KEY_NULL (0)

struct silofs_baddr;
struct silofs_bstore;

/* base of all persistent-segment nodes */
struct silofs_pnode_info {
	struct silofs_baddr      pn_baddr;
	struct silofs_hmapq_elem pn_hmqe;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pni_init(struct silofs_pnode_info  *pni,
                     const struct silofs_baddr *baddr);

void silofs_pni_fini(struct silofs_pnode_info *pni);

enum silofs_mtype silofs_pni_mtype(const struct silofs_pnode_info *pni);

void silofs_pni_dirtify(struct silofs_pnode_info *pni);

void silofs_pni_undirtify(struct silofs_pnode_info *pni);

void silofs_pni_incref(struct silofs_pnode_info *pni);

void silofs_pni_decref(struct silofs_pnode_info *pni);

void silofs_pni_set_dq(struct silofs_pnode_info *pni,
                       struct silofs_dirtyq     *dq);

#endif /* SILOFS_PNODE_H_ */
