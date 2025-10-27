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
#ifndef SILOFS_BTREE_H_
#define SILOFS_BTREE_H_

#include "infra.h"
#include "addr.h"

struct silofs_bcache;
struct silofs_repo;

/* b+tree base refs  */
struct silofs_btree_base {
	struct silofs_bcache *bcache;
	struct silofs_repo   *repo;
};

/* b+tree in-memory control object */
struct silofs_btree {
	struct silofs_btree_base bt_base;
	struct silofs_baddr      bt_root;
};

void silofs_btree_init(struct silofs_btree            *btree,
                       const struct silofs_btree_base *base);

void silofs_btree_fini(struct silofs_btree *btree);

void silofs_btree_update_root(struct silofs_btree       *btree,
                              const struct silofs_baddr *baddr);

int silofs_btree_format(struct silofs_btree *btree);

int silofs_btree_lookup(struct silofs_btree       *btree,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_baddr       *out_baddr);

int silofs_btree_insert(struct silofs_btree       *btree,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_baddr *baddr);

#endif /* SILOFS_BTREE_H_ */
