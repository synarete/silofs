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

#include <silofs/infra.h>
#include <silofs/addr.h>

struct silofs_pcache;
struct silofs_repo;

/* b+tree in-memory control object */
struct silofs_btree {
	struct silofs_pcache *bt_pcache;
	struct silofs_repo   *bt_repo;
	struct silofs_paddr   bt_root;
};

void silofs_btree_init(struct silofs_btree  *btree,
                       struct silofs_pcache *pcache, struct silofs_repo *repo);

void silofs_btree_fini(struct silofs_btree *btree);

void silofs_btree_update_root(struct silofs_btree       *btree,
                              const struct silofs_paddr *paddr);

int silofs_btree_lookup(const struct silofs_btree *btree,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_paddr       *out_paddr);

#endif /* SILOFS_BTREE_H_ */
