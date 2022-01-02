/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_WALK_H_
#define SILOFS_WALK_H_

#include <silofs/infra.h>
#include <silofs/fs/types.h>


struct silofs_visitor;

typedef int (*silofs_visit_unode_fn)(struct silofs_visitor *vis,
                                     struct silofs_unode_info *ui);

struct silofs_visitor {
	silofs_visit_unode_fn start_hook;
	silofs_visit_unode_fn finish_hook;
	bool nodescend;
	bool halt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_usaddr_info {
	struct silofs_avl_node  us_an;
	struct silofs_uaddr     us_uaddr;
	size_t us_refcnt;
};

struct silofs_usaddr_set {
	struct silofs_avl       uss_avl;
	struct silofs_alloc_if *uss_alif;
};

struct silofs_uspace_visitor {
	struct silofs_visitor    vis;
	struct silofs_usaddr_set uss;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_usvisitor_init(struct silofs_uspace_visitor *usv,
                           struct silofs_alloc_if *alif);

void silofs_usvisitor_fini(struct silofs_uspace_visitor *usv);

int silofs_walk_space_tree(struct silofs_fs_apex *apex,
                           struct silofs_visitor *vis);


#endif /* SILOFS_WALK_H_ */
