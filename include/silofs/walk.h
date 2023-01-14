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
#include <silofs/types.h>


struct silofs_visitor;
struct silofs_space_iter;

typedef int (*silofs_visit_fn)(struct silofs_visitor *vis,
                               const struct silofs_space_iter *spit);

struct silofs_space_iter {
	struct silofs_sb_info      *sbi;
	struct silofs_spnode_info  *sni5;
	struct silofs_spnode_info  *sni4;
	struct silofs_spnode_info  *sni3;
	struct silofs_spnode_info  *sni2;
	struct silofs_spnode_info  *sni1;
	struct silofs_spleaf_info  *sli;
	enum silofs_height          height;
	enum silofs_stype           vspace;
	loff_t                      voff;
};

struct silofs_visitor {
	silofs_visit_fn exec_hook;
	silofs_visit_fn post_hook;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_walk_space_tree(struct silofs_task *task,
                           struct silofs_sb_info *sbi,
                           struct silofs_visitor *vis, bool warm);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_walk_inspect_fs(struct silofs_task *task,
                           struct silofs_sb_info *sbi);

int silofs_walk_unref_fs(struct silofs_task *task,
                         struct silofs_sb_info *sbi);

#endif /* SILOFS_WALK_H_ */
