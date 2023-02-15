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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>

/*
 * TODO-0041: Proper space accounting
 *
 * Do full space-stats collection and export result to caller. Verify collected
 * stats against top-level space-stats accountings.
 */


/*
 * TODO-0049: Proper file-system traverse and repair
 *
 * Extend fsck logic to enable file-system repair.
 */

struct silofs_space_visitor {
	struct silofs_visitor    vis;
	struct silofs_spacestats spst;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int spvi_visit_exec_at(struct silofs_space_visitor *spvi,
                              const struct silofs_space_iter *spit)
{
	struct silofs_spacestats *spst = &spvi->spst;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		spst->objs.nspleaf++;
		break;
	case SILOFS_HEIGHT_SPNODE1:
	case SILOFS_HEIGHT_SPNODE2:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE5:
		spst->objs.nspnode++;
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_LAST:
	default:
		break;
	}
	return 0;
}

static int spvi_visit_post_at(struct silofs_space_visitor *spvi,
                              const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sbi);
	silofs_unused(spvi);
	return 0;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_space_visitor *spvi_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_space_visitor, vis);
}

static int spvi_visit_exec_hook(struct silofs_visitor *vis,
                                const struct silofs_space_iter *uit)
{
	return spvi_visit_exec_at(spvi_of(vis), uit);
}

static int spvi_visit_post_hook(struct silofs_visitor *vis,
                                const struct silofs_space_iter *uit)
{
	return spvi_visit_post_at(spvi_of(vis), uit);
}

static void spvi_init(struct silofs_space_visitor *spvi)
{
	silofs_memzero(spvi, sizeof(*spvi));
	spvi->vis.exec_hook = spvi_visit_exec_hook;
	spvi->vis.post_hook = spvi_visit_post_hook;
}

static void spvi_fini(struct silofs_space_visitor *spvi)
{
	silofs_memffff(spvi, sizeof(*spvi));
}

int silofs_walk_inspect_fs(struct silofs_task *task,
                           struct silofs_sb_info *sbi)
{
	struct silofs_space_visitor spvi;
	int ret;

	spvi_init(&spvi);
	ret = silofs_walk_space_tree(task, sbi, &spvi.vis);
	spvi_fini(&spvi);
	return ret;
}



