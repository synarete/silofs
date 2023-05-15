/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

static int spvis_visit_exec_at(struct silofs_space_visitor *spvis,
                               const struct silofs_space_iter *spit)
{
	struct silofs_spacestats *spst = &spvis->spst;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		spst->objs.nspleaf++;
		break;
	case SILOFS_HEIGHT_SPNODE1:
	case SILOFS_HEIGHT_SPNODE2:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE4:
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

static int spvis_visit_post_at(struct silofs_space_visitor *spvis,
                               const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sbi);
	silofs_unused(spvis);
	return 0;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_space_visitor *spvis_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_space_visitor, vis);
}

static int spvis_visit_exec_hook(struct silofs_visitor *vis,
                                 const struct silofs_space_iter *spit)
{
	return spvis_visit_exec_at(spvis_of(vis), spit);
}

static int spvis_visit_post_hook(struct silofs_visitor *vis,
                                 const struct silofs_space_iter *spit)
{
	return spvis_visit_post_at(spvis_of(vis), spit);
}

static void spvis_init(struct silofs_space_visitor *spvis)
{
	silofs_memzero(spvis, sizeof(*spvis));
	spvis->vis.exec_hook = spvis_visit_exec_hook;
	spvis->vis.post_hook = spvis_visit_post_hook;
}

static void spvis_fini(struct silofs_space_visitor *spvis)
{
	silofs_memffff(spvis, sizeof(*spvis));
}

int silofs_walk_inspect_fs(struct silofs_task *task,
                           struct silofs_sb_info *sbi)
{
	struct silofs_space_visitor spvis;
	int ret;

	spvis_init(&spvis);
	ret = silofs_walk_space_tree(task, sbi, &spvis.vis);
	spvis_fini(&spvis);
	return ret;
}



