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
#include <silofs/fs/private.h>

/*
 * TODO-0041: Proper space accounting
 *
 * Do full space-stats collection and export result to caller. Verify collected
 * stats against top-level space-stats accountings.
 */

struct silofs_space_visitor {
	struct silofs_visitor    vis;
	struct silofs_spacestats spst;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int spvi_visit_prep_by(struct silofs_space_visitor *spvi,
                              const struct silofs_uiterator *uit)
{
	silofs_assert_not_null(uit->parent);
	silofs_unused(spvi);
	return 0;
}

static int spvi_visit_exec_at(struct silofs_space_visitor *spvi,
                              const struct silofs_uiterator *uit)
{
	struct silofs_spacestats *spst = &spvi->spst;
	const struct silofs_uaddr *uaddr = ui_uaddr(uit->ui);
	const enum silofs_stype stype = uaddr->stype;

	silofs_assert(!stype_isvnode(stype));
	if (stype_issuper(stype)) {
		spst->objs.nsuper++;
	} else if (stype_isspstats(stype)) {
		spst->objs.nspstats++;
	} else if (stype_isspnode(stype)) {
		spst->objs.nspnode++;
	} else if (stype_isspleaf(stype)) {
		spst->objs.nspleaf++;
	}
	return 0;
}

static int spvi_visit_post_at(struct silofs_space_visitor *spvi,
                              const struct silofs_uiterator *uit)
{
	silofs_assert_not_null(uit->ui);
	silofs_unused(spvi);
	return 0;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_space_visitor *spvi_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_space_visitor, vis);
}

static int spvi_visit_prep_by_hook(struct silofs_visitor *vis,
                                   const struct silofs_uiterator *uit)
{
	return spvi_visit_prep_by(spvi_of(vis), uit);
}

static int spvi_visit_exec_at_hook(struct silofs_visitor *vis,
                                   const struct silofs_uiterator *uit)
{
	silofs_assert_not_null(uit->ui);
	return spvi_visit_exec_at(spvi_of(vis), uit);
}

static int spvi_visit_post_at_hook(struct silofs_visitor *vis,
                                   const struct silofs_uiterator *uit)
{
	silofs_assert_not_null(uit->ui);
	return spvi_visit_post_at(spvi_of(vis), uit);
}

static void spvi_init(struct silofs_space_visitor *spvi)
{
	silofs_memzero(spvi, sizeof(*spvi));
	spvi->vis.visit_prep_by_hook = spvi_visit_prep_by_hook;
	spvi->vis.visit_exec_at_hook = spvi_visit_exec_at_hook;
	spvi->vis.visit_post_at_hook = spvi_visit_post_at_hook;
}

static void spvi_fini(struct silofs_space_visitor *spvi)
{
	silofs_memffff(spvi, sizeof(*spvi));
}

int silofs_inspect_fs(struct silofs_sb_info *sbi)
{
	struct silofs_space_visitor spvi;
	int ret;

	spvi_init(&spvi);
	ret = silofs_walk_space_tree(sbi, &spvi.vis);
	spvi_fini(&spvi);
	return ret;
}



