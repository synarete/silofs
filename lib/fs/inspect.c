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


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_sp_visitor {
	struct silofs_visitor           vis;
	struct silofs_spacestats        sp_st;
	struct silofs_spleaf_urefs      urefs;
	silofs_visit_taddr_fn           cb;
};

static bool spvis_unique_tsegid(const struct silofs_sp_visitor *sp_vis,
                                const struct silofs_tsegid *tsegid, size_t cnt)
{
	if (tsegid_isnull(tsegid)) {
		return false;
	}
	for (size_t i = 0; i < cnt; ++i) {
		if (tsegid_isequal(tsegid, &sp_vis->urefs.subs[i].tsegid)) {
			return false;
		}
	}
	return true;
}

static void
spvis_exec_at_spleaf(struct silofs_sp_visitor *sp_vis,
                     const struct silofs_spleaf_info *sli, loff_t voff)
{
	const struct silofs_taddr *taddr = NULL;

	silofs_sli_childrens(sli, &sp_vis->urefs);
	for (size_t i = 0; i < ARRAY_SIZE(sp_vis->urefs.subs); ++i) {
		taddr = &sp_vis->urefs.subs[i];
		if (spvis_unique_tsegid(sp_vis, &taddr->tsegid, i)) {
			sp_vis->cb(taddr, voff);
		}
		voff = off_next_lbk(voff);
	}
}

static int spvis_exec_at(struct silofs_sp_visitor *sp_vis,
                         const struct silofs_walk_iter *witr)
{
	switch (witr->height) {
	case SILOFS_HEIGHT_UBER:
		break;
	case SILOFS_HEIGHT_SUPER:
		sp_vis->cb(sbi_taddr(witr->sbi), witr->voff);
		sp_vis->sp_st.objs.nsuper++;
		break;
	case SILOFS_HEIGHT_SPNODE4:
		sp_vis->cb(sni_taddr(witr->sni4), witr->voff);
		sp_vis->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPNODE3:
		sp_vis->cb(sni_taddr(witr->sni3), witr->voff);
		sp_vis->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPNODE2:
		sp_vis->cb(sni_taddr(witr->sni2), witr->voff);
		sp_vis->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		sp_vis->cb(sni_taddr(witr->sni1), witr->voff);
		sp_vis->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPLEAF:
		sp_vis->cb(sli_taddr(witr->sli), witr->voff);
		spvis_exec_at_spleaf(sp_vis, witr->sli, witr->voff);
		sp_vis->sp_st.objs.nspleaf++;
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		break;
	}
	return 0;
}

static struct silofs_sp_visitor *spvis_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_sp_visitor, vis);
}

static int spvis_exec_hook(struct silofs_visitor *vis,
                           const struct silofs_walk_iter *witr)
{
	return spvis_exec_at(spvis_of(vis), witr);
}

static void noop_callback(const struct silofs_taddr *taddr, loff_t voff)
{
	silofs_unused(taddr);
	silofs_unused(voff);
}

static void spvis_init(struct silofs_sp_visitor *sp_vis,
                       silofs_visit_taddr_fn cb)
{
	silofs_memzero(sp_vis, sizeof(*sp_vis));
	sp_vis->vis.exec_hook = spvis_exec_hook;
	sp_vis->cb = cb ? cb : noop_callback;
}

static void spvis_fini(struct silofs_sp_visitor *sp_vis)
{
	silofs_memzero(sp_vis, sizeof(*sp_vis));
}

static struct silofs_sp_visitor *
spvis_new(struct silofs_alloc *alloc, silofs_visit_taddr_fn cb)
{
	struct silofs_sp_visitor *sp_vis = NULL;

	sp_vis = silofs_allocate(alloc, sizeof(*sp_vis), 0);
	if (sp_vis != NULL) {
		spvis_init(sp_vis, cb);
	}
	return sp_vis;
}

static void spvis_del(struct silofs_sp_visitor *sp_vis,
                      struct silofs_alloc *alloc)
{
	spvis_fini(sp_vis);
	silofs_deallocate(alloc, sp_vis, sizeof(*sp_vis), 0);
}

int silofs_walk_inspect_fs(struct silofs_task *task,
                           struct silofs_sb_info *sbi,
                           silofs_visit_taddr_fn cb)
{
	struct silofs_alloc *alloc = task->t_uber->ub.alloc;
	struct silofs_sp_visitor *sp_vis = NULL;
	int ret;

	sp_vis = spvis_new(alloc, cb);
	if (sp_vis == NULL) {
		return -SILOFS_ENOMEM;
	}
	ret = silofs_walk_space_tree(task, sbi, &sp_vis->vis);
	spvis_del(sp_vis, alloc);
	return ret;
}
