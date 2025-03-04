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
#include "configs.h"
#include <silofs/infra.h>
#include "uber.h"
#include "lnodes.h"
#include "task.h"
#include "super.h"
#include "inode.h"
#include "env.h"
#include "spmaps.h"
#include "stage.h"
#include "walk.h"

#define check_ok_or_bailout(err_)      \
	do {                           \
		if (err_)              \
			return (err_); \
	} while (0)

struct silofs_walk_ctx {
	struct silofs_task *task;
	struct silofs_visitor *vis;
	struct silofs_env *env;
	struct silofs_sb_info *sbi;
	struct silofs_spnode_info *sni4;
	struct silofs_spnode_info *sni3;
	struct silofs_spnode_info *sni2;
	struct silofs_spnode_info *sni1;
	struct silofs_spleaf_info *sli;
	enum silofs_height height;
	enum silofs_ltype vspace;
	loff_t voff;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
sbi_vrange(const struct silofs_sb_info *sbi, struct silofs_vrange *out_vrange)
{
	const loff_t voff_end = silofs_sbst_vspace_end(sbi);

	silofs_vrange_setup(out_vrange, SILOFS_HEIGHT_SUPER, 0, voff_end);
}

static bool sni_has_subref(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_ulink ulink;

	return silofs_sni_resolve_child(sni, voff, &ulink) == 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void wit_increfs(const struct silofs_walk_iter *witr)
{
	sbi_incref(witr->sbi);
	sni_incref(witr->sni4);
	sni_incref(witr->sni3);
	sni_incref(witr->sni2);
	sni_incref(witr->sni1);
	sli_incref(witr->sli);
}

static void wit_decrefs(const struct silofs_walk_iter *witr)
{
	sli_decref(witr->sli);
	sni_decref(witr->sni1);
	sni_decref(witr->sni2);
	sni_decref(witr->sni3);
	sni_decref(witr->sni4);
	sbi_decref(witr->sbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void wac_setup_space_iter(const struct silofs_walk_ctx *wa_ctx,
                                 struct silofs_walk_iter *witr)
{
	silofs_memzero(witr, sizeof(*witr));
	witr->sbi = wa_ctx->sbi;
	witr->sni4 = wa_ctx->sni4;
	witr->sni3 = wa_ctx->sni3;
	witr->sni2 = wa_ctx->sni2;
	witr->sni1 = wa_ctx->sni1;
	witr->sli = wa_ctx->sli;
	witr->height = wa_ctx->height;
	witr->vspace = wa_ctx->vspace;
	witr->voff = wa_ctx->voff;
}

static void
wac_resetup(struct silofs_walk_ctx *wa_ctx, enum silofs_ltype vspace)
{
	wa_ctx->vspace = vspace;
	wa_ctx->sni4 = NULL;
	wa_ctx->sni3 = NULL;
	wa_ctx->sni2 = NULL;
	wa_ctx->sni1 = NULL;
	wa_ctx->sli = NULL;
	wa_ctx->voff = 0;
}

static void wac_relax_cache(const struct silofs_walk_ctx *wa_ctx)
{
	silofs_env_relax_caches(wa_ctx->env, SILOFS_CTLF_OPSTART);
}

static void wac_push_height(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->height -= 1;
}

static void wac_pop_height(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->height += 1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_do_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_walk_iter *witr)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->exec_hook) {
		wac_relax_cache(wa_ctx);
		ret = vis->exec_hook(vis, witr);
	}
	return ret;
}

static int wac_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_walk_iter *witr)
{
	int err;

	wit_increfs(witr);
	err = wac_do_visit_exec_at(wa_ctx, witr);
	wit_decrefs(witr);
	return err;
}

static int wac_do_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_walk_iter *witr)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->post_hook) {
		wac_relax_cache(wa_ctx);
		ret = vis->post_hook(vis, witr);
	}
	return ret;
}

static int wac_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_walk_iter *witr)
{
	int err;

	wit_increfs(witr);
	err = wac_do_visit_post_at(wa_ctx, witr);
	wit_decrefs(witr);
	return err;
}

static int wac_visit_exec_at_unode(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_walk_iter witr;

	wac_setup_space_iter(wa_ctx, &witr);
	return wac_visit_exec_at(wa_ctx, &witr);
}

static int wac_visit_post_at_unode(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_walk_iter witr;

	wac_setup_space_iter(wa_ctx, &witr);
	return wac_visit_post_at(wa_ctx, &witr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_stage_spnode_at(const struct silofs_walk_ctx *wa_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spnode_info **out_sni)
{
	return silofs_stage_spnode(wa_ctx->env, ulink, out_sni);
}

static int wac_stage_spleaf_at(const struct silofs_walk_ctx *wa_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf(wa_ctx->env, ulink, out_sli);
}

static int wac_stage_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	struct silofs_vrange vrange;
	int err;

	sbi_vrange(wa_ctx->sbi, &vrange);
	if (wa_ctx->voff > vrange.end) {
		return -SILOFS_ENOENT;
	}
	err = silofs_sbi_resolve_child(wa_ctx->sbi, wa_ctx->vspace, &ulink);
	check_ok_or_bailout(err);

	err = wac_stage_spnode_at(wa_ctx, &ulink, &wa_ctx->sni4);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_stage_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = silofs_sni_resolve_child(wa_ctx->sni4, wa_ctx->voff, &ulink);
	check_ok_or_bailout(err);

	err = wac_stage_spnode_at(wa_ctx, &ulink, &wa_ctx->sni3);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_stage_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = silofs_sni_resolve_child(wa_ctx->sni3, wa_ctx->voff, &ulink);
	check_ok_or_bailout(err);

	err = wac_stage_spnode_at(wa_ctx, &ulink, &wa_ctx->sni2);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_stage_spnode1(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };
	int err;

	err = silofs_sni_resolve_child(wa_ctx->sni2, wa_ctx->voff, &ulink);
	check_ok_or_bailout(err);

	err = wac_stage_spnode_at(wa_ctx, &ulink, &wa_ctx->sni1);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_stage_spleaf(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_ulink ulink;
	int err;

	err = silofs_sni_resolve_child(wa_ctx->sni1, wa_ctx->voff, &ulink);
	check_ok_or_bailout(err);

	err = wac_stage_spleaf_at(wa_ctx, &ulink, &wa_ctx->sli);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_do_traverse_spleaf(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_unode(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_visit_post_at_unode(wa_ctx);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_traverse_spleaf(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	sli_incref(wa_ctx->sli);
	err = wac_do_traverse_spleaf(wa_ctx);
	sli_decref(wa_ctx->sli);
	return err;
}

static void wac_depart_spleaf(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->sli = NULL;
}

static int wac_do_traverse_spnode1_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spleaf(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_spleaf(wa_ctx);
	check_ok_or_bailout(err);

	wac_depart_spleaf(wa_ctx);
	return 0;
}

static int wac_traverse_spnode1_child(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	wac_push_height(wa_ctx);
	ret = wac_do_traverse_spnode1_child(wa_ctx);
	wac_pop_height(wa_ctx);
	return ret;
}

static int wac_do_traverse_spnode1(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err = 0;

	silofs_sni_vspace_range(wa_ctx->sni1, &vrange);
	wa_ctx->voff = vrange.beg;
	while (wa_ctx->voff < vrange.end) {
		voff = wa_ctx->voff;
		if (!sni_has_subref(wa_ctx->sni1, wa_ctx->voff)) {
			break;
		}
		err = wac_traverse_spnode1_child(wa_ctx);
		if (err && (err != -SILOFS_ENOENT)) {
			break;
		}
		wa_ctx->voff = silofs_vrange_next(&vrange, voff);
	}
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

static int wac_traverse_spnode1(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	sni_incref(wa_ctx->sni1);
	ret = wac_do_traverse_spnode1(wa_ctx);
	sni_decref(wa_ctx->sni1);
	return ret;
}

static int wac_traverse_at_spnode1(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_unode(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_spnode1(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_visit_post_at_unode(wa_ctx);
	check_ok_or_bailout(err);
	return 0;
}

static void wac_depart_spnode1(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->sni1 = NULL;
}

static int wac_do_traverse_spnode2_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spnode1(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_at_spnode1(wa_ctx);
	check_ok_or_bailout(err);

	wac_depart_spnode1(wa_ctx);
	return 0;
}

static int wac_traverse_spnode2_child(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	wac_push_height(wa_ctx);
	ret = wac_do_traverse_spnode2_child(wa_ctx);
	wac_pop_height(wa_ctx);
	return ret;
}

static int wac_do_traverse_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err = 0;

	silofs_sni_vspace_range(wa_ctx->sni2, &vrange);
	wa_ctx->voff = vrange.beg;
	while (wa_ctx->voff < vrange.end) {
		voff = wa_ctx->voff;
		if (!sni_has_subref(wa_ctx->sni2, wa_ctx->voff)) {
			break;
		}
		err = wac_traverse_spnode2_child(wa_ctx);
		if (err && (err != -SILOFS_ENOENT)) {
			break;
		}
		wa_ctx->voff = silofs_vrange_next(&vrange, voff);
	}
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

static int wac_traverse_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	sni_incref(wa_ctx->sni2);
	ret = wac_do_traverse_spnode2(wa_ctx);
	sni_decref(wa_ctx->sni2);
	return ret;
}

static int wac_traverse_at_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_unode(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_spnode2(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_visit_post_at_unode(wa_ctx);
	check_ok_or_bailout(err);
	return 0;
}

static void wac_depart_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->sni2 = NULL;
}

static int wac_do_traverse_spnode3_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spnode2(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_at_spnode2(wa_ctx);
	check_ok_or_bailout(err);

	wac_depart_spnode2(wa_ctx);
	return 0;
}

static int wac_traverse_spnode3_child(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	wac_push_height(wa_ctx);
	ret = wac_do_traverse_spnode3_child(wa_ctx);
	wac_pop_height(wa_ctx);
	return ret;
}

static int wac_do_traverse_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err = 0;

	silofs_sni_vspace_range(wa_ctx->sni3, &vrange);
	wa_ctx->voff = vrange.beg;
	while (wa_ctx->voff < vrange.end) {
		voff = wa_ctx->voff;
		if (!sni_has_subref(wa_ctx->sni3, wa_ctx->voff)) {
			break;
		}
		err = wac_traverse_spnode3_child(wa_ctx);
		if (err && (err != -SILOFS_ENOENT)) {
			break;
		}
		wa_ctx->voff = silofs_vrange_next(&vrange, voff);
	}
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

static int wac_traverse_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	sni_incref(wa_ctx->sni3);
	ret = wac_do_traverse_spnode3(wa_ctx);
	sni_decref(wa_ctx->sni3);
	return ret;
}

static int wac_traverse_at_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_unode(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_spnode3(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_visit_post_at_unode(wa_ctx);
	check_ok_or_bailout(err);
	return 0;
}

static void wac_depart_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->sni3 = NULL;
}

static int wac_do_traverse_spnode4_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spnode3(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_at_spnode3(wa_ctx);
	check_ok_or_bailout(err);

	wac_depart_spnode3(wa_ctx);
	return 0;
}

static int wac_traverse_spnode4_child(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	wac_push_height(wa_ctx);
	ret = wac_do_traverse_spnode4_child(wa_ctx);
	wac_pop_height(wa_ctx);
	return ret;
}

static int wac_do_traverse_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err = 0;

	silofs_sni_vspace_range(wa_ctx->sni4, &vrange);
	wa_ctx->voff = vrange.beg;
	while (wa_ctx->voff < vrange.end) {
		voff = wa_ctx->voff;
		if (!sni_has_subref(wa_ctx->sni4, wa_ctx->voff)) {
			break;
		}
		err = wac_traverse_spnode4_child(wa_ctx);
		if (err && (err != -SILOFS_ENOENT)) {
			break;
		}
		wa_ctx->voff = silofs_vrange_next(&vrange, voff);
	}
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

static int wac_traverse_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	sni_incref(wa_ctx->sni4);
	ret = wac_do_traverse_spnode4(wa_ctx);
	sni_decref(wa_ctx->sni4);
	return ret;
}

static int wac_traverse_at_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_unode(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_spnode4(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_visit_post_at_unode(wa_ctx);
	check_ok_or_bailout(err);
	return 0;
}

static void wac_depart_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->sni4 = NULL;
}

static int wac_do_traverse_super_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spnode4(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_traverse_at_spnode4(wa_ctx);
	check_ok_or_bailout(err);

	wac_depart_spnode4(wa_ctx);
	return 0;
}

static int wac_traverse_super_child(struct silofs_walk_ctx *wa_ctx)
{
	int ret;

	wac_push_height(wa_ctx);
	ret = wac_do_traverse_super_child(wa_ctx);
	wac_pop_height(wa_ctx);
	return ret;
}

static int wac_do_traverse_sptree(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	err = silofs_sbi_sproot_of(wa_ctx->sbi, wa_ctx->vspace, &uaddr);
	if (err) {
		goto out;
	}
	err = wac_traverse_super_child(wa_ctx);
	if (err) {
		goto out;
	}
out:
	return (err == -SILOFS_ENOENT) ? 0 : err;
}

static int wac_traverse_sptree(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_unode(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_do_traverse_sptree(wa_ctx);
	check_ok_or_bailout(err);

	err = wac_visit_post_at_unode(wa_ctx);
	check_ok_or_bailout(err);
	return 0;
}

static int wac_traverse_sptree_of(struct silofs_walk_ctx *wa_ctx,
                                  enum silofs_ltype vspace)
{
	int err;

	wac_resetup(wa_ctx, vspace);
	err = wac_traverse_sptree(wa_ctx);
	wac_resetup(wa_ctx, SILOFS_LTYPE_NONE);
	return err;
}

static int wac_traverse_spaces(struct silofs_walk_ctx *wa_ctx)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = wac_traverse_sptree_of(wa_ctx, ltype);
		if (err) {
			return err;
		}
		wac_relax_cache(wa_ctx);
	}
	return 0;
}

int silofs_visit_sptree(struct silofs_task *task, struct silofs_sb_info *sbi,
                        struct silofs_visitor *vis)
{
	struct silofs_walk_ctx wa_ctx = {
		.task = task,
		.vis = vis,
		.env = task->t_env,
		.sbi = sbi,
		.height = SILOFS_HEIGHT_SUPER,
	};
	int err;

	sbi_incref(sbi);
	err = wac_traverse_spaces(&wa_ctx);
	sbi_decref(sbi);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

struct silofs_inspect_ctx {
	struct silofs_visitor vis;
	struct silofs_space_stats sp_st;
	struct silofs_spmap_lmap lmap;
	struct silofs_task *task;
	struct silofs_sb_info *sbi;
	silofs_visit_laddr_fn cb;
	void *user_ctx;
};

static int inspc_exec_lmap(const struct silofs_inspect_ctx *insp_ctx)
{
	const struct silofs_laddr *laddr = NULL;
	int err;

	for (size_t i = 0; i < insp_ctx->lmap.cnt; ++i) {
		laddr = &insp_ctx->lmap.laddr[i];
		err = insp_ctx->cb(insp_ctx->user_ctx, laddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int inspc_exec_at_super(struct silofs_inspect_ctx *insp_ctx,
                               const struct silofs_sb_info *sbi)
{
	silofs_sbi_resolve_lmap(sbi, &insp_ctx->lmap);
	return inspc_exec_lmap(insp_ctx);
}

static int inspc_exec_at_spnode(struct silofs_inspect_ctx *insp_ctx,
                                const struct silofs_spnode_info *sni)
{
	silofs_sni_resolve_lmap(sni, &insp_ctx->lmap);
	return inspc_exec_lmap(insp_ctx);
}

static int inspc_exec_at_spleaf(struct silofs_inspect_ctx *insp_ctx,
                                const struct silofs_spleaf_info *sli)
{
	silofs_sli_resolve_lmap(sli, &insp_ctx->lmap);
	return inspc_exec_lmap(insp_ctx);
}

static int inspc_exec_at(struct silofs_inspect_ctx *insp_ctx,
                         const struct silofs_walk_iter *witr)
{
	int ret = 0;

	switch (witr->height) {
	case SILOFS_HEIGHT_SPNODE4:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni4);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni3);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni2);
		break;
	case SILOFS_HEIGHT_SPNODE1:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni1);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		insp_ctx->sp_st.objs.nspleaf++;
		ret = inspc_exec_at_spleaf(insp_ctx, witr->sli);
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_BOOT:
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		break;
	}
	return ret;
}

static struct silofs_inspect_ctx *inspc_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_inspect_ctx, vis);
}

static int inspc_exec_hook(struct silofs_visitor *vis,
                           const struct silofs_walk_iter *witr)
{
	return inspc_exec_at(inspc_of(vis), witr);
}

static int noop_callback(void *ctx, const struct silofs_laddr *laddr)
{
	silofs_unused(laddr);
	silofs_unused(ctx);
	return 0;
}

static void inspc_init(struct silofs_inspect_ctx *insp_ctx,
                       struct silofs_task *task, struct silofs_sb_info *sbi,
                       silofs_visit_laddr_fn cb, void *user_ctx)
{
	silofs_memzero(insp_ctx, sizeof(*insp_ctx));
	insp_ctx->vis.post_hook = inspc_exec_hook;
	insp_ctx->task = task;
	insp_ctx->sbi = sbi;
	insp_ctx->cb = cb ? cb : noop_callback;
	insp_ctx->user_ctx = user_ctx;
}

static void inspc_fini(struct silofs_inspect_ctx *insp_ctx)
{
	silofs_memzero(insp_ctx, sizeof(*insp_ctx));
}

static struct silofs_inspect_ctx *
inspc_new(struct silofs_alloc *alloc, struct silofs_task *task,
          struct silofs_sb_info *sbi, silofs_visit_laddr_fn cb, void *user_ctx)
{
	struct silofs_inspect_ctx *insp_ctx = NULL;

	insp_ctx = silofs_memalloc(alloc, sizeof(*insp_ctx), 0);
	if (insp_ctx != NULL) {
		inspc_init(insp_ctx, task, sbi, cb, user_ctx);
	}
	return insp_ctx;
}

static void
inspc_del(struct silofs_inspect_ctx *insp_ctx, struct silofs_alloc *alloc)
{
	inspc_fini(insp_ctx);
	silofs_memfree(alloc, insp_ctx, sizeof(*insp_ctx), 0);
}

static int inspc_walk_spmaps(struct silofs_inspect_ctx *insp_ctx)
{
	return silofs_visit_sptree(insp_ctx->task, insp_ctx->sbi,
	                           &insp_ctx->vis);
}

static int inspc_walk_super(struct silofs_inspect_ctx *insp_ctx)
{
	const struct silofs_laddr *sb_laddr = sbi_laddr(insp_ctx->sbi);
	int err;

	insp_ctx->sp_st.objs.nsuper++;
	err = inspc_exec_at_super(insp_ctx, insp_ctx->sbi);
	if (err) {
		return err;
	}
	err = insp_ctx->cb(insp_ctx->user_ctx, sb_laddr);
	if (err) {
		return err;
	}
	return 0;
}

static int inspc_walk_boot(struct silofs_inspect_ctx *insp_ctx)
{
	struct silofs_uaddr uber_uaddr = { .voff = -1 };
	const struct silofs_laddr *sb_laddr = sbi_laddr(insp_ctx->sbi);

	silofs_make_uber_uaddr(&sb_laddr->lsid.volid, &uber_uaddr);
	return insp_ctx->cb(insp_ctx->user_ctx, &uber_uaddr.laddr);
}

static int inspc_walk_fs(struct silofs_inspect_ctx *insp_ctx)
{
	int err;

	err = inspc_walk_spmaps(insp_ctx);
	if (err) {
		return err;
	}
	err = inspc_walk_super(insp_ctx);
	if (err) {
		return err;
	}
	err = inspc_walk_boot(insp_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_walkfs_at(struct silofs_task *task, struct silofs_sb_info *sbi,
                     const struct silofs_laddr_visitor *lvis)
{
	struct silofs_alloc *alloc = task->t_env->base.alloc;
	struct silofs_inspect_ctx *insp_ctx = NULL;
	int ret;

	insp_ctx = inspc_new(alloc, task, sbi, lvis->hook, lvis->userp);
	if (insp_ctx == NULL) {
		return -SILOFS_ENOMEM;
	}
	ret = inspc_walk_fs(insp_ctx);
	inspc_del(insp_ctx, alloc);
	return ret;
}
