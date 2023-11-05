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

#define check_ok_or_bailout(err_) \
	do { if (err_) return (err_); } while (0)


struct silofs_walk_ctx {
	struct silofs_task         *task;
	struct silofs_visitor      *vis;
	struct silofs_fsenv         *fsenv;
	struct silofs_sb_info      *sbi;
	struct silofs_spnode_info  *sni4;
	struct silofs_spnode_info  *sni3;
	struct silofs_spnode_info  *sni2;
	struct silofs_spnode_info  *sni1;
	struct silofs_spleaf_info  *sli;
	enum silofs_height height;
	enum silofs_stype  vspace;
	loff_t voff;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_vrange(const struct silofs_sb_info *sbi,
                       struct silofs_vrange *out_vrange)
{
	loff_t voff_end = 0;

	silofs_sti_vspace_end(&sbi->sb_sti, &voff_end);
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

static void wac_resetup(struct silofs_walk_ctx *wa_ctx,
                        enum silofs_stype vspace)
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
	silofs_relax_caches(wa_ctx->task, SILOFS_F_WALKFS);
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
	return silofs_stage_spnode_at(wa_ctx->fsenv, ulink, out_sni);
}

static int wac_stage_spleaf_at(const struct silofs_walk_ctx *wa_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf_at(wa_ctx->fsenv, ulink, out_sli);
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

	sni_vrange(wa_ctx->sni1, &vrange);
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

	sni_vrange(wa_ctx->sni2, &vrange);
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

	sni_vrange(wa_ctx->sni3, &vrange);
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

	sni_vrange(wa_ctx->sni4, &vrange);
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
                                  enum silofs_stype vspace)
{
	int err;

	wac_resetup(wa_ctx, vspace);
	err = wac_traverse_sptree(wa_ctx);
	wac_resetup(wa_ctx, SILOFS_STYPE_NONE);
	return err;
}

static int wac_traverse_spaces(struct silofs_walk_ctx *wa_ctx)
{
	enum silofs_stype stype;
	int err;

	for (stype = SILOFS_STYPE_NONE; stype < SILOFS_STYPE_LAST; ++stype) {
		if (!stype_isvnode(stype)) {
			continue;
		}
		err = wac_traverse_sptree_of(wa_ctx, stype);
		if (err) {
			return err;
		}
		wac_relax_cache(wa_ctx);
	}
	return 0;
}

int silofs_walk_space_tree(struct silofs_task *task,
                           struct silofs_sb_info *sbi,
                           struct silofs_visitor *vis)
{
	struct silofs_walk_ctx wa_ctx = {
		.task = task,
		.vis = vis,
		.fsenv = task->t_fsenv,
		.sbi = sbi,
		.height = SILOFS_HEIGHT_SUPER,
	};
	int err;

	sbi_incref(sbi);
	err = wac_traverse_spaces(&wa_ctx);
	sbi_decref(sbi);
	return err;
}
