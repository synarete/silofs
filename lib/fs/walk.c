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


struct silofs_walk_ctx {
	struct silofs_visitor      *vis;
	struct silofs_fs_uber      *uber;
	struct silofs_sb_info      *sbi;
	struct silofs_spnode_info  *sni4;
	struct silofs_spnode_info  *sni3;
	struct silofs_spnode_info  *sni2;
	struct silofs_spleaf_info  *sli;
	enum silofs_height height;
	enum silofs_stype  vspace;
	loff_t voff;
	bool main;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_vrange(const struct silofs_sb_info *sbi,
                       struct silofs_vrange *out_vrange)
{
	const loff_t voff_end = silofs_sti_vspace_end(&sbi->sb_sti);

	silofs_vrange_setup(out_vrange, SILOFS_HEIGHT_SUPER, 0, voff_end);
}

static bool sni_has_subref(const struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_uaddr uaddr;

	return silofs_sni_subref_of(sni, voff, &uaddr) == 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spit_increfs(const struct silofs_space_iter *spit)
{
	sbi_incref(spit->sbi);
	sni_incref(spit->sni4);
	sni_incref(spit->sni3);
	sni_incref(spit->sni2);
	sli_incref(spit->sli);
}

static void spit_decrefs(const struct silofs_space_iter *spit)
{
	sli_decref(spit->sli);
	sni_decref(spit->sni2);
	sni_decref(spit->sni3);
	sni_decref(spit->sni4);
	sbi_decref(spit->sbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void wac_setup_space_iter(const struct silofs_walk_ctx *wa_ctx,
                                 struct silofs_space_iter *spit)
{
	silofs_memzero(spit, sizeof(*spit));
	spit->sbi = wa_ctx->sbi;
	spit->sni4 = wa_ctx->sni4;
	spit->sni3 = wa_ctx->sni3;
	spit->sni2 = wa_ctx->sni2;
	spit->sli = wa_ctx->sli;
	spit->height = wa_ctx->height;
	spit->vspace = wa_ctx->vspace;
	spit->voff = wa_ctx->voff;
}

static void wac_resetup(struct silofs_walk_ctx *wa_ctx,
                        enum silofs_stype vspace)
{
	wa_ctx->vspace = vspace;
	wa_ctx->sni4 = NULL;
	wa_ctx->sni3 = NULL;
	wa_ctx->sni2 = NULL;
	wa_ctx->sli = NULL;
	wa_ctx->voff = 0;
}

static void wac_relax_cache(const struct silofs_walk_ctx *wa_ctx)
{
	silofs_uber_relax_caches(wa_ctx->uber, SILOFS_F_WALKFS);
}

static void wac_push_height(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->height -= 1;
	silofs_assert_ge(wa_ctx->height, SILOFS_HEIGHT_VDATA);
}

static void wac_pop_height(struct silofs_walk_ctx *wa_ctx)
{
	wa_ctx->height += 1;
	silofs_assert_le(wa_ctx->height, SILOFS_HEIGHT_SUPER);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_do_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_space_iter *spit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->exec_hook) {
		wac_relax_cache(wa_ctx);
		ret = vis->exec_hook(vis, spit);
	}
	return ret;
}

static int wac_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_space_iter *spit)
{
	int err;

	spit_increfs(spit);
	err = wac_do_visit_exec_at(wa_ctx, spit);
	spit_decrefs(spit);
	return err;
}

static int wac_do_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_space_iter *spit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->post_hook) {
		ret = vis->post_hook(vis, spit);
		wac_relax_cache(wa_ctx);
	}
	return ret;
}

static int wac_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_space_iter *spit)
{
	int err;

	spit_increfs(spit);
	err = wac_do_visit_post_at(wa_ctx, spit);
	spit_decrefs(spit);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_visit_exec_at_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spleaf(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_spleaf(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;

	wac_setup_space_iter(wa_ctx, &spit);
	return wac_visit_post_at(wa_ctx, &spit);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_stage_spnode_at(const struct silofs_walk_ctx *wa_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	return silofs_stage_spnode_at(wa_ctx->uber, wa_ctx->main,
	                              uaddr, out_sni);
}

static int wac_stage_spleaf_at(const struct silofs_walk_ctx *wa_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf_at(wa_ctx->uber, wa_ctx->main,
	                              uaddr, out_sli);
}

static int wac_stage_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange;
	struct silofs_uaddr uaddr;
	int err;

	sbi_vrange(wa_ctx->sbi, &vrange);
	if (wa_ctx->voff > vrange.end) {
		return -ENOENT;
	}
	err = silofs_sbi_sproot_of(wa_ctx->sbi, wa_ctx->vspace, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spnode_at(wa_ctx, &uaddr, &wa_ctx->sni4);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_stage_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sni_subref_of(wa_ctx->sni4, wa_ctx->voff, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spnode_at(wa_ctx, &uaddr, &wa_ctx->sni3);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_stage_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sni_subref_of(wa_ctx->sni3, wa_ctx->voff, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spnode_at(wa_ctx, &uaddr, &wa_ctx->sni2);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_stage_spleaf(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sni_subref_of(wa_ctx->sni2, wa_ctx->voff, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spleaf_at(wa_ctx, &uaddr, &wa_ctx->sli);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_do_traverse_spleaf(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_spleaf(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at_spleaf(wa_ctx);
	if (err) {
		return err;
	}
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

static int wac_do_traverse_spnode2_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spleaf(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_traverse_spleaf(wa_ctx);
	if (err) {
		return err;
	}
	wac_depart_spleaf(wa_ctx);
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
		if (err && (err != -ENOENT)) {
			break;
		}
		wa_ctx->voff = vrange_next(&vrange, voff);
	}
	return (err == -ENOENT) ? 0 : err;
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

	err = wac_visit_exec_at_spnode2(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode2(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at_spnode2(wa_ctx);
	if (err) {
		return err;
	}
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
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode2(wa_ctx);
	if (err) {
		return err;
	}
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
		if (err && (err != -ENOENT)) {
			break;
		}
		wa_ctx->voff = vrange_next(&vrange, voff);
	}
	return (err == -ENOENT) ? 0 : err;
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

	err = wac_visit_exec_at_spnode3(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode3(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at_spnode3(wa_ctx);
	if (err) {
		return err;
	}
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
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode3(wa_ctx);
	if (err) {
		return err;
	}
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
		if (err && (err != -ENOENT)) {
			break;
		}
		wa_ctx->voff = vrange_next(&vrange, voff);
	}
	return (err == -ENOENT) ? 0 : err;
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

	err = wac_visit_exec_at_spnode4(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode4(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at_spnode4(wa_ctx);
	if (err) {
		return err;
	}
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
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode4(wa_ctx);
	if (err) {
		return err;
	}
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
	return (err == -ENOENT) ? 0 : err;
}

static int wac_traverse_sptree_of(struct silofs_walk_ctx *wa_ctx,
                                  enum silofs_stype vspace)
{
	int err;

	wac_resetup(wa_ctx, vspace);
	err = wac_visit_exec_at_super(wa_ctx);
	if (err) {
		goto out;
	}
	err = wac_do_traverse_sptree(wa_ctx);
	if (err) {
		goto out;
	}
	err = wac_visit_post_at_super(wa_ctx);
	if (err) {
		goto out;
	}
out:
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

static bool sbi_is_main(const struct silofs_sb_info *sbi)
{
	const struct silofs_fs_uber *uber = sbi_uber(sbi);
	const struct silofs_repo *warm_repo = &uber->ub_repos->repo_warm;

	return (sbi->sb_ui.u_repo == warm_repo);
}

int silofs_walk_space_tree(struct silofs_sb_info *sbi,
                           struct silofs_visitor *vis)
{
	struct silofs_walk_ctx wa_ctx = {
		.vis = vis,
		.uber = sbi_uber(sbi),
		.sbi = sbi,
		.sni4 = NULL,
		.sni3 = NULL,
		.sni2 = NULL,
		.sli = NULL,
		.height = SILOFS_HEIGHT_SUPER,
		.main = sbi_is_main(sbi),
	};
	int err;

	sbi_incref(sbi);
	err = wac_traverse_spaces(&wa_ctx);
	sbi_decref(sbi);
	return err;
}
