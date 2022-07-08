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
	struct silofs_spstats_info *spi;
	struct silofs_spnode_info  *sni4;
	struct silofs_spnode_info  *sni3;
	struct silofs_spnode_info  *sni2;
	struct silofs_spleaf_info  *sli;
	enum silofs_height height;
	enum silofs_stype  vspace;
	size_t slot4;
	size_t slot3;
	size_t slot2;
	loff_t voff;
	bool main;
	bool halt;
};

static void sbi_vrange(const struct silofs_sb_info *sbi,
                       struct silofs_vrange *out_vrange)
{
	const loff_t voff_end = silofs_spi_vspace_end(sbi->sb_spi);

	silofs_vrange_setup(out_vrange, SILOFS_HEIGHT_SUPER, 0, voff_end);
}

static loff_t vrange_voff_at(const struct silofs_vrange *vrange, size_t slot)
{
	ssize_t span;
	loff_t voff;

	span = silofs_height_to_span(vrange->height - 1);
	voff = silofs_off_next_n(vrange->beg, span, slot);
	silofs_assert_le(voff, vrange->end);
	return voff;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spit_increfs(const struct silofs_space_iter *spit)
{
	sbi_incref(spit->sbi);
	spi_incref(spit->spi);
	sni_incref(spit->sni4);
	sni_incref(spit->sni3);
	sni_incref(spit->sni2);
	sli_incref(spit->sli);

	ui_incref(spit->parent);
	ui_incref(spit->ui);
}

static void spit_decrefs(const struct silofs_space_iter *spit)
{
	ui_decref(spit->ui);
	ui_decref(spit->parent);

	sli_decref(spit->sli);
	sni_decref(spit->sni2);
	sni_decref(spit->sni3);
	sni_decref(spit->sni4);
	spi_decref(spit->spi);
	sbi_decref(spit->sbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void wac_setup_space_iter(const struct silofs_walk_ctx *wa_ctx,
                                 struct silofs_space_iter *spit,
                                 enum silofs_stype stype,
                                 struct silofs_unode_info *parent,
                                 struct silofs_unode_info *ui, size_t slot)
{
	silofs_memzero(spit, sizeof(*spit));
	spit->sbi = wa_ctx->sbi;
	spit->spi = wa_ctx->spi;
	spit->sni4 = wa_ctx->sni4;
	spit->sni3 = wa_ctx->sni3;
	spit->sni2 = wa_ctx->sni2;
	spit->sli = wa_ctx->sli;
	spit->height = wa_ctx->height;
	spit->stype = stype;
	spit->vspace = wa_ctx->vspace;
	spit->voff = wa_ctx->voff;
	spit->slot = slot;
	spit->parent = parent;
	spit->ui = ui;
}

static void wac_resetup(struct silofs_walk_ctx *wa_ctx,
                        enum silofs_stype vspace)
{
	wa_ctx->vspace = vspace;
	wa_ctx->sni4 = NULL;
	wa_ctx->sni3 = NULL;
	wa_ctx->sni2 = NULL;
	wa_ctx->sli = NULL;
	wa_ctx->slot4 = 0;
	wa_ctx->slot3 = 0;
	wa_ctx->slot2 = 0;
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

static int wac_do_visit_prep_by(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_space_iter *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->prep_by_hook) {
		ret = vis->prep_by_hook(vis, uit);
	}
	return ret;
}

static int wac_visit_prep_by(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_space_iter *uit)
{
	int err;

	spit_increfs(uit);
	err = wac_do_visit_prep_by(wa_ctx, uit);
	spit_decrefs(uit);
	return err;
}

static int wac_do_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_space_iter *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->exec_at_hook) {
		wac_relax_cache(wa_ctx);
		ret = vis->exec_at_hook(vis, uit);
	}
	return ret;
}

static int wac_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_space_iter *uit)
{
	int err;

	spit_increfs(uit);
	err = wac_do_visit_exec_at(wa_ctx, uit);
	spit_decrefs(uit);
	return err;
}

static int wac_do_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_space_iter *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->post_at_hook) {
		ret = vis->post_at_hook(vis, uit);
		wac_relax_cache(wa_ctx);
	}
	return ret;
}

static int wac_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_space_iter *uit)
{
	int err;

	spit_increfs(uit);
	err = wac_do_visit_post_at(wa_ctx, uit);
	spit_decrefs(uit);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_visit_exec_at_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SUPER,
	                     NULL, sbi_ui, 0);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_prep_by_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SUPER,
	                     sbi_ui, NULL, 0);
	return wac_visit_prep_by(wa_ctx, &spit);
}

static int wac_visit_post_at_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SUPER,
	                     NULL, sbi_ui, 0);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spstats(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *spi_ui = &wa_ctx->spi->sp_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPSTATS,
	                     NULL, spi_ui, 1);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_spstats(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *spi_ui = &wa_ctx->spi->sp_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPSTATS,
	                     NULL, spi_ui, 1);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni4->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     sbi_ui, sni_ui, 0);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_prep_by_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni4->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     sni_ui, NULL, wa_ctx->slot4);
	return wac_visit_prep_by(wa_ctx, &spit);
}

static int wac_visit_post_at_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni4->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     sbi_ui, sni_ui, wa_ctx->slot4);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni4->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni3->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     parent_ui, sni_ui, wa_ctx->slot4);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_prep_by_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni3->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     sni_ui, NULL, wa_ctx->slot3);
	return wac_visit_prep_by(wa_ctx, &spit);
}

static int wac_visit_post_at_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni4->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni3->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     parent_ui, sni_ui, wa_ctx->slot3);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni3->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni2->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     parent_ui, sni_ui, wa_ctx->slot3);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_prep_by_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni2->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     sni_ui, NULL, wa_ctx->slot2);
	return wac_visit_prep_by(wa_ctx, &spit);
}

static int wac_visit_post_at_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni3->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni2->sn_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPNODE,
	                     parent_ui, sni_ui, wa_ctx->slot2);
	return wac_visit_post_at(wa_ctx, &spit);
}

static int wac_visit_exec_at_spleaf(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni2->sn_ui;
	struct silofs_unode_info *sli_ui = &wa_ctx->sli->sl_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPLEAF,
	                     parent_ui, sli_ui, wa_ctx->slot2);
	return wac_visit_exec_at(wa_ctx, &spit);
}

static int wac_visit_post_at_spleaf(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_space_iter spit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni2->sn_ui;
	struct silofs_unode_info *sli_ui = &wa_ctx->sli->sl_ui;

	wac_setup_space_iter(wa_ctx, &spit,
	                     SILOFS_STYPE_SPLEAF,
	                     parent_ui, sli_ui, wa_ctx->slot2);
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
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_spnode_info *sni = wa_ctx->sni2;
	int err = 0;

	sni_vrange(sni, &vrange);
	wa_ctx->slot2 = 0;
	while (wa_ctx->slot2 < ARRAY_SIZE(sni->sn->sn_subref)) {
		wa_ctx->voff = vrange_voff_at(&vrange, wa_ctx->slot2);
		if (wa_ctx->voff >= vrange.end) {
			break;
		}
		err = silofs_sni_subref_of(sni, wa_ctx->voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_by_spnode2(wa_ctx);
		if (err) {
			break;
		}
		err = wac_traverse_spnode2_child(wa_ctx);
		if (err && (err != -ENOENT)) {
			break;
		}
		wa_ctx->slot2++;
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
	wa_ctx->slot2 = 0;
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
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_spnode_info *sni = wa_ctx->sni3;
	int err = 0;

	sni_vrange(sni, &vrange);
	wa_ctx->slot3 = 0;
	while (wa_ctx->slot3 < ARRAY_SIZE(sni->sn->sn_subref)) {
		wa_ctx->voff = vrange_voff_at(&vrange, wa_ctx->slot3);
		if (wa_ctx->voff >= vrange.end) {
			break;
		}
		err = silofs_sni_subref_of(sni, wa_ctx->voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_by_spnode3(wa_ctx);
		if (err) {
			break;
		}
		err = wac_traverse_spnode3_child(wa_ctx);
		if (err && (err != -ENOENT)) {
			break;
		}
		wa_ctx->slot3++;
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
	wa_ctx->slot3 = 0;
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
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_spnode_info *sni = wa_ctx->sni4;
	int err = 0;

	sni_vrange(sni, &vrange);
	wa_ctx->slot4 = 0;
	while (wa_ctx->slot4 < ARRAY_SIZE(sni->sn->sn_subref)) {
		wa_ctx->voff = vrange_voff_at(&vrange, wa_ctx->slot4);
		if (wa_ctx->voff >= vrange.end) {
			break;
		}
		err = silofs_sni_subref_of(sni, wa_ctx->voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_by_spnode4(wa_ctx);
		if (err) {
			break;
		}
		err = wac_traverse_spnode4_child(wa_ctx);
		if (err && (err != -ENOENT)) {
			break;
		}
		wa_ctx->slot4++;
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
	wa_ctx->slot4 = 0;
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
	err = wac_visit_prep_by_super(wa_ctx);
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
	err = wac_do_traverse_sptree(wa_ctx);
	wac_resetup(wa_ctx, SILOFS_STYPE_NONE);
	return err;
}

static int wac_traverse_space_trees(struct silofs_walk_ctx *wa_ctx)
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
	}
	return 0;
}

static int wac_traverse_supers(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_visit_exec_at_super(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_exec_at_spstats(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_traverse_space_trees(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at_spstats(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at_super(wa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_fs(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_traverse_supers(wa_ctx);
	wac_relax_cache(wa_ctx);
	return err;
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
		.spi = sbi->sb_spi,
		.sni4 = NULL,
		.sni3 = NULL,
		.sni2 = NULL,
		.sli = NULL,
		.height = SILOFS_HEIGHT_SUPER,
		.main = sbi_is_main(sbi),
		.halt = false,
	};
	int err;

	sbi_incref(sbi);
	err = wac_traverse_fs(&wa_ctx);
	sbi_decref(sbi);
	return err;
}
