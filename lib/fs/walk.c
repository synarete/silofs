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
	enum silofs_stype vspace;
	size_t slot4;
	size_t slot3;
	size_t slot2;
	loff_t voff;
	bool main;
	bool halt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_vrange(const struct silofs_sb_info *sbi,
                       struct silofs_vrange *out_vrange)
{
	const loff_t voff_end = silofs_spi_vspace_end(sbi->sb_spi);

	silofs_vrange_setup(out_vrange, SILOFS_HEIGHT_SUPER, 0, voff_end);
}

static enum silofs_height ui_height(const struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr;

	silofs_assert_not_null(ui);
	uaddr = ui_uaddr(ui);
	return uaddr->height;
}

static enum silofs_height ui_child_height(const struct silofs_unode_info *ui)
{
	return ui_height(ui) - 1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void uiter_setup(struct silofs_uiterator *uit,
                        struct silofs_sb_info *sbi,
                        struct silofs_unode_info *parent,
                        struct silofs_unode_info *ui,
                        enum silofs_stype vspace,
                        enum silofs_height height,
                        loff_t voff, size_t slot)
{
	uit->sbi = sbi;
	uit->parent = parent;
	uit->ui = ui;
	uit->vspace = vspace;
	uit->height = height;
	uit->voff = voff;
	uit->slot = slot;
}

static void uiter_increfs(const struct silofs_uiterator *uit)
{
	sbi_incref(uit->sbi);
	ui_incref(uit->parent);
	ui_incref(uit->ui);
}

static void uiter_decrefs(const struct silofs_uiterator *uit)
{
	ui_decref(uit->ui);
	ui_decref(uit->parent);
	sbi_decref(uit->sbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void wac_setup_uiter(const struct silofs_walk_ctx *wa_ctx,
                            struct silofs_uiterator *uit,
                            struct silofs_unode_info *parent,
                            struct silofs_unode_info *ui,
                            enum silofs_height height, size_t slot)
{
	uiter_setup(uit, wa_ctx->sbi, parent, ui,
	            wa_ctx->vspace, height, wa_ctx->voff, slot);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_do_visit_prep_by(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_uiterator *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->visit_prep_by_hook) {
		ret = vis->visit_prep_by_hook(vis, uit);
	}
	return ret;
}

static int wac_visit_prep_by(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_uiterator *uit)
{
	int err;

	uiter_increfs(uit);
	err = wac_do_visit_prep_by(wa_ctx, uit);
	uiter_decrefs(uit);
	return err;
}

static int wac_do_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_uiterator *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->visit_exec_at_hook) {
		wac_relax_cache(wa_ctx);
		ret = vis->visit_exec_at_hook(vis, uit);
	}
	return ret;
}

static int wac_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_uiterator *uit)
{
	int err;

	uiter_increfs(uit);
	err = wac_do_visit_exec_at(wa_ctx, uit);
	uiter_decrefs(uit);
	return err;
}

static int wac_do_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                                const struct silofs_uiterator *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->visit_post_at_hook) {
		ret = vis->visit_post_at_hook(vis, uit);
		wac_relax_cache(wa_ctx);
	}
	return ret;
}

static int wac_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_uiterator *uit)
{
	int err;

	uiter_increfs(uit);
	err = wac_do_visit_post_at(wa_ctx, uit);
	uiter_decrefs(uit);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int wac_visit_exec_at_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;

	wac_setup_uiter(wa_ctx, &uit, NULL, sbi_ui, ui_height(sbi_ui), 0);
	return wac_visit_exec_at(wa_ctx, &uit);
}

static int wac_visit_prep_by_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;

	wac_setup_uiter(wa_ctx, &uit, sbi_ui, NULL,
	                ui_child_height(sbi_ui), 0);
	return wac_visit_prep_by(wa_ctx, &uit);
}

static int wac_visit_post_at_super(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;

	wac_setup_uiter(wa_ctx, &uit, NULL, sbi_ui, ui_height(sbi_ui), 0);
	return wac_visit_post_at(wa_ctx, &uit);
}

static int wac_visit_exec_at_spstats(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *spi_ui = &wa_ctx->spi->sp_ui;

	wac_setup_uiter(wa_ctx, &uit, NULL, spi_ui, ui_height(spi_ui), 1);
	return wac_visit_exec_at(wa_ctx, &uit);
}

static int wac_visit_post_at_spstats(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *spi_ui = &wa_ctx->spi->sp_ui;

	wac_setup_uiter(wa_ctx, &uit, NULL, spi_ui, ui_height(spi_ui), 1);
	return wac_visit_post_at(wa_ctx, &uit);
}

static int wac_visit_exec_at_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni4->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, sbi_ui, sni_ui, ui_height(sni_ui), 0);
	return wac_visit_exec_at(wa_ctx, &uit);
}

static int wac_visit_prep_by_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni4->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, sni_ui, NULL,
	                ui_child_height(sni_ui), wa_ctx->slot4);
	return wac_visit_prep_by(wa_ctx, &uit);
}

static int wac_visit_post_at_spnode4(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sbi_ui = &wa_ctx->sbi->sb_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni4->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, sbi_ui, sni_ui,
	                ui_height(sni_ui), wa_ctx->slot4);
	return wac_visit_post_at(wa_ctx, &uit);
}

static int wac_visit_exec_at_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni4->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni3->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, parent_ui, sni_ui,
	                ui_height(sni_ui), wa_ctx->slot4);
	return wac_visit_exec_at(wa_ctx, &uit);
}

static int wac_visit_prep_by_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni3->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, sni_ui, NULL,
	                ui_child_height(sni_ui), wa_ctx->slot3);
	return wac_visit_prep_by(wa_ctx, &uit);
}

static int wac_visit_post_at_spnode3(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni4->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni3->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, parent_ui, sni_ui,
	                ui_height(sni_ui), wa_ctx->slot3);
	return wac_visit_post_at(wa_ctx, &uit);
}

static int wac_visit_exec_at_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni3->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni2->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, parent_ui, sni_ui,
	                ui_height(sni_ui), wa_ctx->slot3);
	return wac_visit_exec_at(wa_ctx, &uit);
}

static int wac_visit_prep_by_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni2->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, sni_ui, NULL,
	                ui_child_height(sni_ui), wa_ctx->slot2);
	return wac_visit_prep_by(wa_ctx, &uit);
}

static int wac_visit_post_at_spnode2(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni3->sn_ui;
	struct silofs_unode_info *sni_ui = &wa_ctx->sni2->sn_ui;

	wac_setup_uiter(wa_ctx, &uit, parent_ui, sni_ui,
	                ui_height(sni_ui), wa_ctx->slot2);
	return wac_visit_post_at(wa_ctx, &uit);
}

static int wac_visit_exec_at_spleaf(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni2->sn_ui;
	struct silofs_unode_info *sli_ui = &wa_ctx->sli->sl_ui;

	wac_setup_uiter(wa_ctx, &uit, parent_ui, sli_ui,
	                ui_height(sli_ui), wa_ctx->slot2);
	return wac_visit_exec_at(wa_ctx, &uit);
}

static int wac_visit_post_at_spleaf(const struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_uiterator uit;
	struct silofs_unode_info *parent_ui = &wa_ctx->sni2->sn_ui;
	struct silofs_unode_info *sli_ui = &wa_ctx->sli->sl_ui;

	wac_setup_uiter(wa_ctx, &uit, parent_ui, sli_ui,
	                ui_height(sli_ui), wa_ctx->slot2);
	return wac_visit_post_at(wa_ctx, &uit);
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

static int wac_traverse_at_spleaf(struct silofs_walk_ctx *wa_ctx)
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

static int wac_traverse_spnode2_child(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_stage_spleaf(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_traverse_at_spleaf(wa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_do_traverse_spnode2(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_uaddr uaddr = { .voff = -1 };
	struct silofs_spnode_info *sni = wa_ctx->sni2;
	ssize_t span;
	int err = 0;

	sni_vrange(sni, &vrange);
	span = silofs_height_to_span(vrange.height - 1);
	wa_ctx->slot2 = 0;
	while (wa_ctx->slot2 < ARRAY_SIZE(sni->sn->sn_subref)) {
		wa_ctx->voff = off_next_n(vrange.beg, span, wa_ctx->slot2);
		if (wa_ctx->voff >= vrange.end) {
			break;
		}
		/* Space-nodes at level2 are non-continuous; do not try to
		 * traverse into non-existing leaves */
		err = silofs_sni_subref_of(sni, wa_ctx->voff, &uaddr);
		if (err) {
			// XXX continue
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

static int wac_traverse_spnode3_child(struct silofs_walk_ctx *wa_ctx)
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
	return 0;
}

static int wac_do_traverse_spnode3(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_uaddr uaddr = { .voff = -1 };
	struct silofs_spnode_info *sni = wa_ctx->sni3;
	ssize_t span;
	int err = 0;

	sni_vrange(sni, &vrange);
	span = silofs_height_to_span(vrange.height - 1);
	wa_ctx->slot3 = 0;
	while (wa_ctx->slot3 < ARRAY_SIZE(sni->sn->sn_subref)) {
		wa_ctx->voff = off_next_n(vrange.beg, span, wa_ctx->slot3);
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

static int wac_traverse_spnode4_child(struct silofs_walk_ctx *wa_ctx)
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
	return 0;
}

static int wac_do_traverse_spnode4(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_uaddr uaddr = { .voff = -1 };
	struct silofs_spnode_info *sni = wa_ctx->sni4;
	ssize_t span;
	int err = 0;

	sni_vrange(sni, &vrange);
	span = silofs_height_to_span(vrange.height - 1);
	wa_ctx->slot4 = 0;
	while (wa_ctx->slot4 < ARRAY_SIZE(sni->sn->sn_subref)) {
		wa_ctx->voff = off_next_n(vrange.beg, span, wa_ctx->slot4);
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

static int wac_traverse_super_child(struct silofs_walk_ctx *wa_ctx)
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
	return 0;
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
		.main = sbi_is_main(sbi),
		.halt = false,
	};
	int err;

	sbi_incref(sbi);
	err = wac_traverse_fs(&wa_ctx);
	sbi_decref(sbi);
	return err;
}
