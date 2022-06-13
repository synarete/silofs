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
	struct silofs_spstats_info *sti;
	struct silofs_spnode_info  *sni4;
	struct silofs_spnode_info  *sni3;
	struct silofs_spnode_info  *sni2;
	struct silofs_spleaf_info  *sli;
	bool main;
	bool halt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_vrange(const struct silofs_sb_info *sbi,
                       struct silofs_vrange *out_vrange)
{
	const loff_t voff_end = silofs_sti_vspace_end(sbi->sb_sti);

	silofs_vrange_setup(out_vrange, SILOFS_HEIGHT_SUPER, 0, voff_end);
}

static size_t ui_height(const struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr;

	silofs_assert_not_null(ui);
	uaddr = ui_uaddr(ui);
	return uaddr->height;
}

static void uiter_setup(struct silofs_uiterator *uit,
                        struct silofs_sb_info *sbi,
                        struct silofs_unode_info *parent,
                        struct silofs_unode_info *ui, loff_t voff, size_t slot)
{
	uit->sbi = sbi;
	uit->parent = parent;
	uit->ui = ui;
	uit->voff = voff;
	uit->slot = slot;
	if (ui != NULL) {
		uit->height = ui_height(ui);
	} else {
		uit->height = ui_height(parent) - 1;
	}
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

static void wac_relax_cache(const struct silofs_walk_ctx *wa_ctx)
{
	silofs_uber_relax_caches(wa_ctx->uber, SILOFS_F_WALKFS);
}

static int wac_visit_prep(const struct silofs_walk_ctx *wa_ctx,
                          const struct silofs_uiterator *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->visit_prep_hook) {
		ret = vis->visit_prep_hook(vis, uit);
	}
	return ret;
}

static int wac_visit_prep_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_unode_info *parent,
                             loff_t voff, size_t slot)
{
	struct silofs_uiterator uit;
	int err;

	uiter_setup(&uit, wa_ctx->sbi, parent, NULL, voff, slot);
	uiter_increfs(&uit);
	err = wac_visit_prep(wa_ctx, &uit);
	uiter_decrefs(&uit);
	return err;
}

static int wac_visit_exec(const struct silofs_walk_ctx *wa_ctx,
                          const struct silofs_uiterator *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->visit_exec_hook) {
		wac_relax_cache(wa_ctx);
		ret = vis->visit_exec_hook(vis, uit);
	}
	return ret;
}

static int wac_visit_exec_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_unode_info *parent,
                             struct silofs_unode_info *child,
                             loff_t voff, size_t slot)
{
	struct silofs_uiterator uit;
	int err;

	uiter_setup(&uit, wa_ctx->sbi, parent, child, voff, slot);
	uiter_increfs(&uit);
	err = wac_visit_exec(wa_ctx, &uit);
	uiter_decrefs(&uit);
	return err;
}

static int wac_visit_post(const struct silofs_walk_ctx *wa_ctx,
                          const struct silofs_uiterator *uit)
{
	struct silofs_visitor *vis = wa_ctx->vis;
	int ret = 0;

	if (vis && vis->visit_post_hook) {
		ret = vis->visit_post_hook(vis, uit);
		wac_relax_cache(wa_ctx);
	}
	return ret;
}

static int wac_visit_post_at(const struct silofs_walk_ctx *wa_ctx,
                             struct silofs_unode_info *parent,
                             struct silofs_unode_info *child,
                             loff_t voff, size_t slot)
{
	struct silofs_uiterator uit;
	int err;

	uiter_setup(&uit, wa_ctx->sbi, parent, child, voff, slot);
	uiter_increfs(&uit);
	err = wac_visit_post(wa_ctx, &uit);
	uiter_decrefs(&uit);
	return err;
}

static int wac_stage_spnode_at(const struct silofs_walk_ctx *wa_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	return silofs_stage_spnode_at(wa_ctx->uber, wa_ctx->main,
	                              uaddr, out_sni);
}

static int wac_stage_spnode4(struct silofs_walk_ctx *wa_ctx, loff_t voff)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_subref_of(wa_ctx->sbi, voff, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spnode_at(wa_ctx, &uaddr, &wa_ctx->sni4);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_stage_spnode3(struct silofs_walk_ctx *wa_ctx, loff_t voff)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sni_subref_of(wa_ctx->sni4, voff, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spnode_at(wa_ctx, &uaddr, &wa_ctx->sni3);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_stage_spnode2(struct silofs_walk_ctx *wa_ctx, loff_t voff)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sni_subref_of(wa_ctx->sni3, voff, &uaddr);
	if (err) {
		return err;
	}
	err = wac_stage_spnode_at(wa_ctx, &uaddr, &wa_ctx->sni2);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_stage_spleaf(struct silofs_walk_ctx *wa_ctx, loff_t voff)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sni_subref_of(wa_ctx->sni2, voff, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_stage_spleaf_at(wa_ctx->uber, wa_ctx->main,
	                             &uaddr, &wa_ctx->sli);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_at_spleaf(struct silofs_walk_ctx *wa_ctx,
                                  loff_t voff, size_t slot)
{
	struct silofs_spnode_info *sni = wa_ctx->sni2;
	struct silofs_spleaf_info *sli = wa_ctx->sli;
	int err;

	err = wac_visit_exec_at(wa_ctx, &sni->sn_ui, &sli->sl_ui, voff, slot);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, &sni->sn_ui, &sli->sl_ui, voff, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_spnode2_child(struct silofs_walk_ctx *wa_ctx,
                                      loff_t voff, size_t slot)
{
	int err;

	err = wac_stage_spleaf(wa_ctx, voff);
	if (err) {
		return err;
	}
	err = wac_traverse_at_spleaf(wa_ctx, voff, slot);
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
	size_t slot = 0;
	loff_t voff;
	int err = 0;

	sni_vrange(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = silofs_sni_subref_of(sni, voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_at(wa_ctx, &sni->sn_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_traverse_spnode2_child(wa_ctx, voff, slot);
		if (err && (err != -ENOENT)) {
			break;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
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

static int wac_traverse_at_spnode2(struct silofs_walk_ctx *wa_ctx,
                                   loff_t voff, size_t slot)
{
	struct silofs_spnode_info *sni3 = wa_ctx->sni3;
	struct silofs_spnode_info *sni = wa_ctx->sni2;
	int err;

	err = wac_visit_exec_at(wa_ctx, &sni3->sn_ui, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode2(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, &sni3->sn_ui, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_spnode3_child(struct silofs_walk_ctx *wa_ctx,
                                      loff_t voff, size_t slot)
{
	int err;

	err = wac_stage_spnode2(wa_ctx, voff);
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode2(wa_ctx, voff, slot);
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
	size_t slot = 0;
	loff_t voff;
	int err = 0;

	sni_vrange(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = silofs_sni_subref_of(sni, voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_at(wa_ctx, &sni->sn_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_traverse_spnode3_child(wa_ctx, voff, slot);
		if (err && (err != -ENOENT)) {
			break;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
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

static int wac_traverse_at_spnode3(struct silofs_walk_ctx *wa_ctx,
                                   loff_t voff, size_t slot)
{
	struct silofs_spnode_info *sni4 = wa_ctx->sni4;
	struct silofs_spnode_info *sni = wa_ctx->sni3;
	int err;

	err = wac_visit_exec_at(wa_ctx, &sni4->sn_ui, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode3(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, &sni4->sn_ui, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_spnode4_child(struct silofs_walk_ctx *wa_ctx,
                                      loff_t voff, size_t slot)
{
	int err;

	err = wac_stage_spnode3(wa_ctx, voff);
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode3(wa_ctx, voff, slot);
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
	size_t slot = 0;
	loff_t voff;
	int err = 0;

	sni_vrange(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = silofs_sni_subref_of(sni, voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_at(wa_ctx, &sni->sn_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_traverse_spnode4_child(wa_ctx, voff, slot);
		if (err && (err != -ENOENT)) {
			break;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
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

static int wac_traverse_at_spnode4(struct silofs_walk_ctx *wa_ctx,
                                   loff_t voff, size_t slot)
{
	struct silofs_unode_info *parent = &wa_ctx->sbi->sb_ui;
	struct silofs_spnode_info *sni = wa_ctx->sni4;
	int err;

	err = wac_visit_exec_at(wa_ctx, parent, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode4(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, parent, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_super_child(struct silofs_walk_ctx *wa_ctx,
                                    loff_t voff, size_t slot)
{
	int err;

	err = wac_stage_spnode4(wa_ctx, voff);
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode4(wa_ctx, voff, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_traverse_utree(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_uaddr uaddr = { .voff = -1 };
	struct silofs_sb_info *sbi = wa_ctx->sbi;
	size_t slot = 0;
	loff_t voff;
	int err = 0;

	sbi_vrange(sbi, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = silofs_sbi_subref_of(sbi, voff, &uaddr);
		if (err) {
			break;
		}
		err = wac_visit_prep_at(wa_ctx, &sbi->sb_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_traverse_super_child(wa_ctx, voff, slot);
		if (err) {
			break;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
	}
	return (err == -ENOENT) ? 0 : err;
}

static int wac_traverse_supers(struct silofs_walk_ctx *wa_ctx)
{
	struct silofs_sb_info *sbi = wa_ctx->sbi;
	struct silofs_spstats_info *sti = wa_ctx->sti;
	loff_t voff = 0;
	int err;

	err = wac_visit_exec_at(wa_ctx, NULL, &sbi->sb_ui, voff, 0);
	if (err) {
		return err;
	}
	err = wac_visit_exec_at(wa_ctx, NULL, &sti->sp_ui, voff, 1);
	if (err) {
		return err;
	}
	err = wac_traverse_utree(wa_ctx);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, NULL, &sti->sp_ui, voff, 1);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, NULL, &sbi->sb_ui, voff, 0);
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
	const struct silofs_repo *main_repo = &uber->ub_repos->repo_main;

	return (sbi->sb_ui.u_repo == main_repo);
}

int silofs_walk_space_tree(struct silofs_sb_info *sbi,
                           struct silofs_visitor *vis)
{
	struct silofs_walk_ctx wa_ctx = {
		.vis = vis,
		.uber = sbi_uber(sbi),
		.sbi = sbi,
		.sti = sbi->sb_sti,
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void usi_init(struct silofs_usaddr_info *usi,
                     const struct silofs_uaddr *uaddr)
{
	silofs_avl_node_init(&usi->us_an);
	silofs_uaddr_assign(&usi->us_uaddr, uaddr);
	usi->us_refcnt = 1;
}

static void usi_fini(struct silofs_usaddr_info *usi)
{
	silofs_uaddr_reset(&usi->us_uaddr);
	silofs_avl_node_fini(&usi->us_an);
}

static struct silofs_usaddr_info *
usi_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_usaddr_info *usi = NULL;

	usi = silofs_allocate(alloc, sizeof(*usi));
	if (usi != NULL) {
		usi_init(usi, uaddr);
	}
	return usi;
}

static void usi_delete(struct silofs_usaddr_info *usi,
                       struct silofs_alloc *alloc)
{
	usi_fini(usi);
	silofs_deallocate(alloc, usi, sizeof(*usi));
}


static struct silofs_usaddr_info *
usi_from_avl_node(const struct silofs_avl_node *an)
{
	const struct silofs_usaddr_info *usi;

	usi = container_of2(an, struct silofs_usaddr_info, us_an);
	return unconst(usi);
}

static const void *usi_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_usaddr_info *usi = usi_from_avl_node(an);

	return &usi->us_uaddr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long uaddr_compare(const void *x, const void *y)
{
	const struct silofs_uaddr *uaddr_x = x;
	const struct silofs_uaddr *uaddr_y = y;

	return silofs_uaddr_compare(uaddr_x, uaddr_y);
}

static void uss_delete_usi(struct silofs_usaddr_set *uss,
                           struct silofs_usaddr_info *usi)
{
	usi_delete(usi, uss->uss_alloc);
}

static void uss_init(struct silofs_usaddr_set *uss,
                     struct silofs_alloc *alloc)
{
	silofs_avl_init(&uss->uss_avl, usi_getkey, uaddr_compare, uss);
	uss->uss_alloc = alloc;
}

static void uss_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_usaddr_set *uss = p;
	struct silofs_usaddr_info *usi = usi_from_avl_node(an);

	uss_delete_usi(uss, usi);
}

static void uss_clear(struct silofs_usaddr_set *uss)
{
	const struct silofs_avl_node_functor fn = {
		.fn = uss_avl_node_delete_cb,
		.ctx = uss
	};

	silofs_avl_clear(&uss->uss_avl, &fn);
}

static void uss_fini(struct silofs_usaddr_set *uss)
{
	uss_clear(uss);
	silofs_avl_fini(&uss->uss_avl);
	uss->uss_alloc = NULL;
}

static int uss_insert(struct silofs_usaddr_set *uss,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_usaddr_info *usi;

	usi = usi_new(uss->uss_alloc, uaddr);
	if (usi == NULL) {
		return -ENOMEM;
	}
	silofs_avl_insert(&uss->uss_avl, &usi->us_an);
	return 0;
}

static struct silofs_usaddr_info *
uss_lookup(const struct silofs_usaddr_set *uss,
           const struct silofs_uaddr *uaddr)
{
	const struct silofs_avl_node *an;
	struct silofs_usaddr_info *usi = NULL;

	an = silofs_avl_find(&uss->uss_avl, uaddr);
	if (an != NULL) {
		usi = usi_from_avl_node(an);
	}
	return usi;
}

static int uss_update(struct silofs_usaddr_set *uss,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_usaddr_info *usi;
	int ret;

	usi = uss_lookup(uss, uaddr);
	if (usi == NULL) {
		ret = uss_insert(uss, uaddr);
	} else {
		usi->us_refcnt++;
		ret = 0;
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_uspace_visitor *usvisitor_of(struct silofs_visitor *vis)
{
	return silofs_container_of(vis, struct silofs_uspace_visitor, vis);
}

static int usv_visit_node(struct silofs_uspace_visitor *usv,
                          struct silofs_unode_info *ui)
{
	int err;

	if (ui == NULL) {
		usv->vis.nodescend = true;
		return 0;
	}
	err = uss_update(&usv->uss, ui_uaddr(ui));
	if (err) {
		return err;
	}
	return 0;
}

static int usv_visit_hook(struct silofs_visitor *vis,
                          const struct silofs_uiterator *uit)
{
	return usv_visit_node(usvisitor_of(vis), uit->ui);
}

void silofs_usvisitor_init(struct silofs_uspace_visitor *usv,
                           struct silofs_alloc *alloc)
{
	silofs_memzero(usv, sizeof(*usv));
	uss_init(&usv->uss, alloc);
	usv->vis.visit_prep_hook = NULL;
	usv->vis.visit_exec_hook = usv_visit_hook;
	usv->vis.visit_post_hook = NULL;
}

void silofs_usvisitor_fini(struct silofs_uspace_visitor *usv)
{
	uss_fini(&usv->uss);
	usv->vis.visit_exec_hook = NULL;
}

