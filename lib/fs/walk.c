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
#include <silofs/fs/address.h>
#include <silofs/fs/types.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/walk.h>
#include <silofs/fs/private.h>


struct silofs_walk_ctx {
	struct silofs_visitor     *vis;
	struct silofs_fs_apex     *apex;
	struct silofs_sb_info     *sbi;
	bool halt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static int wac_traverse_at_spnode(struct silofs_walk_ctx *wa_ctx,
                                  struct silofs_spnode_info *sni);

static void wac_relax_cache(const struct silofs_walk_ctx *wa_ctx)
{
	silofs_apex_relax_caches(wa_ctx->apex, SILOFS_F_WALKFS);
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

static int
wac_stage_child_spnode(struct silofs_walk_ctx *wa_ctx, loff_t voff,
                       struct silofs_spnode_info *sni_parent,
                       struct silofs_spnode_info **out_sni)
{
	return silofs_sbi_stage_child_spnode(wa_ctx->sbi, voff, sni_parent,
	                                     SILOFS_STAGE_RDONLY, out_sni);
}

static int
wac_stage_child_spleaf(struct silofs_walk_ctx *wa_ctx, loff_t voff,
                       struct silofs_spnode_info *sni_parent,
                       struct silofs_spleaf_info **out_sli)
{
	return silofs_sbi_stage_spleaf_of(wa_ctx->sbi, sni_parent, voff,
	                                  SILOFS_STAGE_RDONLY, out_sli);
}

static int wac_traverse_spleaf(struct silofs_walk_ctx *wa_ctx,
                               struct silofs_spnode_info *sni,
                               struct silofs_spleaf_info *sli,
                               loff_t voff, size_t slot)
{
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

static int wac_traverse_spnode(struct silofs_walk_ctx *wa_ctx,
                               struct silofs_unode_info *parent,
                               struct silofs_spnode_info *sni,
                               loff_t voff, size_t slot)
{
	int err;

	err = wac_visit_exec_at(wa_ctx, parent, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	err = wac_traverse_at_spnode(wa_ctx, sni);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, parent, &sni->sn_ui, voff, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int wac_at_bottom_spnode(struct silofs_walk_ctx *wa_ctx,
                                struct silofs_spnode_info *sni,
                                loff_t voff, size_t slot,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = wac_stage_child_spleaf(wa_ctx, voff, sni, &sli);
	if (err) {
		return err;
	}
	err = wac_traverse_spleaf(wa_ctx, sni, sli, voff, slot);
	if (err) {
		return err;
	}
	*out_sli = sli;
	return 0;
}

static int wac_traverse_bottom_spnode(struct silofs_walk_ctx *wa_ctx,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_spleaf_info *sli = NULL;
	loff_t voff;
	size_t slot = 0;
	int err = 0;

	sni_incref(sni);
	silofs_sni_vspace_range(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = wac_visit_prep_at(wa_ctx, &sni->sn_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_at_bottom_spnode(wa_ctx, sni, voff, slot, &sli);
		if (err) {
			break;
		}
		voff = silofs_sli_voff_end(sli);
		slot++;
	}
	sni_decref(sni);

	return (err == -ENOENT) ? 0 : err;
}

static int wac_at_inner_spnode(struct silofs_walk_ctx *wa_ctx,
                               struct silofs_spnode_info *sni,
                               loff_t voff, size_t slot,
                               struct silofs_spnode_info **out_child)
{
	struct silofs_spnode_info *child = NULL;
	int err;

	err = wac_stage_child_spnode(wa_ctx, voff, sni, &child);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode(wa_ctx, &sni->sn_ui, child, voff, slot);
	if (err) {
		return err;
	}
	*out_child = child;
	return 0;
}

static int wac_traverse_inner_spnode(struct silofs_walk_ctx *wa_ctx,
                                     struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_spnode_info *child = NULL;
	loff_t voff;
	size_t slot = 0;
	int err = 0;

	sni_incref(sni);
	silofs_sni_vspace_range(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = wac_visit_prep_at(wa_ctx, &sni->sn_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_at_inner_spnode(wa_ctx, sni, voff, slot, &child);
		if (err) {
			break;
		}
		voff = silofs_sni_last_voff(child);
		slot++;
	}
	sni_decref(sni);

	return (err == -ENOENT) ? 0 : err;
}

static int wac_traverse_at_spnode(struct silofs_walk_ctx *wa_ctx,
                                  struct silofs_spnode_info *sni)
{
	enum silofs_stype stype_child;
	int err;

	silofs_sni_incref(sni);
	stype_child = silofs_sni_child_stype(sni);
	if (stype_isspnode(stype_child)) {
		err = wac_traverse_inner_spnode(wa_ctx, sni);
	} else {
		err = wac_traverse_bottom_spnode(wa_ctx, sni);
	}
	silofs_sni_decref(sni);
	return err;
}

static int wac_at_top_super(struct silofs_walk_ctx *wa_ctx,
                            struct silofs_sb_info *sbi,
                            loff_t voff, size_t slot,
                            struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = wac_stage_child_spnode(wa_ctx, voff, NULL, &sni);
	if (err) {
		return err;
	}
	err = wac_traverse_spnode(wa_ctx, &sbi->s_ui, sni, voff, slot);
	if (err) {
		return err;
	}
	*out_sni = sni;
	return 0;
}

static int wac_traverse_top_super(struct silofs_walk_ctx *wa_ctx,
                                  struct silofs_sb_info *sbi, loff_t *out_voff)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_spnode_info *sni = NULL;
	loff_t voff;
	size_t slot = 0;
	int err = 0;

	sbi_incref(sbi);
	silofs_sbi_vspace_range(sbi, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = wac_visit_prep_at(wa_ctx, &sbi->s_ui, voff, slot);
		if (err) {
			break;
		}
		err = wac_at_top_super(wa_ctx, sbi, voff, slot, &sni);
		if (err) {
			break;
		}
		voff = silofs_sni_last_voff(sni);
		slot++;
	}
	sbi_decref(sbi);

	*out_voff = voff;
	return err;
}

static int wac_traverse_super(struct silofs_walk_ctx *wa_ctx,
                              struct silofs_sb_info *sbi)
{
	loff_t voff = 0;
	int err;

	err = wac_visit_exec_at(wa_ctx, NULL, &sbi->s_ui, voff, 0);
	if (err) {
		return err;
	}
	err = wac_traverse_top_super(wa_ctx, sbi, &voff);
	if (err) {
		return err;
	}
	err = wac_visit_post_at(wa_ctx, NULL, &sbi->s_ui, voff, 0);
	if (err) {
		return err;
	}
	return 0;
}


static int wac_traverse_fs(struct silofs_walk_ctx *wa_ctx)
{
	int err;

	err = wac_traverse_super(wa_ctx, wa_ctx->sbi);
	wac_relax_cache(wa_ctx);
	return err;
}

int silofs_walk_space_tree(struct silofs_sb_info *sbi,
                           struct silofs_visitor *vis)
{
	struct silofs_walk_ctx wa_ctx = {
		.vis = vis,
		.apex = sbi_apex(sbi),
		.sbi = sbi,
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
usi_new(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr)
{
	struct silofs_usaddr_info *usi = NULL;

	usi = silofs_allocate(alif, sizeof(*usi));
	if (usi != NULL) {
		usi_init(usi, uaddr);
	}
	return usi;
}

static void usi_delete(struct silofs_usaddr_info *usi,
                       struct silofs_alloc_if *alif)
{
	usi_fini(usi);
	silofs_deallocate(alif, usi, sizeof(*usi));
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
	usi_delete(usi, uss->uss_alif);
}

static void uss_init(struct silofs_usaddr_set *uss,
                     struct silofs_alloc_if *alif)
{
	silofs_avl_init(&uss->uss_avl, usi_getkey, uaddr_compare, uss);
	uss->uss_alif = alif;
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
	uss->uss_alif = NULL;
}

static int uss_insert(struct silofs_usaddr_set *uss,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_usaddr_info *usi;

	usi = usi_new(uss->uss_alif, uaddr);
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
                           struct silofs_alloc_if *alif)
{
	silofs_memzero(usv, sizeof(*usv));
	uss_init(&usv->uss, alif);
	usv->vis.visit_prep_hook = NULL;
	usv->vis.visit_exec_hook = usv_visit_hook;
	usv->vis.visit_post_hook = NULL;
}

void silofs_usvisitor_fini(struct silofs_uspace_visitor *usv)
{
	uss_fini(&usv->uss);
	usv->vis.visit_exec_hook = NULL;
}

