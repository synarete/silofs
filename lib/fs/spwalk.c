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
#include <silofs/fs/repo.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/private.h>


struct silofs_ushared_info {
	struct silofs_avl_node  us_an;
	struct silofs_uaddr     us_uaddr;
	size_t us_refcnt;
};

struct silofs_ushared_set {
	struct silofs_avl       uss_avl;
	struct silofs_alloc_if *uss_alif;
};

struct silofs_spwalk_ctx {
	struct silofs_fs_apex     *apex;
	struct silofs_alloc_if    *alif;
	struct silofs_sb_info     *sbi;
	struct silofs_ushared_set  uss;
	long pad;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void usi_init(struct silofs_ushared_info *usi,
                     const struct silofs_uaddr *uaddr)
{
	silofs_avl_node_init(&usi->us_an);
	silofs_uaddr_assign(&usi->us_uaddr, uaddr);
	usi->us_refcnt = 1;
}

static void usi_fini(struct silofs_ushared_info *usi)
{
	silofs_uaddr_reset(&usi->us_uaddr);
	silofs_avl_node_fini(&usi->us_an);
}

static struct silofs_ushared_info *
usi_new(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr)
{
	struct silofs_ushared_info *usi = NULL;

	usi = silofs_allocate(alif, sizeof(*usi));
	if (usi != NULL) {
		usi_init(usi, uaddr);
	}
	return usi;
}

static void usi_delete(struct silofs_ushared_info *usi,
                       struct silofs_alloc_if *alif)
{
	usi_fini(usi);
	silofs_deallocate(alif, usi, sizeof(*usi));
}


static struct silofs_ushared_info *
usi_from_avl_node(const struct silofs_avl_node *an)
{
	const struct silofs_ushared_info *usi;

	usi = container_of2(an, struct silofs_ushared_info, us_an);
	return unconst(usi);
}

static const void *usi_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_ushared_info *usi = usi_from_avl_node(an);

	return &usi->us_uaddr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long uaddr_compare(const void *x, const void *y)
{
	const struct silofs_uaddr *uaddr_x = x;
	const struct silofs_uaddr *uaddr_y = y;

	return silofs_uaddr_compare(uaddr_x, uaddr_y);
}

static void uss_delete_usi(struct silofs_ushared_set *uss,
                           struct silofs_ushared_info *usi)
{
	usi_delete(usi, uss->uss_alif);
}

static void uss_init(struct silofs_ushared_set *uss,
                     struct silofs_alloc_if *alif)
{
	silofs_avl_init(&uss->uss_avl, usi_getkey, uaddr_compare, uss);
	uss->uss_alif = alif;
}

static void uss_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_ushared_set *uss = p;
	struct silofs_ushared_info *usi = usi_from_avl_node(an);

	uss_delete_usi(uss, usi);
}

static void uss_clear(struct silofs_ushared_set *uss)
{
	const struct silofs_avl_node_functor fn = {
		.fn = uss_avl_node_delete_cb,
		.ctx = uss
	};

	silofs_avl_clear(&uss->uss_avl, &fn);
}

static void uss_fini(struct silofs_ushared_set *uss)
{
	uss_clear(uss);
	silofs_avl_fini(&uss->uss_avl);
	uss->uss_alif = NULL;
}

static int uss_insert(struct silofs_ushared_set *uss,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_ushared_info *usi;

	usi = usi_new(uss->uss_alif, uaddr);
	if (usi == NULL) {
		return -ENOMEM;
	}
	silofs_avl_insert(&uss->uss_avl, &usi->us_an);
	return 0;
}

static struct silofs_ushared_info *
uss_lookup(const struct silofs_ushared_set *uss,
           const struct silofs_uaddr *uaddr)
{
	const struct silofs_avl_node *an;
	struct silofs_ushared_info *usi = NULL;

	an = silofs_avl_find(&uss->uss_avl, uaddr);
	if (an != NULL) {
		usi = usi_from_avl_node(an);
	}
	return usi;
}

static int uss_update(struct silofs_ushared_set *uss,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_ushared_info *usi;
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int spwc_populate_by_sni(struct silofs_spwalk_ctx *spw_ctx,
                                struct silofs_spnode_info *sni_parent);

static void spwc_bind_sbi(struct silofs_spwalk_ctx *spw_ctx,
                          struct silofs_sb_info *sbi)
{
	if (spw_ctx->sbi != NULL) {
		silofs_sbi_decref(spw_ctx->sbi);
		spw_ctx->sbi = NULL;
	}
	if (sbi != NULL) {
		silofs_sbi_incref(sbi);
		spw_ctx->sbi = sbi;
	}
}

static int spwc_add_uref(struct silofs_spwalk_ctx *spw_ctx,
                         const struct silofs_uaddr *parent,
                         const struct silofs_uaddr *uaddr)
{
	struct silofs_ushared_set *uss = &spw_ctx->uss;

	if (parent == NULL) {
		return uss_update(uss, uaddr);
	}
	return uss_update(uss, uaddr);
}

static int
spwc_stage_child_spnode(struct silofs_spwalk_ctx *spw_ctx, loff_t voff,
                        struct silofs_spnode_info *sni_parent,
                        struct silofs_spnode_info **out_sni)
{
	return silofs_sbi_stage_child_spnode(spw_ctx->sbi, voff, sni_parent,
	                                     SILOFS_STAGE_RDONLY, out_sni);
}

static int
spwc_stage_child_spleaf(struct silofs_spwalk_ctx *spw_ctx, loff_t voff,
                        struct silofs_spnode_info *sni_parent,
                        struct silofs_spleaf_info **out_sli)
{
	return silofs_sbi_stage_spleaf_of(spw_ctx->sbi, sni_parent, voff,
	                                  SILOFS_STAGE_RDONLY, out_sli);
}

static int spwc_populate_by_sli(struct silofs_spwalk_ctx *spw_ctx,
                                struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_uaddr uaddr;
	const long bk_size = SILOFS_BK_SIZE;
	int err = 0;

	silofs_sli_incref(sli);
	silofs_sli_vspace_range(sli, &vrange);
	for (loff_t voff = vrange.beg; voff < vrange.end; voff += bk_size) {
		if (!silofs_sli_has_refs_at(sli, voff)) {
			continue;
		}
		silofs_sli_resolve_child(sli, voff, &uaddr);
		err = spwc_add_uref(spw_ctx, sli_uaddr(sli), &uaddr);
		if (err) {
			goto out;
		}
	}
out:
	silofs_sli_decref(sli);
	return err;
}

static int spwc_populate_by_bottom_sni(struct silofs_spwalk_ctx *spw_ctx,
                                       struct silofs_spnode_info *sni_parent)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_spleaf_info *sli;
	loff_t voff;
	int err = 0;

	silofs_sni_incref(sni_parent);
	silofs_sni_vspace_range(sni_parent, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = spwc_stage_child_spleaf(spw_ctx, voff, sni_parent, &sli);
		if (err) {
			goto out;
		}
		err = spwc_add_uref(spw_ctx, sni_uaddr(sni_parent),
		                    sli_uaddr(sli));
		if (err) {
			goto out;
		}
		err = spwc_populate_by_sli(spw_ctx, sli);
		if (err) {
			goto out;
		}
		voff = silofs_sli_last_voff(sli);
	}
out:
	silofs_sni_decref(sni_parent);
	return (err == -ENOENT) ? 0 : err;
}

static int spwc_populate_by_inter_sni(struct silofs_spwalk_ctx *spw_ctx,
                                      struct silofs_spnode_info *sni_parent)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_spnode_info *sni;
	loff_t voff;
	int err = 0;

	silofs_sni_incref(sni_parent);
	silofs_sni_vspace_range(sni_parent, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = spwc_stage_child_spnode(spw_ctx, voff, sni_parent, &sni);
		if (err) {
			goto out;
		}
		err = spwc_add_uref(spw_ctx, sni_uaddr(sni_parent),
		                    sni_uaddr(sni));
		if (err) {
			goto out;
		}
		err = spwc_populate_by_sni(spw_ctx, sni);
		if (err) {
			goto out;
		}
		voff = silofs_sni_last_voff(sni);
	}
out:
	silofs_sni_decref(sni_parent);
	return (err == -ENOENT) ? 0 : err;
}

static int spwc_populate_by_sni(struct silofs_spwalk_ctx *spw_ctx,
                                struct silofs_spnode_info *sni_parent)
{
	const enum silofs_stype stype = silofs_sni_child_stype(sni_parent);
	int err;

	if (stype_isspnode(stype)) {
		err = spwc_populate_by_inter_sni(spw_ctx, sni_parent);
	} else {
		err = spwc_populate_by_bottom_sni(spw_ctx, sni_parent);
	}
	return err;
}

static int spwc_populate_by_sbi(struct silofs_spwalk_ctx *spw_ctx,
                                struct silofs_sb_info *sbi)
{
	struct silofs_vrange vrange = { .beg = -1 };
	struct silofs_spnode_info *sni = NULL;
	const struct silofs_uaddr *uaddr = NULL;
	loff_t voff;
	int err = 0;

	spwc_bind_sbi(spw_ctx, sbi);
	silofs_sbi_vspace_range(sbi, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = spwc_stage_child_spnode(spw_ctx, voff, NULL, &sni);
		if (err) {
			goto out;
		}
		uaddr = silofs_sni_uaddr(sni);
		err = spwc_add_uref(spw_ctx, sbi_uaddr(sbi), uaddr);
		if (err) {
			goto out;
		}
		err = spwc_populate_by_sni(spw_ctx, sni);
		if (err) {
			goto out;
		}
		voff = silofs_sni_last_voff(sni);
	}
out:
	spwc_bind_sbi(spw_ctx, NULL);
	return (err == -ENOENT) ? 0 : err;
}

static int spwc_populate_by_fs(struct silofs_spwalk_ctx *spw_ctx,
                               const struct silofs_namestr *name,
                               const struct silofs_uaddr *uaddr)
{
	struct silofs_fs_apex *apex = spw_ctx->apex;
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_apex_stage_super(apex, name, uaddr, &sbi);
	if (err) {
		return err;
	}
	err = spwc_add_uref(spw_ctx, NULL, uaddr);
	if (err) {
		return err;
	}
	err = spwc_populate_by_sbi(spw_ctx, sbi);
	if (err) {
		return err;
	}
	return 0;
}

static int spwc_populate_ushared_set(struct silofs_spwalk_ctx *spw_ctx)
{
	struct silofs_bootsec bsec = { .bootf = -1 };
	struct silofs_namestr name = { .str.len = 0 };
	int err = 0;

	while (!err) {
		err = -ENOENT; /* TODO XXX FIXME */
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		silofs_namebuf_str(&bsec.name, &name);
		err = spwc_populate_by_fs(spw_ctx, &name, &bsec.sb_uaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static void spwc_ctx_init(struct silofs_spwalk_ctx *spw_ctx,
                          struct silofs_fs_apex *apex)
{
	spw_ctx->apex = apex;
	spw_ctx->alif = apex->ap_alif;
	spw_ctx->sbi = NULL;
	uss_init(&spw_ctx->uss, spw_ctx->alif);
}

static void spwc_ctx_fini(struct silofs_spwalk_ctx *spw_ctx)
{
	spwc_bind_sbi(spw_ctx, NULL);
	uss_fini(&spw_ctx->uss);
	spw_ctx->apex = NULL;
	spw_ctx->alif = NULL;
}

int silofs_apex_prune_space(struct silofs_fs_apex *apex)
{
	struct silofs_spwalk_ctx gc_ctx = { .pad = 0 };
	int err = 0;

	spwc_ctx_init(&gc_ctx, apex);
	err = spwc_populate_ushared_set(&gc_ctx);
	if (err) {
		goto out;
	}

	/* XXX complete me */

out:
	spwc_ctx_fini(&gc_ctx);
	return err;
}


