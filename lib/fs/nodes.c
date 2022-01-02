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
#include <silofs/fs/address.h>
#include <silofs/fs/types.h>
#include <silofs/fs/mpool.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>
#include <silofs/fs/private.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

/* local functions forward declarations */
static const struct silofs_tnode_vtbl sbi_vtbl;
static const struct silofs_tnode_vtbl sni_vtbl;
static const struct silofs_tnode_vtbl sli_vtbl;
static const struct silofs_tnode_vtbl itni_vtbl;
static const struct silofs_tnode_vtbl ii_vtbl;
static const struct silofs_tnode_vtbl xai_vtbl;
static const struct silofs_tnode_vtbl syi_vtbl;
static const struct silofs_tnode_vtbl dni_vtbl;
static const struct silofs_tnode_vtbl fni_vtbl;
static const struct silofs_tnode_vtbl fli_vtbl;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lh_init(struct silofs_list_head *lh)
{
	silofs_list_head_init(lh);
}

static void lh_fini(struct silofs_list_head *lh)
{
	silofs_list_head_fini(lh);
}

static void an_init(struct silofs_avl_node *an)
{
	silofs_avl_node_init(an);
}

static void an_fini(struct silofs_avl_node *an)
{
	silofs_avl_node_fini(an);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t uaddr_bk_pos(const struct silofs_uaddr *uaddr)
{
	return silofs_off_in_bk(uaddr->oaddr.pos);
}

static loff_t vaddr_bk_pos(const struct silofs_vaddr *vaddr)
{
	return silofs_off_in_bk(vaddr_off(vaddr));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ti_init(struct silofs_tnode_info *ti, enum silofs_stype stype,
                    const struct silofs_tnode_vtbl *vtbl)
{
	silofs_ce_init(&ti->t_ce);
	lh_init(&ti->t_dq_lh);
	an_init(&ti->t_ds_an);
	ti->t_stype = stype;
	ti->t_ds_next = NULL;
	ti->t_apex = NULL;
	ti->t_view = NULL;
	ti->t_vtbl = vtbl;
	ti->t_noflush = false;
}

static void ti_fini(struct silofs_tnode_info *ti)
{
	silofs_ce_fini(&ti->t_ce);
	lh_fini(&ti->t_dq_lh);
	an_fini(&ti->t_ds_an);
	ti->t_stype = SILOFS_STYPE_NONE;
	ti->t_ds_next = NULL;
	ti->t_apex = NULL;
	ti->t_view = NULL;
	ti->t_vtbl = NULL;
}

static void ti_seal_noop(struct silofs_tnode_info *ti)
{
	silofs_unused(ti);
}

static bool ti_evictable(const struct silofs_tnode_info *ti)
{
	return silofs_ti_isevictable(ti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *ui_unconst(const struct silofs_unode_info *ui)
{
	union {
		const struct silofs_unode_info *p;
		struct silofs_unode_info *q;
	} u = {
		.p = ui
	};
	return u.q;
}

static void ui_init(struct silofs_unode_info *ui,
                    const struct silofs_uaddr *uaddr,
                    const struct silofs_tnode_vtbl *vtbl)
{
	ti_init(&ui->u_ti, uaddr->stype, vtbl);
	lh_init(&ui->u_sptm_lh);
	silofs_uaddr_assign(&ui->u_uaddr, uaddr);
	silofs_taddr_by_uaddr(&ui->u_taddr, uaddr);
	ui->u_ubi = NULL;
	ui->u_tmapped = false;
	ui->u_verified = false;
}

static void ui_fini(struct silofs_unode_info *ui)
{
	silofs_assert(!ui->u_tmapped);
	silofs_uaddr_reset(&ui->u_uaddr);
	lh_fini(&ui->u_sptm_lh);
	ti_fini(&ui->u_ti);
}

struct silofs_unode_info *
silofs_ui_from_ti(const struct silofs_tnode_info *ti)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(ti != NULL)) {
		ui = container_of2(ti, struct silofs_unode_info, u_ti);
	}
	return ui_unconst(ui);
}

static int ui_resolve(const struct silofs_unode_info *ui,
                      struct silofs_oaddr *out_oaddr)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	oaddr_assign(out_oaddr, &uaddr->oaddr);
	return 0;
}

static int ui_resolve_as_ti(const struct silofs_tnode_info *ti,
                            struct silofs_oaddr *out_oaddr)
{
	return ui_resolve(silofs_ui_from_ti(ti), out_oaddr);
}

static void ui_seal_as_ti(struct silofs_tnode_info *ti)
{
	struct silofs_unode_info *ui = silofs_ui_from_ti(ti);

	silofs_unused(ui);
}

static size_t ui_length(const struct silofs_unode_info *ui)
{
	return silofs_stype_size(ui->u_ti.t_stype);
}

void silofs_ui_clone_into(const struct silofs_unode_info *ui,
                          struct silofs_unode_info *ui_other)
{
	const size_t len = ui_length(ui);
	const union silofs_view *src_view = ui->u_ti.t_view;
	union silofs_view *dst_view = ui_other->u_ti.t_view;

	silofs_assert_eq(ui->u_ti.t_stype, ui_other->u_ti.t_stype);
	memcpy(dst_view, src_view, len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *vi_unconst(const struct silofs_vnode_info *vi)
{
	union {
		const struct silofs_vnode_info *p;
		struct silofs_vnode_info *q;
	} u = {
		.p = vi
	};
	return u.q;
}

static struct silofs_vnode_info *
vi_from_fiovref(const struct silofs_fiovref *fir)
{
	const struct silofs_vnode_info *vi = NULL;

	vi = container_of2(fir, struct silofs_vnode_info, v_fir);
	return vi_unconst(vi);
}


static void vi_fiov_pre(struct silofs_fiovref *fir)
{
	struct silofs_vnode_info *vi = vi_from_fiovref(fir);

	silofs_vi_incref(vi);
	vi->v_ti.t_noflush = true;
}

static void vi_fiov_post(struct silofs_fiovref *fir)
{
	struct silofs_vnode_info *vi = vi_from_fiovref(fir);

	silofs_vi_decref(vi);
	vi->v_ti.t_noflush = false;
}

static void vi_init(struct silofs_vnode_info *vi,
                    const struct silofs_vaddr *vaddr,
                    const struct silofs_tnode_vtbl *vtbl)
{
	ti_init(&vi->v_ti, vaddr->stype, vtbl);
	vaddr_assign(&vi->v_vaddr, vaddr);
	silofs_fiovref_init(&vi->v_fir, vi_fiov_pre, vi_fiov_post);
	vi->v_recheck = false;
	vi->v_verified = false;
	vi->v_vbi = NULL;
}

static void vi_fini(struct silofs_vnode_info *vi)
{
	ti_fini(&vi->v_ti);
	vaddr_reset(&vi->v_vaddr);
	silofs_fiovref_fini(&vi->v_fir);
}

struct silofs_vnode_info *
silofs_vi_from_ti(const struct silofs_tnode_info *ti)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(ti != NULL)) {
		vi = container_of2(ti, struct silofs_vnode_info, v_ti);
	}
	return vi_unconst(vi);
}

bool silofs_vi_isdata(const struct silofs_vnode_info *vi)
{
	return silofs_stype_isdata(vi_stype(vi));
}

static int vi_resolve(const struct silofs_vnode_info *vi,
                      struct silofs_oaddr *out_oaddr)
{
	struct silofs_uvaddr uva;
	struct silofs_sb_info *sbi = vi_sbi(vi);
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_RDONLY;
	int err;

	err = silofs_sbi_resolve_uva(sbi, vi_vaddr(vi), stg_flags, &uva);
	if (!err) {
		oaddr_assign(out_oaddr, &uva.uaddr.oaddr);
	}
	return err;
}

static int vi_resolve_as_ti(const struct silofs_tnode_info *ti,
                            struct silofs_oaddr *out_oaddr)
{
	const struct silofs_vnode_info *vi = silofs_vi_from_ti(ti);

	return (likely(vi != NULL)) ? vi_resolve(vi, out_oaddr) : -ENOENT;
}

static void vi_seal_as_ti(struct silofs_tnode_info *ti)
{
	struct silofs_vnode_info *vi = silofs_vi_from_ti(ti);

	silofs_vi_seal_meta(vi);
}

static bool vi_has_stype(const struct silofs_vnode_info *vi,
                         enum silofs_stype stype)
{
	return vi_stype(vi) == stype;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *
sbi_to_ui(const struct silofs_sb_info *sbi)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(sbi != NULL)) {
		ui = &sbi->s_ui;
	}
	return ui_unconst(ui);
}

struct silofs_sb_info *
silofs_sbi_from_ui(const struct silofs_unode_info *ui)
{
	const struct silofs_sb_info *sbi = NULL;

	if (likely(ui != NULL)) {
		sbi = container_of2(ui, struct silofs_sb_info, s_ui);
	}
	return unconst(sbi);
}

static struct silofs_sb_info *sbi_from_ti(const struct silofs_tnode_info *ti)
{
	return silofs_sbi_from_ui(silofs_ui_from_ti(ti));
}

static void sbi_init(struct silofs_sb_info *sbi,
                     const struct silofs_uaddr *uaddr)
{
	silofs_sbi_init_commons(sbi);
	ui_init(&sbi->s_ui, uaddr, &sbi_vtbl);
}

static void sbi_fini(struct silofs_sb_info *sbi)
{
	silofs_sbi_fini(sbi);
	ui_fini(&sbi->s_ui);
	silofs_memffff(sbi, sizeof(*sbi));
}

static struct silofs_sb_info *sbi_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_sb_info *sbi;

	sbi = silofs_allocate(alif, sizeof(*sbi));
	return sbi;
}

static void sbi_free(struct silofs_sb_info *sbi,
                     struct silofs_alloc_if *alif)
{
	silofs_memffff(sbi, sizeof(*sbi));
	silofs_deallocate(alif, sbi, sizeof(*sbi));
}

static void sbi_delete(struct silofs_sb_info *sbi,
                       struct silofs_alloc_if *alif)
{
	sbi_fini(sbi);
	sbi_free(sbi, alif);
}

static void sbi_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc_if *alif)
{
	sbi_delete(silofs_sbi_from_ui(ui), alif);
}

static void sbi_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	sbi_delete_as_ui(silofs_ui_from_ti(ti), alif);
}

static bool sbi_evictable_as_ti(const struct silofs_tnode_info *ti)
{
	const struct silofs_sb_info *sbi = sbi_from_ti(ti);

	silofs_assert(ti ==  &sbi->s_ui.u_ti);

	return ti_evictable(&sbi->s_ui.u_ti);
}

static struct silofs_sb_info *
sbi_new(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr)
{
	struct silofs_sb_info *sbi;

	sbi = sbi_malloc(alif);
	if (sbi != NULL) {
		sbi_init(sbi, uaddr);
	}
	return sbi;
}

static const struct silofs_tnode_vtbl sbi_vtbl = {
	.del = sbi_delete_as_ti,
	.evictable = sbi_evictable_as_ti,
	.seal = ui_seal_as_ti,
	.resolve = ui_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *
sni_to_ui(const struct silofs_spnode_info *sni)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(sni != NULL)) {
		ui = &sni->sn_ui;
	}
	return ui_unconst(ui);
}

static void sni_init(struct silofs_spnode_info *sni,
                     const struct silofs_uaddr *uaddr)
{
	ui_init(&sni->sn_ui, uaddr, &sni_vtbl);
	sni->sn = NULL;
	sni->sn_nchild_form = 0;
	sni->sn_nused_bytes = 0;
}

static void sni_fini(struct silofs_spnode_info *sni)
{
	ui_fini(&sni->sn_ui);
	sni->sn = NULL;
	sni->sn_nchild_form = 0;
	sni->sn_nused_bytes = ULONG_MAX;
}

static struct silofs_spnode_info *sni_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_spnode_info *sni;

	sni = silofs_allocate(alif, sizeof(*sni));
	return sni;
}

static void sni_free(struct silofs_spnode_info *sni,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, sni, sizeof(*sni));
}

static void sni_delete(struct silofs_spnode_info *sni,
                       struct silofs_alloc_if *alif)
{
	sni_fini(sni);
	sni_free(sni, alif);
}

static void sni_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc_if *alif)
{
	sni_delete(silofs_sni_from_ui(ui), alif);
}

static void sni_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	sni_delete_as_ui(silofs_ui_from_ti(ti), alif);
}

static struct silofs_spnode_info *
sni_new(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr)
{
	struct silofs_spnode_info *sni;

	sni = sni_malloc(alif);
	if (sni != NULL) {
		sni_init(sni, uaddr);
	}
	return sni;
}

struct silofs_spnode_info *
silofs_sni_from_ui(const struct silofs_unode_info *ui)
{
	const struct silofs_spnode_info *sni = NULL;

	if (ui != NULL) {
		sni = container_of2(ui, struct silofs_spnode_info, sn_ui);
	}
	return unconst(sni);
}

void silofs_sni_rebind_view(struct silofs_spnode_info *sni)
{
	sni->sn = &sni->sn_ui.u_ti.t_view->sn;
}

static const struct silofs_tnode_vtbl sni_vtbl = {
	.del = sni_delete_as_ti,
	.evictable = ti_evictable,
	.seal = ui_seal_as_ti,
	.resolve = ui_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *
sli_to_ui(const struct silofs_spleaf_info *sli)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(sli != NULL)) {
		ui = &sli->sl_ui;
	}
	return ui_unconst(ui);
}

static void sli_init(struct silofs_spleaf_info *sli,
                     const struct silofs_uaddr *uaddr)
{
	ui_init(&sli->sl_ui, uaddr, &sli_vtbl);
	sli->sl = NULL;
	sli->sl_nused_bytes = 0;
	sli->sl_voff_last = SILOFS_OFF_NULL;
}

static void sli_fini(struct silofs_spleaf_info *sli)
{
	ui_fini(&sli->sl_ui);
	sli->sl = NULL;
	sli->sl_nused_bytes = ULONG_MAX;
	sli->sl_voff_last = SILOFS_OFF_NULL;
}

static struct silofs_spleaf_info *sli_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_spleaf_info *sli;

	sli = silofs_allocate(alif, sizeof(*sli));
	return sli;
}

static void sli_free(struct silofs_spleaf_info *sli,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, sli, sizeof(*sli));
}

static void sli_delete(struct silofs_spleaf_info *sli,
                       struct silofs_alloc_if *alif)
{
	sli_fini(sli);
	sli_free(sli, alif);
}

static void sli_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc_if *alif)
{
	sli_delete(silofs_sli_from_ui(ui), alif);
}

static void sli_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	sli_delete_as_ui(silofs_ui_from_ti(ti), alif);
}

static struct silofs_spleaf_info *
sli_new(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr)
{
	struct silofs_spleaf_info *sli;

	sli = sli_malloc(alif);
	if (sli != NULL) {
		sli_init(sli, uaddr);
	}
	return sli;
}

struct silofs_spleaf_info *
silofs_sli_from_ui(const struct silofs_unode_info *ui)
{
	const struct silofs_spleaf_info *sli = NULL;

	if (ui != NULL) {
		sli = container_of2(ui, struct silofs_spleaf_info, sl_ui);
	}
	return unconst(sli);
}

void silofs_sli_rebind_view(struct silofs_spleaf_info *sli)
{
	sli->sl = &sli->sl_ui.u_ti.t_view->sl;
}

static const struct silofs_tnode_vtbl sli_vtbl = {
	.del = sli_delete_as_ti,
	.evictable = ti_evictable,
	.seal = ui_seal_as_ti,
	.resolve = ui_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
itni_to_vi(const struct silofs_itnode_info *itni)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(itni != NULL)) {
		vi = &itni->itn_vi;
	}
	return vi_unconst(vi);
}

static void itni_init(struct silofs_itnode_info *itni,
                      const struct silofs_vaddr *vaddr)
{
	vi_init(&itni->itn_vi, vaddr, &itni_vtbl);
	itni->itn = NULL;
}

static void itni_fini(struct silofs_itnode_info *itni)
{
	vi_fini(&itni->itn_vi);
	itni->itn = NULL;
}

static struct silofs_itnode_info *itni_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_itnode_info *itni;

	itni = silofs_allocate(alif, sizeof(*itni));
	return itni;
}

static void itni_free(struct silofs_itnode_info *itni,
                      struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, itni, sizeof(*itni));
}

static void itni_delete(struct silofs_itnode_info *itni,
                        struct silofs_alloc_if *alif)
{
	itni_fini(itni);
	itni_free(itni, alif);
}

static void itni_delete_as_vi(struct silofs_vnode_info *vi,
                              struct silofs_alloc_if *alif)
{
	itni_delete(silofs_itni_from_vi(vi), alif);
}

static void itni_delete_as_ti(struct silofs_tnode_info *ti,
                              struct silofs_alloc_if *alif)
{
	itni_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_itnode_info *
itni_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_itnode_info *itni;

	itni = itni_malloc(alif);
	if (itni != NULL) {
		itni_init(itni, vaddr);
	}
	return itni;
}

struct silofs_itnode_info *silofs_itni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_itnode_info *itni = NULL;

	silofs_assert_not_null(vi);

	silofs_assert(vi_has_stype(vi, SILOFS_STYPE_ITNODE));
	itni = container_of(vi, struct silofs_itnode_info, itn_vi);
	return itni;
}

void silofs_itni_rebind_view(struct silofs_itnode_info *itni)
{
	itni->itn = &itni->itn_vi.v_ti.t_view->itn;
}

static const struct silofs_tnode_vtbl itni_vtbl = {
	.del = itni_delete_as_ti,
	.evictable = ti_evictable,
	.seal = vi_seal_as_ti,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_info *ii_from_ti(const struct silofs_tnode_info
                *ti)
{
	return silofs_ii_from_vi(silofs_vi_from_ti(ti));
}

static void ii_init(struct silofs_inode_info *ii,
                    const struct silofs_vaddr *vaddr)
{
	vi_init(&ii->i_vi, vaddr, &ii_vtbl);
	ii->inode = NULL;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = 0;
	ii->i_nlookup = 0;
	ii->i_pinned = false;
}

static void ii_fini(struct silofs_inode_info *ii)
{
	silofs_assert_ge(ii->i_nopen, 0);

	vi_fini(&ii->i_vi);
	ii->inode = NULL;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static struct silofs_inode_info *ii_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_inode_info *ii;

	ii = silofs_allocate(alif, sizeof(*ii));
	return ii;
}

static void ii_free(struct silofs_inode_info *ii,
                    struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, ii, sizeof(*ii));
}

static void ii_delete(struct silofs_inode_info *ii,
                      struct silofs_alloc_if *alif)
{
	ii_fini(ii);
	ii_free(ii, alif);
}

static void ii_delete_as_vi(struct silofs_vnode_info *vi,
                            struct silofs_alloc_if *alif)
{
	ii_delete(silofs_ii_from_vi(vi), alif);
}

static void ii_delete_as_ti(struct silofs_tnode_info *ti,
                            struct silofs_alloc_if *alif)
{
	ii_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_info *ii;

	ii = ii_malloc(alif);
	if (ii != NULL) {
		ii_init(ii, vaddr);
	}
	return ii;
}

static bool ii_evictable_as_ti(const struct silofs_tnode_info *ti)
{
	const struct silofs_inode_info *ii = ii_from_ti(ti);

	return silofs_ii_isevictable(ii);
}

struct silofs_inode_info *silofs_ii_from_vi(const struct silofs_vnode_info *vi)
{
	const struct silofs_inode_info *ii = NULL;

	if (likely(vi != NULL)) {
		ii = container_of2(vi, struct silofs_inode_info, i_vi);
	}
	return ii_unconst(ii);
}

void silofs_ii_rebind_view(struct silofs_inode_info *ii, ino_t ino)
{
	silofs_assert_not_null(ii);

	ii->inode = &ii->i_vi.v_ti.t_view->in;
	ii->i_ino = ino;
}

static const struct silofs_tnode_vtbl ii_vtbl = {
	.del = ii_delete_as_ti,
	.evictable = ii_evictable_as_ti,
	.seal = vi_seal_as_ti,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
xai_to_vi(const struct silofs_xanode_info *xai)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(xai != NULL)) {
		vi = &xai->xa_vi;
	}
	return vi_unconst(vi);
}

static void xai_init(struct silofs_xanode_info *xai,
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&xai->xa_vi, vaddr, &xai_vtbl);
	xai->xan = NULL;
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vi_fini(&xai->xa_vi);
	xai->xan = NULL;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_xanode_info *xai;

	xai = silofs_allocate(alif, sizeof(*xai));
	return xai;
}

static void xai_free(struct silofs_xanode_info *xai,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, xai, sizeof(*xai));
}

static void xai_delete(struct silofs_xanode_info *xai,
                       struct silofs_alloc_if *alif)
{
	xai_fini(xai);
	xai_free(xai, alif);
}

static void xai_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc_if *alif)
{
	xai_delete(silofs_xai_from_vi(vi), alif);
}

static void xai_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	xai_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_xanode_info *xai;

	xai = xai_malloc(alif);
	if (xai != NULL) {
		xai_init(xai, vaddr);
	}
	return xai;
}

struct silofs_xanode_info *silofs_xai_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_xanode_info *xai = NULL;

	silofs_assert_not_null(vi);
	silofs_assert(vi_has_stype(vi, SILOFS_STYPE_XANODE));
	xai = container_of(vi, struct silofs_xanode_info, xa_vi);
	return xai;
}

void silofs_xai_rebind_view(struct silofs_xanode_info *xai)
{
	xai->xan = &xai->xa_vi.v_ti.t_view->xan;
}

static const struct silofs_tnode_vtbl xai_vtbl = {
	.del = xai_delete_as_ti,
	.evictable = ti_evictable,
	.seal = vi_seal_as_ti,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
syi_to_vi(const struct silofs_symval_info *syi)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(syi != NULL)) {
		vi = &syi->sy_vi;
	}
	return vi_unconst(vi);
}

static void syi_init(struct silofs_symval_info *syi,
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&syi->sy_vi, vaddr, &syi_vtbl);
	syi->syv = NULL;
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vi_fini(&syi->sy_vi);
	syi->syv = NULL;
}

static struct silofs_symval_info *syi_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_symval_info *syi;

	syi = silofs_allocate(alif, sizeof(*syi));
	return syi;
}

static void syi_free(struct silofs_symval_info *syi,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, syi, sizeof(*syi));
}

static void syi_delete(struct silofs_symval_info *syi,
                       struct silofs_alloc_if *alif)
{
	syi_fini(syi);
	syi_free(syi, alif);
}

static void syi_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc_if *alif)
{
	syi_delete(silofs_syi_from_vi(vi), alif);
}

static void syi_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	syi_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_symval_info *
syi_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_symval_info *syi;

	syi = syi_malloc(alif);
	if (syi != NULL) {
		syi_init(syi, vaddr);
	}
	return syi;
}

struct silofs_symval_info *silofs_syi_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_symval_info *syi = NULL;

	silofs_assert_not_null(vi);
	silofs_assert(vi_has_stype(vi, SILOFS_STYPE_SYMVAL));
	syi = container_of(vi, struct silofs_symval_info, sy_vi);
	return syi;
}

void silofs_syi_rebind_view(struct silofs_symval_info *syi)
{
	syi->syv = &syi->sy_vi.v_ti.t_view->sym;
}

static const struct silofs_tnode_vtbl syi_vtbl = {
	.del = syi_delete_as_ti,
	.evictable = ti_evictable,
	.seal = vi_seal_as_ti,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
dni_to_vi(const struct silofs_dnode_info *dni)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(dni != NULL)) {
		vi = &dni->dn_vi;
	}
	return vi_unconst(vi);
}

static void dni_init(struct silofs_dnode_info *dni,
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&dni->dn_vi, vaddr, &dni_vtbl);
	dni->dtn = NULL;
}

static void dni_fini(struct silofs_dnode_info *dni)
{
	vi_fini(&dni->dn_vi);
	dni->dtn = NULL;
}

static struct silofs_dnode_info *dni_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_dnode_info *dni;

	dni = silofs_allocate(alif, sizeof(*dni));
	return dni;
}

static void dni_free(struct silofs_dnode_info *dni,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, dni, sizeof(*dni));
}

static void dni_delete(struct silofs_dnode_info *dni,
                       struct silofs_alloc_if *alif)
{
	dni_fini(dni);
	dni_free(dni, alif);
}

static void dni_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc_if *alif)
{
	dni_delete(silofs_dni_from_vi(vi), alif);
}

static void dni_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	dni_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_dnode_info *
dni_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_dnode_info *dni;

	dni = dni_malloc(alif);
	if (dni != NULL) {
		dni_init(dni, vaddr);
	}
	return dni;
}

struct silofs_dnode_info *silofs_dni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_dnode_info *dni = NULL;

	silofs_assert_not_null(vi);

	if (vi != NULL) {
		silofs_assert(vi_has_stype(vi, SILOFS_STYPE_DTNODE));
		dni = container_of(vi, struct silofs_dnode_info, dn_vi);
	}
	return dni;
}

void silofs_dni_rebind_view(struct silofs_dnode_info *dni)
{
	dni->dtn = &dni->dn_vi.v_ti.t_view->dtn;
}

static const struct silofs_tnode_vtbl dni_vtbl = {
	.del = dni_delete_as_ti,
	.evictable = ti_evictable,
	.seal = vi_seal_as_ti,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
fni_to_vi(const struct silofs_finode_info *fni)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(fni != NULL)) {
		vi = &fni->fn_vi;
	}
	return vi_unconst(vi);
}

static void fni_init(struct silofs_finode_info *fni,
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&fni->fn_vi, vaddr, &fni_vtbl);
	fni->ftn = NULL;
}

static void fni_fini(struct silofs_finode_info *fni)
{
	vi_fini(&fni->fn_vi);
	fni->ftn = NULL;
}

static struct silofs_finode_info *fni_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_finode_info *fni;

	fni = silofs_allocate(alif, sizeof(*fni));
	return fni;
}

static void fni_free(struct silofs_finode_info *fni,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, fni, sizeof(*fni));
}

static void fni_delete(struct silofs_finode_info *fni,
                       struct silofs_alloc_if *alif)
{
	fni_fini(fni);
	fni_free(fni, alif);
}

static void fni_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc_if *alif)
{
	fni_delete(silofs_fni_from_vi(vi), alif);
}

static void fni_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	fni_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_finode_info *
fni_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_finode_info *fni;

	fni = fni_malloc(alif);
	if (fni != NULL) {
		fni_init(fni, vaddr);
	}
	return fni;
}

struct silofs_finode_info *silofs_fni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_finode_info *fni = NULL;

	silofs_assert_not_null(vi);

	silofs_assert(vi_has_stype(vi, SILOFS_STYPE_FTNODE));
	fni = container_of(vi, struct silofs_finode_info, fn_vi);
	return fni;
}

void silofs_fni_rebind_view(struct silofs_finode_info *fni)
{
	fni->ftn = &fni->fn_vi.v_ti.t_view->ftn;
}

static const struct silofs_tnode_vtbl fni_vtbl = {
	.del = fni_delete_as_ti,
	.evictable = ti_evictable,
	.seal = vi_seal_as_ti,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
fli_to_vi(const struct silofs_fileaf_info *fli)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(fli != NULL)) {
		vi = &fli->fl_vi;
	}
	return vi_unconst(vi);
}

static void fli_init(struct silofs_fileaf_info *fli,
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&fli->fl_vi, vaddr, &fli_vtbl);
	fli->flu.db = NULL;
}

static void fli_fini(struct silofs_fileaf_info *fli)
{
	vi_fini(&fli->fl_vi);
	fli->flu.db = NULL;
}

static struct silofs_fileaf_info *fli_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_fileaf_info *fli;

	fli = silofs_allocate(alif, sizeof(*fli));
	return fli;
}

static void fli_free(struct silofs_fileaf_info *fli,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, fli, sizeof(*fli));
}

static void fli_delete(struct silofs_fileaf_info *fli,
                       struct silofs_alloc_if *alif)
{
	fli_fini(fli);
	fli_free(fli, alif);
}

static void fli_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc_if *alif)
{
	fli_delete(silofs_fli_from_vi(vi), alif);
}

static void fli_delete_as_ti(struct silofs_tnode_info *ti,
                             struct silofs_alloc_if *alif)
{
	fli_delete_as_vi(silofs_vi_from_ti(ti), alif);
}

static struct silofs_fileaf_info *
fli_new(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_fileaf_info *fli;

	fli = fli_malloc(alif);
	if (fli != NULL) {
		fli_init(fli, vaddr);
	}
	return fli;
}

static enum silofs_stype fli_stype(const struct silofs_fileaf_info *fli)
{
	return vi_stype(&fli->fl_vi);
}

struct silofs_fileaf_info *silofs_fli_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_fileaf_info *fli = NULL;

	silofs_assert_not_null(vi);
	fli = container_of(vi, struct silofs_fileaf_info, fl_vi);
	return fli;
}

void silofs_fli_rebind_view(struct silofs_fileaf_info *fli)
{
	const enum silofs_stype stype = fli_stype(fli);

	if (stype == SILOFS_STYPE_DATA1K) {
		fli->flu.db1 = &fli->fl_vi.v_ti.t_view->db1;
	} else if (stype == SILOFS_STYPE_DATA4K) {
		fli->flu.db4 = &fli->fl_vi.v_ti.t_view->db4;
	} else {
		silofs_assert_eq(stype, SILOFS_STYPE_DATABK);
		fli->flu.db = &fli->fl_vi.v_ti.t_view->db;
	}
}

static const struct silofs_tnode_vtbl fli_vtbl = {
	.del = fli_delete_as_ti,
	.evictable = ti_evictable,
	.seal = ti_seal_noop,
	.resolve = vi_resolve_as_ti,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	switch (uaddr->stype) {
	case SILOFS_STYPE_SUPER:
		ui = sbi_to_ui(sbi_new(alif, uaddr));
		break;
	case SILOFS_STYPE_SPNODE:
		ui = sni_to_ui(sni_new(alif, uaddr));
		break;
	case SILOFS_STYPE_SPLEAF:
		ui = sli_to_ui(sli_new(alif, uaddr));
		break;
	case SILOFS_STYPE_ITNODE:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		ui = NULL;
		break;
	}
	return ui;
}

struct silofs_vnode_info *
silofs_new_vi(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	switch (vaddr->stype) {
	case SILOFS_STYPE_ITNODE:
		vi = itni_to_vi(itni_new(alif, vaddr));
		break;
	case SILOFS_STYPE_INODE:
		vi = ii_to_vi(ii_new(alif, vaddr));
		break;
	case SILOFS_STYPE_XANODE:
		vi = xai_to_vi(xai_new(alif, vaddr));
		break;
	case SILOFS_STYPE_SYMVAL:
		vi = syi_to_vi(syi_new(alif, vaddr));
		break;
	case SILOFS_STYPE_DTNODE:
		vi = dni_to_vi(dni_new(alif, vaddr));
		break;
	case SILOFS_STYPE_FTNODE:
		vi = fni_to_vi(fni_new(alif, vaddr));
		break;
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		vi = fli_to_vi(fli_new(alif, vaddr));
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		vi = NULL;
		silofs_assert_not_null(vi);
		break;
	}
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const void *
opaque_view_of(const struct silofs_block *bk, long bk_pos)
{
	silofs_assert_ge(bk_pos, 0);
	silofs_assert_lt(bk_pos, SILOFS_BK_SIZE);
	return &bk->u.bk[bk_pos];
}

static union silofs_view *make_view(const void *opaque_view)
{
	union {
		const union silofs_view *vp;
		union silofs_view *vq;
	} u = {
		.vp = opaque_view
	};
	return u.vq;
}

static void ti_bind_view(struct silofs_tnode_info *ti,
                         struct silofs_block *bk, long bk_pos)
{
	ti->t_view = make_view(opaque_view_of(bk, bk_pos));
}

void silofs_ui_bind_view(struct silofs_unode_info *ui)
{
	const loff_t bk_pos = uaddr_bk_pos(ui_uaddr(ui));

	ti_bind_view(&ui->u_ti, ui->u_ubi->ubk, bk_pos);
}

void silofs_vi_bind_view(struct silofs_vnode_info *vi)
{
	const loff_t bk_pos = vaddr_bk_pos(vi_vaddr(vi));

	ti_bind_view(&vi->v_ti, vi->v_vbi->vbk, bk_pos);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint32_t hdr_magic(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_magic);
}

static void hdr_set_magic(struct silofs_header *hdr, uint32_t magic)
{
	hdr->h_magic = silofs_cpu_to_le32(magic);
}

static size_t hdr_size(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_size);
}

static size_t hdr_payload_size(const struct silofs_header *hdr)
{
	return hdr_size(hdr) - sizeof(*hdr);
}

static void hdr_set_size(struct silofs_header *hdr, size_t size)
{
	hdr->h_size = silofs_cpu_to_le32((uint32_t)size);
}

static enum silofs_stype hdr_stype(const struct silofs_header *hdr)
{
	return (enum silofs_stype)(hdr->h_stype);
}

static void hdr_set_stype(struct silofs_header *hdr, enum silofs_stype stype)
{
	hdr->h_stype = (uint8_t)stype;
}

static uint32_t hdr_csum(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct silofs_header *hdr, uint32_t csum)
{
	hdr->h_csum = silofs_cpu_to_le32(csum);
	hdr->h_flags |= SILOFS_HDRF_CSUM;
}

static bool hdr_has_csum(const struct silofs_header *hdr)
{
	return (hdr->h_flags & SILOFS_HDRF_CSUM) > 0;
}

static const void *hdr_payload(const struct silofs_header *hdr)
{
	return hdr + 1;
}

static void hdr_stamp(struct silofs_header *hdr,
                      enum silofs_stype stype, size_t size)
{
	hdr_set_magic(hdr, SILOFS_STYPE_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_stype(hdr, stype);
	hdr->h_csum = 0;
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t calc_meta_chekcsum(const struct silofs_header *hdr,
                                   const struct silofs_mdigest *md)
{
	uint32_t csum = 0;
	const void *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	silofs_assert_le(pl_size, SILOFS_BK_SIZE - SILOFS_HEADER_SIZE);

	silofs_crc32_of(md, payload, pl_size, &csum);
	return csum;
}

static uint32_t calc_data_checksum(const void *dat, size_t len,
                                   const struct silofs_mdigest *md)
{
	uint32_t csum = 0;

	silofs_crc32_of(md, dat, len, &csum);
	return csum;
}

static const struct silofs_mdigest *
vi_mdigest(const struct silofs_vnode_info *vi)
{
	return &vi->v_ti.t_apex->ap_crypto->md;
}

static uint32_t calc_chekcsum_of(const struct silofs_vnode_info *vi)
{
	uint32_t csum;
	const struct silofs_mdigest *md = vi_mdigest(vi);
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);

	if (vaddr_isdata(vaddr)) {
		csum = calc_data_checksum(vi->v_ti.t_view, vaddr->len, md);
	} else {
		csum = calc_meta_chekcsum(&vi->v_ti.t_view->hdr, md);
	}
	return csum;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int view_verify_hdr(const union silofs_view *view,
                           enum silofs_stype stype)
{
	const struct silofs_header *hdr = &view->hdr;
	const size_t hsz = hdr_size(hdr);
	const size_t psz = stype_size(stype);

	if (stype_isdata(stype)) {
		return 0;
	}
	if (hdr_magic(hdr) != SILOFS_STYPE_MAGIC) {
		return -EFSCORRUPTED;
	}
	if (hdr_stype(hdr) != stype) {
		return -EFSCORRUPTED;
	}
	if (hsz != psz) {
		return -EFSCORRUPTED;
	}

	return 0;
}

static int view_verify_checksum(const union silofs_view *view,
                                const struct silofs_mdigest *md)
{
	uint32_t csum;
	const struct silofs_header *hdr = &view->hdr;

	if (hdr_has_csum(hdr)) {
		csum = calc_meta_chekcsum(hdr, md);
		if (csum != hdr_csum(hdr)) {
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

static int view_verify_sub(const union silofs_view *view,
                           enum silofs_stype stype)
{
	int err;

	switch (stype) {
	case SILOFS_STYPE_SUPER:
		err = silofs_verify_super_block(&view->sb);
		break;
	case SILOFS_STYPE_SPNODE:
		err = silofs_verify_spmap_node(&view->sn);
		break;
	case SILOFS_STYPE_SPLEAF:
		err = silofs_verify_spmap_leaf(&view->sl);
		break;
	case SILOFS_STYPE_ITNODE:
		err = silofs_verify_itable_node(&view->itn);
		break;
	case SILOFS_STYPE_INODE:
		err = silofs_verify_inode(&view->in);
		break;
	case SILOFS_STYPE_XANODE:
		err = silofs_verify_xattr_node(&view->xan);
		break;
	case SILOFS_STYPE_DTNODE:
		err = silofs_verify_dtree_node(&view->dtn);
		break;
	case SILOFS_STYPE_FTNODE:
		err = silofs_verify_ftree_node(&view->ftn);
		break;
	case SILOFS_STYPE_SYMVAL:
		err = silofs_verify_symlnk_value(&view->sym);
		break;
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_ANONBK:
		err = 0;
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		err = -EFSCORRUPTED;
		break;
	}
	return err;
}

static int view_verify(const union silofs_view *view,
                       const enum silofs_stype stype,
                       const struct silofs_mdigest *md)
{
	int err;

	if (stype_isdata(stype)) {
		return 0;
	}
	err = view_verify_hdr(view, stype);
	if (err) {
		return err;
	}
	err = view_verify_checksum(view, md);
	if (err) {
		return err;
	}
	err = view_verify_sub(view, stype);
	if (err) {
		return err;
	}
	return 0;
}

static const struct silofs_mdigest *
ti_mdigest(const struct silofs_tnode_info *ti)
{
	return &ti->t_apex->ap_crypto->md;
}

static int ti_verify_view(struct silofs_tnode_info *ti)
{
	return view_verify(ti->t_view, ti->t_stype, ti_mdigest(ti));
}

int silofs_ui_verify_view(struct silofs_unode_info *ui)
{
	int err;

	if (ui->u_verified) {
		return 0;
	}
	err = ti_verify_view(&ui->u_ti);
	if (err) {
		return err;
	}
	ui->u_verified = true;
	return 0;
}

int silofs_vi_verify_view(struct silofs_vnode_info *vi)
{
	int err;

	if (vi->v_verified) {
		return 0;
	}
	err = ti_verify_view(&vi->v_ti);
	if (err) {
		return err;
	}
	vi->v_verified = true;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_vi_seal_meta(const struct silofs_vnode_info *vi)
{
	const struct silofs_sb_info *sbi = vi_sbi(vi);

	if ((sbi->s_ctl_flags & SILOFS_F_SEAL) && !vi_isdata(vi)) {
		hdr_set_csum(&vi->v_ti.t_view->hdr, calc_chekcsum_of(vi));
	}
}

void silofs_vi_stamp_mark_visible(struct silofs_vnode_info *vi)
{
	const enum silofs_stype stype = vi_stype(vi);

	if (!stype_isdata(stype)) {
		silofs_zero_stamp_view(vi->v_ti.t_view, stype);
	}
	vi->v_verified = true;
	vi_dirtify(vi);
}

void silofs_zero_stamp_view(union silofs_view *view, enum silofs_stype stype)
{
	const size_t len = stype_size(stype);

	silofs_memzero(view, len);
	hdr_stamp(&view->hdr, stype, len);
}
