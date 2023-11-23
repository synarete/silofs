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
#include <limits.h>

/* local functions forward declarations */
static void sbi_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void sni_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void sli_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void ii_delete_by(struct silofs_lnode_info *lni,
                         struct silofs_alloc *alloc, int flags);
static void xai_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void syi_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void dni_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void fni_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);
static void fli_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags);

static int verify_view_by(const struct silofs_view *view,
                          const enum silofs_stype stype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static int hdr_verify_base(const struct silofs_header *hdr,
                           const enum silofs_stype stype)
{
	const size_t hsz = hdr_size(hdr);
	const size_t psz = stype_size(stype);

	if (hdr_magic(hdr) != SILOFS_STYPE_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_stype(hdr) != stype) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hsz != psz) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static uint32_t hdr_calc_chekcsum(const struct silofs_header *hdr)
{
	const void *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	return silofs_hash_xxh32(payload, pl_size, SILOFS_STYPE_MAGIC);
}

static int hdr_verify_checksum(const struct silofs_header *hdr)
{
	uint32_t csum;

	if (!hdr_has_csum(hdr)) {
		return 0;
	}
	csum = hdr_calc_chekcsum(hdr);
	if (csum != hdr_csum(hdr)) {
		return -SILOFS_EFSBADCRC;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lh_init(struct silofs_list_head *lh)
{
	silofs_list_head_init(lh);
}

static void lh_fini(struct silofs_list_head *lh)
{
	silofs_list_head_fini(lh);
}

static void ce_init(struct silofs_cache_elem *ce)
{
	silofs_ce_init(ce);
}

static void ce_fini(struct silofs_cache_elem *ce)
{
	silofs_ce_fini(ce);
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

static uint32_t calc_meta_chekcsum(const struct silofs_header *hdr)
{
	return hdr_calc_chekcsum(hdr);
}

static uint32_t calc_data_checksum(const void *dat, size_t len,
                                   const struct silofs_mdigest *md)
{
	uint32_t csum = 0;

	silofs_crc32_of(md, dat, len, &csum);
	return csum;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void view_init_by(struct silofs_view *view, enum silofs_stype stype)
{
	const size_t len = stype_size(stype);

	if (!stype_isdata(stype)) {
		silofs_memzero(view, len);
		hdr_stamp(&view->u.hdr, stype, len);
	}
}

static int view_alloc_flags_of(enum silofs_stype stype, bool alloc)
{
	int flags = 0;

	if (alloc) {
		if (stype_issuper(stype)) {
			flags |= SILOFS_ALLOCF_BZERO;
		}
	} else {
		if (stype_isdatabk(stype)) {
			flags |= SILOFS_ALLOCF_PUNCH;
		}
	}
	return flags;
}

static struct silofs_view *
view_new_by(struct silofs_alloc *alloc, enum silofs_stype stype)
{
	struct silofs_view *view;

	view = silofs_allocate(alloc, stype_size(stype),
	                       view_alloc_flags_of(stype, true));
	if (view != NULL) {
		view_init_by(view, stype);
	}
	return view;
}

static struct silofs_view *
view_new_by_ulink(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	return view_new_by(alloc, ulink->uaddr.stype);
}

static struct silofs_view *
view_new_by_vaddr(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	return view_new_by(alloc, vaddr->stype);
}

static void view_del_by(struct silofs_view *view,
                        enum silofs_stype stype, struct silofs_alloc *alloc)
{
	const size_t size = stype_size(stype);

	if (likely(view != NULL)) {
		silofs_deallocate(alloc, view, size,
		                  view_alloc_flags_of(stype, false));
	}
}

static void view_del_by_ulink(struct silofs_view *view,
                              const struct silofs_ulink *ulink,
                              struct silofs_alloc *alloc)
{
	view_del_by(view, ulink->uaddr.stype, alloc);
}

static void view_del_by_vaddr(struct silofs_view *view,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_alloc *alloc)
{
	view_del_by(view, vaddr->stype, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lni_init(struct silofs_lnode_info *lni,
                     enum silofs_stype stype,
                     struct silofs_view *view,
                     silofs_lnode_del_fn del_fn)
{
	ce_init(&lni->l_ce);
	an_init(&lni->l_ds_avl_node);
	lni->l_stype = stype;
	lni->l_ds_next = NULL;
	lni->l_fsenv = NULL;
	lni->l_view = view;
	lni->l_del_cb = del_fn;
	lni->l_flags = 0;
}

static void lni_fini(struct silofs_lnode_info *lni)
{
	ce_fini(&lni->l_ce);
	an_fini(&lni->l_ds_avl_node);
	lni->l_stype = SILOFS_STYPE_NONE;
	lni->l_ds_next = NULL;
	lni->l_fsenv = NULL;
	lni->l_view = NULL;
	lni->l_del_cb = NULL;
}

static bool lni_evictable(const struct silofs_lnode_info *lni)
{
	return silofs_lni_isevictable(lni);
}

static uint32_t lni_calc_chekcsum(const struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni->l_view);
	return calc_meta_chekcsum(&lni->l_view->u.hdr);
}

static int lni_verify_view(struct silofs_lnode_info *lni)
{
	silofs_assert_not_null(lni->l_view);
	return verify_view_by(lni->l_view, lni->l_stype);
}

size_t silofs_lni_view_len(const struct silofs_lnode_info *lni)
{
	return silofs_stype_size(lni->l_stype);
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
                    const struct silofs_ulink *ulink,
                    struct silofs_view *view,
                    silofs_lnode_del_fn del_fn)
{
	lni_init(&ui->u_lni, ulink->uaddr.stype, view, del_fn);
	lh_init(&ui->u_dq_lh);
	ulink_assign(&ui->u_ulink, ulink);
	ui->u_dq = NULL;
}

static void ui_fini(struct silofs_unode_info *ui)
{
	ulink_reset(&ui->u_ulink);
	lh_fini(&ui->u_dq_lh);
	lni_fini(&ui->u_lni);
	ui->u_dq = NULL;
}

struct silofs_unode_info *
silofs_ui_from_lni(const struct silofs_lnode_info *lni)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(lni != NULL)) {
		ui = container_of2(lni, struct silofs_unode_info, u_lni);
	}
	return ui_unconst(ui);
}

void silofs_seal_unode(struct silofs_unode_info *ui)
{
	hdr_set_csum(&ui->u_lni.l_view->u.hdr, lni_calc_chekcsum(&ui->u_lni));
}

void silofs_ui_set_fsenv(struct silofs_unode_info *ui,
                         struct silofs_fsenv *fsenv)
{
	ui->u_lni.l_fsenv = fsenv;
}

struct silofs_unode_info *
silofs_ui_from_dirty_lh(struct silofs_list_head *lh)
{
	struct silofs_unode_info *ui = NULL;

	ui = container_of(lh, struct silofs_unode_info, u_dq_lh);
	return ui;
}

static void ui_del_view(struct silofs_unode_info *ui,
                        struct silofs_alloc *alloc)
{
	view_del_by_ulink(ui->u_lni.l_view, ui_ulink(ui), alloc);
	ui->u_lni.l_view = NULL;
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

struct silofs_vnode_info *
silofs_vi_from_dirty_lh(struct silofs_list_head *lh)
{
	struct silofs_vnode_info *vi = NULL;

	vi = container_of(lh, struct silofs_vnode_info, v_dq_lh);
	return vi;
}

static void vi_init(struct silofs_vnode_info *vi,
                    const struct silofs_vaddr *vaddr,
                    struct silofs_view *view,
                    silofs_lnode_del_fn del_fn)
{
	lni_init(&vi->v_lni, vaddr->stype, view, del_fn);
	list_head_init(&vi->v_dq_lh);
	vaddr_assign(&vi->v_vaddr, vaddr);
	silofs_llink_reset(&vi->v_llink);
	vi->v_dq = NULL;
	vi->v_asyncwr = 0;
}

static void vi_fini(struct silofs_vnode_info *vi)
{
	silofs_assert_eq(vi->v_asyncwr, 0);

	lni_fini(&vi->v_lni);
	list_head_fini(&vi->v_dq_lh);
	vaddr_reset(&vi->v_vaddr);
	vi->v_dq = NULL;
}

struct silofs_vnode_info *
silofs_vi_from_lni(const struct silofs_lnode_info *lni)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(lni != NULL)) {
		vi = container_of2(lni, struct silofs_vnode_info, v_lni);
	}
	return vi_unconst(vi);
}

bool silofs_vi_isdata(const struct silofs_vnode_info *vi)
{
	return stype_isdata(vi_stype(vi));
}

static const struct silofs_mdigest *
vi_mdigest(const struct silofs_vnode_info *vi)
{
	const struct silofs_fsenv *fsenv = vi_fsenv(vi);

	return &fsenv->fse_crypto.md;
}

static uint32_t vi_calc_chekcsum(const struct silofs_vnode_info *vi)
{
	const struct silofs_mdigest *md = vi_mdigest(vi);
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);
	uint32_t csum;

	silofs_assert_not_null(vi->v_lni.l_view);

	if (vaddr_isdata(vaddr)) {
		csum = calc_data_checksum(vi->v_lni.l_view, vaddr->len, md);
	} else {
		csum = calc_meta_chekcsum(&vi->v_lni.l_view->u.hdr);
	}
	return csum;
}

void silofs_seal_vnode(struct silofs_vnode_info *vi)
{
	silofs_assert_not_null(vi->v_lni.l_view);

	hdr_set_csum(&vi->v_lni.l_view->u.hdr, vi_calc_chekcsum(vi));
}

static bool vi_has_stype(const struct silofs_vnode_info *vi,
                         enum silofs_stype stype)
{
	return vi_stype(vi) == stype;
}

static void vi_del_view(struct silofs_vnode_info *vi,
                        struct silofs_alloc *alloc)
{
	view_del_by_vaddr(vi->v_lni.l_view, vi_vaddr(vi), alloc);
	vi->v_lni.l_view = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *
sbi_to_ui(const struct silofs_sb_info *sbi)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(sbi != NULL)) {
		ui = &sbi->sb_ui;
	}
	return ui_unconst(ui);
}

struct silofs_sb_info *
silofs_sbi_from_ui(const struct silofs_unode_info *ui)
{
	const struct silofs_sb_info *sbi = NULL;

	if (likely(ui != NULL)) {
		sbi = container_of2(ui, struct silofs_sb_info, sb_ui);
	}
	return unconst(sbi);
}

static int sbi_init(struct silofs_sb_info *sbi,
                    const struct silofs_ulink *ulink, struct silofs_view *view)
{
	ui_init(&sbi->sb_ui, ulink, view, sbi_delete_by);
	sbi->sb = &view->u.sb;
	return 0;
}

static void sbi_fini(struct silofs_sb_info *sbi)
{
	ui_fini(&sbi->sb_ui);
	sbi->sb = NULL;
}

static struct silofs_sb_info *sbi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sb_info *sbi;

	sbi = silofs_allocate(alloc, sizeof(*sbi), SILOFS_ALLOCF_BZERO);
	return sbi;
}

static void sbi_free(struct silofs_sb_info *sbi,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, sbi, sizeof(*sbi), flags);
}

static void sbi_delete(struct silofs_sb_info *sbi,
                       struct silofs_alloc *alloc, int flags)
{
	ui_del_view(&sbi->sb_ui, alloc);
	sbi_fini(sbi);
	sbi_free(sbi, alloc, flags);
}

static void sbi_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(ui != NULL)) { /* make gcc-analyzer happy */
		sbi_delete(silofs_sbi_from_ui(ui), alloc, flags);
	}
}

static void sbi_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		sbi_delete_as_ui(silofs_ui_from_lni(lni), alloc, flags);
	}
}

static struct silofs_sb_info *
sbi_new(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_view *view;
	struct silofs_sb_info *sbi;
	int err;

	view = view_new_by_ulink(alloc, ulink);
	if (view == NULL) {
		return NULL;
	}
	sbi = sbi_malloc(alloc);
	if (sbi == NULL) {
		view_del_by_ulink(view, ulink, alloc);
		return NULL;
	}
	err = sbi_init(sbi, ulink, view);
	if (err) {
		sbi_free(sbi, alloc, 0);
		view_del_by_ulink(view, ulink, alloc);
		return NULL;
	}
	return sbi;
}

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
                     const struct silofs_ulink *ulink,
                     struct silofs_view *view)
{
	ui_init(&sni->sn_ui, ulink, view, sni_delete_by);
	sni->sn = &view->u.sn;
	sni->sn_nactive_subs = 0;
}

static void sni_fini(struct silofs_spnode_info *sni)
{
	ui_fini(&sni->sn_ui);
	sni->sn = NULL;
	sni->sn_nactive_subs = 0;
}

static struct silofs_spnode_info *sni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spnode_info *sni;

	sni = silofs_allocate(alloc, sizeof(*sni), 0);
	return sni;
}

static void sni_free(struct silofs_spnode_info *sni,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, sni, sizeof(*sni), flags);
}

static void sni_delete(struct silofs_spnode_info *sni,
                       struct silofs_alloc *alloc, int flags)
{
	ui_del_view(&sni->sn_ui, alloc);
	sni_fini(sni);
	sni_free(sni, alloc, flags);
}

static void sni_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(ui != NULL)) { /* make gcc-analyzer happy */
		sni_delete(silofs_sni_from_ui(ui), alloc, flags);
	}
}

static void sni_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		sni_delete_as_ui(silofs_ui_from_lni(lni), alloc, flags);
	}
}

static struct silofs_spnode_info *
sni_new(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_view *view;
	struct silofs_spnode_info *sni;

	view = view_new_by_ulink(alloc, ulink);
	if (view == NULL) {
		return NULL;
	}
	sni = sni_malloc(alloc);
	if (sni == NULL) {
		view_del_by_ulink(view, ulink, alloc);
		return NULL;
	}
	sni_init(sni, ulink, view);
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
                     const struct silofs_ulink *ulink,
                     struct silofs_view *view)
{
	ui_init(&sli->sl_ui, ulink, view, sli_delete_by);
	sli->sl = &view->u.sl;
	sli->sl_nused_bytes = 0;
}

static void sli_fini(struct silofs_spleaf_info *sli)
{
	ui_fini(&sli->sl_ui);
	sli->sl = NULL;
	sli->sl_nused_bytes = UINT_MAX;
}

static struct silofs_spleaf_info *sli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spleaf_info *sli;

	sli = silofs_allocate(alloc, sizeof(*sli), 0);
	return sli;
}

static void sli_free(struct silofs_spleaf_info *sli,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, sli, sizeof(*sli), flags);
}

static void sli_delete(struct silofs_spleaf_info *sli,
                       struct silofs_alloc *alloc, int flags)
{
	ui_del_view(&sli->sl_ui, alloc);
	sli_fini(sli);
	sli_free(sli, alloc, flags);
}

static void sli_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(ui != NULL)) { /* make gcc-analyzer happy */
		sli_delete(silofs_sli_from_ui(ui), alloc, flags);
	}
}

static void sli_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		sli_delete_as_ui(silofs_ui_from_lni(lni), alloc, flags);
	}
}

static struct silofs_spleaf_info *
sli_new(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_view *view;
	struct silofs_spleaf_info *sli;

	view = view_new_by_ulink(alloc, ulink);
	if (view == NULL) {
		return NULL;
	}
	sli = sli_malloc(alloc);
	if (sli == NULL) {
		view_del_by_ulink(view, ulink, alloc);
		return NULL;
	}
	sli_init(sli, ulink, view);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ii_init(struct silofs_inode_info *ii,
                    const struct silofs_vaddr *vaddr,
                    struct silofs_view *view)
{
	vi_init(&ii->i_vi, vaddr, view, ii_delete_by);
	silofs_dirtyq_init(&ii->i_dq_vis);
	ii->inode = &view->u.in;
	ii->i_looseq_next = NULL;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = 0;
	ii->i_nlookup = 0;
	ii->i_in_looseq = false;
}

static void ii_fini(struct silofs_inode_info *ii)
{
	silofs_assert_eq(ii->i_dq_vis.dq.sz, 0);
	silofs_assert_eq(ii->i_dq_vis.dq_accum, 0);
	silofs_assert(!ii->i_in_looseq);
	silofs_assert_null(ii->i_looseq_next);

	vi_fini(&ii->i_vi);
	silofs_dirtyq_fini(&ii->i_dq_vis);
	ii->inode = NULL;
	ii->i_ino = SILOFS_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static struct silofs_inode_info *ii_malloc(struct silofs_alloc *alloc)
{
	struct silofs_inode_info *ii;

	ii = silofs_allocate(alloc, sizeof(*ii), 0);
	return ii;
}

static void ii_free(struct silofs_inode_info *ii,
                    struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, ii, sizeof(*ii), flags);
}

static void ii_delete(struct silofs_inode_info *ii,
                      struct silofs_alloc *alloc, int flags)
{
	silofs_assert_eq(ii->i_dq_vis.dq.sz, 0);
	silofs_assert_ge(ii->i_nopen, 0);

	vi_del_view(&ii->i_vi, alloc);
	ii_fini(ii);
	ii_free(ii, alloc, flags);
}

static void ii_delete_as_vi(struct silofs_vnode_info *vi,
                            struct silofs_alloc *alloc, int flags)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		ii_delete(silofs_ii_from_vi(vi), alloc, flags);
	}
}

static void ii_delete_by(struct silofs_lnode_info *lni,
                         struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		ii_delete_as_vi(silofs_vi_from_lni(lni), alloc, flags);
	}
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_inode_info *ii;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	ii = ii_malloc(alloc);
	if (ii == NULL) {
		view_del_by_vaddr(view, vaddr, alloc);
		return NULL;
	}
	ii_init(ii, vaddr, view);
	return ii;
}

static bool ii_evictable_as(const struct silofs_lnode_info *lni)
{
	const struct silofs_inode_info *ii = silofs_ii_from_lni(lni);

	return silofs_ii_isevictable(ii);
}

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni)
{
	return silofs_ii_from_vi(silofs_vi_from_lni(lni));
}

struct silofs_inode_info *silofs_ii_from_vi(const struct silofs_vnode_info *vi)
{
	const struct silofs_inode_info *ii = NULL;

	if (likely(vi != NULL)) {
		ii = container_of2(vi, struct silofs_inode_info, i_vi);
	}
	return ii_unconst(ii);
}

struct silofs_inode_info *
silofs_ii_from_dirty_lh(struct silofs_list_head *lh)
{
	return silofs_ii_from_vi(silofs_vi_from_dirty_lh(lh));
}

void silofs_ii_set_ino(struct silofs_inode_info *ii, ino_t ino)
{
	/* ii->inode = &ii->i_vi.v.view->u.in; */
	silofs_assert_not_null(ii->i_vi.v_lni.l_view);
	silofs_assert_not_null(ii->inode);
	ii->i_ino = ino;
}

void silofs_ii_undirtify_vis(struct silofs_inode_info *ii)
{
	struct silofs_vnode_info *vi;
	struct silofs_list_head *lh;
	struct silofs_dirtyq *dq = &ii->i_dq_vis;

	while (dq->dq.sz > 0) {
		lh = silofs_dirtyq_front(dq);
		vi = silofs_vi_from_dirty_lh(lh);
		silofs_vi_undirtify(vi);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
xai_to_vi(const struct silofs_xanode_info *xai)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(xai != NULL)) {
		vi = &xai->xan_vi;
	}
	return vi_unconst(vi);
}

static void xai_init(struct silofs_xanode_info *xai,
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&xai->xan_vi, vaddr, view, xai_delete_by);
	xai->xan = &view->u.xan;
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vi_fini(&xai->xan_vi);
	xai->xan = NULL;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc *alloc)
{
	struct silofs_xanode_info *xai;

	xai = silofs_allocate(alloc, sizeof(*xai), 0);
	return xai;
}

static void xai_free(struct silofs_xanode_info *xai,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, xai, sizeof(*xai), flags);
}

static void xai_delete(struct silofs_xanode_info *xai,
                       struct silofs_alloc *alloc, int flags)
{
	vi_del_view(&xai->xan_vi, alloc);
	xai_fini(xai);
	xai_free(xai, alloc, flags);
}

static void xai_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		xai_delete(silofs_xai_from_vi(vi), alloc, flags);
	}
}

static void xai_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		xai_delete_as_vi(silofs_vi_from_lni(lni), alloc, flags);
	}
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_xanode_info *xai;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	xai = xai_malloc(alloc);
	if (xai == NULL) {
		view_del_by_vaddr(view, vaddr, alloc);
		return NULL;
	}
	xai_init(xai, vaddr, view);
	return xai;
}

struct silofs_xanode_info *silofs_xai_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_xanode_info *xai = NULL;

	xai = container_of(vi, struct silofs_xanode_info, xan_vi);
	return xai;
}

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
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&syi->sy_vi, vaddr, view, syi_delete_by);
	syi->syv = &view->u.syv;
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vi_fini(&syi->sy_vi);
	syi->syv = NULL;
}

static struct silofs_symval_info *syi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_symval_info *syi;

	syi = silofs_allocate(alloc, sizeof(*syi), 0);
	return syi;
}

static void syi_free(struct silofs_symval_info *syi,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, syi, sizeof(*syi), flags);
}

static void syi_delete(struct silofs_symval_info *syi,
                       struct silofs_alloc *alloc, int flags)
{
	vi_del_view(&syi->sy_vi, alloc);
	syi_fini(syi);
	syi_free(syi, alloc, flags);
}

static void syi_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		syi_delete(silofs_syi_from_vi(vi), alloc, flags);
	}
}

static void syi_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		syi_delete_as_vi(silofs_vi_from_lni(lni), alloc, flags);
	}
}

static struct silofs_symval_info *
syi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_symval_info *syi;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	syi = syi_malloc(alloc);
	if (syi == NULL) {
		view_del_by_vaddr(view, vaddr, alloc);
		return NULL;
	}
	syi_init(syi, vaddr, view);
	return syi;
}

struct silofs_symval_info *silofs_syi_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_symval_info *syi = NULL;

	syi = container_of(vi, struct silofs_symval_info, sy_vi);
	return syi;
}

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
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&dni->dn_vi, vaddr, view, dni_delete_by);
	dni->dtn = &view->u.dtn;
}

static void dni_fini(struct silofs_dnode_info *dni)
{
	vi_fini(&dni->dn_vi);
	dni->dtn = NULL;
}

static struct silofs_dnode_info *dni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_dnode_info *dni;

	dni = silofs_allocate(alloc, sizeof(*dni), 0);
	return dni;
}

static void dni_free(struct silofs_dnode_info *dni,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, dni, sizeof(*dni), flags);
}

static void dni_delete(struct silofs_dnode_info *dni,
                       struct silofs_alloc *alloc, int flags)
{
	vi_del_view(&dni->dn_vi, alloc);
	dni_fini(dni);
	dni_free(dni, alloc, flags);
}

static void dni_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		dni_delete(silofs_dni_from_vi(vi), alloc, flags);
	}
}

static void dni_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		dni_delete_as_vi(silofs_vi_from_lni(lni), alloc, flags);
	}
}

static struct silofs_dnode_info *
dni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_dnode_info *dni;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	dni = dni_malloc(alloc);
	if (dni == NULL) {
		view_del_by_vaddr(view, vaddr, alloc);
		return NULL;
	}
	dni_init(dni, vaddr, view);
	return dni;
}

struct silofs_dnode_info *silofs_dni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_dnode_info *dni = NULL;

	if (vi != NULL) {
		silofs_assert(vi_has_stype(vi, SILOFS_STYPE_DTNODE));
		dni = container_of(vi, struct silofs_dnode_info, dn_vi);
	}
	return dni;
}

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
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&fni->fn_vi, vaddr, view, fni_delete_by);
	fni->ftn = &view->u.ftn;
}

static void fni_fini(struct silofs_finode_info *fni)
{
	vi_fini(&fni->fn_vi);
	fni->ftn = NULL;
}

static struct silofs_finode_info *fni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_finode_info *fni;

	fni = silofs_allocate(alloc, sizeof(*fni), 0);
	return fni;
}

static void fni_free(struct silofs_finode_info *fni,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, fni, sizeof(*fni), flags);
}

static void fni_delete(struct silofs_finode_info *fni,
                       struct silofs_alloc *alloc, int flags)
{
	vi_del_view(&fni->fn_vi, alloc);
	fni_fini(fni);
	fni_free(fni, alloc, flags);
}

static void fni_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		fni_delete(silofs_fni_from_vi(vi), alloc, flags);
	}
}

static void fni_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		fni_delete_as_vi(silofs_vi_from_lni(lni), alloc, flags);
	}
}

static struct silofs_finode_info *
fni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_finode_info *fni;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	fni = fni_malloc(alloc);
	if (fni == NULL) {
		view_del_by_vaddr(view, vaddr, alloc);
		return NULL;
	}
	fni_init(fni, vaddr, view);
	return fni;
}

struct silofs_finode_info *silofs_fni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_finode_info *fni = NULL;

	fni = container_of(vi, struct silofs_finode_info, fn_vi);
	return fni;
}

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
                     const struct silofs_vaddr *vaddr,
                     struct silofs_view *view)
{
	vi_init(&fli->fl_vi, vaddr, view, fli_delete_by);

	if (stype_isdata1k(vaddr->stype)) {
		fli->flu.db1 = &view->u.dbk1;
	} else if (stype_isdata4k(vaddr->stype)) {
		fli->flu.db4 = &view->u.dbk4;
	} else if (stype_isdatabk(vaddr->stype)) {
		fli->flu.db = &view->u.dbk64;
	}
}

static void fli_fini(struct silofs_fileaf_info *fli)
{
	vi_fini(&fli->fl_vi);
	fli->flu.db = NULL;
}

static struct silofs_fileaf_info *fli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_fileaf_info *fli;

	fli = silofs_allocate(alloc, sizeof(*fli), 0);
	return fli;
}

static void fli_free(struct silofs_fileaf_info *fli,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, fli, sizeof(*fli), flags);
}

static void fli_delete(struct silofs_fileaf_info *fli,
                       struct silofs_alloc *alloc, int flags)
{
	vi_del_view(&fli->fl_vi, alloc);
	fli_fini(fli);
	fli_free(fli, alloc, flags);
}

static void fli_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc, int flags)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		fli_delete(silofs_fli_from_vi(vi), alloc, flags);
	}
}

static void fli_delete_by(struct silofs_lnode_info *lni,
                          struct silofs_alloc *alloc, int flags)
{
	if (likely(lni != NULL)) { /* make gcc-analyzer happy */
		fli_delete_as_vi(silofs_vi_from_lni(lni), alloc, flags);
	}
}

static struct silofs_fileaf_info *
fli_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_view *view;
	struct silofs_fileaf_info *fli;

	view = view_new_by_vaddr(alloc, vaddr);
	if (view == NULL) {
		return NULL;
	}
	fli = fli_malloc(alloc);
	if (fli == NULL) {
		view_del_by_vaddr(view, vaddr, alloc);
		return NULL;
	}
	fli_init(fli, vaddr, view);
	return fli;
}

struct silofs_fileaf_info *silofs_fli_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_fileaf_info *fli = NULL;

	silofs_assert_not_null(vi);
	fli = container_of(vi, struct silofs_fileaf_info, fl_vi);
	return fli;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_test_evictable(const struct silofs_lnode_info *lni)
{
	return stype_isinode(lni->l_stype) ?
	       ii_evictable_as(lni) : lni_evictable(lni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc *alloc, const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	switch (ulink->uaddr.stype) {
	case SILOFS_STYPE_BOOTREC:
		ui = NULL;
		break;
	case SILOFS_STYPE_SUPER:
		ui = sbi_to_ui(sbi_new(alloc, ulink));
		break;
	case SILOFS_STYPE_SPNODE:
		ui = sni_to_ui(sni_new(alloc, ulink));
		break;
	case SILOFS_STYPE_SPLEAF:
		ui = sli_to_ui(sli_new(alloc, ulink));
		break;
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		ui = NULL;
		break;
	}
	return ui;
}

struct silofs_vnode_info *
silofs_new_vi(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi = NULL;

	switch (vaddr->stype) {
	case SILOFS_STYPE_INODE:
		vi = ii_to_vi(ii_new(alloc, vaddr));
		break;
	case SILOFS_STYPE_XANODE:
		vi = xai_to_vi(xai_new(alloc, vaddr));
		break;
	case SILOFS_STYPE_SYMVAL:
		vi = syi_to_vi(syi_new(alloc, vaddr));
		break;
	case SILOFS_STYPE_DTNODE:
		vi = dni_to_vi(dni_new(alloc, vaddr));
		break;
	case SILOFS_STYPE_FTNODE:
		vi = fni_to_vi(fni_new(alloc, vaddr));
		break;
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		vi = fli_to_vi(fli_new(alloc, vaddr));
		break;
	case SILOFS_STYPE_BOOTREC:
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		log_crit("illegal vaddr stype: stype=%d voff=%ld",
		         (int)vaddr->stype, (long)vaddr->off);
		break;
	}
	return vi;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


static int view_verify_hdr(const struct silofs_view *view,
                           enum silofs_stype stype)
{
	return hdr_verify_base(&view->u.hdr, stype);
}

static int view_verify_checksum(const struct silofs_view *view)
{
	return hdr_verify_checksum(&view->u.hdr);
}

static int view_verify_sub(const struct silofs_view *view,
                           enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_BOOTREC:
		break;
	case SILOFS_STYPE_SUPER:
		return silofs_verify_super_block(&view->u.sb);
	case SILOFS_STYPE_SPNODE:
		return silofs_verify_spmap_node(&view->u.sn);
	case SILOFS_STYPE_SPLEAF:
		return silofs_verify_spmap_leaf(&view->u.sl);
	case SILOFS_STYPE_INODE:
		return silofs_verify_inode(&view->u.in);
	case SILOFS_STYPE_XANODE:
		return silofs_verify_xattr_node(&view->u.xan);
	case SILOFS_STYPE_DTNODE:
		return silofs_verify_dtree_node(&view->u.dtn);
	case SILOFS_STYPE_FTNODE:
		return silofs_verify_ftree_node(&view->u.ftn);
	case SILOFS_STYPE_SYMVAL:
		return silofs_verify_symlnk_value(&view->u.syv);
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_LAST:
	default:
		log_err("illegal sub-type: stype=%d", (int)stype);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_view_by(const struct silofs_view *view,
                          const enum silofs_stype stype)
{
	int err;

	if (stype_isdata(stype)) {
		return 0;
	}
	err = view_verify_hdr(view, stype);
	if (err) {
		return err;
	}
	err = view_verify_checksum(view);
	if (err) {
		return err;
	}
	err = view_verify_sub(view, stype);
	if (err) {
		return err;
	}
	return 0;
}

bool silofs_ui_is_active(const struct silofs_unode_info *ui)
{
	return (ui->u_lni.l_flags & SILOFS_LNF_ACTIVE) > 0;
}

void silofs_ui_set_active(struct silofs_unode_info *ui)
{
	ui->u_lni.l_flags |= SILOFS_LNF_ACTIVE;
}

int silofs_ui_verify_view(struct silofs_unode_info *ui)
{
	return lni_verify_view(&ui->u_lni);
}

int silofs_vi_verify_view(struct silofs_vnode_info *vi)
{
	return lni_verify_view(&vi->v_lni);
}
