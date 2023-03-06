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
static void sbi_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void sni_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void sli_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void ii_delete_as_si(struct silofs_snode_info *si,
                            struct silofs_alloc *alloc);
static void xai_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void syi_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void dni_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void fni_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);
static void fli_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc);

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

static void hdr_calc_set_csum(struct silofs_header *hdr)
{
	hdr_set_csum(hdr, hdr_calc_chekcsum(hdr));
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
	silofs_assert_ge(uaddr->oaddr.pos, 0);

	return silofs_off_in_bk(uaddr->oaddr.pos);
}

static loff_t vaddr_bk_pos(const struct silofs_vaddr *vaddr)
{
	return silofs_off_in_bk(vaddr->off);
}

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

static void si_init(struct silofs_snode_info *si, enum silofs_stype stype,
                    silofs_snode_del_fn del_fn)
{
	silofs_ce_init(&si->s_ce);
	lh_init(&si->s_dq_lh);
	an_init(&si->s_ds_an);
	si->s_dqid = SILOFS_DQID_DFL;
	si->s_stype = stype;
	si->s_ds_next = NULL;
	si->s_uber = NULL;
	si->s_md = NULL;
	si->s_bki = NULL;
	si->s_view = NULL;
	si->s_view_len = 0;
	si->s_del_hook = del_fn;
	si->s_noflush = false;
}

static void si_fini(struct silofs_snode_info *si)
{
	silofs_ce_fini(&si->s_ce);
	lh_fini(&si->s_dq_lh);
	an_fini(&si->s_ds_an);
	si->s_stype = SILOFS_STYPE_NONE;
	si->s_ds_next = NULL;
	si->s_uber = NULL;
	si->s_md = NULL;
	si->s_bki = NULL;
	si->s_view = NULL;
	si->s_del_hook = NULL;
}

static bool si_evictable(const struct silofs_snode_info *si)
{
	return silofs_si_isevictable(si);
}

static uint32_t si_calc_chekcsum(const struct silofs_snode_info *si)
{
	return calc_meta_chekcsum(&si->s_view->hdr);
}

static int si_verify_view(struct silofs_snode_info *si)
{
	return silofs_verify_view_by(si->s_view, si->s_stype);
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
                    silofs_snode_del_fn del_fn)
{
	si_init(&ui->u_si, uaddr->stype, del_fn);
	lh_init(&ui->u_pack_lh);
	uaddr_assign(&ui->u_uaddr, uaddr);
	ui->u_repo = NULL;
	ui->u_ubki = NULL;
	ui->u_verified = false;
	ui->u_in_pq = false;
}

static void ui_fini(struct silofs_unode_info *ui)
{
	silofs_assert(!ui->u_in_pq);

	uaddr_reset(&ui->u_uaddr);
	lh_fini(&ui->u_pack_lh);
	si_fini(&ui->u_si);
	ui->u_repo = NULL;
	ui->u_ubki = NULL;
}

struct silofs_unode_info *silofs_ui_from_si(const struct silofs_snode_info *si)
{
	const struct silofs_unode_info *ui = NULL;

	if (likely(si != NULL)) {
		ui = container_of2(si, struct silofs_unode_info, u_si);
	}
	return ui_unconst(ui);
}

void silofs_seal_unode(struct silofs_unode_info *ui)
{
	hdr_set_csum(&ui->u_si.s_view->hdr, si_calc_chekcsum(&ui->u_si));
}

void silofs_ui_bind_uber(struct silofs_unode_info *ui,
                         struct silofs_uber *uber)
{
	ui->u_si.s_uber = uber;
}

void silofs_ui_seal_meta(struct silofs_unode_info *ui)
{
	silofs_fill_csum_meta(ui->u_si.s_view);
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
vi_from_iovref(const struct silofs_iovref *iovr)
{
	const struct silofs_vnode_info *vi = NULL;

	vi = container_of2(iovr, struct silofs_vnode_info, v_iovr);
	return vi_unconst(vi);
}


static void vi_iov_pre(struct silofs_iovref *iovr)
{
	struct silofs_vnode_info *vi = vi_from_iovref(iovr);

	silofs_vi_incref(vi);
	vi->v_si.s_noflush = true;
}

static void vi_iov_post(struct silofs_iovref *iovr)
{
	struct silofs_vnode_info *vi = vi_from_iovref(iovr);

	silofs_vi_decref(vi);
	vi->v_si.s_noflush = false;
}

static void vi_init(struct silofs_vnode_info *vi,
                    const struct silofs_vaddr *vaddr,
                    silofs_snode_del_fn del_fn)
{
	si_init(&vi->v_si, vaddr->stype, del_fn);
	vaddr_assign(&vi->v_vaddr, vaddr);
	oaddr_reset(&vi->v_oaddr);
	silofs_iovref_init(&vi->v_iovr, vi_iov_pre, vi_iov_post);
	vi->v_recheck = false;
	vi->v_verified = false;
	vi->v_vbki = NULL;
	vi->v_sbi = NULL;
}

static void vi_fini(struct silofs_vnode_info *vi)
{
	si_fini(&vi->v_si);
	vaddr_reset(&vi->v_vaddr);
	silofs_iovref_fini(&vi->v_iovr);
}

struct silofs_vnode_info *silofs_vi_from_si(const struct silofs_snode_info *si)
{
	const struct silofs_vnode_info *vi = NULL;

	if (likely(si != NULL)) {
		vi = container_of2(si, struct silofs_vnode_info, v_si);
	}
	return vi_unconst(vi);
}

bool silofs_vi_isdata(const struct silofs_vnode_info *vi)
{
	return silofs_stype_isdata(vi_stype(vi));
}

static uint32_t vi_calc_chekcsum(const struct silofs_vnode_info *vi)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);
	union silofs_view *view = vi->v_si.s_view;
	uint32_t csum;

	if (vaddr_isdata(vaddr)) {
		csum = calc_data_checksum(view, vaddr->len, vi->v_si.s_md);
	} else {
		csum = calc_meta_chekcsum(&view->hdr);
	}
	return csum;
}

void silofs_seal_vnode(struct silofs_vnode_info *vi)
{
	hdr_set_csum(&vi->v_si.s_view->hdr, vi_calc_chekcsum(vi));
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
                    const struct silofs_uaddr *uaddr)
{
	silofs_memzero(sbi, sizeof(*sbi));
	ui_init(&sbi->sb_ui, uaddr, sbi_delete_as_si);
	sbi->sb = NULL;
	return 0;
}

static void sbi_fini(struct silofs_sb_info *sbi)
{
	ui_fini(&sbi->sb_ui);
	silofs_memffff(sbi, sizeof(*sbi));
}

static struct silofs_sb_info *sbi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_sb_info *sbi;

	sbi = silofs_allocate(alloc, sizeof(*sbi));
	return sbi;
}

static void sbi_free(struct silofs_sb_info *sbi,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, sbi, sizeof(*sbi));
}

static void sbi_delete(struct silofs_sb_info *sbi,
                       struct silofs_alloc *alloc)
{
	sbi_fini(sbi);
	sbi_free(sbi, alloc);
}

static void sbi_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc *alloc)
{
	if (likely(ui != NULL)) { /* make gcc-analyzer happy */
		sbi_delete(silofs_sbi_from_ui(ui), alloc);
	}
}

static void sbi_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		sbi_delete_as_ui(silofs_ui_from_si(si), alloc);
	}
}

static struct silofs_sb_info *
sbi_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_sb_info *sbi;
	int err;

	sbi = sbi_malloc(alloc);
	if (sbi == NULL) {
		return NULL;
	}
	err = sbi_init(sbi, uaddr);
	if (err) {
		sbi_free(sbi, alloc);
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
                     const struct silofs_uaddr *uaddr)
{
	ui_init(&sni->sn_ui, uaddr, sni_delete_as_si);
	sni->sn = NULL;
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

	sni = silofs_allocate(alloc, sizeof(*sni));
	return sni;
}

static void sni_free(struct silofs_spnode_info *sni,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, sni, sizeof(*sni));
}

static void sni_delete(struct silofs_spnode_info *sni,
                       struct silofs_alloc *alloc)
{
	sni_fini(sni);
	sni_free(sni, alloc);
}

static void sni_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc *alloc)
{
	if (likely(ui != NULL)) { /* make gcc-analyzer happy */
		sni_delete(silofs_sni_from_ui(ui), alloc);
	}
}

static void sni_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		sni_delete_as_ui(silofs_ui_from_si(si), alloc);
	}
}

static struct silofs_spnode_info *
sni_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_spnode_info *sni;

	sni = sni_malloc(alloc);
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
	ui_init(&sli->sl_ui, uaddr, sli_delete_as_si);
	sli->sl = NULL;
	sli->sl_nused_bytes = 0;
}

static void sli_fini(struct silofs_spleaf_info *sli)
{
	ui_fini(&sli->sl_ui);
	sli->sl = NULL;
	sli->sl_nused_bytes = ULONG_MAX;
}

static struct silofs_spleaf_info *sli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_spleaf_info *sli;

	sli = silofs_allocate(alloc, sizeof(*sli));
	return sli;
}

static void sli_free(struct silofs_spleaf_info *sli,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, sli, sizeof(*sli));
}

static void sli_delete(struct silofs_spleaf_info *sli,
                       struct silofs_alloc *alloc)
{
	sli_fini(sli);
	sli_free(sli, alloc);
}

static void sli_delete_as_ui(struct silofs_unode_info *ui,
                             struct silofs_alloc *alloc)
{
	if (likely(ui != NULL)) { /* make gcc-analyzer happy */
		sli_delete(silofs_sli_from_ui(ui), alloc);
	}
}

static void sli_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		sli_delete_as_ui(silofs_ui_from_si(si), alloc);
	}
}

static struct silofs_spleaf_info *
sli_new(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_spleaf_info *sli;

	sli = sli_malloc(alloc);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_info *ii_from_si(const struct silofs_snode_info *si)
{
	return silofs_ii_from_vi(silofs_vi_from_si(si));
}

static void ii_init(struct silofs_inode_info *ii,
                    const struct silofs_vaddr *vaddr)
{
	vi_init(&ii->i_vi, vaddr, ii_delete_as_si);
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

static struct silofs_inode_info *ii_malloc(struct silofs_alloc *alloc)
{
	struct silofs_inode_info *ii;

	ii = silofs_allocate(alloc, sizeof(*ii));
	return ii;
}

static void ii_free(struct silofs_inode_info *ii,
                    struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, ii, sizeof(*ii));
}

static void ii_delete(struct silofs_inode_info *ii,
                      struct silofs_alloc *alloc)
{
	ii_fini(ii);
	ii_free(ii, alloc);
}

static void ii_delete_as_vi(struct silofs_vnode_info *vi,
                            struct silofs_alloc *alloc)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		ii_delete(silofs_ii_from_vi(vi), alloc);
	}
}

static void ii_delete_as_si(struct silofs_snode_info *si,
                            struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		ii_delete_as_vi(silofs_vi_from_si(si), alloc);
	}
}

static struct silofs_inode_info *
ii_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_inode_info *ii;

	ii = ii_malloc(alloc);
	if (ii != NULL) {
		ii_init(ii, vaddr);
	}
	return ii;
}

static bool ii_evictable_as_si(const struct silofs_snode_info *si)
{
	const struct silofs_inode_info *ii = ii_from_si(si);

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
	ii->inode = &ii->i_vi.v_si.s_view->in;
	ii->i_ino = ino;
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
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&xai->xan_vi, vaddr, xai_delete_as_si);
	xai->xan = NULL;
}

static void xai_fini(struct silofs_xanode_info *xai)
{
	vi_fini(&xai->xan_vi);
	xai->xan = NULL;
}

static struct silofs_xanode_info *xai_malloc(struct silofs_alloc *alloc)
{
	struct silofs_xanode_info *xai;

	xai = silofs_allocate(alloc, sizeof(*xai));
	return xai;
}

static void xai_free(struct silofs_xanode_info *xai,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, xai, sizeof(*xai));
}

static void xai_delete(struct silofs_xanode_info *xai,
                       struct silofs_alloc *alloc)
{
	xai_fini(xai);
	xai_free(xai, alloc);
}

static void xai_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		xai_delete(silofs_xai_from_vi(vi), alloc);
	}
}

static void xai_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		xai_delete_as_vi(silofs_vi_from_si(si), alloc);
	}
}

static struct silofs_xanode_info *
xai_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_xanode_info *xai;

	xai = xai_malloc(alloc);
	if (xai != NULL) {
		xai_init(xai, vaddr);
	}
	return xai;
}

struct silofs_xanode_info *silofs_xai_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_xanode_info *xai = NULL;

	xai = container_of(vi, struct silofs_xanode_info, xan_vi);
	return xai;
}

void silofs_xai_rebind_view(struct silofs_xanode_info *xai)
{
	xai->xan = &xai->xan_vi.v_si.s_view->xan;
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
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&syi->sy_vi, vaddr, syi_delete_as_si);
	syi->syv = NULL;
}

static void syi_fini(struct silofs_symval_info *syi)
{
	vi_fini(&syi->sy_vi);
	syi->syv = NULL;
}

static struct silofs_symval_info *syi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_symval_info *syi;

	syi = silofs_allocate(alloc, sizeof(*syi));
	return syi;
}

static void syi_free(struct silofs_symval_info *syi,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, syi, sizeof(*syi));
}

static void syi_delete(struct silofs_symval_info *syi,
                       struct silofs_alloc *alloc)
{
	syi_fini(syi);
	syi_free(syi, alloc);
}

static void syi_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		syi_delete(silofs_syi_from_vi(vi), alloc);
	}
}

static void syi_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		syi_delete_as_vi(silofs_vi_from_si(si), alloc);
	}
}

static struct silofs_symval_info *
syi_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_symval_info *syi;

	syi = syi_malloc(alloc);
	if (syi != NULL) {
		syi_init(syi, vaddr);
	}
	return syi;
}

struct silofs_symval_info *silofs_syi_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_symval_info *syi = NULL;

	syi = container_of(vi, struct silofs_symval_info, sy_vi);
	return syi;
}

void silofs_syi_rebind_view(struct silofs_symval_info *syi)
{
	syi->syv = &syi->sy_vi.v_si.s_view->sym;
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
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&dni->dn_vi, vaddr, dni_delete_as_si);
	dni->dtn = NULL;
}

static void dni_fini(struct silofs_dnode_info *dni)
{
	vi_fini(&dni->dn_vi);
	dni->dtn = NULL;
}

static struct silofs_dnode_info *dni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_dnode_info *dni;

	dni = silofs_allocate(alloc, sizeof(*dni));
	return dni;
}

static void dni_free(struct silofs_dnode_info *dni,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, dni, sizeof(*dni));
}

static void dni_delete(struct silofs_dnode_info *dni,
                       struct silofs_alloc *alloc)
{
	dni_fini(dni);
	dni_free(dni, alloc);
}

static void dni_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		dni_delete(silofs_dni_from_vi(vi), alloc);
	}
}

static void dni_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		dni_delete_as_vi(silofs_vi_from_si(si), alloc);
	}
}

static struct silofs_dnode_info *
dni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_dnode_info *dni;

	dni = dni_malloc(alloc);
	if (dni != NULL) {
		dni_init(dni, vaddr);
	}
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

void silofs_dni_rebind_view(struct silofs_dnode_info *dni)
{
	dni->dtn = &dni->dn_vi.v_si.s_view->dtn;
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
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&fni->fn_vi, vaddr, fni_delete_as_si);
	fni->ftn = NULL;
}

static void fni_fini(struct silofs_finode_info *fni)
{
	vi_fini(&fni->fn_vi);
	fni->ftn = NULL;
}

static struct silofs_finode_info *fni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_finode_info *fni;

	fni = silofs_allocate(alloc, sizeof(*fni));
	return fni;
}

static void fni_free(struct silofs_finode_info *fni,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, fni, sizeof(*fni));
}

static void fni_delete(struct silofs_finode_info *fni,
                       struct silofs_alloc *alloc)
{
	fni_fini(fni);
	fni_free(fni, alloc);
}

static void fni_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		fni_delete(silofs_fni_from_vi(vi), alloc);
	}
}

static void fni_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		fni_delete_as_vi(silofs_vi_from_si(si), alloc);
	}
}

static struct silofs_finode_info *
fni_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_finode_info *fni;

	fni = fni_malloc(alloc);
	if (fni != NULL) {
		fni_init(fni, vaddr);
	}
	return fni;
}

struct silofs_finode_info *silofs_fni_from_vi(struct silofs_vnode_info *vi)
{
	struct silofs_finode_info *fni = NULL;

	fni = container_of(vi, struct silofs_finode_info, fn_vi);
	return fni;
}

void silofs_fni_rebind_view(struct silofs_finode_info *fni)
{
	fni->ftn = &fni->fn_vi.v_si.s_view->ftn;
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
                     const struct silofs_vaddr *vaddr)
{
	vi_init(&fli->fl_vi, vaddr, fli_delete_as_si);
	fli->flu.db = NULL;
}

static void fli_fini(struct silofs_fileaf_info *fli)
{
	vi_fini(&fli->fl_vi);
	fli->flu.db = NULL;
}

static struct silofs_fileaf_info *fli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_fileaf_info *fli;

	fli = silofs_allocate(alloc, sizeof(*fli));
	return fli;
}

static void fli_free(struct silofs_fileaf_info *fli,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, fli, sizeof(*fli));
}

static void fli_delete(struct silofs_fileaf_info *fli,
                       struct silofs_alloc *alloc)
{
	fli_fini(fli);
	fli_free(fli, alloc);
}

static void fli_delete_as_vi(struct silofs_vnode_info *vi,
                             struct silofs_alloc *alloc)
{
	if (likely(vi != NULL)) { /* make gcc-analyzer happy */
		fli_delete(silofs_fli_from_vi(vi), alloc);
	}
}

static void fli_delete_as_si(struct silofs_snode_info *si,
                             struct silofs_alloc *alloc)
{
	if (likely(si != NULL)) { /* make gcc-analyzer happy */
		fli_delete_as_vi(silofs_vi_from_si(si), alloc);
	}
}

static struct silofs_fileaf_info *
fli_new(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr)
{
	struct silofs_fileaf_info *fli;

	fli = fli_malloc(alloc);
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

	if (stype_isequal(stype, SILOFS_STYPE_DATA1K)) {
		fli->flu.db1 = &fli->fl_vi.v_si.s_view->db1;
	} else if (stype_isequal(stype, SILOFS_STYPE_DATA4K)) {
		fli->flu.db4 = &fli->fl_vi.v_si.s_view->db4;
	} else if (stype_isequal(stype, SILOFS_STYPE_DATABK)) {
		fli->flu.db = &fli->fl_vi.v_si.s_view->db;
	} else {
		silofs_panic("illegal file leaf: stype=%d", (int)stype);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_test_evictable(const struct silofs_snode_info *si)
{
	return stype_isinode(si->s_stype) ?
	       ii_evictable_as_si(si) : si_evictable(si);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	switch (uaddr->stype) {
	case SILOFS_STYPE_SUPER:
		ui = sbi_to_ui(sbi_new(alloc, uaddr));
		break;
	case SILOFS_STYPE_SPNODE:
		ui = sni_to_ui(sni_new(alloc, uaddr));
		break;
	case SILOFS_STYPE_SPLEAF:
		ui = sli_to_ui(sli_new(alloc, uaddr));
		break;
	case SILOFS_STYPE_RESERVED:
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
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_RESERVED:
	case SILOFS_STYPE_LAST:
	default:
		log_crit("illegal vaddr stype: stype=%d voff=%ld",
		         (int)vaddr->stype, (long)vaddr->off);
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

static void si_bind_view(struct silofs_snode_info *si,
                         struct silofs_block *bk, long bk_pos)
{
	si->s_view = make_view(opaque_view_of(bk, bk_pos));
	si->s_view_pos = bk_pos;
	si->s_view_len = stype_size(si->s_stype);
}

void silofs_ui_bind_view(struct silofs_unode_info *ui)
{
	const loff_t bk_pos = uaddr_bk_pos(ui_uaddr(ui));

	si_bind_view(&ui->u_si, ui->u_ubki->ubk_base.bk, bk_pos);
}

void silofs_vi_bind_view(struct silofs_vnode_info *vi)
{
	const loff_t bk_pos = vaddr_bk_pos(vi_vaddr(vi));

	si_bind_view(&vi->v_si, vi->v_vbki->vbk_base.bk, bk_pos);
}

union silofs_view *silofs_make_view_of(struct silofs_header *hdr)
{
	return make_view(hdr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


static int view_verify_hdr(const union silofs_view *view,
                           enum silofs_stype stype)
{
	return hdr_verify_base(&view->hdr, stype);
}

static int view_verify_checksum(const union silofs_view *view)
{
	return hdr_verify_checksum(&view->hdr);
}

static int view_verify_sub(const union silofs_view *view,
                           enum silofs_stype stype)
{
	switch (stype) {
	case SILOFS_STYPE_SUPER:
		return silofs_verify_super_block(&view->sb);
	case SILOFS_STYPE_SPNODE:
		return silofs_verify_spmap_node(&view->sn);
	case SILOFS_STYPE_SPLEAF:
		return silofs_verify_spmap_leaf(&view->sl);
	case SILOFS_STYPE_INODE:
		return silofs_verify_inode(&view->in);
	case SILOFS_STYPE_XANODE:
		return silofs_verify_xattr_node(&view->xan);
	case SILOFS_STYPE_DTNODE:
		return silofs_verify_dtree_node(&view->dtn);
	case SILOFS_STYPE_FTNODE:
		return silofs_verify_ftree_node(&view->ftn);
	case SILOFS_STYPE_SYMVAL:
		return silofs_verify_symlnk_value(&view->sym);
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_DATABK:
	case SILOFS_STYPE_ANONBK:
		break;
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_RESERVED:
	case SILOFS_STYPE_LAST:
	default:
		log_err("illegal sub-type: stype=%d", (int)stype);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_view_by(const union silofs_view *view,
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

int silofs_ui_verify_view(struct silofs_unode_info *ui)
{
	int err;

	if (ui->u_verified) {
		return 0;
	}
	err = si_verify_view(&ui->u_si);
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
	err = si_verify_view(&vi->v_si);
	if (err) {
		return err;
	}
	vi->v_verified = true;
	return 0;
}

void silofs_vi_stamp_mark_visible(struct silofs_vnode_info *vi)
{
	const enum silofs_stype stype = vi_stype(vi);

	if (!stype_isdata(stype)) {
		silofs_zero_stamp_meta(vi->v_si.s_view, stype);
	}
	vi->v_verified = true;
	vi_dirtify(vi);
}

void silofs_vi_set_dqid(struct silofs_vnode_info *vi, silofs_dqid_t dqid)
{
	if (vi->v_si.s_dqid == SILOFS_DQID_DFL) {
		vi->v_si.s_dqid = dqid;
	}
}

struct silofs_bk_info *silofs_bki_of(const struct silofs_snode_info *si)
{
	struct silofs_bk_info *bki = NULL;
	const struct silofs_unode_info *ui = NULL;
	const struct silofs_vnode_info *vi = NULL;

	if (stype_isunode(si->s_stype)) {
		ui = silofs_ui_from_si(si);
		silofs_assert_not_null(ui->u_ubki);
		bki = &ui->u_ubki->ubk_base;
	} else if (stype_isvnode(si->s_stype)) {
		vi = silofs_vi_from_si(si);
		silofs_assert_not_null(vi->v_vbki);
		bki = &vi->v_vbki->vbk_base;
	}
	silofs_assert_not_null(bki);
	return bki;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_zero_stamp_meta(union silofs_view *view, enum silofs_stype stype)
{
	const size_t len = stype_size(stype);

	silofs_memzero(view, len);
	hdr_stamp(&view->hdr, stype, len);
}

void silofs_fill_csum_meta(union silofs_view *view)
{
	hdr_calc_set_csum(&view->hdr);
}

int silofs_verify_csum_meta(const union silofs_view *view)
{
	return view_verify_checksum(view);
}
