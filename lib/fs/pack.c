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
#include <silofs/fs/crypto.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/stage.h>
#include <silofs/fs/walk.h>
#include <silofs/fs/pack.h>
#include <silofs/fs/private.h>


struct silofs_pack_ctx {
	struct silofs_bootsec           bsec;
	struct silofs_visitor           vis;
	struct silofs_fs_apex          *apex;
	struct silofs_alloc_if         *alif;
	struct silofs_sb_info          *sbi;
	struct silofs_listq             uil;
	bool archive;
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_blobid *blobid_of(const struct silofs_uaddr *uaddr)
{
	return silofs_uaddr_blobid(uaddr);
}

static struct silofs_sb_info *sbi_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SUPER));

	return silofs_sbi_from_ui(ui);
}

static struct silofs_spnode_info *
sni_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SPNODE));

	return silofs_sni_from_ui(ui);
}

static struct silofs_spleaf_info *
sli_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SPLEAF));

	return silofs_sli_from_ui(ui);
}

static bool sni_istoplevel(const struct silofs_spnode_info *sni)
{
	return silofs_sni_height(sni) == SILOFS_SPNODE_HEIGHT_MAX;
}

static bool ui_isspleaf(const struct silofs_unode_info *ui)
{
	return stype_isspleaf(ui_stype(ui));
}

static bool ui_isspnode(const struct silofs_unode_info *ui)
{
	return stype_isspnode(ui_stype(ui));
}

static bool ui_istopspnode(const struct silofs_unode_info *ui)
{
	return ui_isspnode(ui) && sni_istoplevel(sni_from_ui(ui));
}

static bool ui_ismidspnode(const struct silofs_unode_info *ui)
{
	return ui_isspnode(ui) && !sni_istoplevel(sni_from_ui(ui));
}

static bool ui_issuper(const struct silofs_unode_info *ui)
{
	return stype_issuper(ui_stype(ui));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ui_bb_setup(struct silofs_unode_info *ui, size_t bsz,
                       struct silofs_alloc_if *alif)
{
	struct silofs_bytebuf *bb = &ui->u_bb;
	void *blob = NULL;

	silofs_assert_null(bb->ptr);
	silofs_assert_eq(bb->cap, 0);

	blob = silofs_allocate(alif, bsz);
	if (blob == NULL) {
		return -ENOMEM;
	}
	silofs_bytebuf_init(bb, blob, bsz);
	return 0;
}

static void ui_bb_clear(struct silofs_unode_info *ui,
                        struct silofs_alloc_if *alif)
{
	struct silofs_bytebuf *bb = &ui->u_bb;

	silofs_deallocate(alif, bb->ptr, bb->cap);
	silofs_bytebuf_fini(bb);
}

static int ui_bb_insert(struct silofs_unode_info *ui,
                        size_t pos, const void *p, size_t len)
{
	struct silofs_bytebuf *bb = &ui->u_bb;
	size_t cnt;

	cnt = silofs_bytebuf_insert(bb, pos, p, len);
	return (cnt < len) ? -ENOSPC : 0;
}

static int sli_bb_insert_ubk(struct silofs_spleaf_info *sli,
                             const struct silofs_ubk_info *ubi, size_t slot)
{
	const struct silofs_block *ubk = ubi->ubk;
	const size_t len = sizeof(*ubk);

	return ui_bb_insert(&sli->sl_ui, slot * len, ubk, len);
}

static int
sni_bb_insert_spleaf(struct silofs_spnode_info *sni,
                     const struct silofs_spleaf_info *sli, size_t slot)
{
	const struct silofs_spmap_leaf *sl = sli->sl;
	const size_t len = sizeof(*sl);

	return ui_bb_insert(&sni->sn_ui, slot * len, sl, len);
}

static int
sni_bb_insert_spnode(struct silofs_spnode_info *sni,
                     const struct silofs_spnode_info *child, size_t slot)
{
	const struct silofs_spmap_node *sn = child->sn;
	const size_t len = sizeof(*sn);

	return ui_bb_insert(&sni->sn_ui, slot * len, sn, len);
}

static int
sbi_bb_insert_spnode(struct silofs_sb_info *sbi,
                     const struct silofs_spnode_info *sni, size_t slot)
{
	const struct silofs_spmap_node *sn = sni->sn;
	const size_t len = sizeof(*sn);

	return ui_bb_insert(&sbi->s_ui, slot * len, sn, len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_setup_bb_of(const struct silofs_pack_ctx *pa_ctx,
                           struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	silofs_assert_ge(uaddr->oaddr.blobid.size, SILOFS_BK_SIZE);
	silofs_assert_le(uaddr->oaddr.blobid.size, SILOFS_VSEC_SIZE);
	return ui_bb_setup(ui, uaddr->oaddr.blobid.size, pa_ctx->alif);
}

static void pac_clear_bb_of(const struct silofs_pack_ctx *pa_ctx,
                            struct silofs_unode_info *ui)
{
	ui_bb_clear(ui, pa_ctx->alif);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_unode_info *
ui_from_pack_lh(const struct silofs_list_head *lh)
{
	const struct silofs_unode_info *ui;

	silofs_assert_not_null(lh);
	ui = container_of2(lh, struct silofs_unode_info, u_pack_lh);
	return unconst(ui);
}

static void pac_uil_insert(struct silofs_pack_ctx *pa_ctx,
                           struct silofs_unode_info *ui)
{
	struct silofs_listq *uil = &pa_ctx->uil;

	if ((ui != NULL) && !ui->u_plinked) {
		ui_incref(ui);
		listq_push_back(uil, &ui->u_pack_lh);
		ui->u_plinked = true;
	}
}

static void pac_uil_remove(struct silofs_pack_ctx *pa_ctx,
                           struct silofs_unode_info *ui)
{
	struct silofs_listq *uil = &pa_ctx->uil;

	if ((ui != NULL) && ui->u_plinked) {
		silofs_assert(ui->u_plinked);

		listq_remove(uil, &ui->u_pack_lh);
		ui->u_plinked = false;
		ui_decref(ui);

		pac_clear_bb_of(pa_ctx, ui);
	}
}

static void pac_uil_clear(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_list_head *lh;
	struct silofs_unode_info *ui = NULL;
	struct silofs_listq *uil = &pa_ctx->uil;

	while ((lh = listq_front(uil)) != NULL) {
		ui = ui_from_pack_lh(lh);
		pac_uil_remove(pa_ctx, ui);
	}
}

static void pac_uil_init(struct silofs_pack_ctx *pa_ctx)
{
	listq_init(&pa_ctx->uil);
}

static void pac_uil_fini(struct silofs_pack_ctx *pa_ctx)
{
	listq_fini(&pa_ctx->uil);
}

static void pa_ctx_start(struct silofs_pack_ctx *pa_ctx)
{
	pac_uil_init(pa_ctx);
}

static void pa_ctx_finish(struct silofs_pack_ctx *pa_ctx)
{
	silofs_bootsec_init(&pa_ctx->bsec);
	pac_uil_clear(pa_ctx);
	pac_uil_fini(pa_ctx);
	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *pac_src_repo(const struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_fs_apex *apex = pa_ctx->apex;

	return pa_ctx->archive ? apex->ap_mrepo : apex->ap_crepo;
}

static struct silofs_repo *pac_dst_repo(const struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_fs_apex *apex = pa_ctx->apex;

	return pa_ctx->archive ? apex->ap_crepo : apex->ap_mrepo;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_mdigest *
pac_mdigest(const struct silofs_pack_ctx *pa_ctx)
{
	return &pa_ctx->apex->ap_crypto->md;
}

static void pac_seal_meta_of(const struct silofs_pack_ctx *pa_ctx,
                             struct silofs_unode_info *ui)
{
	silofs_fill_csum_meta(ui->u_ti.t_view, pac_mdigest(pa_ctx));
}

static int pac_verify_meta_of(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_unode_info *ui)
{
	return silofs_verify_csum_meta(ui->u_ti.t_view, pac_mdigest(pa_ctx));
}

static void pac_calc_cas_blobid(const struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_bytebuf *bb,
                                struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;

	silofs_sha256_of(pac_mdigest(pa_ctx), bb->ptr, bb->len, &hash);
	silofs_blobid_make_cas(out_blobid, &hash, bb->len);
}

static void pac_resolve_packid_of(const struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_bytebuf *bb,
                                  struct silofs_packid *out_packid)
{
	struct silofs_blobid cas_blobid;

	pac_calc_cas_blobid(pa_ctx, bb, &cas_blobid);
	packid_setup(out_packid, &cas_blobid);
}

static int pac_stage_block(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_blobid *blobid, size_t slot,
                           struct silofs_ubk_info **out_ubi)
{
	struct silofs_oaddr oaddr;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);

	silofs_assert_lt(slot, SILOFS_NBK_IN_VSEC);

	silofs_oaddr_of_bk(&oaddr, blobid, (silofs_lba_t)slot);
	return silofs_repo_stage_ubk(repo, &oaddr, out_ubi);
}

static int pac_require_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_ubk_info **out_ubi)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	int err;

	err = silofs_repo_lookup_blob(repo, &oaddr->blobid);
	if (!err) {
		err = silofs_repo_stage_ubk(repo, oaddr, out_ubi);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_ubk(repo, oaddr, out_ubi);
	}
	return err;
}

static int pac_restore_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_ubk_info *ubi_src,
                           const struct silofs_oaddr *oaddr_dst)
{
	struct silofs_ubk_info *ubi_dst = NULL;
	int err;

	err = pac_require_ubk(pa_ctx, oaddr_dst, &ubi_dst);
	if (err) {
		return err;
	}
	err = silofs_bli_store_bk(ubi_dst->bli, oaddr_dst, ubi_src->ubk);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_blob(const struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_blobid *blobid,
                         const struct silofs_bytebuf *bb)
{
	struct silofs_oaddr oaddr;
	struct silofs_blob_info *bli = NULL;
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	int err;

	if (repo == NULL) {
		return -EBADF;
	}
	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		return 0; /* ok -- already exists */
	}
	err = silofs_repo_spawn_blob(repo, blobid, &bli);
	if (err) {
		return err;
	}
	silofs_oaddr_setup_all(&oaddr, blobid);
	err = silofs_bli_store(bli, &oaddr, bb);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_archive_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli,
                                  loff_t voff, size_t slot)
{
	struct silofs_ulink ulink;
	const struct silofs_blobid *blobid;
	struct silofs_ubk_info *ubi = NULL;
	int err;

	err = silofs_sli_subref_of(sli, voff, &ulink);
	if (err) {
		return err;
	}
	blobid = blobid_of(&ulink.child);
	err = pac_stage_block(pa_ctx, blobid, slot, &ubi);
	if (err) {
		return err;
	}
	err = sli_bb_insert_ubk(sli, ubi, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_exec_archive_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	loff_t voff;
	size_t slot = 0;
	int err;

	silofs_sli_vspace_range(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_archive_spleaf_sub(pa_ctx, sli, voff, slot);
		if (err && (err != -ENOENT)) {
			return err;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
	}
	return 0;
}

static int pac_post_archive_spleaf(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_spnode_info *parent,
                                   struct silofs_spleaf_info *sli, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_bytebuf *bb = &sli->sl_ui.u_bb;
	int err;

	pac_resolve_packid_of(pa_ctx, bb, &packid);
	err = pac_save_blob(pa_ctx, &packid.blobid, bb);
	if (err) {
		return err;
	}
	silofs_sli_bind_main_pack(sli, &packid);
	pac_seal_meta_of(pa_ctx, &sli->sl_ui);

	err = sni_bb_insert_spleaf(parent, sli, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int
pac_post_archive_mid_spnode(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_spnode_info *parent,
                            struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_bytebuf *bb = &sni->sn_ui.u_bb;
	int err;

	pac_resolve_packid_of(pa_ctx, bb, &packid);
	err = pac_save_blob(pa_ctx, &packid.blobid, bb);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_pack(sni, &packid);
	pac_seal_meta_of(pa_ctx, &sni->sn_ui);

	err = sni_bb_insert_spnode(parent, sni, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int
pac_post_archive_top_spnode(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_sb_info *sbi,
                            struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_bytebuf *bb = &sni->sn_ui.u_bb;
	int err;

	pac_resolve_packid_of(pa_ctx, bb, &packid);
	err = pac_save_blob(pa_ctx, &packid.blobid, bb);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_pack(sni, &packid);
	pac_seal_meta_of(pa_ctx, &sni->sn_ui);

	err = sbi_bb_insert_spnode(sbi, sni, slot);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_post_archive_super(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_sb_info *sbi)
{
	struct silofs_packid packid;
	const struct silofs_bytebuf *bb = &sbi->s_ui.u_bb;
	int err;

	pac_resolve_packid_of(pa_ctx, bb, &packid);
	err = pac_save_blob(pa_ctx, &packid.blobid, bb);
	if (err) {
		return err;
	}
	silofs_sbi_bind_main_pack(sbi, &packid);
	pac_seal_meta_of(pa_ctx, &sbi->s_ui);
	return 0;
}

static int pac_post_archive(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_uiterator *uit)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spnode_info *parent = NULL;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const size_t slot = uit->slot;
	int err = 0;

	if (ui_isspleaf(uit->ui)) {
		sni = sni_from_ui(uit->parent);
		sli = sli_from_ui(uit->ui);
		err = pac_post_archive_spleaf(pa_ctx, sni, sli, slot);
	} else if (ui_ismidspnode(uit->ui)) {
		parent = sni_from_ui(uit->parent);
		sni = sni_from_ui(uit->ui);
		err = pac_post_archive_mid_spnode(pa_ctx, parent, sni, slot);
	} else if (ui_istopspnode(uit->ui)) {
		sbi = sbi_from_ui(uit->parent);
		sni = sni_from_ui(uit->ui);
		err = pac_post_archive_top_spnode(pa_ctx, sbi, sni, slot);
	} else if (ui_issuper(uit->ui)) {
		sbi = sbi_from_ui(uit->ui);
		err = pac_post_archive_super(pa_ctx, sbi);
	} else {
		err = -EFSCORRUPTED;
	}
	return err;
}

static int pac_exec_archive_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uiterator *uit)
{
	int err;

	if ((uit == NULL) || (uit->ui == NULL)) {
		return 0; /* make clangscan happy */
	}
	err = pac_setup_bb_of(pa_ctx, uit->ui);
	if (err) {
		return err;
	}
	pac_uil_insert(pa_ctx, uit->ui);

	if (!ui_isspleaf(uit->ui)) {
		return 0;
	}
	err = pac_exec_archive_at_spleaf(pa_ctx, sli_from_ui(uit->ui));
	if (err) {
		return err;
	}
	return 0;
}

static int pac_post_archive_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uiterator *uit)
{
	int err;

	if ((uit == NULL) || (uit->ui == NULL)) {
		return 0; /* make clangscan happy */
	}
	err = pac_post_archive(pa_ctx, uit);
	if (err) {
		return err;
	}
	pac_uil_remove(pa_ctx, uit->ui);
	return 0;
}

static int pac_prep_archive_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uiterator *uit)
{
	silofs_unused(pa_ctx);

	return (uit && uit->parent) ? 0 : -EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_save_bootsec(const struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_namestr *name)
{
	const struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	const struct silofs_bootsec *bsec = &pa_ctx->bsec;

	return repo ? silofs_repo_save_bsec(repo, bsec, name) : -EBADF;
}

static int pac_load_bootsec(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_namestr *name)
{
	const struct silofs_repo *repo = pac_src_repo(pa_ctx);
	struct silofs_bootsec *bsec = &pa_ctx->bsec;

	return repo ? silofs_repo_load_bsec(repo, name, bsec) : -EBADF;
}

static int pac_stage_super(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_repo *repo = pac_src_repo(pa_ctx);
	int err;

	err = silofs_repo_stage_super(repo, uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_apex(*out_sbi, pa_ctx->apex);
	return 0;
}

static int pac_load_super(const struct silofs_pack_ctx *pa_ctx,
                          struct silofs_sb_info **out_sbi)
{
	return pac_stage_super(pa_ctx, &pa_ctx->bsec.sb_uaddr, out_sbi);
}

static void bytebuf_of(struct silofs_bytebuf *bb,
                       const struct silofs_sb_info *sbi)
{
	struct silofs_super_block *sb = sbi->sb;

	silofs_bytebuf_init2(bb, sb, sizeof(*sb));
}

static int pac_save_super_as_pack(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_sb_info *sbi)
{
	struct silofs_bytebuf bb;
	struct silofs_packid packid;
	struct silofs_bootsec *bsec = &pa_ctx->bsec;
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);
	int err;

	bytebuf_of(&bb, sbi);
	pac_seal_meta_of(pa_ctx, &sbi->s_ui);
	pac_resolve_packid_of(pa_ctx, &bb, &packid);
	err = pac_save_blob(pa_ctx, &packid.blobid, &bb);
	if (err) {
		return err;
	}
	silofs_bootsec_set_packid(bsec, &packid);
	silofs_bootsec_set_uaddr(bsec, uaddr);
	return 0;
}

static int pac_save_super_as_unpack(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_sb_info *sbi)
{
	struct silofs_bytebuf bb;
	struct silofs_bootsec *bsec = &pa_ctx->bsec;
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);
	int err;

	bytebuf_of(&bb, sbi);
	pac_seal_meta_of(pa_ctx, &sbi->s_ui);
	err = pac_save_blob(pa_ctx, blobid_of(uaddr), &bb);
	if (err) {
		return err;
	}
	silofs_bootsec_set_uaddr(bsec, uaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pack_ctx *pack_ctx_of(struct silofs_visitor *vis)
{
	return silofs_container_of(vis, struct silofs_pack_ctx, vis);
}

static int pack_visit_prep(struct silofs_visitor *vis,
                           const struct silofs_uiterator *uit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_prep_archive_at(pa_ctx, uit);
}

static int pack_visit_exec(struct silofs_visitor *vis,
                           const struct silofs_uiterator *uit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_exec_archive_at(pa_ctx, uit);
}

static int pack_visit_post(struct silofs_visitor *vis,
                           const struct silofs_uiterator *uit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_post_archive_at(pa_ctx, uit);
}

int silofs_apex_pack_fs(struct silofs_fs_apex *apex,
                        const struct silofs_namestr *src_name,
                        const struct silofs_namestr *dst_name)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.visit_prep_hook =  pack_visit_prep,
		.vis.visit_exec_hook = pack_visit_exec,
		.vis.visit_post_hook = pack_visit_post,
		.apex = apex,
		.alif = apex->ap_alif,
		.archive = true,
	};
	int err;

	pa_ctx_start(&pa_ctx);
	err = pac_load_bootsec(&pa_ctx, src_name);
	if (err) {
		goto out;
	}
	err = pac_load_super(&pa_ctx, &pa_ctx.sbi);
	if (err) {
		goto out;
	}
	err = silofs_walk_space_tree(pa_ctx.sbi, &pa_ctx.vis);
	if (err) {
		goto out;
	}
	err = pac_save_super_as_pack(&pa_ctx, pa_ctx.sbi);
	if (err) {
		goto out;
	}
	err = pac_save_bootsec(&pa_ctx, dst_name);
	if (err) {
		goto out;
	}
out:
	pa_ctx_finish(&pa_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_refill_ghost(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_ubk_info *src_ubi,
                            struct silofs_unode_info *ui)
{
	struct silofs_block *ubk = ui->u_ubi->ubk;

	memcpy(ubk, src_ubi->ubk, sizeof(*ubk));
	return pac_verify_meta_of(pa_ctx, ui);
}

static int pac_restore_ghost_unode(struct silofs_pack_ctx *pa_ctx,
                                   const struct silofs_packid *packid,
                                   size_t slot, struct silofs_unode_info *ui)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	err = pac_stage_block(pa_ctx, &packid->blobid, slot, &ubi);
	if (err) {
		return err;
	}
	err = pac_refill_ghost(pa_ctx, ubi, ui);
	if (err) {
		return err;
	}
	silofs_ui_bind_apex(ui, pa_ctx->apex);
	return 0;
}

static int pac_restore_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli,
                                  loff_t voff, size_t slot)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	struct silofs_ubk_info *ubi_src = NULL;
	int err;

	err = silofs_sli_subref_of(sli, voff, &ulink);
	if (err) {
		return err;
	}
	err = silofs_sli_main_pack(sli, &packid);
	silofs_assert_ok(err);
	if (err) {
		return err;
	}
	err = pac_stage_block(pa_ctx, &packid.blobid, slot, &ubi_src);
	if (err) {
		return err;
	}
	err = pac_restore_ubk(pa_ctx, ubi_src, &ulink.child.oaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_spleaf_subs(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	loff_t voff;
	size_t slot = 0;
	int err;

	silofs_sli_vspace_range(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_restore_spleaf_sub(pa_ctx, sli, voff, slot);
		if (err && (err != -ENOENT)) {
			return err;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
	}
	return 0;
}

static int pac_exec_restore_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uiterator *uit)
{
	struct silofs_spleaf_info *sli = NULL;
	int ret = 0;

	if (uit && uit->ui && ui_isspleaf(uit->ui)) {
		sli = sli_from_ui(uit->ui);
		ret = pac_restore_spleaf_subs(pa_ctx, sli);
	}
	return ret;
}

static int pac_restore_unode(struct silofs_pack_ctx *pa_ctx,
                             const struct silofs_uiterator *uit)
{
	const struct silofs_unode_info *ui = uit->ui;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	int err;

	err = pac_restore_ubk(pa_ctx, ui->u_ubi, &uaddr->oaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_post_restore_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uiterator *uit)
{
	int ret = 0;

	if (uit && uit->ui) {
		ret = pac_restore_unode(pa_ctx, uit);
	}
	return ret;
}

static int pac_restore_ghost_super(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_sb_info *sbi,
                                   const struct silofs_packid *packid)
{
	int ret;

	sbi_incref(sbi);
	ret = pac_restore_ghost_unode(pa_ctx, packid, 0, &sbi->s_ui);
	sbi_decref(sbi);
	return ret;
}

static int
pac_restore_ghost_spnode(struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_packid *packid,
                         size_t slot, struct silofs_spnode_info *sni)
{
	int ret;

	sni_incref(sni);
	ret = pac_restore_ghost_unode(pa_ctx, packid, slot, &sni->sn_ui);
	sni_decref(sni);
	return ret;
}

static int
pac_restore_ghost_spleaf(struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_packid *packid,
                         size_t slot, struct silofs_spleaf_info *sli)
{
	int ret;

	sli_incref(sli);
	ret = pac_restore_ghost_unode(pa_ctx, packid, slot, &sli->sl_ui);
	sli_decref(sli);
	return ret;
}

static int pac_reload_by_top_spnode(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_spnode_info *sni,
                                    loff_t voff, size_t slot)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);
	struct silofs_spnode_info *sni_child = NULL;
	int err;

	err = silofs_sni_main_pack(sni, &packid);
	if (err) {
		return err;
	}
	err = silofs_sni_subref_of(sni, voff, &ulink);
	if (err) {
		return err;
	}
	err = silofs_repo_ghost_spnode(repo, &ulink.child, &sni_child);
	if (err) {
		return err;
	}
	err = pac_restore_ghost_spnode(pa_ctx, &packid, slot, sni_child);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_mid_spnode(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_spnode_info *sni,
                                    loff_t voff, size_t slot)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_main_pack(sni, &packid);
	if (err) {
		return err;
	}
	err = silofs_sni_subref_of(sni, voff, &ulink);
	if (err) {
		return err;
	}
	err = silofs_repo_ghost_spleaf(repo, &ulink.child, &sli);
	if (err) {
		return err;
	}
	err = pac_restore_ghost_spleaf(pa_ctx, &packid, slot, sli);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_super(struct silofs_pack_ctx *pa_ctx,
                               struct silofs_sb_info *sbi,
                               loff_t voff, size_t slot)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sbi_main_pack(sbi, &packid);
	if (err) {
		return err;
	}
	err = silofs_sbi_subref_of(sbi, voff, &ulink);
	if (err) {
		return err;
	}
	err = silofs_repo_ghost_spnode(repo, &ulink.child, &sni);
	if (err) {
		return err;
	}
	err = pac_restore_ghost_spnode(pa_ctx, &packid, slot, sni);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_prep_restore(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_uiterator *uit)
{
	struct silofs_unode_info *parent = uit->parent;
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spnode_info *sni = NULL;
	const loff_t voff = uit->voff;
	const size_t slot = uit->slot;
	int ret = 0;

	if (ui_issuper(parent)) {
		sbi = sbi_from_ui(parent);
		ret = pac_reload_by_super(pa_ctx, sbi, voff, slot);
	} else if (ui_istopspnode(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_top_spnode(pa_ctx, sni, voff, slot);
	} else if (ui_ismidspnode(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_mid_spnode(pa_ctx, sni, voff, slot);
	}
	return ret;
}

static int pac_prep_restore_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uiterator *uit)
{
	int ret = 0;

	if (uit && uit->parent) {
		ret = pac_prep_restore(pa_ctx, uit);
	}
	return ret;
}

static int pac_reload_super(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_sb_info **out_sbi)
{
	struct silofs_repo *repo = pac_src_repo(pa_ctx);
	const struct silofs_bootsec *bsec = &pa_ctx->bsec;
	int err;

	err = silofs_repo_ghost_super(repo, &bsec->sb_uaddr, out_sbi);
	if (err) {
		return err;
	}
	err = pac_restore_ghost_super(pa_ctx, *out_sbi, &bsec->sb_packid);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unpack_visit_prep(struct silofs_visitor *vis,
                             const struct silofs_uiterator *uit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_prep_restore_at(pa_ctx, uit);
}

static int unpack_visit_exec(struct silofs_visitor *vis,
                             const struct silofs_uiterator *uit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_exec_restore_at(pa_ctx, uit);
}

static int unpack_visit_post(struct silofs_visitor *vis,
                             const struct silofs_uiterator *uit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_post_restore_at(pa_ctx, uit);
}

int silofs_apex_unpack_fs(struct silofs_fs_apex *apex,
                          const struct silofs_namestr *src_name,
                          const struct silofs_namestr *dst_name)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.visit_prep_hook = unpack_visit_prep,
		.vis.visit_exec_hook = unpack_visit_exec,
		.vis.visit_post_hook = unpack_visit_post,
		.apex = apex,
		.alif = apex->ap_alif,
		.archive = false,
	};
	int err;

	pa_ctx_start(&pa_ctx);
	err = pac_load_bootsec(&pa_ctx, src_name);
	if (err) {
		return err;
	}
	err = pac_reload_super(&pa_ctx, &pa_ctx.sbi);
	if (err) {
		goto out;
	}
	err = silofs_walk_space_tree(pa_ctx.sbi, &pa_ctx.vis);
	if (err) {
		goto out;
	}
	err = pac_save_super_as_unpack(&pa_ctx, pa_ctx.sbi);
	if (err) {
		goto out;
	}
	err = pac_save_bootsec(&pa_ctx, dst_name);
	if (err) {
		goto out;
	}
out:
	pa_ctx_finish(&pa_ctx);
	return err;
}


