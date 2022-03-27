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


struct silofs_pack_iovs {
	struct iovec            pi_iov[SILOFS_UNODE_NCHILDS];
	struct silofs_alloc_if *pi_alif;
	size_t                  pi_cnt;
};

struct silofs_pack_ctx {
	struct silofs_bootsec   bsec;
	struct silofs_visitor   vis;
	struct silofs_fs_apex  *apex;
	struct silofs_alloc_if *alif;
	struct silofs_sb_info  *sbi;
	struct silofs_listq     uil;
	bool                    archive;
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void piov_init(struct silofs_pack_iovs *piov,
                      struct silofs_alloc_if *alif)
{
	silofs_memzero(piov, sizeof(*piov));
	piov->pi_alif = alif;
	piov->pi_cnt = 0;
}

static void piov_fini(struct silofs_pack_iovs *piov)
{
	silofs_memffff(piov, sizeof(*piov));
	piov->pi_alif = NULL;
	piov->pi_cnt = 0;
}

static struct iovec *piov_iovec_at(struct silofs_pack_iovs *piov, size_t slot)
{
	silofs_assert_lt(slot, ARRAY_SIZE(piov->pi_iov));

	return &piov->pi_iov[slot];
}

static int piov_set_at(struct silofs_pack_iovs *piov, size_t slot,
                       const void *dat, size_t len)
{
	struct iovec *iov = piov_iovec_at(piov, slot);
	void *buf = NULL;

	silofs_assert_null(iov->iov_base);
	silofs_assert_eq(iov->iov_len, 0);

	if (dat != NULL) {
		buf = silofs_allocate(piov->pi_alif, len);
		if (buf == NULL) {
			return -ENOMEM;
		}
		memcpy(buf, dat, len);
	}
	iov->iov_base = buf;
	iov->iov_len = len;
	piov->pi_cnt = max(piov->pi_cnt, slot + 1);
	return 0;
}

static void piov_unset_at(struct silofs_pack_iovs *piov, size_t slot)
{
	struct iovec *iov = piov_iovec_at(piov, slot);

	if (iov->iov_base != NULL) {
		silofs_deallocate(piov->pi_alif, iov->iov_base, iov->iov_len);
		iov->iov_base = NULL;
	}
	iov->iov_len = 0;
}

static int piov_add_bk(struct silofs_pack_iovs *piov, size_t slot,
                       const struct silofs_block *bk)
{
	return piov_set_at(piov, slot, bk, sizeof(*bk));
}

static void piov_clear(struct silofs_pack_iovs *piov)
{
	for (size_t slot = 0; slot < piov->pi_cnt; ++slot) {
		piov_unset_at(piov, slot);
	}
}

static struct silofs_pack_iovs *piov_new(struct silofs_alloc_if *alif)
{
	struct silofs_pack_iovs *piov;

	piov = silofs_allocate(alif, sizeof(*piov));
	if (piov != NULL) {
		piov_init(piov, alif);
	}
	return piov;
}

static void piov_del(struct silofs_pack_iovs *piov,
                     struct silofs_alloc_if *alif)
{
	piov_clear(piov);
	piov_fini(piov);
	silofs_deallocate(alif, piov, sizeof(*piov));
}

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
	return silofs_sni_height(sni) == SILOFS_SPNODE3_HEIGHT;
}

static bool ui_isspleaf(const struct silofs_unode_info *ui)
{
	return stype_isspleaf(ui_stype(ui));
}

static bool ui_isspnode(const struct silofs_unode_info *ui)
{
	return stype_isspnode(ui_stype(ui));
}

static bool ui_isspnode3(const struct silofs_unode_info *ui)
{
	return ui_isspnode(ui) && sni_istoplevel(sni_from_ui(ui));
}

static bool ui_isspnode2(const struct silofs_unode_info *ui)
{
	return ui_isspnode(ui) && !sni_istoplevel(sni_from_ui(ui));
}

static bool ui_issuper(const struct silofs_unode_info *ui)
{
	return stype_issuper(ui_stype(ui));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_block *sl_to_bk(const struct silofs_spmap_leaf *sl)
{
	const union silofs_block_u *u;
	const struct silofs_block *bk;

	u = container_of2(sl, union silofs_block_u, sl);
	bk = container_of2(u, struct silofs_block, u);
	return bk;
}

static const struct silofs_block *sn_to_bk(const struct silofs_spmap_node *sn)
{
	const union silofs_block_u *u;
	const struct silofs_block *bk;

	u = container_of2(sn, union silofs_block_u, sn);
	bk = container_of2(u, struct silofs_block, u);
	return bk;
}

static const struct silofs_block *sb_to_bk(const struct silofs_super_block *sb)
{
	const union silofs_block_u *u;
	const struct silofs_block *bk;

	u = container_of2(sb, union silofs_block_u, sb);
	bk = container_of2(u, struct silofs_block, u);
	return bk;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ui_piov_setup(struct silofs_unode_info *ui,
                         struct silofs_alloc_if *alif)
{
	struct silofs_pack_iovs *piov;

	silofs_assert_null(ui->u_piov);
	piov = piov_new(alif);
	if (piov == NULL) {
		return -ENOMEM;
	}
	ui->u_piov = piov;
	return 0;
}

static void ui_piov_clear(struct silofs_unode_info *ui,
                          struct silofs_alloc_if *alif)
{
	struct silofs_pack_iovs *piov = ui->u_piov;

	if (piov != NULL) {
		piov_del(piov, alif);
		ui->u_piov = NULL;
	}
}

static int ui_pack_bk(struct silofs_unode_info *ui,
                      const struct silofs_block *bk, size_t slot)
{
	return piov_add_bk(ui->u_piov, slot, bk);
}

static int sli_pack_bk(struct silofs_spleaf_info *sli, size_t slot,
                       const struct silofs_block *bk)
{
	return ui_pack_bk(&sli->sl_ui, bk, slot);
}

static int sni_pack_spleaf_bk(struct silofs_spnode_info *sni,
                              const struct silofs_block *bk, size_t slot)
{
	return ui_pack_bk(&sni->sn_ui, bk, slot);
}

static int sni_pack_spnode_bk(struct silofs_spnode_info *sni,
                              const struct silofs_block *bk, size_t slot)
{
	return ui_pack_bk(&sni->sn_ui, bk, slot);
}

static int sbi_pack_spnode_bk(struct silofs_sb_info *sbi,
                              const struct silofs_block *bk, size_t slot)
{
	return ui_pack_bk(&sbi->s_ui, bk, slot);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_cipher *
pac_cipher(const struct silofs_pack_ctx *pa_ctx)
{
	return &pa_ctx->apex->ap_crypto->ci;
}

static const struct silofs_kivam *
pac_kivam(const struct silofs_pack_ctx *pa_ctx)
{
	return pa_ctx->apex->ap_kivam;
}

static int pac_alloc_bk(const struct silofs_pack_ctx *pa_ctx,
                        struct silofs_block **out_bk)
{
	struct silofs_block *bk;

	bk = silofs_allocate(pa_ctx->alif, sizeof(*bk));
	if (bk == NULL) {
		return -ENOMEM;
	}
	*out_bk = bk;
	return 0;
}

static void pac_dealloc_bk(const struct silofs_pack_ctx *pa_ctx,
                           struct silofs_block *bk)
{
	if (bk != NULL) {
		silofs_deallocate(pa_ctx->alif, bk, sizeof(*bk));
	}
}

static int pac_encrypt_bk(const struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_block *bk,
                          struct silofs_block *enc_bk)
{
	const struct silofs_cipher *ci = pac_cipher(pa_ctx);
	const struct silofs_kivam *kivam = pac_kivam(pa_ctx);

	return silofs_encrypt_buf(ci, kivam, bk, enc_bk, sizeof(*enc_bk));
}

static int pac_decrypt_bk(const struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_block *enc_bk,
                          struct silofs_block *bk)
{
	const struct silofs_cipher *ci = pac_cipher(pa_ctx);
	const struct silofs_kivam *kivam = pac_kivam(pa_ctx);

	return silofs_decrypt_buf(ci, kivam, enc_bk, bk, sizeof(*bk));
}

static int pac_setup_piov_of(const struct silofs_pack_ctx *pa_ctx,
                             struct silofs_unode_info *ui)
{
	return ui_piov_setup(ui, pa_ctx->alif);
}

static void pac_clear_piov_of(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_unode_info *ui)
{
	ui_piov_clear(ui, pa_ctx->alif);
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

		pac_clear_piov_of(pa_ctx, ui);
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
                                const struct iovec *iov, size_t cnt,
                                struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;
	const size_t len = cnt * SILOFS_BK_SIZE;

	silofs_sha256_ofv(pac_mdigest(pa_ctx), iov, cnt, &hash);
	silofs_blobid_make_cas(out_blobid, &hash, len);
}

static void pac_resolve_packid_of(const struct silofs_pack_ctx *pa_ctx,
                                  const struct iovec *iov, size_t cnt,
                                  struct silofs_packid *out_packid)
{
	struct silofs_blobid cas_blobid;

	pac_calc_cas_blobid(pa_ctx, iov, cnt, &cas_blobid);
	packid_setup(out_packid, &cas_blobid);
}

static void pac_resolve_packid(const struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_pack_iovs *piov,
                               struct silofs_packid *out_packid)
{
	pac_resolve_packid_of(pa_ctx, piov->pi_iov, piov->pi_cnt, out_packid);
}

static int pac_stage_block(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_blobid *blobid, size_t slot,
                           struct silofs_ubk_info **out_ubi)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);

	silofs_assert_lt(slot, SILOFS_NBK_IN_VSEC);

	silofs_bkaddr_setup(&bkaddr, blobid, (silofs_lba_t)slot);
	return silofs_repo_stage_ubk(repo, &bkaddr, out_ubi);
}

static int pac_require_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubi)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	int err;

	err = silofs_repo_lookup_blob(repo, &bkaddr->blobid);
	if (!err) {
		err = silofs_repo_stage_ubk(repo, bkaddr, out_ubi);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_ubk(repo, bkaddr, out_ubi);
	}
	return err;
}

static int pac_restore_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_ubk_info *ubi_src,
                           const struct silofs_bkaddr *bkaddr_dst)
{
	struct silofs_ubk_info *ubi_dst = NULL;
	int err;

	err = pac_require_ubk(pa_ctx, bkaddr_dst, &ubi_dst);
	if (err) {
		return err;
	}
	err = silofs_bli_store_bk(ubi_dst->ubk_bli, bkaddr_dst, ubi_src->ubk);
	if (err) {
		return err;
	}
	return 0;
}

static void iovec_scan_hole(const struct iovec *beg,
                            const struct iovec *end,
                            size_t *out_cnt, size_t *out_len)
{
	const struct iovec *itr = beg;

	*out_cnt = 0;
	*out_len = 0;
	while (itr < end) {
		if (itr->iov_base != NULL) {
			break;
		}
		*out_cnt += 1;
		*out_len += itr->iov_len;
		itr++;
	}
}

static void iovec_scan_data(const struct iovec *beg,
                            const struct iovec *end,
                            size_t *out_cnt, size_t *out_len)
{
	const struct iovec *itr = beg;

	*out_cnt = 0;
	*out_len = 0;
	while (itr < end) {
		if (itr->iov_base == NULL) {
			break;
		}
		*out_cnt += 1;
		*out_len += itr->iov_len;
		itr++;
	}
}

static int bli_save_blob(const struct silofs_blob_info *bli,
                         const struct iovec *iov, size_t n)
{
	const struct iovec *itr = iov;
	const struct iovec *end = iov + n;
	loff_t off = 0;
	size_t cnt = 0;
	size_t len = 0;
	int err = 0;

	while ((itr < end) && !err) {
		iovec_scan_hole(itr, end, &cnt, &len);
		off += (long)len;
		itr += cnt;
		iovec_scan_data(itr, end, &cnt, &len);
		err = silofs_bli_storev2(bli, off, itr, cnt);
		off += (long)len;
		itr += cnt;
	}
	return err;
}

static int pac_save_blob(const struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_blobid *blobid,
                         const struct iovec *iov, size_t cnt)
{
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
	err = bli_save_blob(bli, iov, cnt);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_blob_of(const struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_blobid *blobid,
                            const struct silofs_pack_iovs *piov)
{
	return pac_save_blob(pa_ctx, blobid, piov->pi_iov, piov->pi_cnt);
}

static int pac_archive_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli,
                                  loff_t voff, size_t slot)
{
	struct silofs_uaddr ulink;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_block *enc_bk = NULL;
	size_t nalloc;
	int err;

	nalloc = silofs_sli_nallocated_at(sli, off_to_lba(voff));
	if (!nalloc) {
		goto out_ok;
	}
	err = pac_alloc_bk(pa_ctx, &enc_bk);
	if (err) {
		goto out;
	}
	err = silofs_sli_subref_of(sli, voff, &ulink);
	if (err) {
		goto out;
	}
	err = pac_stage_block(pa_ctx, blobid_of(&ulink), slot, &ubi);
	if (err) {
		goto out;
	}
	err = pac_encrypt_bk(pa_ctx, ubi->ubk, enc_bk);
	if (err) {
		goto out;
	}
out_ok:
	err = sli_pack_bk(sli, slot, enc_bk);
out:
	pac_dealloc_bk(pa_ctx, enc_bk);
	return err;
}

static int pac_exec_archive_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	size_t slot = 0;
	int err;

	sli_vrange(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_archive_spleaf_sub(pa_ctx, sli, voff, slot);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, vrange.stepsz);
		slot++;
	}
	return 0;
}

static int pac_post_archive_spleaf(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_spnode_info *sni,
                                   struct silofs_spleaf_info *sli, size_t slot)
{
	struct silofs_packid packid;
	struct silofs_block *enc_bk = NULL;
	const struct silofs_pack_iovs *piov = sli->sl_ui.u_piov;
	int err;

	err = pac_alloc_bk(pa_ctx, &enc_bk);
	if (err) {
		goto out;
	}
	pac_resolve_packid(pa_ctx, piov, &packid);
	err = pac_save_blob_of(pa_ctx, &packid.blobid, piov);
	if (err) {
		goto out;
	}
	silofs_sli_bind_main_pack(sli, &packid);
	pac_seal_meta_of(pa_ctx, &sli->sl_ui);

	err = pac_encrypt_bk(pa_ctx, sl_to_bk(sli->sl), enc_bk);
	if (err) {
		goto out;
	}
	err = sni_pack_spleaf_bk(sni, enc_bk, slot);
	if (err) {
		goto out;
	}
out:
	pac_dealloc_bk(pa_ctx, enc_bk);
	return err;
}

static int
pac_post_archive_spnode2(struct silofs_pack_ctx *pa_ctx,
                         struct silofs_spnode_info *sni_parent,
                         struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	struct silofs_block *enc_bk = NULL;
	const struct silofs_pack_iovs *piov = sni->sn_ui.u_piov;
	int err;

	err = pac_alloc_bk(pa_ctx, &enc_bk);
	if (err) {
		goto out;
	}
	pac_resolve_packid(pa_ctx, piov, &packid);
	err = pac_save_blob_of(pa_ctx, &packid.blobid, piov);
	if (err) {
		goto out;
	}
	silofs_sni_bind_main_pack(sni, &packid);
	pac_seal_meta_of(pa_ctx, &sni->sn_ui);

	err = pac_encrypt_bk(pa_ctx, sn_to_bk(sni->sn), enc_bk);
	if (err) {
		goto out;
	}
	err = sni_pack_spnode_bk(sni_parent, enc_bk, slot);
	if (err) {
		goto out;
	}
out:
	pac_dealloc_bk(pa_ctx, enc_bk);
	return err;
}

static int
pac_post_archive_spnode3(struct silofs_pack_ctx *pa_ctx,
                         struct silofs_sb_info *sbi,
                         struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	struct silofs_block *enc_bk = NULL;
	const struct silofs_pack_iovs *piov = sni->sn_ui.u_piov;
	int err;

	err = pac_alloc_bk(pa_ctx, &enc_bk);
	if (err) {
		goto out;
	}
	pac_resolve_packid(pa_ctx, piov, &packid);
	err = pac_save_blob_of(pa_ctx, &packid.blobid, piov);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_pack(sni, &packid);
	pac_seal_meta_of(pa_ctx, &sni->sn_ui);

	err = pac_encrypt_bk(pa_ctx, sn_to_bk(sni->sn), enc_bk);
	if (err) {
		goto out;
	}
	err = sbi_pack_spnode_bk(sbi, enc_bk, slot);
	if (err) {
		return err;
	}
out:
	pac_dealloc_bk(pa_ctx, enc_bk);
	return err;
}

static int pac_post_archive_super(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_sb_info *sbi)
{
	struct silofs_packid packid;
	const struct silofs_pack_iovs *piov = sbi->s_ui.u_piov;
	int err;

	pac_resolve_packid(pa_ctx, piov, &packid);
	err = pac_save_blob_of(pa_ctx, &packid.blobid, piov);
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
	} else if (ui_isspnode2(uit->ui)) {
		parent = sni_from_ui(uit->parent);
		sni = sni_from_ui(uit->ui);
		err = pac_post_archive_spnode2(pa_ctx, parent, sni, slot);
	} else if (ui_isspnode3(uit->ui)) {
		sbi = sbi_from_ui(uit->parent);
		sni = sni_from_ui(uit->ui);
		err = pac_post_archive_spnode3(pa_ctx, sbi, sni, slot);
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
	err = pac_setup_piov_of(pa_ctx, uit->ui);
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

static void pac_setup_bootsec_keyhash(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_hash256 hash;
	const struct silofs_kivam *kivam = pa_ctx->apex->ap_kivam;

	if (pa_ctx->archive) {
		silofs_calc_key_hash(&kivam->key, pac_mdigest(pa_ctx), &hash);
		silofs_bootsec_set_keyhash(&pa_ctx->bsec, &hash);
	} else {
		silofs_bootsec_clear_keyhash(&pa_ctx->bsec);
	}
}

static int pac_save_bootsec(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_namestr *name)
{
	const struct silofs_repo *repo = pac_dst_repo(pa_ctx);

	pac_setup_bootsec_keyhash(pa_ctx);
	return silofs_repo_save_bsec(repo, &pa_ctx->bsec, name);
}

static int pac_load_bootsec(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_namestr *name)
{
	const struct silofs_repo *repo = pac_src_repo(pa_ctx);

	return silofs_repo_load_bsec(repo, name, &pa_ctx->bsec);
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

static int pac_save_super_as_pack(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_sb_info *sbi)
{
	struct silofs_packid packid;
	struct iovec iov;
	struct silofs_block *enc_bk = NULL;
	struct silofs_bootsec *bsec = &pa_ctx->bsec;
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);
	int err;

	err = pac_alloc_bk(pa_ctx, &enc_bk);
	if (err) {
		goto out;
	}
	pac_seal_meta_of(pa_ctx, &sbi->s_ui);
	err = pac_encrypt_bk(pa_ctx, sb_to_bk(sbi->sb), enc_bk);
	if (err) {
		goto out;
	}
	iov.iov_base = enc_bk;
	iov.iov_len = sizeof(*enc_bk);
	pac_resolve_packid_of(pa_ctx, &iov, 1, &packid);
	err = pac_save_blob(pa_ctx, &packid.blobid, &iov, 1);
	if (err) {
		goto out;
	}
	silofs_bootsec_set_packid(bsec, &packid);
	silofs_bootsec_set_uaddr(bsec, uaddr);
out:
	pac_dealloc_bk(pa_ctx, enc_bk);
	return err;
}

static int pac_save_super_as_unpack(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_sb_info *sbi)
{
	struct silofs_bootsec *bsec = &pa_ctx->bsec;
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);
	struct iovec iov = {
		.iov_base = sbi->sb,
		.iov_len = sizeof(*sbi->sb),
	};
	int err;

	pac_seal_meta_of(pa_ctx, &sbi->s_ui);
	err = pac_save_blob(pa_ctx, blobid_of(uaddr), &iov, 1);
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
                            const struct silofs_block *bk,
                            struct silofs_unode_info *ui)
{
	struct silofs_block *ubk = ui->u_ubi->ubk;

	memcpy(ubk, bk, sizeof(*ubk));
	return pac_verify_meta_of(pa_ctx, ui);
}

static int pac_restore_ghost_unode(struct silofs_pack_ctx *pa_ctx,
                                   const struct silofs_packid *packid,
                                   size_t slot, struct silofs_unode_info *ui)
{
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_block *bk = NULL;
	int err;

	err = pac_alloc_bk(pa_ctx, &bk);
	if (err) {
		goto out;
	}
	err = pac_stage_block(pa_ctx, &packid->blobid, slot, &ubi);
	if (err) {
		goto out;
	}
	err = pac_decrypt_bk(pa_ctx, ubi->ubk, bk);
	if (err) {
		goto out;
	}
	err = pac_refill_ghost(pa_ctx, bk, ui);
	if (err) {
		goto out;
	}
	silofs_ui_bind_apex(ui, pa_ctx->apex);
out:
	pac_dealloc_bk(pa_ctx, bk);
	return err;
}

static int pac_restore_spleaf_blob_of(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_uaddr *uaddr)
{
	const struct silofs_blobid *blobid = blobid_of(uaddr);
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	struct silofs_blob_info *bli = NULL;
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(repo, blobid, &bli);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, &bli);
	}
	return err;
}

static int pac_restore_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli,
                                  loff_t voff, size_t slot)
{
	struct silofs_uaddr ulink;
	struct silofs_packid packid;
	struct silofs_ubk_info *ubi_src = NULL;
	struct silofs_ubk_info *ubi_dst = NULL;
	const struct silofs_bkaddr *bkaddr = &ulink.oaddr.bka;
	size_t nalloc;
	int err;

	err = silofs_sli_subref_of(sli, voff, &ulink);
	if (err) {
		return err;
	}
	err = pac_restore_spleaf_blob_of(pa_ctx, &ulink);
	if (err) {
		return err;
	}
	nalloc = silofs_sli_nallocated_at(sli, off_to_lba(voff));
	if (!nalloc) {
		return 0;
	}
	err = silofs_sli_main_pack(sli, &packid);
	if (err) {
		return err;
	}
	err = pac_stage_block(pa_ctx, &packid.blobid, slot, &ubi_src);
	if (err) {
		return err;
	}
	err = pac_require_ubk(pa_ctx, bkaddr, &ubi_dst);
	if (err) {
		return err;
	}
	err = pac_decrypt_bk(pa_ctx, ubi_src->ubk, ubi_dst->ubk);
	if (err) {
		return err;
	}
	err = silofs_bli_store_bk(ubi_dst->ubk_bli, bkaddr, ubi_dst->ubk);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_spleaf_subs(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	size_t slot = 0;
	int err;

	sli_vrange(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_restore_spleaf_sub(pa_ctx, sli, voff, slot);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
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

	return pac_restore_ubk(pa_ctx, ui->u_ubi, ui_bkaddr(ui));
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

static int pac_reload_by_spnode3(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni,
                                 loff_t voff, size_t slot)
{
	struct silofs_uaddr ulink;
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
	err = silofs_repo_ghost_spnode(repo, &ulink, &sni_child);
	if (err) {
		return err;
	}
	err = pac_restore_ghost_spnode(pa_ctx, &packid, slot, sni_child);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_spnode2(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni,
                                 loff_t voff, size_t slot)
{
	struct silofs_uaddr ulink;
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
	err = silofs_repo_ghost_spleaf(repo, &ulink, &sli);
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
	struct silofs_uaddr ulink;
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
	err = silofs_repo_ghost_spnode(repo, &ulink, &sni);
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
	} else if (ui_isspnode3(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_spnode3(pa_ctx, sni, voff, slot);
	} else if (ui_isspnode2(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_spnode2(pa_ctx, sni, voff, slot);
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


