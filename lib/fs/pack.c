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


struct silofs_pack_iovs {
	struct iovec            pi_iov[SILOFS_UNODE_NCHILDS];
	struct silofs_alloc    *pi_alloc;
	size_t                  pi_cnt;
};

struct silofs_pack_ctx {
	struct silofs_visitor           vis;
	struct silofs_listq             uil;
	struct silofs_crypto            cryp;
	const struct silofs_kivam      *kivam;
	const struct silofs_bootsec    *src_bsec;
	struct silofs_bootsec          *dst_bsec;
	struct silofs_fs_uber          *uber;
	struct silofs_alloc            *alloc;
	struct silofs_sb_info          *sbi;
	struct silofs_block            *tbk;
	struct silofs_pack_iovs        *piov;
	bool                            pack;
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void piov_init(struct silofs_pack_iovs *piov,
                      struct silofs_alloc *alloc)
{
	silofs_memzero(piov, sizeof(*piov));
	piov->pi_alloc = alloc;
	piov->pi_cnt = 0;
}

static void piov_fini(struct silofs_pack_iovs *piov)
{
	silofs_memffff(piov, sizeof(*piov));
	piov->pi_alloc = NULL;
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
		buf = silofs_allocate(piov->pi_alloc, len);
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
		silofs_deallocate(piov->pi_alloc, iov->iov_base, iov->iov_len);
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

static struct silofs_pack_iovs *piov_new(struct silofs_alloc *alloc)
{
	struct silofs_pack_iovs *piov;

	piov = silofs_allocate(alloc, sizeof(*piov));
	if (piov != NULL) {
		piov_init(piov, alloc);
	}
	return piov;
}

static void piov_del(struct silofs_pack_iovs *piov,
                     struct silofs_alloc *alloc)
{
	piov_clear(piov);
	piov_fini(piov);
	silofs_deallocate(alloc, piov, sizeof(*piov));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_blobid *blobid_of(const struct silofs_uaddr *uaddr)
{
	return silofs_uaddr_blobid(uaddr);
}

static struct silofs_sb_info *
sbi_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SUPER));

	return silofs_sbi_from_ui(ui);
}

static struct silofs_spstats_info *
spi_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SPSTATS));

	return silofs_spi_from_ui(ui);
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
	return silofs_sli_from_ui(ui);
}

static bool sni_has_height(const struct silofs_spnode_info *sni,
                           enum silofs_height height)
{
	return (silofs_sni_height(sni) == height);
}

static bool ui_isspleaf(const struct silofs_unode_info *ui)
{
	return stype_isspleaf(ui_stype(ui));
}

static bool ui_isspnode(const struct silofs_unode_info *ui)
{
	return stype_isspnode(ui_stype(ui));
}

static bool ui_isspnode_with(const struct silofs_unode_info *ui,
                             enum silofs_height height)
{
	const struct silofs_spnode_info *sni = NULL;
	bool ret = false;

	if (ui_isspnode(ui)) {
		sni = sni_from_ui(ui);
		ret = sni_has_height(sni, height);
	}
	return ret;
}

static bool ui_isspnode4(const struct silofs_unode_info *ui)
{
	return ui_isspnode_with(ui, SILOFS_HEIGHT_SPNODE4);
}

static bool ui_isspnode3(const struct silofs_unode_info *ui)
{
	return ui_isspnode_with(ui, SILOFS_HEIGHT_SPNODE3);
}

static bool ui_isspnode2(const struct silofs_unode_info *ui)
{
	return ui_isspnode_with(ui, SILOFS_HEIGHT_SPNODE2);
}

static bool ui_isstats(const struct silofs_unode_info *ui)
{
	return stype_isstats(ui_stype(ui));
}

static bool ui_issuper(const struct silofs_unode_info *ui)
{
	return stype_issuper(ui_stype(ui));
}

static struct silofs_block *ui_block(const struct silofs_unode_info *ui)
{
	return ui->u_ubi->ubk;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ui_piov_setup(struct silofs_unode_info *ui,
                         struct silofs_alloc *alloc)
{
	struct silofs_pack_iovs *piov;

	silofs_assert_null(ui->u_piov);
	piov = piov_new(alloc);
	if (piov == NULL) {
		return -ENOMEM;
	}
	ui->u_piov = piov;
	return 0;
}

static void ui_piov_clear(struct silofs_unode_info *ui,
                          struct silofs_alloc *alloc)
{
	struct silofs_pack_iovs *piov = ui->u_piov;

	if (piov != NULL) {
		piov_del(piov, alloc);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_cipher *
pac_cipher(const struct silofs_pack_ctx *pa_ctx)
{
	return &pa_ctx->cryp.ci;
}

static int pac_encrypt_bk(const struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_block *bk,
                          struct silofs_block *enc_bk)
{
	const struct silofs_cipher *ci = pac_cipher(pa_ctx);
	const size_t enc_sz = sizeof(*enc_bk);

	return silofs_encrypt_buf(ci, pa_ctx->kivam, bk, enc_bk, enc_sz);
}

static int pac_decrypt_bk(const struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_block *enc_bk,
                          struct silofs_block *bk)
{
	const struct silofs_cipher *ci = pac_cipher(pa_ctx);
	const size_t dec_sz = sizeof(*bk);

	return silofs_decrypt_buf(ci, pa_ctx->kivam, enc_bk, bk, dec_sz);
}

static int pac_setup_piov_of(const struct silofs_pack_ctx *pa_ctx,
                             struct silofs_unode_info *ui)
{
	return ui_piov_setup(ui, pa_ctx->alloc);
}

static void pac_clear_piov_of(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_unode_info *ui)
{
	ui_piov_clear(ui, pa_ctx->alloc);
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

static int pac_init_tmp_bk(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_block *bk;

	bk = silofs_allocate(pa_ctx->alloc, sizeof(*bk));
	if (bk == NULL) {
		return -ENOMEM;
	}
	silofs_memzero(bk, sizeof(*bk));
	pa_ctx->tbk = bk;
	return 0;
}

static void pac_fini_tmp_bk(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_block *bk = pa_ctx->tbk;

	if (bk != NULL) {
		silofs_memzero(bk, sizeof(*bk));
		silofs_deallocate(pa_ctx->alloc, bk, sizeof(*bk));
		pa_ctx->tbk = NULL;
	}
}

static int pac_init_piov(struct silofs_pack_ctx *pa_ctx)
{
	pa_ctx->piov = piov_new(pa_ctx->alloc);
	return (pa_ctx->piov != NULL) ? 0 : -ENOMEM;
}

static void pac_fini_piov(struct silofs_pack_ctx *pa_ctx)
{
	if (pa_ctx->piov != NULL) {
		piov_del(pa_ctx->piov, pa_ctx->alloc);
		pa_ctx->piov = NULL;
	}
}

static int pac_init_crypto(struct silofs_pack_ctx *pa_ctx)
{
	return silofs_crypto_init(&pa_ctx->cryp);
}

static void pac_fini_crypto(struct silofs_pack_ctx *pa_ctx)
{
	silofs_crypto_fini(&pa_ctx->cryp);
}

static void pac_setup_dst_bsec(struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_bootsec *src_bsec = pa_ctx->src_bsec;
	struct silofs_bootsec *dst_bsec = pa_ctx->dst_bsec;

	silofs_bootsec_init(dst_bsec);
	silofs_bootsec_set_uaddr(dst_bsec, &src_bsec->sb_uaddr);
}

static void pac_bind_to(struct silofs_pack_ctx *pa_ctx,
                        struct silofs_sb_info *sbi,
                        struct silofs_spstats_info *spi)
{
	if (pa_ctx->sbi != NULL) {
		silofs_sbi_bind_stats(pa_ctx->sbi, NULL);
		silofs_sbi_decref(pa_ctx->sbi);
		pa_ctx->sbi = NULL;
	}
	if (sbi != NULL) {
		silofs_sbi_bind_stats(sbi, spi);
		silofs_sbi_incref(sbi);
		pa_ctx->sbi = sbi;
	}
}

static int pac_start(struct silofs_pack_ctx *pa_ctx)
{
	int err;

	pac_uil_init(pa_ctx);
	pac_bind_to(pa_ctx, NULL, NULL);
	err = pac_init_tmp_bk(pa_ctx);
	if (err) {
		goto out_err;
	}
	err = pac_init_piov(pa_ctx);
	if (err) {
		goto out_err;
	}
	err = pac_init_crypto(pa_ctx);
	if (err) {
		goto out_err;
	}
	pac_setup_dst_bsec(pa_ctx);
	return 0;
out_err:
	pac_fini_tmp_bk(pa_ctx);
	pac_fini_piov(pa_ctx);
	return err;
}

static void pac_cleanup(struct silofs_pack_ctx *pa_ctx)
{
	pac_bind_to(pa_ctx, NULL, NULL);
	pac_fini_crypto(pa_ctx);
	pac_fini_piov(pa_ctx);
	pac_fini_tmp_bk(pa_ctx);
	pac_uil_clear(pa_ctx);
	pac_uil_fini(pa_ctx);
	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *pac_src_repo(const struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_repo *repo;

	if (pa_ctx->pack) {
		repo = &pa_ctx->uber->ub_repos->repo_warm;
	} else {
		repo = &pa_ctx->uber->ub_repos->repo_cold;
	}
	return repo;
}

static struct silofs_repo *pac_dst_repo(const struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_repo *repo;

	if (pa_ctx->pack) {
		repo = &pa_ctx->uber->ub_repos->repo_cold;
	} else {
		repo = &pa_ctx->uber->ub_repos->repo_warm;
	}
	return repo;
}

static const struct silofs_mdigest *
pac_mdigest(const struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_repo *repo = pac_src_repo(pa_ctx);

	return &repo->re_bootldr.btl_md;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pac_seal_meta_of(const struct silofs_pack_ctx *pa_ctx,
                             const struct silofs_unode_info *ui)
{
	silofs_unused(pa_ctx);
	silofs_fill_csum_meta(ui->u_si.s_view);
}

static int pac_verify_meta_of(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_unode_info *ui)
{
	silofs_unused(pa_ctx);
	return silofs_verify_csum_meta(ui->u_si.s_view);
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

	silofs_assert_lt(slot, SILOFS_NBK_IN_BLOB_MAX);

	silofs_bkaddr_setup(&bkaddr, blobid, (silofs_lba_t)slot);
	return silofs_repo_stage_ubk(repo, &bkaddr, out_ubi);
}

static int pac_require_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubi)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	const struct silofs_blobid *blobid = &bkaddr->blobid;
	struct silofs_blob_info *bli = NULL;
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(repo, blobid, &bli);
		if (err) {
			return err;
		}
		bli_incref(bli);
		err = silofs_repo_stage_ubk(repo, bkaddr, out_ubi);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, &bli);
		if (err) {
			return err;
		}
		bli_incref(bli);
		err = silofs_repo_spawn_ubk(repo, bkaddr, out_ubi);
	}
	bli_decref(bli);
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

static int bli_save_iov(const struct silofs_blob_info *bli, loff_t off_base,
                        const struct iovec *iov, size_t niovs)
{
	const struct iovec *itr = iov;
	const struct iovec *end = iov + niovs;
	loff_t off = off_base;
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
	err = bli_save_iov(bli, 0, iov, cnt);
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

static int pac_resolve_save_blob(const struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_pack_iovs *piov,
                                 struct silofs_packid *out_packid)
{
	pac_resolve_packid(pa_ctx, piov, out_packid);
	return pac_save_blob_of(pa_ctx, &out_packid->blobid, piov);
}

static int pac_require_blob_of(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_blobid *blobid,
                               struct silofs_blob_info **out_bli)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);

	return silofs_repo_require_blob(repo, blobid, out_bli);
}

static int pac_repack_unode(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_pack_iovs *piov, size_t slot,
                            const struct silofs_unode_info *ui)
{
	struct silofs_block *enc_bk = pa_ctx->tbk;
	int err;

	pac_seal_meta_of(pa_ctx, ui);
	err = pac_encrypt_bk(pa_ctx, ui_block(ui), enc_bk);
	if (err) {
		return err;
	}
	err = piov_add_bk(piov, slot, enc_bk);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_unode(struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_unode_info *ui)
{
	struct silofs_blob_info *bli = NULL;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	struct iovec iov = {
		.iov_base = ui->u_si.s_view,
		.iov_len = uaddr->oaddr.len,
	};
	int err;

	err = pac_require_blob_of(pa_ctx, blobid_of(uaddr), &bli);
	if (err) {
		return err;
	}
	err = bli_save_iov(bli, uaddr->oaddr.pos, &iov, 1);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_archive_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli,
                                  loff_t voff, size_t slot)
{
	struct silofs_uaddr uaddr;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_block *enc_bk = NULL;
	size_t nalloc;
	int err;

	nalloc = silofs_sli_nallocated_at(sli, off_to_lba(voff));
	if (!nalloc) {
		goto out;
	}
	err = silofs_sli_subref_of(sli, voff, &uaddr);
	if (err) {
		return err;
	}
	err = pac_stage_block(pa_ctx, blobid_of(&uaddr), slot, &ubi);
	if (err) {
		return err;
	}
	enc_bk = pa_ctx->tbk;
	err = pac_encrypt_bk(pa_ctx, ubi->ubk, enc_bk);
	if (err) {
		return err;
	}
out:
	return sli_pack_bk(sli, slot, enc_bk);
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
	const struct silofs_unode_info *ui = &sli->sl_ui;
	int err;

	err = pac_resolve_save_blob(pa_ctx, ui->u_piov, &packid);
	if (!err) {
		silofs_sli_bind_main_pack(sli, &packid);
		err = pac_repack_unode(pa_ctx, sni->sn_ui.u_piov, slot, ui);
	}
	return err;
}

static int
pac_post_archive_spnode2(struct silofs_pack_ctx *pa_ctx,
                         struct silofs_spnode_info *parent,
                         struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_unode_info *ui = &sni->sn_ui;
	int err;

	err = pac_resolve_save_blob(pa_ctx, ui->u_piov, &packid);
	if (!err) {
		silofs_sni_bind_main_pack(sni, &packid);
		err = pac_repack_unode(pa_ctx, parent->sn_ui.u_piov, slot, ui);
	}
	return err;
}

static int
pac_post_archive_spnode3(struct silofs_pack_ctx *pa_ctx,
                         struct silofs_spnode_info *parent,
                         struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_unode_info *ui = &sni->sn_ui;
	int err;

	err = pac_resolve_save_blob(pa_ctx, ui->u_piov, &packid);
	if (!err) {
		silofs_sni_bind_main_pack(sni, &packid);
		err = pac_repack_unode(pa_ctx, parent->sn_ui.u_piov, slot, ui);
	}
	return err;
}

static int
pac_post_archive_spnode4(struct silofs_pack_ctx *pa_ctx,
                         struct silofs_sb_info *sbi,
                         struct silofs_spnode_info *sni, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_unode_info *ui = &sni->sn_ui;
	int err;

	err = pac_resolve_save_blob(pa_ctx, ui->u_piov, &packid);
	if (!err) {
		silofs_sni_bind_main_pack(sni, &packid);
		err = pac_repack_unode(pa_ctx, sbi->sb_ui.u_piov, slot, ui);
	}
	return err;
}

static int pac_post_archive_stats(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spstats_info *spi, size_t slot)
{
	silofs_assert_eq(slot, 1);
	return pac_repack_unode(pa_ctx, pa_ctx->piov, slot, &spi->sp_ui);
}

static int pac_post_archive_super(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_sb_info *sbi, size_t slot)
{
	struct silofs_packid packid;
	const struct silofs_unode_info *ui = &sbi->sb_ui;
	int err;

	silofs_assert_eq(slot, 0);
	err = pac_resolve_save_blob(pa_ctx, ui->u_piov, &packid);
	if (!err) {
		silofs_sbi_bind_main_pack(sbi, &packid);
		err = pac_repack_unode(pa_ctx, pa_ctx->piov, 0, ui);
	}
	return err;
}

static int pac_post_archive(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_uiterator *uit)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spstats_info *spi = NULL;
	struct silofs_spnode_info *sni4 = NULL;
	struct silofs_spnode_info *sni3 = NULL;
	struct silofs_spnode_info *sni2 = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const size_t slot = uit->slot;
	int err = 0;

	if (ui_isspleaf(uit->ui)) {
		sni2 = sni_from_ui(uit->parent);
		sli = sli_from_ui(uit->ui);
		err = pac_post_archive_spleaf(pa_ctx, sni2, sli, slot);
	} else if (ui_isspnode2(uit->ui)) {
		sni3 = sni_from_ui(uit->parent);
		sni2 = sni_from_ui(uit->ui);
		err = pac_post_archive_spnode2(pa_ctx, sni3, sni2, slot);
	} else if (ui_isspnode3(uit->ui)) {
		sni4 = sni_from_ui(uit->parent);
		sni3 = sni_from_ui(uit->ui);
		err = pac_post_archive_spnode3(pa_ctx, sni4, sni3, slot);
	} else if (ui_isspnode4(uit->ui)) {
		sbi = sbi_from_ui(uit->parent);
		sni4 = sni_from_ui(uit->ui);
		err = pac_post_archive_spnode4(pa_ctx, sbi, sni4, slot);
	} else if (ui_isstats(uit->ui)) {
		spi = spi_from_ui(uit->ui);
		err = pac_post_archive_stats(pa_ctx, spi, slot);
	} else if (ui_issuper(uit->ui)) {
		sbi = sbi_from_ui(uit->ui);
		err = pac_post_archive_super(pa_ctx, sbi, slot);
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

static void pac_update_dst_bootsec(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_hash256 hash;
	const struct silofs_sb_info *sbi = pa_ctx->sbi;
	const struct silofs_mdigest *md = pac_mdigest(pa_ctx);

	silofs_bootsec_set_uaddr(pa_ctx->dst_bsec, sbi_uaddr(sbi));
	if (pa_ctx->pack) {
		silofs_calc_key_hash(&pa_ctx->kivam->key, md, &hash);
		silofs_bootsec_set_keyhash(pa_ctx->dst_bsec, &hash);
	} else {
		silofs_bootsec_clear_keyhash(pa_ctx->dst_bsec);
	}
}

static int pac_stage_super(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_fs_uber *uber = pa_ctx->uber;
	int err;

	err = silofs_stage_super_at(uber, pa_ctx->pack, uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(*out_sbi, uber);
	return 0;
}

static int pac_stage_stats(const struct silofs_pack_ctx *pa_ctx,
                           struct silofs_sb_info *sbi,
                           struct silofs_spstats_info **out_spi)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	struct silofs_fs_uber *uber = pa_ctx->uber;
	int err;

	sbi_incref(sbi);
	err = silofs_sbi_stats_uaddr(sbi, &uaddr);
	if (err) {
		goto out;
	}
	err = silofs_stage_stats_at(uber, pa_ctx->pack, &uaddr, out_spi);
	if (err) {
		goto out;
	}
	silofs_spi_bind_uber(*out_spi, uber);
out:
	sbi_decref(sbi);
	return err;
}

static int pac_stage_supers(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spstats_info *spi = NULL;
	const struct silofs_bootsec *bsec = pa_ctx->src_bsec;
	int err;

	err = pac_stage_super(pa_ctx, &bsec->sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	err = pac_stage_stats(pa_ctx, sbi, &spi);
	if (err) {
		return err;
	}
	pac_bind_to(pa_ctx, sbi, spi);
	return 0;
}

static int pac_refill_view_of(struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_block *bk,
                              struct silofs_unode_info *ui)
{
	struct silofs_block *ubk = ui->u_ubi->ubk;
	int err;

	memcpy(ubk, bk, sizeof(*ubk));
	err = pac_verify_meta_of(pa_ctx, ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_refill_unode(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_packid *packid,
                            size_t slot, struct silofs_unode_info *ui)
{
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_block *bk = pa_ctx->tbk;
	int err;

	ui_incref(ui);
	err = pac_stage_block(pa_ctx, &packid->blobid, slot, &ubi);
	if (err) {
		goto out;
	}
	err = pac_decrypt_bk(pa_ctx, ubi->ubk, bk);
	if (err) {
		goto out;
	}
	err = pac_refill_view_of(pa_ctx, bk, ui);
	if (err) {
		goto out;
	}
	silofs_ui_bind_uber(ui, pa_ctx->uber);
out:
	ui_decref(ui);
	return err;
}

static int pac_shadow_super(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_sb_info **out_sbi)
{
	struct silofs_fs_uber *uber = pa_ctx->uber;
	const struct silofs_bootsec *bsec = pa_ctx->src_bsec;
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_shadow_super_at(uber, pa_ctx->pack,
	                             &bsec->sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &bsec->sb_packid, 0, &sbi->sb_ui);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(sbi, uber);
	*out_sbi = sbi;
	return 0;
}

static int pac_shadow_stats(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_sb_info *sbi,
                            struct silofs_spstats_info **out_spi)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	struct silofs_fs_uber *uber = pa_ctx->uber;
	const struct silofs_bootsec *bsec = pa_ctx->src_bsec;
	struct silofs_spstats_info *spi = NULL;
	int err;

	sbi_incref(sbi);
	err = silofs_sbi_stats_uaddr(sbi, &uaddr);
	if (err) {
		goto out;
	}
	err = silofs_shadow_stats_at(uber, pa_ctx->pack, &uaddr, &spi);
	if (err) {
		goto out;
	}
	err = pac_refill_unode(pa_ctx, &bsec->sb_packid, 1, &spi->sp_ui);
	if (err) {
		return err;
	}
	silofs_spi_bind_uber(spi, uber);
out:
	sbi_decref(sbi);
	*out_spi = spi;
	return err;
}

static int pac_shadow_supers(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spstats_info *spi = NULL;
	int err;

	err = pac_shadow_super(pa_ctx, &sbi);
	if (err) {
		return err;
	}
	err = pac_shadow_stats(pa_ctx, sbi, &spi);
	if (err) {
		return err;
	}
	pac_bind_to(pa_ctx, sbi, spi);
	return 0;
}

static int pac_load_supers(struct silofs_pack_ctx *pa_ctx)
{
	int ret;

	if (pa_ctx->pack) {
		ret = pac_stage_supers(pa_ctx);
	} else {
		ret = pac_shadow_supers(pa_ctx);
	}
	return ret;
}

static int pac_save_supers_as_pack(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_packid packid;
	int err;

	err = pac_resolve_save_blob(pa_ctx, pa_ctx->piov, &packid);
	if (err) {
		return err;
	}
	silofs_bootsec_set_packid(pa_ctx->dst_bsec, &packid);
	return 0;
}

static int pac_save_stats_as_unpack(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_spstats_info *spi = pa_ctx->sbi->sb_spi;
	int err;

	pac_seal_meta_of(pa_ctx, &spi->sp_ui);
	err = pac_save_unode(pa_ctx, &spi->sp_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_super_as_unpack(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = pa_ctx->sbi;

	pac_seal_meta_of(pa_ctx, &sbi->sb_ui);
	return pac_save_unode(pa_ctx, &sbi->sb_ui);
}

static int pac_save_supers_as_unpack(struct silofs_pack_ctx *pa_ctx)
{
	int err;

	err = pac_save_stats_as_unpack(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_save_super_as_unpack(pa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_supers(struct silofs_pack_ctx *pa_ctx)
{
	int ret;

	if (pa_ctx->pack) {
		ret = pac_save_supers_as_pack(pa_ctx);
	} else {
		ret = pac_save_supers_as_unpack(pa_ctx);
	}
	return ret;
}

static int pac_traverse_fs(struct silofs_pack_ctx *pa_ctx)
{
	return silofs_walk_space_tree(pa_ctx->sbi, &pa_ctx->vis);
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

int silofs_uber_pack_fs(struct silofs_fs_uber *uber,
                        const struct silofs_kivam *kivam,
                        const struct silofs_bootsec *src_bsec,
                        struct silofs_bootsec *dst_bsec)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.visit_prep_hook =  pack_visit_prep,
		.vis.visit_exec_hook = pack_visit_exec,
		.vis.visit_post_hook = pack_visit_post,
		.kivam = kivam,
		.src_bsec = src_bsec,
		.dst_bsec = dst_bsec,
		.uber = uber,
		.alloc = uber->ub_alloc,
		.sbi = NULL,
		.pack = true,
	};
	int err;

	err = pac_start(&pa_ctx);
	if (err) {
		return err;
	}
	err = pac_load_supers(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_traverse_fs(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_save_supers(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_restore_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli,
                                  loff_t voff, size_t slot)
{
	struct silofs_uaddr uaddr;
	struct silofs_packid packid;
	struct silofs_blob_info *bli = NULL;
	struct silofs_ubk_info *ubi_src = NULL;
	struct silofs_ubk_info *ubi_dst = NULL;
	const struct silofs_bkaddr *bkaddr = &uaddr.oaddr.bka;
	size_t nalloc;
	int err;

	err = silofs_sli_subref_of(sli, voff, &uaddr);
	if (err) {
		return err;
	}
	err = pac_require_blob_of(pa_ctx, blobid_of(&uaddr), &bli);
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

static int pac_reload_by_spnode4(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni,
                                 loff_t voff, size_t slot)
{
	struct silofs_uaddr uaddr;
	struct silofs_packid packid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spnode_info *sni_child = NULL;
	int err;

	err = silofs_sni_main_pack(sni, &packid);
	if (err) {
		return err;
	}
	err = silofs_sni_subref_of(sni, voff, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_shadow_spnode_at(uber, pa_ctx->pack, &uaddr, &sni_child);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &packid, slot, &sni_child->sn_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_spnode3(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni,
                                 loff_t voff, size_t slot)
{
	struct silofs_uaddr uaddr;
	struct silofs_packid packid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spnode_info *sni_child = NULL;
	int err;

	err = silofs_sni_main_pack(sni, &packid);
	if (err) {
		return err;
	}
	err = silofs_sni_subref_of(sni, voff, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_shadow_spnode_at(uber, pa_ctx->pack, &uaddr, &sni_child);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &packid, slot, &sni_child->sn_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_spnode2(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni,
                                 loff_t voff, size_t slot)
{
	struct silofs_uaddr uaddr;
	struct silofs_packid packid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_main_pack(sni, &packid);
	if (err) {
		return err;
	}
	err = silofs_sni_subref_of(sni, voff, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_shadow_spleaf_at(uber, pa_ctx->pack, &uaddr, &sli);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &packid, slot, &sli->sl_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_super(struct silofs_pack_ctx *pa_ctx,
                               struct silofs_sb_info *sbi,
                               loff_t voff, size_t slot)
{
	struct silofs_uaddr uaddr;
	struct silofs_packid packid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spnode_info *sni = NULL;
	int err;

	if ((voff != 0) || (slot != 0)) {
		return -EFSCORRUPTED; /* TODO: other err */
	}
	err = silofs_sbi_main_pack(sbi, &packid);
	if (err) {
		return err;
	}
	err = silofs_sbi_sproot_uaddr(sbi, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_shadow_spnode_at(uber, pa_ctx->pack, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &packid, slot, &sni->sn_ui);
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
	} else if (ui_isspnode4(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_spnode4(pa_ctx, sni, voff, slot);
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

int silofs_uber_unpack_fs(struct silofs_fs_uber *uber,
                          const struct silofs_kivam *kivam,
                          const struct silofs_bootsec *src_bsec,
                          struct silofs_bootsec *dst_bsec)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.visit_prep_hook = unpack_visit_prep,
		.vis.visit_exec_hook = unpack_visit_exec,
		.vis.visit_post_hook = unpack_visit_post,
		.kivam = kivam,
		.src_bsec = src_bsec,
		.dst_bsec = dst_bsec,
		.uber = uber,
		.alloc = uber->ub_alloc,
		.sbi = NULL,
		.pack = false,
	};
	int err;

	err = pac_start(&pa_ctx);
	if (err) {
		return err;
	}
	err = pac_load_supers(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_traverse_fs(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_save_supers(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}


