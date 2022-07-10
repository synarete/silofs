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

union silofs_pack_qelem_u {
	struct silofs_sb_info          *sbi;
	struct silofs_spstats_info     *spsti;
	struct silofs_spnode_info      *sni;
	struct silofs_spleaf_info      *sli;
	struct silofs_ubk_info         *ubki;
	void *ptr;
};

struct silofs_pack_qelem {
	struct silofs_list_head         pqe_lh;
	union silofs_pack_qelem_u       pqe_u;
	struct silofs_cache_elem       *pqe_ce_ref;
	struct silofs_ubk_info         *pqe_ubki;
	enum silofs_stype               pqe_stype;
};

struct silofs_pack_queues {
	struct silofs_alloc            *alloc;
	struct silofs_listq             pq[SILOFS_HEIGHT_LAST];
};


struct silofs_pack_iovs {
	struct iovec                    pi_iov[SILOFS_SPNODE_NCHILDS];
	struct silofs_alloc            *pi_alloc;
	size_t                          pi_cnt;
};

struct silofs_pack_ctx {
	struct silofs_visitor           vis;
	struct silofs_pack_queues       pqs;
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
	enum silofs_stype               vspace;
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

static void piov_unset_at(struct silofs_pack_iovs *piov,
                          struct silofs_alloc *alloc, size_t slot)
{
	struct iovec *iov = piov_iovec_at(piov, slot);

	if (iov->iov_base != NULL) {
		silofs_deallocate(alloc, iov->iov_base, iov->iov_len);
		iov->iov_base = NULL;
	}
	iov->iov_len = 0;
}

static int piov_add_bk(struct silofs_pack_iovs *piov, size_t slot,
                       const struct silofs_block *bk)
{
	return piov_set_at(piov, slot, bk, sizeof(*bk));
}

static void piov_clear(struct silofs_pack_iovs *piov,
                       struct silofs_alloc *alloc)
{
	for (size_t slot = 0; slot < piov->pi_cnt; ++slot) {
		piov_unset_at(piov, alloc, slot);
	}
	piov->pi_cnt = 0;
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
	piov_clear(piov, alloc);
	piov_fini(piov);
	silofs_deallocate(alloc, piov, sizeof(*piov));
}

static void piov_calc_blobid(const struct silofs_pack_iovs *piov,
                             const struct silofs_mdigest *md,
                             struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;
	const size_t cnt = ARRAY_SIZE(piov->pi_iov);
	const size_t len = cnt * SILOFS_BK_SIZE;

	silofs_sha256_ofv(md, piov->pi_iov, cnt, &hash);
	silofs_blobid_make_ca(out_blobid, &hash, len);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_pack_qelem *
qpe_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_pack_qelem *pqe;

	pqe = container_of2(lh, struct silofs_pack_qelem, pqe_lh);
	return unconst(pqe);
}

static void pqe_init(struct silofs_pack_qelem *pqe,
                     struct silofs_cache_elem *ce_ref,
                     enum silofs_stype stype)
{
	list_head_init(&pqe->pqe_lh);
	pqe->pqe_u.ptr = NULL;
	pqe->pqe_ce_ref = ce_ref;
	pqe->pqe_ubki = NULL;
	pqe->pqe_stype = stype;
	silofs_ce_incref(pqe->pqe_ce_ref);
}

static void pqe_fini(struct silofs_pack_qelem *pqe)
{
	silofs_ce_decref(pqe->pqe_ce_ref);
	list_head_fini(&pqe->pqe_lh);
	pqe->pqe_u.ptr = NULL;
	pqe->pqe_ce_ref = NULL;
	pqe->pqe_ubki = NULL;
	pqe->pqe_stype = SILOFS_STYPE_NONE;
}

static struct silofs_pack_qelem *
pqe_new(struct silofs_alloc *alloc,
        struct silofs_cache_elem *ce_ref, enum silofs_stype stype)
{
	struct silofs_pack_qelem *pqe = NULL;

	pqe = silofs_allocate(alloc, sizeof(*pqe));
	if (pqe != NULL) {
		pqe_init(pqe, ce_ref, stype);
	}
	return pqe;
}

static void pqe_del(struct silofs_pack_qelem *pqe, struct silofs_alloc *alloc)
{
	pqe_fini(pqe);
	silofs_deallocate(alloc, pqe, sizeof(*pqe));
}

static struct silofs_pack_qelem *
pqe_new_for_ubk(struct silofs_alloc *alloc, struct silofs_ubk_info *ubki)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new(alloc, &ubki->ubk_ce, SILOFS_STYPE_ANONBK);
	if (pqe != NULL) {
		pqe->pqe_u.ubki = ubki;
		pqe->pqe_ubki = ubki;
	}
	return pqe;
}

static struct silofs_pack_qelem *
pqe_new_for_spleaf(struct silofs_alloc *alloc, struct silofs_spleaf_info *sli)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new(alloc, &sli->sl_ui.u_si.s_ce, SILOFS_STYPE_SPLEAF);
	if (pqe != NULL) {
		pqe->pqe_u.sli = sli;
		pqe->pqe_ubki = sli->sl_ui.u_ubki;
	}
	return pqe;
}

static struct silofs_pack_qelem *
pqe_new_for_spnode(struct silofs_alloc *alloc, struct silofs_spnode_info *sni)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new(alloc, &sni->sn_ui.u_si.s_ce, SILOFS_STYPE_SPNODE);
	if (pqe != NULL) {
		pqe->pqe_u.sni = sni;
		pqe->pqe_ubki = sni->sn_ui.u_ubki;
	}
	return pqe;
}

static struct silofs_pack_qelem *
pqe_new_for_super(struct silofs_alloc *alloc, struct silofs_sb_info *sbi)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new(alloc, &sbi->sb_ui.u_si.s_ce, SILOFS_STYPE_SUPER);
	if (pqe != NULL) {
		pqe->pqe_u.sbi = sbi;
		pqe->pqe_ubki = sbi->sb_ui.u_ubki;
	}
	return pqe;
}

static silofs_lba_t pqe_lba(const struct silofs_pack_qelem *pqe)
{
	return pqe->pqe_ubki->ubk_addr.lba;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pqs_init(struct silofs_pack_queues *pqs,
                     struct silofs_alloc *alloc)
{
	pqs->alloc = alloc;
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pq); ++i) {
		listq_init(&pqs->pq[i]);
	}
}

static void pqs_fini(struct silofs_pack_queues *pqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pq); ++i) {
		listq_fini(&pqs->pq[i]);
	}
	pqs->alloc = NULL;
}

static void pqs_clear_at(struct silofs_pack_queues *pqs,
                         struct silofs_listq *pq)
{
	struct silofs_list_head *lh;
	struct silofs_pack_qelem *pqe;

	lh = listq_pop_front(pq);
	while (lh != NULL) {
		pqe = qpe_from_lh(lh);
		pqe_del(pqe, pqs->alloc);
		lh = listq_pop_front(pq);
	}
}

static struct silofs_listq *
pqs_queue_of(const struct silofs_pack_queues *pqs, enum silofs_height height)
{
	const struct silofs_listq *lq = &pqs->pq[height];

	silofs_assert_ge(height, 0);
	silofs_assert_lt(height, SILOFS_HEIGHT_LAST);
	silofs_assert_lt(height, ARRAY_SIZE(pqs->pq));

	return unconst(lq);
}

static void pqs_insert_by(struct silofs_pack_queues *pqs,
                          struct silofs_pack_qelem *pqe,
                          enum silofs_height height)
{
	struct silofs_listq *lq = pqs_queue_of(pqs, height);

	listq_push_back(lq, &pqe->pqe_lh);
}

static int pqs_insert_ubk(struct silofs_pack_queues *pqs,
                          struct silofs_ubk_info *ubki)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new_for_ubk(pqs->alloc, ubki);
	if (pqe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_by(pqs, pqe, SILOFS_HEIGHT_VDATA);
	return 0;
}

static int pqs_insert_spleaf(struct silofs_pack_queues *pqs,
                             struct silofs_spleaf_info *sli)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new_for_spleaf(pqs->alloc, sli);
	if (pqe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_by(pqs, pqe, SILOFS_HEIGHT_SPLEAF);
	return 0;
}

static int pqs_insert_spnode(struct silofs_pack_queues *pqs,
                             struct silofs_spnode_info *sni,
                             enum silofs_height height)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new_for_spnode(pqs->alloc, sni);
	if (pqe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_by(pqs, pqe, height);
	return 0;
}

static int pqs_insert_super(struct silofs_pack_queues *pqs,
                            struct silofs_sb_info *sbi)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new_for_super(pqs->alloc, sbi);
	if (pqe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_by(pqs, pqe, SILOFS_HEIGHT_SUPER);
	return 0;
}

static void pqs_clear_by(struct silofs_pack_queues *pqs,
                         enum silofs_height height)
{
	pqs_clear_at(pqs, pqs_queue_of(pqs, height));
}

static void pqs_clear_ubks(struct silofs_pack_queues *pqs)
{
	pqs_clear_by(pqs, SILOFS_HEIGHT_VDATA);
}

static void pqs_clear_spleafs(struct silofs_pack_queues *pqs)
{
	pqs_clear_by(pqs, SILOFS_HEIGHT_SPLEAF);
}

static void pqs_clear_spnodes2(struct silofs_pack_queues *pqs)
{
	pqs_clear_by(pqs, SILOFS_HEIGHT_SPNODE2);
}

static void pqs_clear_spnodes3(struct silofs_pack_queues *pqs)
{
	pqs_clear_by(pqs, SILOFS_HEIGHT_SPNODE3);
}

static void pqs_clear_spnodes4(struct silofs_pack_queues *pqs)
{
	pqs_clear_by(pqs, SILOFS_HEIGHT_SPNODE4);
}

static void pqs_clear_all(struct silofs_pack_queues *pqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pq); ++i) {
		pqs_clear_at(pqs, &pqs->pq[i]);
	}
}

static struct silofs_block *
new_enc_ubk(struct silofs_alloc *alloc, const struct silofs_cipher *cipher,
            const struct silofs_kivam *kivam, const struct silofs_block *ubk)
{
	struct silofs_block *enc_ubk = NULL;
	const size_t bk_size = sizeof(*enc_ubk);

	enc_ubk = silofs_allocate(alloc, bk_size);
	if (enc_ubk == NULL) {
		return NULL;
	}
	silofs_encrypt_buf(cipher, kivam, ubk, enc_ubk, bk_size);
	return enc_ubk;
}

static int pqs_make_enc_piov(struct silofs_pack_queues *pqs,
                             struct silofs_alloc *alloc,
                             const struct silofs_cipher *cipher,
                             const struct silofs_kivam *kivam,
                             enum silofs_height height,
                             struct silofs_pack_iovs *piov)
{
	const struct silofs_list_head *lh;
	const struct silofs_pack_qelem *pqe;
	const struct silofs_block *ubk = NULL;
	struct silofs_block *enc_ubk = NULL;
	const struct silofs_listq *pq = pqs_queue_of(pqs, height);
	struct iovec *iov;
	size_t slot;

	silofs_assert_le(pq->sz, ARRAY_SIZE(piov->pi_iov));

	for (lh = listq_front(pq); lh != NULL; lh = listq_next(pq, lh)) {
		pqe = qpe_from_lh(lh);
		ubk = pqe->pqe_ubki->ubk;
		enc_ubk = new_enc_ubk(alloc, cipher, kivam, ubk);
		if (enc_ubk == NULL) {
			piov_clear(piov, pqs->alloc);
			return -ENOMEM;
		}

		slot = (size_t)pqe_lba(pqe) % ARRAY_SIZE(piov->pi_iov);
		silofs_assert_eq(slot, piov->pi_cnt);
		silofs_assert_null(piov->pi_iov[slot].iov_base);

		iov = piov_iovec_at(piov, slot);
		iov->iov_base = enc_ubk;
		iov->iov_len = sizeof(*enc_ubk);
		piov->pi_cnt++;
	}
	return 0;
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

static struct silofs_spnode_info *
sni_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SPNODE));

	return silofs_sni_from_ui(ui);
}

static bool sni_has_height(const struct silofs_spnode_info *sni,
                           enum silofs_height height)
{
	return (silofs_sni_height(sni) == height);
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

static bool ui_issuper(const struct silofs_unode_info *ui)
{
	return stype_issuper(ui_stype(ui));
}

static struct silofs_block *ui_block(const struct silofs_unode_info *ui)
{
	return ui->u_ubki->ubk;
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
                        struct silofs_sb_info *sbi)
{
	if (pa_ctx->sbi != NULL) {
		silofs_sbi_decref(pa_ctx->sbi);
		pa_ctx->sbi = NULL;
	}
	if (sbi != NULL) {
		silofs_sbi_incref(sbi);
		pa_ctx->sbi = sbi;
	}
}

static int pac_start(struct silofs_pack_ctx *pa_ctx)
{
	int err;

	pac_uil_init(pa_ctx);
	pac_bind_to(pa_ctx, NULL);
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
	pqs_init(&pa_ctx->pqs, pa_ctx->alloc);
	return 0;
out_err:
	pac_fini_tmp_bk(pa_ctx);
	pac_fini_piov(pa_ctx);
	return err;
}

static void pac_cleanup(struct silofs_pack_ctx *pa_ctx)
{
	pqs_clear_all(&pa_ctx->pqs);
	pqs_fini(&pa_ctx->pqs);
	pac_bind_to(pa_ctx, NULL);
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
	silofs_blobid_make_ca(out_blobid, &hash, len);
}

static void pac_resolve_blobid_of(const struct silofs_pack_ctx *pa_ctx,
                                  const struct iovec *iov, size_t cnt,
                                  struct silofs_blobid *out_blobid)
{
	pac_calc_cas_blobid(pa_ctx, iov, cnt, out_blobid);
}

static void pac_resolve_blobid(const struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_pack_iovs *piov,
                               struct silofs_blobid *out_blobid)
{
	pac_resolve_blobid_of(pa_ctx, piov->pi_iov, piov->pi_cnt, out_blobid);
}

static int pac_stage_block(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_blobid *blobid, size_t slot,
                           struct silofs_ubk_info **out_ubki)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);

	silofs_assert_lt(slot, SILOFS_NBK_IN_BLOB_MAX);

	silofs_bkaddr_setup(&bkaddr, blobid, (silofs_lba_t)slot);
	return silofs_repo_stage_ubk(repo, &bkaddr, out_ubki);
}

static int pac_require_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki)
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
		err = silofs_repo_stage_ubk(repo, bkaddr, out_ubki);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, &bli);
		if (err) {
			return err;
		}
		bli_incref(bli);
		err = silofs_repo_spawn_ubk(repo, bkaddr, out_ubki);
	}
	bli_decref(bli);
	return err;
}

static int pac_restore_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_ubk_info *ubki_src,
                           const struct silofs_bkaddr *bkaddr_dst)
{
	struct silofs_ubk_info *ubki_dst = NULL;
	int err;

	err = pac_require_ubk(pa_ctx, bkaddr_dst, &ubki_dst);
	if (err) {
		return err;
	}
	err = silofs_bli_store_bk(ubki_dst->ubk_bli, bkaddr_dst, ubki_src->ubk);
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
                                 struct silofs_blobid *out_blobid)
{
	pac_resolve_blobid(pa_ctx, piov, out_blobid);
	return pac_save_blob_of(pa_ctx, out_blobid, piov);
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

static int pac_archive_exec_at_ubk(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_spleaf_info *sli,
                                   loff_t voff, size_t slot)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_ubk_info *ubki = NULL;
	struct silofs_block *enc_bk = NULL;
	size_t nalloc;
	int err;

	nalloc = silofs_sli_nallocated_at(sli, off_to_lba(voff));
	if (!nalloc) {
		goto out;
	}
	err = silofs_sli_resolve_ubk(sli, voff, &bkaddr);
	if (err) {
		return err;
	}
	err = pac_stage_block(pa_ctx, &bkaddr.blobid, slot, &ubki);
	if (err) {
		return err;
	}
	enc_bk = pa_ctx->tbk;
	err = pac_encrypt_bk(pa_ctx, ubki->ubk, enc_bk);
	if (err) {
		return err;
	}
out:
	err = sli_pack_bk(sli, slot, enc_bk);
	if (!err && (ubki != NULL)) {
		err = pqs_insert_ubk(&pa_ctx->pqs, ubki);
	}
	return err;
}

static int pac_archive_exec_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	size_t slot = 0;
	ssize_t span;
	int err;

	silofs_assert_not_null(spit->sli);
	silofs_assert(stype_isspleaf(spit->stype));

	err = pqs_insert_spleaf(&pa_ctx->pqs, spit->sli);
	if (err) {
		return err;
	}

	sli_vrange(spit->sli, &vrange);
	span = silofs_height_to_span(vrange.height - 1);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_archive_exec_at_ubk(pa_ctx, spit->sli, voff, slot);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, span);
		slot++;
	}
	return 0;
}

static int pac_archive_exec_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sni2);
	silofs_assert(stype_isspnode(spit->stype));
	silofs_assert_eq(spit->height, SILOFS_HEIGHT_SPNODE2);

	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni2, spit->height);
}

static int pac_archive_exec_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sni3);
	silofs_assert(stype_isspnode(spit->stype));
	silofs_assert_eq(spit->height, SILOFS_HEIGHT_SPNODE3);

	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni3, spit->height);
}

static int pac_archive_exec_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sni4);
	silofs_assert(stype_isspnode(spit->stype));
	silofs_assert_eq(spit->height, SILOFS_HEIGHT_SPNODE4);

	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni4, spit->height);
}

static int pac_archive_exec_at_sb(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sbi);
	silofs_assert(stype_issuper(spit->stype));
	silofs_assert_eq(spit->height, SILOFS_HEIGHT_SUPER);

	return pqs_insert_super(&pa_ctx->pqs, spit->sbi);
}

static int pac_archive_exec_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	err = pac_setup_piov_of(pa_ctx, spit->ui);
	if (err) {
		goto out;
	}
	pac_uil_insert(pa_ctx, spit->ui);

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_archive_exec_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_archive_exec_at_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_archive_exec_at_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_archive_exec_at_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_archive_exec_at_sb(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EFSCORRUPTED;
		break;
	}
out:
	return err;
}

static int pac_repack_spleaf_at(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_space_iter *spit)
{
	return pac_repack_unode(pa_ctx, spit->sni2->sn_ui.u_piov,
	                        spit->slot, &spit->sli->sl_ui);
}

static int pac_resolve_save_ubks_blob(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_blobid *out_blobid)
{
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;
	struct silofs_pack_iovs *piov;
	int err;

	piov = piov_new(pa_ctx->alloc);
	if (piov == NULL) {
		return -ENOMEM;
	}
	err = pqs_make_enc_piov(pqs, pa_ctx->alloc, pac_cipher(pa_ctx),
	                        pa_ctx->kivam, SILOFS_HEIGHT_VDATA, piov);
	if (err) {
		goto out;
	}
	piov_calc_blobid(piov, pac_mdigest(pa_ctx), out_blobid);

	err = pac_save_blob_of(pa_ctx, out_blobid, piov);
	if (err) {
		goto out;
	}
out:
	piov_clear(piov, pa_ctx->alloc);
	piov_del(piov, pa_ctx->alloc);
	return err;
}


static int pac_archive_post_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_resolve_save_ubks_blob(pa_ctx, &blobid);
	if (err) {
		return err;
	}
	pqs_clear_ubks(&pa_ctx->pqs);

	silofs_sli_bind_pack_blob(spit->sli, &blobid);

	err = pac_repack_spleaf_at(pa_ctx, spit);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_repack_spnode2_at(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_space_iter *spit)
{
	return pac_repack_unode(pa_ctx, spit->sni3->sn_ui.u_piov,
	                        spit->slot, &spit->sni2->sn_ui);
}

static int pac_archive_post_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	silofs_assert_not_null(spit->sni2);
	silofs_assert(stype_isspnode(spit->stype));

	err = pac_resolve_save_blob(pa_ctx, spit->sni2->sn_ui.u_piov, &blobid);
	if (err) {
		return err;
	}

	silofs_sni_bind_pack_blob(spit->sni2, &blobid);

	err = pac_repack_spnode2_at(pa_ctx, spit);
	if (err) {
		return err;
	}
	pqs_clear_spleafs(&pa_ctx->pqs);
	return 0;
}

static int pac_repack_spnode3_at(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_space_iter *spit)
{
	return pac_repack_unode(pa_ctx, spit->sni4->sn_ui.u_piov,
	                        spit->slot, &spit->sni3->sn_ui);
}

static int pac_archive_post_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	silofs_assert_not_null(spit->sni3);
	silofs_assert(stype_isspnode(spit->stype));

	err = pac_resolve_save_blob(pa_ctx, spit->sni3->sn_ui.u_piov, &blobid);
	if (err) {
		return err;
	}

	silofs_sni_bind_pack_blob(spit->sni3, &blobid);

	err = pac_repack_spnode3_at(pa_ctx, spit);
	if (err) {
		return err;
	}
	pqs_clear_spnodes2(&pa_ctx->pqs);
	return 0;
}

static int pac_repack_spnode4_at(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_space_iter *spit)
{
	const size_t slot = (size_t)spit->vspace; // XXX

	return pac_repack_unode(pa_ctx, spit->sbi->sb_ui.u_piov,
	                        slot, &spit->sni4->sn_ui);
}

static int pac_archive_post_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	silofs_assert_not_null(spit->sni4);
	silofs_assert(stype_isspnode(spit->stype));

	silofs_assert(stype_isvnode(spit->vspace));
	err = pac_resolve_save_blob(pa_ctx, spit->sni4->sn_ui.u_piov, &blobid);
	if (err) {
		return err;
	}

	silofs_sni_bind_pack_blob(spit->sni4, &blobid);

	err = pac_repack_spnode4_at(pa_ctx, spit);
	if (err) {
		return err;
	}
	pqs_clear_spnodes3(&pa_ctx->pqs);
	return 0;
}

static int pac_archive_post_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	const struct silofs_unode_info *ui = &spit->sbi->sb_ui;
	int err;

	silofs_assert_eq(spit->slot, 0);
	err = pac_resolve_save_blob(pa_ctx, ui->u_piov, &blobid);
	if (err) {
		return err;
	}

	silofs_sbi_bind_pack_blob(spit->sbi, spit->vspace, &blobid);

	err = pac_repack_unode(pa_ctx, pa_ctx->piov,
	                       spit->slot, &spit->sbi->sb_ui);
	if (err) {
		return err;
	}
	pqs_clear_spnodes4(&pa_ctx->pqs);
	return 0;
}

static int pac_archive_post_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_archive_post_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_archive_post_at_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_archive_post_at_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_archive_post_at_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_archive_post_at_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EFSCORRUPTED;
		break;
	}

	pac_uil_remove(pa_ctx, spit->ui);

	return err;
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
	int err;

	err = silofs_stage_super_at(pa_ctx->uber, pa_ctx->pack,
	                            uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(*out_sbi, pa_ctx->uber);
	return 0;
}

static int pac_stage_supers(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	const struct silofs_bootsec *bsec = pa_ctx->src_bsec;
	int err;

	err = pac_stage_super(pa_ctx, &bsec->sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	pac_bind_to(pa_ctx, sbi);
	return 0;
}

static int pac_refill_view_of(struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_block *bk,
                              struct silofs_unode_info *ui)
{
	struct silofs_block *ubk = ui->u_ubki->ubk;
	int err;

	memcpy(ubk, bk, sizeof(*ubk));
	err = pac_verify_meta_of(pa_ctx, ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_refill_unode(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_blobid *blobid,
                            size_t slot, struct silofs_unode_info *ui)
{
	struct silofs_ubk_info *ubki = NULL;
	struct silofs_block *bk = pa_ctx->tbk;
	int err;

	ui_incref(ui);
	err = pac_stage_block(pa_ctx, blobid, slot, &ubki);
	if (err) {
		goto out;
	}
	err = pac_decrypt_bk(pa_ctx, ubki->ubk, bk);
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
	err = pac_refill_unode(pa_ctx, &bsec->sb_blobid, 0, &sbi->sb_ui);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(sbi, uber);
	*out_sbi = sbi;
	return 0;
}

static int pac_shadow_supers(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = pac_shadow_super(pa_ctx, &sbi);
	if (err) {
		return err;
	}
	pac_bind_to(pa_ctx, sbi);
	return 0;
}

static int pac_save_supers_as_pack(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_resolve_save_blob(pa_ctx, pa_ctx->piov, &blobid);
	if (err) {
		return err;
	}
	silofs_bootsec_set_blobid(pa_ctx->dst_bsec, &blobid);
	return 0;
}

static int pac_save_super_as_unpack(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = pa_ctx->sbi;

	return pac_save_unode(pa_ctx, &sbi->sb_ui);
}

static int pac_save_supers_as_unpack(struct silofs_pack_ctx *pa_ctx)
{
	int err;

	err = pac_save_super_as_unpack(pa_ctx);
	if (err) {
		return err;
	}
	return 0;
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

static int pack_exec_at(struct silofs_visitor *vis,
                        const struct silofs_space_iter *spit)
{
	return pac_archive_exec_at(pack_ctx_of(vis), spit);
}

static int pack_post_at(struct silofs_visitor *vis,
                        const struct silofs_space_iter *spit)
{
	return pac_archive_post_at(pack_ctx_of(vis), spit);
}

int silofs_uber_pack_fs(struct silofs_fs_uber *uber,
                        const struct silofs_kivam *kivam,
                        const struct silofs_bootsec *src_bsec,
                        struct silofs_bootsec *dst_bsec)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.exec_at_hook = pack_exec_at,
		.vis.post_at_hook = pack_post_at,
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
	err = pac_stage_supers(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_traverse_fs(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_save_supers_as_pack(&pa_ctx);
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
	struct silofs_bkaddr bkaddr;
	struct silofs_blobid blobid;
	struct silofs_blob_info *bli = NULL;
	struct silofs_ubk_info *ubki_src = NULL;
	struct silofs_ubk_info *ubki_dst = NULL;
	size_t nalloc;
	int err;

	err = silofs_sli_resolve_ubk(sli, voff, &bkaddr);
	if (err) {
		return err;
	}
	err = pac_require_blob_of(pa_ctx, &bkaddr.blobid, &bli);
	if (err) {
		return err;
	}
	nalloc = silofs_sli_nallocated_at(sli, off_to_lba(voff));
	if (!nalloc) {
		return 0;
	}
	err = silofs_sli_pack_blob(sli, &blobid);
	if (err) {
		return err;
	}
	err = pac_stage_block(pa_ctx, &blobid, slot, &ubki_src);
	if (err) {
		return err;
	}
	err = pac_require_ubk(pa_ctx, &bkaddr, &ubki_dst);
	if (err) {
		return err;
	}
	err = pac_decrypt_bk(pa_ctx, ubki_src->ubk, ubki_dst->ubk);
	if (err) {
		return err;
	}
	err = silofs_bli_store_bk(ubki_dst->ubk_bli, &bkaddr, ubki_dst->ubk);
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
	ssize_t span;
	int err;

	sli_vrange(sli, &vrange);
	span = silofs_height_to_span(vrange.height - 1);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_restore_spleaf_sub(pa_ctx, sli, voff, slot);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, span);
		slot++;
	}
	return 0;
}

static int pac_reload_by_spnode4(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid blobid;
	struct silofs_spnode_info *sni_child = NULL;
	int err;

	err = silofs_sni_pack_blob(sni, &blobid);
	if (err) {
		return err;
	}
	err = silofs_sni_subref_of(sni, voff, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_shadow_spnode_at(pa_ctx->uber, pa_ctx->pack,
	                              &uaddr, &sni_child);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &blobid, sni_slot_of(sni, voff),
	                       &sni_child->sn_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_spnode3(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid blobid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spnode_info *sni_child = NULL;
	int err;

	err = silofs_sni_pack_blob(sni, &blobid);
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
	err = pac_refill_unode(pa_ctx, &blobid, sni_slot_of(sni, voff),
	                       &sni_child->sn_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_spnode2(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid blobid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_pack_blob(sni, &blobid);
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
	err = pac_refill_unode(pa_ctx, &blobid, sni_slot_of(sni, voff),
	                       &sli->sl_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_reload_by_super(struct silofs_pack_ctx *pa_ctx,
                               struct silofs_sb_info *sbi,
                               enum silofs_stype vspace)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid blobid;
	struct silofs_fs_uber *uber = pa_ctx->uber;
	struct silofs_spnode_info *sni = NULL;
	const size_t slot = (size_t)vspace; // XXX assuming block per spnode
	int err;

	if (!stype_isvnode(vspace)) {
		return -SILOFS_EFSCORRUPTED; /* TODO: other err */
	}
	err = silofs_sbi_pack_blobid(sbi, vspace, &blobid);
	if (err) {
		return err;
	}
	err = silofs_sbi_sproot_of(sbi, vspace, &uaddr);
	if (err) {
		return err;
	}
	err = silofs_shadow_spnode_at(uber, pa_ctx->pack, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = pac_refill_unode(pa_ctx, &blobid, slot, &sni->sn_ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	struct silofs_unode_info *parent = spit->parent;
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spnode_info *sni = NULL;
	int ret = 0;

	if (parent == NULL) {
		ret = 0;
	} else if (ui_issuper(parent)) {
		sbi = sbi_from_ui(parent);
		ret = pac_reload_by_super(pa_ctx, sbi, spit->vspace);
	} else if (ui_isspnode4(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_spnode4(pa_ctx, sni, spit->voff);
	} else if (ui_isspnode3(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_spnode3(pa_ctx, sni, spit->voff);
	} else if (ui_isspnode2(parent)) {
		sni = sni_from_ui(parent);
		ret = pac_reload_by_spnode2(pa_ctx, sni, spit->voff);
	}
	return ret;
}

static int pac_restore_exec_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	return spit->sli ? pac_restore_spleaf_subs(pa_ctx, spit->sli) : 0;
}

static int pac_restore_post_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	const struct silofs_unode_info *ui = spit->ui;
	int err;

	err = pac_restore_ubk(pa_ctx, ui->u_ubki, ui_bkaddr(ui));
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unpack_prep_by(struct silofs_visitor *vis,
                          const struct silofs_space_iter *spit)
{
	return pac_restore_prep_by(pack_ctx_of(vis), spit);
}

static int unpack_exec_at(struct silofs_visitor *vis,
                          const struct silofs_space_iter *spit)
{
	return pac_restore_exec_at(pack_ctx_of(vis), spit);
}

static int unpack_post_at(struct silofs_visitor *vis,
                          const struct silofs_space_iter *spit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_restore_post_at(pa_ctx, spit);
}

int silofs_uber_unpack_fs(struct silofs_fs_uber *uber,
                          const struct silofs_kivam *kivam,
                          const struct silofs_bootsec *src_bsec,
                          struct silofs_bootsec *dst_bsec)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.prep_by_hook = unpack_prep_by,
		.vis.exec_at_hook = unpack_exec_at,
		.vis.post_at_hook = unpack_post_at,
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
	err = pac_shadow_supers(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_traverse_fs(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_save_supers_as_unpack(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}


