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



struct silofs_pack_blob {
	struct silofs_blobid            pb_blobid;
	struct silofs_block            *pb_blob;
	size_t                          pb_size_max;
	size_t                          pb_nbks_max;
	size_t                          pb_nbks;
	enum silofs_height              pb_height;
};

struct silofs_pack_qelem {
	struct silofs_list_head         pqe_lh;
	struct silofs_cache_elem       *pqe_ce_ref;
	struct silofs_unode_info       *pqe_ui;
	struct silofs_ubk_info         *pqe_ubki;
	silofs_lba_t                    pqe_vlba;
	enum silofs_stype               pqe_stype;
};

struct silofs_pack_queues {
	struct silofs_alloc            *alloc;
	struct silofs_listq             pq[SILOFS_HEIGHT_LAST];
	struct silofs_pack_blob        *pb[SILOFS_HEIGHT_LAST];
};

struct silofs_pack_ctx {
	struct silofs_visitor           vis;
	struct silofs_pack_queues       pqs;
	struct silofs_crypto            cryp;
	const struct silofs_kivam      *kivam;
	const struct silofs_bootsec    *src_bsec;
	struct silofs_bootsec          *dst_bsec;
	struct silofs_fs_uber          *uber;
	struct silofs_alloc            *alloc;
	struct silofs_sb_info          *sbi;
	struct silofs_block            *tbk;
	enum silofs_stype               vspace;
	bool                            pack;
};

struct silofs_cimdka {
	const struct silofs_cipher     *cipher;
	const struct silofs_mdigest    *mdigest;
	const struct silofs_kivam      *kivam;
	struct silofs_alloc            *alloc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_height ui_height(const struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	return uaddr->height;
}

static bool
sli_has_allocated_at(const struct silofs_spleaf_info *sli, loff_t voff)
{
	const silofs_lba_t vlba = off_to_lba(voff);
	const size_t nalloc = silofs_sli_nallocated_at(sli, vlba);

	return (nalloc > 0);
}

static enum silofs_height sni_height(const struct silofs_spnode_info *sni)
{
	const struct silofs_uaddr *uaddr = sni_uaddr(sni);

	return uaddr->height;
}

static void ubk_copyfrom(struct silofs_block *ubk,
                         const struct silofs_block *ubk_other)
{
	memcpy(ubk, ubk_other, sizeof(*ubk));
}

static void ubk_memzero(struct silofs_block *ubk)
{
	memset(ubk, 0, sizeof(*ubk));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void pblob_init(struct silofs_pack_blob *pb, void *blob,
                       size_t bsz, enum silofs_height height)
{
	blobid_reset(&pb->pb_blobid);
	pb->pb_blob = blob;
	pb->pb_size_max = bsz;
	pb->pb_nbks_max = bsz / SILOFS_BK_SIZE;
	pb->pb_nbks = 0;
	pb->pb_height = height;
}

static void pblob_fini(struct silofs_pack_blob *pb)
{
	blobid_reset(&pb->pb_blobid);
	pb->pb_blob = NULL;
	pb->pb_size_max = 0;
	pb->pb_nbks = 0;
}

static struct silofs_pack_blob *
pblob_new(struct silofs_alloc *alloc, enum silofs_height height)
{
	struct silofs_pack_blob *pb;
	const size_t bsz = SILOFS_BLOB_SIZE_MAX;
	void *blob;

	pb = silofs_allocate(alloc, sizeof(*pb));
	if (pb == NULL) {
		return NULL;
	}
	blob = silofs_allocate(alloc, bsz);
	if (blob == NULL) {
		silofs_deallocate(alloc, pb, sizeof(*pb));
		return NULL;
	}
	pblob_init(pb, blob, bsz, height);
	return pb;
}

static void pblob_del(struct silofs_pack_blob *pb, struct silofs_alloc *alloc)
{
	const size_t bsz = pb->pb_size_max;
	void *blob = pb->pb_blob;

	pblob_fini(pb);
	silofs_deallocate(alloc, blob, bsz);
	silofs_deallocate(alloc, pb, sizeof(*pb));
}

static struct silofs_block *
pblob_ubk_of(const struct silofs_pack_blob *pb, loff_t voff)
{
	const silofs_lba_t vlba = off_to_lba(voff);
	const size_t slot = (size_t)vlba % pb->pb_nbks_max;
	const struct silofs_block *ubk = &pb->pb_blob[slot];

	return unconst(ubk);
}

static size_t pblob_length(const struct silofs_pack_blob *pb)
{
	return pb->pb_nbks * sizeof(pb->pb_blob[0]);
}

static void pblob_set_length(struct silofs_pack_blob *pb, size_t size)
{
	const size_t bk_size = sizeof(pb->pb_blob[0]);

	silofs_assert_le(size, pb->pb_size_max);
	pb->pb_nbks = div_round_up(size, bk_size);
}

static void pblob_blobid(const struct silofs_pack_blob *pb,
                         struct silofs_blobid *out_blobid)
{
	blobid_assign(out_blobid, &pb->pb_blobid);
}

static void pblob_set_blobid(struct silofs_pack_blob *pb,
                             const struct silofs_blobid *blobid)
{
	blobid_assign(&pb->pb_blobid, blobid);
}

static void pblob_calc_blobid(const struct silofs_pack_blob *pb,
                              const struct silofs_mdigest *md,
                              struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;
	const size_t len = pblob_length(pb);

	silofs_sha3_256_of(md, pb->pb_blob, len, &hash);
	silofs_blobid_make_ca(out_blobid, &hash, len);
}

static int pblob_check_blobid(const struct silofs_pack_blob *pb,
                              const struct silofs_mdigest *md)
{
	struct silofs_blobid blobid;
	bool eq;

	pblob_calc_blobid(pb, md, &blobid);
	eq = blobid_isequal(&blobid, &pb->pb_blobid);
	return eq ? 0 : -SILOFS_ECSUM;
}

static void pblob_encrypt(struct silofs_pack_blob *pb,
                          const struct silofs_cimdka *cimdka)
{
	struct silofs_blobid blobid;

	silofs_encrypt_buf(cimdka->cipher, cimdka->kivam,
	                   pb->pb_blob, pb->pb_blob, pblob_length(pb));
	pblob_calc_blobid(pb, cimdka->mdigest, &blobid);
	pblob_set_blobid(pb, &blobid);
	pblob_set_length(pb, blobid.size);
}

static void pblob_decrypt(struct silofs_pack_blob *pb,
                          const struct silofs_cimdka *cimdka)
{
	silofs_decrypt_buf(cimdka->cipher, cimdka->kivam,
	                   pb->pb_blob, pb->pb_blob, pblob_length(pb));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void del_ubk(struct silofs_block *ubk, struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, ubk, sizeof(*ubk));
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
                     struct silofs_ubk_info *ubki,
                     silofs_lba_t vlba, enum silofs_stype stype)
{
	list_head_init(&pqe->pqe_lh);
	pqe->pqe_ce_ref = ce_ref;
	pqe->pqe_ui = NULL;
	pqe->pqe_ubki = ubki;
	pqe->pqe_vlba = vlba;
	pqe->pqe_stype = stype;
	silofs_ce_incref(pqe->pqe_ce_ref);
}

static void pqe_fini(struct silofs_pack_qelem *pqe)
{
	silofs_ce_decref(pqe->pqe_ce_ref);
	list_head_fini(&pqe->pqe_lh);
	pqe->pqe_ce_ref = NULL;
	pqe->pqe_ubki = NULL;
	pqe->pqe_vlba = SILOFS_OFF_NULL;
	pqe->pqe_stype = SILOFS_STYPE_NONE;
}

static struct silofs_pack_qelem *
pqe_new(struct silofs_alloc *alloc,
        struct silofs_cache_elem *ce_ref,
        struct silofs_ubk_info *ubki,
        silofs_lba_t vlba, enum silofs_stype stype)
{
	struct silofs_pack_qelem *pqe = NULL;

	pqe = silofs_allocate(alloc, sizeof(*pqe));
	if (pqe != NULL) {
		pqe_init(pqe, ce_ref, ubki, vlba, stype);
	}
	return pqe;
}

static void pqe_del(struct silofs_pack_qelem *pqe, struct silofs_alloc *alloc)
{
	pqe_fini(pqe);
	silofs_deallocate(alloc, pqe, sizeof(*pqe));
}

static struct silofs_pack_qelem *
pqe_new_for_ubk(struct silofs_alloc *alloc,
                struct silofs_ubk_info *ubki, silofs_lba_t vlba)
{
	struct silofs_cache_elem *ce_ref;

	ce_ref = (ubki != NULL) ? &ubki->ubk_ce : NULL;
	return pqe_new(alloc, ce_ref, ubki, vlba, SILOFS_STYPE_ANONBK);
}

static struct silofs_pack_qelem *
pqe_new_for_unode(struct silofs_alloc *alloc, struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	const silofs_lba_t vlba = off_to_lba(uaddr->voff);
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new(alloc, &ui->u_si.s_ce, ui->u_ubki, vlba, uaddr->stype);
	if (pqe != NULL) {
		pqe->pqe_ui = ui;
	}
	return pqe;
}

static struct silofs_pack_qelem *
pqe_new_for_spleaf(struct silofs_alloc *alloc, struct silofs_spleaf_info *sli)
{
	return pqe_new_for_unode(alloc, &sli->sl_ui);
}

static struct silofs_pack_qelem *
pqe_new_for_spnode(struct silofs_alloc *alloc, struct silofs_spnode_info *sni)
{
	return pqe_new_for_unode(alloc, &sni->sn_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pqs_init(struct silofs_pack_queues *pqs,
                     struct silofs_alloc *alloc)
{
	pqs->alloc = alloc;
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pq); ++i) {
		listq_init(&pqs->pq[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pb); ++i) {
		pqs->pb[i] = NULL;
	}
}

static void pqs_fini(struct silofs_pack_queues *pqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pq); ++i) {
		listq_fini(&pqs->pq[i]);
	}
	pqs->alloc = NULL;
}

static struct silofs_pack_qelem *
pq_pop_front_of(struct silofs_listq *pq)
{
	struct silofs_list_head *lh;
	struct silofs_pack_qelem *pqe;

	lh = listq_pop_front(pq);
	if (lh == NULL) {
		return NULL;
	}
	pqe = qpe_from_lh(lh);
	if (pqe->pqe_ui != NULL) {
		pqe->pqe_ui->u_in_pq = false;
	}
	return pqe;
}

static void pqs_clearq_at(struct silofs_pack_queues *pqs,
                          struct silofs_listq *pq)
{
	struct silofs_pack_qelem *pqe;

	pqe = pq_pop_front_of(pq);
	while (pqe != NULL) {
		pqe_del(pqe, pqs->alloc);
		pqe = pq_pop_front_of(pq);
	}
}

static struct silofs_listq *
pqs_elemsq_of(const struct silofs_pack_queues *pqs, enum silofs_height height)
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
	struct silofs_listq *lq = pqs_elemsq_of(pqs, height);

	listq_push_back(lq, &pqe->pqe_lh);
	if (pqe->pqe_ui != NULL) {
		pqe->pqe_ui->u_in_pq = true;
	}
}

static int pqs_insert_ubk(struct silofs_pack_queues *pqs,
                          struct silofs_ubk_info *ubki, silofs_lba_t vlba)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new_for_ubk(pqs->alloc, ubki, vlba);
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
                             struct silofs_spnode_info *sni)
{
	struct silofs_pack_qelem *pqe;

	pqe = pqe_new_for_spnode(pqs->alloc, sni);
	if (pqe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_by(pqs, pqe, sni_height(sni));
	return 0;
}

static int pqs_insert_unode(struct silofs_pack_queues *pqs,
                            struct silofs_unode_info *ui)
{
	struct silofs_pack_qelem *pqe = NULL;

	if (ui->u_in_pq) {
		return 0;
	}
	pqe = pqe_new_for_unode(pqs->alloc, ui);
	if (pqe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_by(pqs, pqe, ui_height(ui));
	return 0;
}

static int pqs_insert_super(struct silofs_pack_queues *pqs,
                            struct silofs_sb_info *sbi)
{
	return pqs_insert_unode(pqs, &sbi->sb_ui);
}

static void pqs_clearq_by(struct silofs_pack_queues *pqs,
                          enum silofs_height height)
{
	pqs_clearq_at(pqs, pqs_elemsq_of(pqs, height));
}

static struct silofs_pack_blob **
pqs_ppblob_of(const struct silofs_pack_queues *pqs, enum silofs_height height)
{
	struct silofs_pack_blob *const *ppb = &pqs->pb[height];

	silofs_assert_ge(height, 0);
	silofs_assert_lt(height, SILOFS_HEIGHT_LAST);
	silofs_assert_lt(height, ARRAY_SIZE(pqs->pb));

	return unconst(ppb);
}

static void pqs_put_pblob(struct silofs_pack_queues *pqs,
                          struct silofs_pack_blob *pb)
{
	struct silofs_pack_blob **ppb = pqs_ppblob_of(pqs, pb->pb_height);

	silofs_assert_null(*ppb);
	*ppb = pb;
}

static inline struct silofs_pack_blob *
pqs_get_pblob(const struct silofs_pack_queues *pqs,
              enum silofs_height height)
{
	struct silofs_pack_blob **ppb = pqs_ppblob_of(pqs, height);

	return *ppb;
}

static void pqs_clearb_at(struct silofs_pack_queues *pqs,
                          struct silofs_pack_blob **ppb)
{
	struct silofs_pack_blob *pb = *ppb;

	if (pb != NULL) {
		pblob_del(pb, pqs->alloc);
		*ppb = NULL;
	}
}

static void pqs_clearb_by(struct silofs_pack_queues *pqs,
                          enum silofs_height height)
{
	pqs_clearb_at(pqs, pqs_ppblob_of(pqs, height));
}

static void pqs_clear_by_height(struct silofs_pack_queues *pqs,
                                enum silofs_height height)
{
	pqs_clearq_by(pqs, height);
	pqs_clearb_by(pqs, height);
}

static void pqs_clear_all(struct silofs_pack_queues *pqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pq); ++i) {
		pqs_clearq_at(pqs, &pqs->pq[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pb); ++i) {
		pqs_clearb_at(pqs, &pqs->pb[i]);
	}
}

static int pqe_assign_to_blob(const struct silofs_pack_qelem *pqe,
                              struct silofs_pack_blob *pb)
{
	struct silofs_block *dst_ubk = NULL;
	const loff_t voff = lba_to_off(pqe->pqe_vlba);

	dst_ubk = pblob_ubk_of(pb, voff);
	if (pqe->pqe_ubki != NULL) {
		ubk_copyfrom(dst_ubk, pqe->pqe_ubki->ubk);
	} else {
		ubk_memzero(dst_ubk);
	}
	pb->pb_nbks++;
	return 0;
}

static int pqs_assign_pblob(struct silofs_pack_queues *pqs,
                            struct silofs_pack_blob *pb)
{
	const struct silofs_list_head *lh;
	const struct silofs_pack_qelem *pqe;
	const struct silofs_listq *pq = pqs_elemsq_of(pqs, pb->pb_height);
	int err;

	for (lh = listq_front(pq); lh != NULL; lh = listq_next(pq, lh)) {
		pqe = qpe_from_lh(lh);
		err = pqe_assign_to_blob(pqe, pb);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static const struct silofs_cipher *
pac_cipher(const struct silofs_pack_ctx *pa_ctx)
{
	return &pa_ctx->cryp.ci;
}

static const struct silofs_mdigest *
pac_mdigest(const struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_repo *repo = pac_src_repo(pa_ctx);

	return &repo->re_bootldr.btl_md;
}

static void pac_make_cimdka(const struct silofs_pack_ctx *pa_ctx,
                            struct silofs_cimdka *cimdka)
{
	cimdka->cipher = pac_cipher(pa_ctx);
	cimdka->mdigest = pac_mdigest(pa_ctx);
	cimdka->kivam = pa_ctx->kivam;
	cimdka->alloc = pa_ctx->alloc;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
		del_ubk(bk, pa_ctx->alloc);
		pa_ctx->tbk = NULL;
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

	pac_bind_to(pa_ctx, NULL);
	err = pac_init_tmp_bk(pa_ctx);
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
	return err;
}

static void pac_cleanup(struct silofs_pack_ctx *pa_ctx)
{
	pqs_clear_all(&pa_ctx->pqs);
	pqs_fini(&pa_ctx->pqs);
	pac_bind_to(pa_ctx, NULL);
	pac_fini_crypto(pa_ctx);
	pac_fini_tmp_bk(pa_ctx);
	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_verify_meta_of(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_unode_info *ui)
{
	silofs_unused(pa_ctx);
	return silofs_verify_csum_meta(ui->u_si.s_view);
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
                           const struct silofs_block *ubk_src,
                           const struct silofs_bkaddr *bkaddr_dst)
{
	struct silofs_ubk_info *ubki_dst = NULL;
	int err;

	err = pac_require_ubk(pa_ctx, bkaddr_dst, &ubki_dst);
	if (err) {
		return err;
	}
	err = silofs_bli_store_bk(ubki_dst->ubk_bli, bkaddr_dst, ubk_src);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_ubk_of(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_ubk_info *ubki_src,
                              const struct silofs_bkaddr *bkaddr_dst)
{
	return pac_restore_ubk(pa_ctx, ubki_src->ubk, bkaddr_dst);
}

static int pac_save_pblob(const struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_pack_blob *pb)
{
	struct silofs_blob_info *bli = NULL;
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	const struct silofs_blobid *blobid = &pb->pb_blobid;
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
	err = silofs_bli_pwriten(bli, 0, pb->pb_blob, pblob_length(pb));
	if (err) {
		return err;
	}
	return 0;
}

static int pac_load_pblob(const struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_pack_blob *pb)
{
	struct silofs_blob_info *bli = NULL;
	struct silofs_repo *repo = pac_src_repo(pa_ctx);
	const struct silofs_blobid *blobid = &pb->pb_blobid;
	int err;

	if (repo == NULL) {
		return -EBADF;
	}
	err = silofs_repo_stage_blob(repo, blobid, &bli);
	if (err) {
		return err;
	}
	err = silofs_bli_preadn(bli, 0, pb->pb_blob, blobid->size);
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
	const silofs_lba_t vlba = off_to_lba(voff);
	int err;

	if (!sli_has_allocated_at(sli, voff)) {
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
out:
	return pqs_insert_ubk(&pa_ctx->pqs, ubki, vlba);
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
	silofs_assert_eq(spit->sni2->sn_ui.u_uaddr.height,
	                 SILOFS_HEIGHT_SPNODE2);

	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni2);
}

static int pac_archive_exec_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sni3);
	silofs_assert(stype_isspnode(spit->stype));
	silofs_assert_eq(spit->height, SILOFS_HEIGHT_SPNODE3);
	silofs_assert_eq(spit->sni3->sn_ui.u_uaddr.height,
	                 SILOFS_HEIGHT_SPNODE3);

	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni3);
}

static int pac_archive_exec_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	silofs_assert_not_null(spit->sni4);
	silofs_assert(stype_isspnode(spit->stype));
	silofs_assert_eq(spit->height, SILOFS_HEIGHT_SPNODE4);
	silofs_assert_eq(spit->sni4->sn_ui.u_uaddr.height,
	                 SILOFS_HEIGHT_SPNODE4);

	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni4);
}

static int pac_archive_exec_at_super(struct silofs_pack_ctx *pa_ctx,
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
		err = pac_archive_exec_at_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EFSCORRUPTED;
		break;
	}
	return err;
}

static int pac_encode_pblob(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_pack_blob *pb)
{
	struct silofs_cimdka cimdka;

	pac_make_cimdka(pa_ctx, &cimdka);
	pblob_encrypt(pb, &cimdka);
	return 0;
}

static int pac_decode_pblob(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_pack_blob *pb)
{
	struct silofs_cimdka cimdka;
	int err;

	pac_make_cimdka(pa_ctx, &cimdka);
	err = pblob_check_blobid(pb, cimdka.mdigest);
	if (err) {
		return err;
	}
	pblob_decrypt(pb, &cimdka);
	return 0;
}

static int pac_put_new_pblob(struct silofs_pack_ctx *pa_ctx,
                             enum silofs_height height,
                             struct silofs_pack_blob **out_pb)
{
	struct silofs_pack_blob *pb = NULL;
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;

	pb = pblob_new(pa_ctx->alloc, height);
	if (pb == NULL) {
		return -ENOMEM;
	}
	pqs_put_pblob(pqs, pb);
	*out_pb = pb;
	return 0;
}

static int pac_put_new_pblob2(struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_blobid *blobid,
                              enum silofs_height height,
                              struct silofs_pack_blob **out_pb)
{
	int err;

	err = pac_put_new_pblob(pa_ctx, height, out_pb);
	if (!err) {
		pblob_set_blobid(*out_pb, blobid);
		pblob_set_length(*out_pb, blobid->size);
	}
	return err;
}

static int pac_assign_pblob(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_pack_blob *pb)
{
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;

	return pqs_assign_pblob(pqs, pb);
}

static void pac_clear_at(struct silofs_pack_ctx *pa_ctx,
                         enum silofs_height height)
{
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;

	pqs_clear_by_height(pqs, height);
}

static int pac_encode_save_pblob(struct silofs_pack_ctx *pa_ctx,
                                 enum silofs_height height,
                                 struct silofs_blobid *out_blobid)
{
	struct silofs_pack_blob *pb = NULL;
	int err;

	err = pac_put_new_pblob(pa_ctx, height, &pb);
	if (err) {
		return err;
	}
	err = pac_assign_pblob(pa_ctx, pb);
	if (err) {
		return err;
	}
	err = pac_encode_pblob(pa_ctx, pb);
	if (err) {
		return err;
	}
	err = pac_save_pblob(pa_ctx, pb);
	if (err) {
		return err;
	}
	pblob_blobid(pb, out_blobid);
	return 0;
}

static int pac_archive_post_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_encode_save_pblob(pa_ctx, spit->height - 1, &blobid);
	if (err) {
		return err;
	}
	silofs_sli_bind_pack_blob(spit->sli, &blobid);
	return 0;
}

static int pac_archive_post_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_encode_save_pblob(pa_ctx, spit->height - 1, &blobid);
	if (err) {
		return err;
	}
	silofs_sni_bind_pack_blob(spit->sni2, &blobid);
	return 0;
}

static int pac_archive_post_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_encode_save_pblob(pa_ctx, spit->height - 1, &blobid);
	if (err) {
		return err;
	}
	silofs_sni_bind_pack_blob(spit->sni3, &blobid);
	return 0;
}

static int pac_archive_post_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_encode_save_pblob(pa_ctx, spit->height - 1, &blobid);
	if (err) {
		return err;
	}
	silofs_sni_bind_pack_blob(spit->sni4, &blobid);
	return 0;
}

static int pac_archive_post_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_encode_save_pblob(pa_ctx, spit->height - 1, &blobid);
	if (err) {
		return err;
	}
	silofs_sbi_bind_pack_blob(spit->sbi, spit->vspace, &blobid);
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
	pac_clear_at(pa_ctx, spit->height - 1);
	return err;
}

static int pac_archive_post_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_encode_save_pblob(pa_ctx, SILOFS_HEIGHT_SUPER, &blobid);
	if (err) {
		return err;
	}
	silofs_bootsec_set_blobid(pa_ctx->dst_bsec, &blobid);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_archive_prep_by_uber(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	const struct silofs_uaddr *uaddr = &pa_ctx->src_bsec->sb_uaddr;
	int err;

	err = silofs_stage_super_at(pa_ctx->uber, pa_ctx->pack, uaddr, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(sbi, pa_ctx->uber);
	pac_bind_to(pa_ctx, sbi);
	return 0;
}

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

static int pac_walk_space_pack(struct silofs_pack_ctx *pa_ctx)
{
	int ret;

	pa_ctx->vis.exec_at_hook = pack_exec_at;
	pa_ctx->vis.post_at_hook = pack_post_at;
	ret = silofs_walk_space_tree(pa_ctx->sbi, &pa_ctx->vis);
	pa_ctx->vis.exec_at_hook = NULL;
	pa_ctx->vis.post_at_hook = NULL;

	return ret;
}

int silofs_uber_pack_fs(struct silofs_fs_uber *uber,
                        const struct silofs_kivam *kivam,
                        const struct silofs_bootsec *src_bsec,
                        struct silofs_bootsec *dst_bsec)
{
	struct silofs_pack_ctx pa_ctx = {
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
	err = pac_archive_prep_by_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_walk_space_pack(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_archive_post_at_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_load_decode_pblob(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_blobid *blobid,
                                 enum silofs_height height)
{
	struct silofs_pack_blob *pb = NULL;
	int err;

	err = pac_put_new_pblob2(pa_ctx, blobid, height, &pb);
	if (err) {
		return err;
	}
	err = pac_load_pblob(pa_ctx, pb);
	if (err) {
		return err;
	}
	err = pac_decode_pblob(pa_ctx, pb);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_refill_view_of(struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_block *src_ubk,
                              struct silofs_unode_info *ui)
{
	struct silofs_block *dst_ubk = ui->u_ubki->ubk;
	int err;

	memcpy(dst_ubk, src_ubk, sizeof(*dst_ubk));
	err = pac_verify_meta_of(pa_ctx, ui);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_do_refill_shadow_unode(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_unode_info *ui)
{
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;
	const struct silofs_pack_blob *pb = NULL;
	const struct silofs_block *src_ubk = NULL;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	int err;

	pb = pqs_get_pblob(pqs, uaddr->height);
	silofs_assert_not_null(pb);
	if (pb == NULL) {
		return -SILOFS_EBUG;
	}
	src_ubk = pblob_ubk_of(pb, uaddr->voff);
	err = pac_refill_view_of(pa_ctx, src_ubk, ui);
	if (err) {
		return err;
	}
	err = pqs_insert_unode(pqs, ui);
	if (err) {
		return err;
	}
	silofs_ui_bind_uber(ui, pa_ctx->uber);
	return 0;
}

static int pac_refill_shadow_unode(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_unode_info *ui)
{
	int err;

	ui_incref(ui);
	err = pac_do_refill_shadow_unode(pa_ctx, ui);
	ui_decref(ui);
	return err;
}

static int pac_refill_shadow_super(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_sb_info *sbi)
{
	return pac_refill_shadow_unode(pa_ctx, &sbi->sb_ui);
}

static int pac_refill_shadow_spnode(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_spnode_info *sni)
{
	return pac_refill_shadow_unode(pa_ctx, &sni->sn_ui);
}

static int pac_refill_shadow_spleaf(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_spleaf_info *sli)
{
	return pac_refill_shadow_unode(pa_ctx, &sli->sl_ui);
}

int silofs_repo_require_blob(struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(repo, blobid, out_bli);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, out_bli);
	}
	return err;
}

static int pac_require_blob_of(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_blobid *blobid,
                               struct silofs_blob_info **out_bli)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);

	return silofs_repo_require_blob(repo, blobid, out_bli);
}

static int pac_load_shadow_super_blob(struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_blobid *blobid = &pa_ctx->src_bsec->sb_blobid;

	return pac_load_decode_pblob(pa_ctx, blobid, SILOFS_HEIGHT_SUPER);
}

static int pac_load_shadow_spnode4_blob(struct silofs_pack_ctx *pa_ctx,
                                        const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = silofs_sbi_pack_blob(spit->sbi, spit->vspace, &blobid);
	if (err) {
		return err;
	}
	err = pac_load_decode_pblob(pa_ctx, &blobid, SILOFS_HEIGHT_SPNODE4);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_load_shadow_spnode3_blob(struct silofs_pack_ctx *pa_ctx,
                                        const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = silofs_sni_pack_blob(spit->sni4, &blobid);
	if (err) {
		return err;
	}
	err = pac_load_decode_pblob(pa_ctx, &blobid, SILOFS_HEIGHT_SPNODE3);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_load_shadow_spnode2_blob(struct silofs_pack_ctx *pa_ctx,
                                        const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = silofs_sni_pack_blob(spit->sni3, &blobid);
	if (err) {
		return err;
	}
	err = pac_load_decode_pblob(pa_ctx, &blobid, SILOFS_HEIGHT_SPNODE2);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_load_shadow_spleaf_blob(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = silofs_sni_pack_blob(spit->sni2, &blobid);
	if (err) {
		return err;
	}
	err = pac_load_decode_pblob(pa_ctx, &blobid, SILOFS_HEIGHT_SPLEAF);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_load_shadow_vdata_blob(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_blobid blobid;
	int err;

	err = silofs_sli_pack_blob(spit->sli, &blobid);
	if (err) {
		return err;
	}
	err = pac_load_decode_pblob(pa_ctx, &blobid, SILOFS_HEIGHT_VDATA);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_shadow_super_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	return silofs_shadow_super_at(pa_ctx->uber, pa_ctx->pack,
	                              uaddr, out_sbi);
}

static int pac_shadow_spnode_at(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spnode_info **out_sni)
{
	return silofs_shadow_spnode_at(pa_ctx->uber, pa_ctx->pack,
	                               uaddr, out_sni);
}

static int pac_shadow_spleaf_at(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_spleaf_info **out_sli)
{
	return silofs_shadow_spleaf_at(pa_ctx->uber, pa_ctx->pack,
	                               uaddr, out_sli);
}

static int pac_restore_shadow_super(struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_bootsec *bsec = pa_ctx->src_bsec;
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = pac_shadow_super_at(pa_ctx, &bsec->sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	err = pac_refill_shadow_super(pa_ctx, sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(sbi, pa_ctx->uber);
	pac_bind_to(pa_ctx, sbi);
	return 0;
}

static int pac_restore_shadow_spnode4(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sbi_sproot_of(spit->sbi, spit->vspace, &uaddr);
	if (err) {
		return err;
	}
	err = pac_shadow_spnode_at(pa_ctx, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = pac_refill_shadow_spnode(pa_ctx, sni);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_shadow_spnode3(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sni_subref_of(spit->sni4, spit->voff, &uaddr);
	if (err) {
		return err;
	}
	err = pac_shadow_spnode_at(pa_ctx, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = pac_refill_shadow_spnode(pa_ctx, sni);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_shadow_spnode2(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sni_subref_of(spit->sni3, spit->voff, &uaddr);
	if (err) {
		return err;
	}
	err = pac_shadow_spnode_at(pa_ctx, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = pac_refill_shadow_spnode(pa_ctx, sni);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_shadow_spleaf(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = silofs_sni_subref_of(spit->sni2, spit->voff, &uaddr);
	if (err) {
		return err;
	}
	err = pac_shadow_spleaf_at(pa_ctx, &uaddr, &sli);
	if (err) {
		return err;
	}
	err = pac_refill_shadow_spleaf(pa_ctx, sli);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by_uber(struct silofs_pack_ctx *pa_ctx)
{
	int err;

	err = pac_load_shadow_super_blob(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_restore_shadow_super(pa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	int err;

	err = pac_load_shadow_spnode4_blob(pa_ctx, spit);
	if (err) {
		return err;
	}
	err = pac_restore_shadow_spnode4(pa_ctx, spit);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	int err;

	err = pac_load_shadow_spnode3_blob(pa_ctx, spit);
	if (err) {
		return err;
	}
	err = pac_restore_shadow_spnode3(pa_ctx, spit);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	int err;

	err = pac_load_shadow_spnode2_blob(pa_ctx, spit);
	if (err) {
		return err;
	}
	err = pac_restore_shadow_spnode2(pa_ctx, spit);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	int err;

	err = pac_load_shadow_spleaf_blob(pa_ctx, spit);
	if (err) {
		return err;
	}
	err = pac_restore_shadow_spleaf(pa_ctx, spit);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	int err;

	err = pac_load_shadow_vdata_blob(pa_ctx, spit);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_prep_by(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SUPER:
		err = pac_restore_prep_by_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_restore_prep_by_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_restore_prep_by_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_restore_prep_by_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_restore_prep_by_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
		err = 0;
		break;
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}

static int pac_restore_exec_at_ubk(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_bkaddr bkaddr;
	const struct silofs_block *src_ubk = NULL;
	const struct silofs_pack_blob *pb = NULL;
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;

	int err;

	if (!sli_has_allocated_at(sli, voff)) {
		return 0;
	}
	err = silofs_sli_resolve_ubk(sli, voff, &bkaddr);
	if (err) {
		return err;
	}
	pb = pqs_get_pblob(pqs, SILOFS_HEIGHT_VDATA);
	silofs_assert_not_null(pb);
	if (pb == NULL) {
		return -SILOFS_EBUG;
	}
	src_ubk = pblob_ubk_of(pb, voff);
	err = pac_restore_ubk(pa_ctx, src_ubk, &bkaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_exec_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	ssize_t span;
	int err;

	sli_vrange(spit->sli, &vrange);
	span = silofs_height_to_span(vrange.height - 1);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_restore_exec_at_ubk(pa_ctx, spit->sli, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, span);
	}
	return 0;
}

static int pac_restore_exec_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SUPER:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE2:
		err = 0;
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_restore_exec_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}

static int pac_restore_post_at_unode(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_unode_info *ui)
{
	struct silofs_blob_info *bli = NULL;
	const struct silofs_bkaddr *bkaddr = ui_bkaddr(ui);
	int err;

	err = pac_require_blob_of(pa_ctx, &bkaddr->blobid, &bli);
	if (err) {
		return err;
	}
	err = pac_restore_ubk_of(pa_ctx, ui->u_ubki, bkaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_restore_post_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	return pac_restore_post_at_unode(pa_ctx, &spit->sli->sl_ui);
}

static int pac_restore_post_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_restore_post_at_unode(pa_ctx, &spit->sni2->sn_ui);
}

static int pac_restore_post_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_restore_post_at_unode(pa_ctx, &spit->sni3->sn_ui);
}

static int pac_restore_post_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_restore_post_at_unode(pa_ctx, &spit->sni4->sn_ui);
}

static int pac_restore_post_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	return pac_restore_post_at_unode(pa_ctx, &spit->sbi->sb_ui);
}

static int pac_restore_post_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_restore_post_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_restore_post_at_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_restore_post_at_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_restore_post_at_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_restore_post_at_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	pac_clear_at(pa_ctx, spit->height - 1);
	return err;
}

static int pac_restore_post_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	return pac_restore_post_at_unode(pa_ctx, &pa_ctx->sbi->sb_ui);
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

static int pac_walk_space_unpack(struct silofs_pack_ctx *pa_ctx)
{
	int ret;

	pa_ctx->vis.prep_by_hook = unpack_prep_by;
	pa_ctx->vis.exec_at_hook = unpack_exec_at;
	pa_ctx->vis.post_at_hook = unpack_post_at;
	ret = silofs_walk_space_tree(pa_ctx->sbi, &pa_ctx->vis);
	pa_ctx->vis.prep_by_hook = NULL;
	pa_ctx->vis.exec_at_hook = NULL;
	pa_ctx->vis.post_at_hook = NULL;
	return ret;
}

int silofs_uber_unpack_fs(struct silofs_fs_uber *uber,
                          const struct silofs_kivam *kivam,
                          const struct silofs_bootsec *src_bsec,
                          struct silofs_bootsec *dst_bsec)
{
	struct silofs_pack_ctx pa_ctx = {
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
	err = pac_restore_prep_by_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_walk_space_unpack(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_restore_post_at_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}


