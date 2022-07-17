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
	struct silofs_alloc            *pb_alloc;
	struct silofs_block            *pb_blob;
	struct silofs_pack_blob        *pb_cold;
	struct silofs_list_head         pb_lh;
	size_t                          pb_size_max;
	enum silofs_height              pb_height;
};

struct silofs_pack_elem {
	struct silofs_list_head         pe_lh;
	struct silofs_unode_info       *pe_ui;
	struct silofs_alloc            *pe_alloc;
};

struct silofs_pack_queues {
	struct silofs_alloc            *alloc;
	struct silofs_listq             peq[SILOFS_HEIGHT_LAST];
	struct silofs_listq             pbq[SILOFS_HEIGHT_LAST];
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

static int sli_resolve_warm_at(const struct silofs_spleaf_info *sli,
                               loff_t voff, struct silofs_blobid *out_blobid)
{
	struct silofs_bkaddr bkaddr;
	int ret;

	ret = silofs_sli_resolve_ubk(sli, voff, &bkaddr);
	if (ret == 0) {
		blobid_assign(out_blobid, &bkaddr.blobid);
	}
	return ret;
}

static int sli_resolve_cold_at(const struct silofs_spleaf_info *sli,
                               loff_t voff, struct silofs_blobid *out_blobid)
{
	return silofs_sli_resolve_cold(sli, voff, out_blobid);
}

static size_t uaddr_to_slot(const struct silofs_uaddr *uaddr)
{
	const ssize_t span = silofs_height_to_span(uaddr->height + 1);
	const loff_t roff = uaddr->voff % span;
	const ssize_t nchilds = SILOFS_SPNODE_NCHILDS;
	ssize_t slot;

	slot = (roff * nchilds) / span;
	silofs_assert_ge(slot, 0);
	return (size_t)slot;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_pack_blob *
pblob_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_pack_blob *pb;

	pb = container_of2(lh, struct silofs_pack_blob, pb_lh);
	return unconst(pb);
}

static void pblob_init(struct silofs_pack_blob *pb, struct silofs_alloc *alloc,
                       void *blob, size_t bsz, enum silofs_height height)
{
	blobid_reset(&pb->pb_blobid);
	list_head_init(&pb->pb_lh);
	pb->pb_alloc = alloc;
	pb->pb_blob = blob;
	pb->pb_cold = NULL;
	pb->pb_size_max = bsz;
	pb->pb_height = height;
}

static void pblob_fini(struct silofs_pack_blob *pb)
{
	blobid_reset(&pb->pb_blobid);
	list_head_fini(&pb->pb_lh);
	pb->pb_alloc = NULL;
	pb->pb_blob = NULL;
	pb->pb_cold = NULL;
	pb->pb_size_max = 0;
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
	pblob_init(pb, alloc, blob, bsz, height);
	return pb;
}

static void pblob_del(struct silofs_pack_blob *pb)
{
	struct silofs_alloc *alloc;

	if (pb != NULL) {
		alloc = pb->pb_alloc;
		silofs_deallocate(alloc, pb->pb_blob, pb->pb_size_max);

		pblob_fini(pb);
		silofs_deallocate(alloc, pb, sizeof(*pb));
	}
}

static void pblob_free_blob(struct silofs_pack_blob *pb)
{
	silofs_deallocate(pb->pb_alloc, pb->pb_blob, pb->pb_size_max);
	pb->pb_blob = NULL;
}

static struct silofs_block *
pblob_ubk_at(const struct silofs_pack_blob *pb, size_t slot)
{
	const size_t nbks = pb->pb_size_max / sizeof(pb->pb_blob[0]);
	const struct silofs_block *ubk = &pb->pb_blob[slot];

	silofs_assert_lt(slot, nbks);

	return unconst(ubk);
}

static size_t pblob_length(const struct silofs_pack_blob *pb)
{
	return pb->pb_blobid.size;
}

static void pblob_set_length(struct silofs_pack_blob *pb, size_t size)
{
	silofs_assert_ge(size, SILOFS_BK_SIZE);
	silofs_assert_le(size, pb->pb_size_max);

	pb->pb_blobid.size = size;
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

static void pblob_encrypt_into(const struct silofs_pack_blob *pb_src,
                               struct silofs_pack_blob *pb_dst,
                               const struct silofs_cimdka *cimdka)
{
	const size_t len = pblob_length(pb_src);

	silofs_assert_gt(len, 0);
	silofs_encrypt_buf(cimdka->cipher, cimdka->kivam,
	                   pb_src->pb_blob, pb_dst->pb_blob, len);
	pblob_set_length(pb_dst, len);
}

static void pblob_decrypt_from(const struct silofs_pack_blob *pb_src,
                               struct silofs_pack_blob *pb_dst,
                               const struct silofs_cimdka *cimdka)
{
	const size_t len = pblob_length(pb_src);

	silofs_assert_gt(len, 0);
	silofs_decrypt_buf(cimdka->cipher, cimdka->kivam,
	                   pb_src->pb_blob, pb_dst->pb_blob, len);
	pblob_set_length(pb_dst, len);
}

static bool pblob_has_blobid(const struct silofs_pack_blob *pb,
                             const struct silofs_blobid *blobid)
{
	return !blobid_isnull(&pb->pb_blobid) &&
	       blobid_isequal(&pb->pb_blobid, blobid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void del_ubk(struct silofs_block *ubk, struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, ubk, sizeof(*ubk));
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_pack_elem *
pe_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_pack_elem *pe;

	pe = container_of2(lh, struct silofs_pack_elem, pe_lh);
	return unconst(pe);
}

static void pe_init(struct silofs_pack_elem *pe,
                    struct silofs_alloc *alloc, struct silofs_unode_info *ui)
{
	ui_incref(ui);
	list_head_init(&pe->pe_lh);
	pe->pe_ui = ui;
	pe->pe_alloc = alloc;
}

static void pe_fini(struct silofs_pack_elem *pe)
{
	ui_decref(pe->pe_ui);
	list_head_fini(&pe->pe_lh);
	pe->pe_ui = NULL;
	pe->pe_alloc = NULL;
}

static struct silofs_pack_elem *
pe_new(struct silofs_alloc *alloc, struct silofs_unode_info *ui)
{
	struct silofs_pack_elem *pe = NULL;

	pe = silofs_allocate(alloc, sizeof(*pe));
	if (pe != NULL) {
		pe_init(pe, alloc, ui);
	}
	return pe;
}

static void pe_del(struct silofs_pack_elem *pe)
{
	struct silofs_alloc *alloc = pe->pe_alloc;

	if (pe != NULL) {
		alloc = pe->pe_alloc;
		pe_fini(pe);
		silofs_deallocate(alloc, pe, sizeof(*pe));
	}
}

static size_t pe_slot(const struct silofs_pack_elem *pe)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(pe->pe_ui);

	return uaddr_to_slot(uaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pqs_init(struct silofs_pack_queues *pqs,
                     struct silofs_alloc *alloc)
{
	pqs->alloc = alloc;
	for (size_t i = 0; i < ARRAY_SIZE(pqs->peq); ++i) {
		listq_init(&pqs->peq[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pbq); ++i) {
		listq_init(&pqs->pbq[i]);
	}
}

static void pqs_fini(struct silofs_pack_queues *pqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(pqs->peq); ++i) {
		listq_fini(&pqs->peq[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pbq); ++i) {
		listq_fini(&pqs->pbq[i]);
	}
	pqs->alloc = NULL;
}

static struct silofs_pack_elem *
peq_pop_front_of(struct silofs_listq *peq)
{
	struct silofs_list_head *lh;
	struct silofs_pack_elem *pe;

	lh = listq_pop_front(peq);
	if (lh == NULL) {
		return NULL;
	}
	pe = pe_from_lh(lh);
	if (pe->pe_ui != NULL) {
		pe->pe_ui->u_in_pq = false;
	}
	return pe;
}

static void peq_clear(struct silofs_listq *peq)
{
	struct silofs_pack_elem *pe;

	pe = peq_pop_front_of(peq);
	while (pe != NULL) {
		pe_del(pe);
		pe = peq_pop_front_of(peq);
	}
}

static struct silofs_listq *
pqs_peq_of(const struct silofs_pack_queues *pqs, enum silofs_height height)
{
	const struct silofs_listq *lq = &pqs->peq[height];

	silofs_assert_ge(height, 0);
	silofs_assert_lt(height, SILOFS_HEIGHT_LAST);
	silofs_assert_lt(height, ARRAY_SIZE(pqs->peq));

	return unconst(lq);
}

static void pqs_insert_elem_by(struct silofs_pack_queues *pqs,
                               struct silofs_pack_elem *pe,
                               enum silofs_height height)
{
	struct silofs_listq *lq = pqs_peq_of(pqs, height);

	listq_push_back(lq, &pe->pe_lh);
	if (pe->pe_ui != NULL) {
		pe->pe_ui->u_in_pq = true;
	}
}

static int pqs_insert_unode(struct silofs_pack_queues *pqs,
                            struct silofs_unode_info *ui)
{
	struct silofs_pack_elem *pe = NULL;

	if (ui->u_in_pq) {
		return 0;
	}
	pe = pe_new(pqs->alloc, ui);
	if (pe == NULL) {
		return -ENOMEM;
	}
	pqs_insert_elem_by(pqs, pe, ui_height(ui));
	return 0;
}

static int pqs_insert_spleaf(struct silofs_pack_queues *pqs,
                             struct silofs_spleaf_info *sli)
{
	return pqs_insert_unode(pqs, &sli->sl_ui);
}

static int pqs_insert_spnode(struct silofs_pack_queues *pqs,
                             struct silofs_spnode_info *sni)
{
	return pqs_insert_unode(pqs, &sni->sn_ui);
}

static int pqs_insert_super(struct silofs_pack_queues *pqs,
                            struct silofs_sb_info *sbi)
{
	return pqs_insert_unode(pqs, &sbi->sb_ui);
}

static void pqs_clear_peq_by(struct silofs_pack_queues *pqs,
                             enum silofs_height height)
{
	peq_clear(pqs_peq_of(pqs, height));
}

static struct silofs_pack_blob *
pbq_pop_front_of(struct silofs_listq *pbq)
{
	struct silofs_list_head *lh;
	struct silofs_pack_blob *pb;

	lh = listq_pop_front(pbq);
	if (lh == NULL) {
		return NULL;
	}
	pb = pblob_from_lh(lh);
	return pb;
}

static void pbq_clear(struct silofs_listq *pbq)
{
	struct silofs_pack_blob *pb;

	pb = pbq_pop_front_of(pbq);
	while (pb != NULL) {
		pblob_del(pb);
		pb = pbq_pop_front_of(pbq);
	}
}

static struct silofs_listq *
pqs_pbq_of(const struct silofs_pack_queues *pqs, enum silofs_height height)
{
	const struct silofs_listq *lq = &pqs->pbq[height];

	silofs_assert_ge(height, 0);
	silofs_assert_lt(height, SILOFS_HEIGHT_LAST);
	silofs_assert_lt(height, ARRAY_SIZE(pqs->pbq));

	return unconst(lq);
}

static void pqs_insert_pblob(struct silofs_pack_queues *pqs,
                             struct silofs_pack_blob *pb)
{
	struct silofs_listq *lq = pqs_pbq_of(pqs, pb->pb_height);

	listq_push_back(lq, &pb->pb_lh);
}

static void pqs_clear_pbq_by(struct silofs_pack_queues *pqs,
                             enum silofs_height height)
{
	pbq_clear(pqs_pbq_of(pqs, height));
}

static void pqs_clear_by_height(struct silofs_pack_queues *pqs,
                                enum silofs_height height)
{
	pqs_clear_peq_by(pqs, height);
	pqs_clear_pbq_by(pqs, height);
}

static void pqs_clear_all(struct silofs_pack_queues *pqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(pqs->peq); ++i) {
		peq_clear(&pqs->peq[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(pqs->pbq); ++i) {
		pbq_clear(&pqs->pbq[i]);
	}
}

static void ubk_copy(struct silofs_block *ubk, const struct silofs_block *ubk2)
{
	memcpy(ubk, ubk2, sizeof(*ubk));
}

static int pe_assign_to_blob(const struct silofs_pack_elem *pe,
                             struct silofs_pack_blob *pb)
{
	struct silofs_block *dst_ubk = NULL;
	const size_t blen = pblob_length(pb);
	const size_t slot = pe_slot(pe);
	size_t size;

	silofs_assert_not_null(pe->pe_ui);
	silofs_assert_not_null(pe->pe_ui->u_ubki);

	dst_ubk = pblob_ubk_at(pb, slot);
	ubk_copy(dst_ubk, pe->pe_ui->u_ubki->ubk);

	size = (slot + 1) * sizeof(*dst_ubk);
	pblob_set_length(pb, max(size, blen));
	return 0;
}

static int pqs_assign_pblob_by_pe(struct silofs_pack_queues *pqs,
                                  struct silofs_pack_blob *pb)
{
	const struct silofs_list_head *lh;
	const struct silofs_pack_elem *pe;
	const struct silofs_listq *lq = pqs_peq_of(pqs, pb->pb_height);
	int err;

	for (lh = listq_front(lq); lh != NULL; lh = listq_next(lq, lh)) {
		pe = pe_from_lh(lh);
		err = pe_assign_to_blob(pe, pb);
		if (err) {
			return err;
		}
	}
	return 0;
}

static struct silofs_pack_blob *
pqs_lookup_pblob(const struct silofs_pack_queues *pqs,
                 const struct silofs_blobid *blobid, enum silofs_height height)
{
	struct silofs_pack_blob *pb;
	const struct silofs_list_head *lh;
	const struct silofs_listq *pbq = pqs_pbq_of(pqs, height);

	lh = listq_front(pbq);
	while (lh != NULL) {
		pb = pblob_from_lh(lh);
		if (pblob_has_blobid(pb, blobid)) {
			return pb;
		}
		lh = listq_next(pbq, lh);
	}
	return NULL;
}

static bool pqs_has_pblob(const struct silofs_pack_queues *pqs,
                          const struct silofs_blobid *blobid,
                          enum silofs_height height)
{
	struct silofs_pack_blob *pb;

	pb = pqs_lookup_pblob(pqs, blobid, height);
	return (pb != NULL);
}

static bool pqs_resolve_cold_of(const struct silofs_pack_queues *pqs,
                                const struct silofs_blobid *warm,
                                enum silofs_height height,
                                struct silofs_blobid *out_cold)
{
	struct silofs_pack_blob *pb;
	bool ret = false;

	pb = pqs_lookup_pblob(pqs, warm, height);
	if (pb && pb->pb_cold) {
		blobid_assign(out_cold, &pb->pb_cold->pb_blobid);
		ret = true;
	}
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_repo *pac_warm_repo(const struct silofs_pack_ctx *pa_ctx)
{
	return &pa_ctx->uber->ub_repos->repo_warm;
}

static struct silofs_repo *pac_cold_repo(const struct silofs_pack_ctx *pa_ctx)
{
	return &pa_ctx->uber->ub_repos->repo_cold;
}

static struct silofs_repo *pac_src_repo(const struct silofs_pack_ctx *pa_ctx)
{
	return pa_ctx->pack ? pac_warm_repo(pa_ctx) : pac_cold_repo(pa_ctx);
}

static struct silofs_repo *pac_dst_repo(const struct silofs_pack_ctx *pa_ctx)
{
	return pa_ctx->pack ? pac_cold_repo(pa_ctx) : pac_warm_repo(pa_ctx);
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
	silofs_bootsec_set_sb_uaddr(dst_bsec, &src_bsec->sb_uaddr);
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

static void pac_clear_at(struct silofs_pack_ctx *pa_ctx,
                         enum silofs_height height)
{
	struct silofs_pack_queues *pqs = &pa_ctx->pqs;

	pqs_clear_by_height(pqs, height);
}

static int pac_new_pblob(struct silofs_pack_ctx *pa_ctx,
                         enum silofs_height height,
                         struct silofs_pack_blob **out_pb)
{
	*out_pb = pblob_new(pa_ctx->alloc, height);
	return (*out_pb == NULL) ? -ENOMEM : 0;
}

static int pac_new_pblob2(struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_blobid *blobid,
                          enum silofs_height height,
                          struct silofs_pack_blob **out_pb)
{
	int err;

	err = pac_new_pblob(pa_ctx, height, out_pb);
	if (!err) {
		pblob_set_blobid(*out_pb, blobid);
	}
	return 0;
}

static int pac_put_new_pblob(struct silofs_pack_ctx *pa_ctx,
                             enum silofs_height height,
                             struct silofs_pack_blob **out_pb)
{
	int err;

	err = pac_new_pblob(pa_ctx, height, out_pb);
	if (err) {
		return err;
	}
	pqs_insert_pblob(&pa_ctx->pqs, *out_pb);
	return 0;
}

static int pac_put_new_pblob2(struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_blobid *blobid,
                              enum silofs_height height,
                              struct silofs_pack_blob **out_pb)
{
	int err;

	err = pac_put_new_pblob(pa_ctx, height, out_pb);
	if (err) {
		return err;
	}
	pblob_set_blobid(*out_pb, blobid);
	pblob_set_length(*out_pb, blobid->size);
	return 0;
}

static int pac_verify_meta_of(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	int err;

	err = silofs_verify_view_by(ui->u_si.s_view, uaddr->stype);
	silofs_assert_ok(err);
	silofs_unused(pa_ctx);
	return err;
}

static int pac_require_ubk(const struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);
	const struct silofs_blobid *blobid = &bkaddr->blobid;
	struct silofs_blobref_info *bri = NULL;
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(repo, blobid, &bri);
		if (err) {
			return err;
		}
		bri_incref(bri);
		err = silofs_repo_stage_ubk(repo, bkaddr, out_ubki);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, &bri);
		if (err) {
			return err;
		}
		bri_incref(bri);
		err = silofs_repo_spawn_ubk(repo, bkaddr, out_ubki);
	}
	bri_decref(bri);
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
	err = silofs_bri_store_bk(ubki_dst->ubk_bri, bkaddr_dst, ubk_src);
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


static int pac_load_warm_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	struct silofs_repo *repo = pac_warm_repo(pa_ctx);
	int err;

	err = silofs_repo_stage_blob(repo, &pb->pb_blobid, &bri);
	if (err) {
		return err;
	}
	err = silofs_bri_preadn(bri, 0, pb->pb_blob, pb->pb_blobid.size);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_cold_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	struct silofs_repo *repo = pac_cold_repo(pa_ctx);
	int err;

	err = silofs_repo_lookup_blob(repo, &pb->pb_blobid);
	if (!err) {
		return 0; /* ok -- already exists */
	}
	err = silofs_repo_spawn_blob(repo, &pb->pb_blobid, &bri);
	if (err) {
		return err;
	}
	err = silofs_bri_pwriten(bri, 0, pb->pb_blob, pb->pb_blobid.size);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_encode_blob_into(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_pack_blob *pb_warm,
                                struct silofs_pack_blob *pb_cold)
{
	struct silofs_blobid blobid;
	struct silofs_cimdka cimdka;

	pac_make_cimdka(pa_ctx, &cimdka);

	pblob_encrypt_into(pb_warm, pb_cold, &cimdka);
	pblob_calc_blobid(pb_cold, cimdka.mdigest, &blobid);
	pblob_set_blobid(pb_cold, &blobid);
	pblob_set_length(pb_cold, blobid.size);
	return 0;
}

static void pac_fixup_used_blobs(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_pack_blob *pb_warm,
                                 struct silofs_pack_blob *pb_cold)
{
	silofs_assert_null(pb_warm->pb_cold);

	pb_warm->pb_cold = pb_cold;
	pblob_free_blob(pb_warm);
	pblob_free_blob(pb_cold);
	silofs_unused(pa_ctx);
}

static int pac_exec_archive_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	return pqs_insert_spleaf(&pa_ctx->pqs, spit->sli);
}

static int pac_exec_archive_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni2);
}

static int pac_exec_archive_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni3);
}

static int pac_exec_archive_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni4);
}

static int pac_exec_archive_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	return pqs_insert_super(&pa_ctx->pqs, spit->sbi);
}

static int pac_exec_archive_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SUPER:
		err = pac_exec_archive_at_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_exec_archive_at_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_exec_archive_at_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_exec_archive_at_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_exec_archive_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}

static int pac_archive_vdata_blob(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_blobid *warm,
                                  enum silofs_height height,
                                  struct silofs_blobid *out_cold)
{
	struct silofs_pack_blob *pb_warm = NULL;
	struct silofs_pack_blob *pb_cold = NULL;
	int err;

	err = pac_put_new_pblob2(pa_ctx, warm, height, &pb_warm);
	if (err) {
		return err;
	}
	err = pac_put_new_pblob(pa_ctx, height, &pb_cold);
	if (err) {
		return err;
	}
	err = pac_load_warm_blob(pa_ctx, pb_warm);
	if (err) {
		return err;
	}
	err = pac_encode_blob_into(pa_ctx, pb_warm, pb_cold);
	if (err) {
		return err;
	}
	err = pac_save_cold_blob(pa_ctx, pb_cold);
	if (err) {
		return err;
	}
	pac_fixup_used_blobs(pa_ctx, pb_warm, pb_cold);
	pblob_blobid(pb_cold, out_cold);
	return 0;
}

static int
pac_post_archive_at_blob_of(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit, loff_t voff)
{
	struct silofs_blobid warm;
	struct silofs_blobid cold;
	const struct silofs_pack_queues *pqs = &pa_ctx->pqs;
	int err;
	bool known;

	err = sli_resolve_warm_at(spit->sli, voff, &warm);
	if (err) {
		return err;
	}
	known = pqs_resolve_cold_of(pqs, &warm, spit->height - 1, &cold);
	if (known) {
		goto out_ok;
	}
	err = pac_archive_vdata_blob(pa_ctx, &warm, spit->height - 1, &cold);
	if (err) {
		return err;
	}
out_ok:
	silofs_sli_rebind_cold(spit->sli, voff, &cold);
	return 0;
}

static int pac_post_archive_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	int err;

	sli_vrange(spit->sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_post_archive_at_blob_of(pa_ctx, spit, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = silofs_vrange_next(&vrange, voff);
	}
	silofs_sli_seal_meta(spit->sli);
	return 0;
}

static int pac_assign_unodes_blob(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_pack_blob *pb)
{
	return pqs_assign_pblob_by_pe(&pa_ctx->pqs, pb);
}

static int pac_archive_unodes_blob(struct silofs_pack_ctx *pa_ctx,
                                   enum silofs_height height,
                                   struct silofs_blobid *out_cold)
{
	struct silofs_pack_blob *pb_warm = NULL;
	struct silofs_pack_blob *pb_cold = NULL;
	int err;

	err = pac_put_new_pblob(pa_ctx, height, &pb_warm);
	if (err) {
		return err;
	}
	err = pac_put_new_pblob(pa_ctx, height, &pb_cold);
	if (err) {
		return err;
	}
	err = pac_assign_unodes_blob(pa_ctx, pb_warm);
	if (err) {
		return err;
	}
	err = pac_encode_blob_into(pa_ctx, pb_warm, pb_cold);
	if (err) {
		return err;
	}
	err = pac_save_cold_blob(pa_ctx, pb_cold);
	if (err) {
		return err;
	}
	pac_fixup_used_blobs(pa_ctx, pb_warm, pb_cold);
	pblob_blobid(pb_cold, out_cold);
	return 0;
}

static int pac_post_archive_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid cold;
	int err;

	err = pac_archive_unodes_blob(pa_ctx, spit->height - 1, &cold);
	if (err) {
		return err;
	}
	silofs_sni_bind_pack_blob(spit->sni2, &cold);
	return 0;
}

static int pac_post_archive_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid cold;
	int err;

	err = pac_archive_unodes_blob(pa_ctx, spit->height - 1, &cold);
	if (err) {
		return err;
	}
	silofs_sni_bind_pack_blob(spit->sni3, &cold);
	return 0;
}

static int pac_post_archive_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	struct silofs_blobid cold;
	int err;

	err = pac_archive_unodes_blob(pa_ctx, spit->height - 1, &cold);
	if (err) {
		return err;
	}
	silofs_sni_bind_pack_blob(spit->sni4, &cold);
	return 0;
}

static int pac_post_archive_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	struct silofs_blobid cold;
	int err;

	err = pac_archive_unodes_blob(pa_ctx, spit->height - 1, &cold);
	if (err) {
		return err;
	}
	silofs_sbi_bind_pack_blob(spit->sbi, spit->vspace, &cold);
	return 0;
}

static int pac_post_archive_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_post_archive_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_post_archive_at_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_post_archive_at_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_post_archive_at_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_post_archive_at_super(pa_ctx, spit);
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

static int pac_post_archive_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_blobid blobid;
	int err;

	err = pac_archive_unodes_blob(pa_ctx, SILOFS_HEIGHT_SUPER, &blobid);
	if (err) {
		return err;
	}
	silofs_bootsec_set_cold_blobid(pa_ctx->dst_bsec, &blobid);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_exec_archive_at_uber(struct silofs_pack_ctx *pa_ctx)
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

	silofs_bootsec_set_sb_uaddr(pa_ctx->dst_bsec, sbi_uaddr(sbi));
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

static int pack_exec(struct silofs_visitor *vis,
                     const struct silofs_space_iter *spit)
{
	return pac_exec_archive_at(pack_ctx_of(vis), spit);
}

static int pack_post(struct silofs_visitor *vis,
                     const struct silofs_space_iter *spit)
{
	return pac_post_archive_at(pack_ctx_of(vis), spit);
}

static int pac_walk_space_pack(struct silofs_pack_ctx *pa_ctx)
{
	int ret;

	pa_ctx->vis.exec_hook = pack_exec;
	pa_ctx->vis.post_hook = pack_post;
	ret = silofs_walk_space_tree(pa_ctx->sbi, &pa_ctx->vis);
	pa_ctx->vis.exec_hook = NULL;
	pa_ctx->vis.post_hook = NULL;

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
	err = pac_exec_archive_at_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_walk_space_pack(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_post_archive_at_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_check_cold_blob(const struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_pack_blob *pb)
{
	struct silofs_cimdka cimdka;
	int err;

	pac_make_cimdka(pa_ctx, &cimdka);
	err = pblob_check_blobid(pb, cimdka.mdigest);
	silofs_assert_ok(err);
	return err;
}

static int pac_load_cold_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	struct silofs_repo *repo = pac_cold_repo(pa_ctx);
	int err;

	err = silofs_repo_stage_blob(repo, &pb->pb_blobid, &bri);
	if (err) {
		return err;
	}
	err = silofs_bri_preadn(bri, 0, pb->pb_blob, pb->pb_blobid.size);
	if (err) {
		return err;
	}
	err = pac_check_cold_blob(pa_ctx, pb);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_decode_blob_from(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_pack_blob *pb_cold,
                                struct silofs_pack_blob *pb_dest)
{
	struct silofs_cimdka cimdka;

	pac_make_cimdka(pa_ctx, &cimdka);
	pblob_decrypt_from(pb_cold, pb_dest, &cimdka);

	return 0;
}

static int pac_save_warm_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	struct silofs_repo *repo = pac_warm_repo(pa_ctx);
	int err;

	err = silofs_repo_lookup_blob(repo, &pb->pb_blobid);
	if (!err) {
		return 0; /* ok -- already exists */
	}
	err = silofs_repo_spawn_blob(repo, &pb->pb_blobid, &bri);
	if (err) {
		return err;
	}
	silofs_assert_ge(pb->pb_blobid.size, SILOFS_BK_SIZE);
	err = silofs_bri_pwriten(bri, 0, pb->pb_blob, pb->pb_blobid.size);
	if (err) {
		return err;
	}
	return 0;
}

static int
pac_restore_shadow_blob(struct silofs_pack_ctx *pa_ctx,
                        const struct silofs_blobid *cold,
                        struct silofs_pack_blob *pb_shadow)
{
	struct silofs_pack_blob *pb_cold = NULL;
	int err;

	err = pac_new_pblob2(pa_ctx, cold, pb_shadow->pb_height, &pb_cold);
	if (err) {
		return err;
	}
	err = pac_load_cold_blob(pa_ctx, pb_cold);
	if (err) {
		goto out;
	}
	err = pac_decode_blob_from(pa_ctx, pb_cold, pb_shadow);
	if (err) {
		goto out;
	}
out:
	pblob_del(pb_cold);
	return err;
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

static int
pac_do_refill_shadow_unode_by(struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb,
                              struct silofs_unode_info *ui)
{
	const struct silofs_block *src_ubk = NULL;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	const size_t slot = uaddr_to_slot(uaddr);
	int err;

	src_ubk = pblob_ubk_at(pb, slot);
	err = pac_refill_view_of(pa_ctx, src_ubk, ui);
	if (err) {
		return err;
	}
	err = pqs_insert_unode(&pa_ctx->pqs, ui);
	if (err) {
		return err;
	}
	silofs_ui_bind_uber(ui, pa_ctx->uber);
	return 0;
}

static int pac_refill_shadow_unode_by(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_pack_blob *pb,
                                      struct silofs_unode_info *ui)
{
	int err;

	ui_incref(ui);
	err = pac_do_refill_shadow_unode_by(pa_ctx, pb, ui);
	ui_decref(ui);
	return err;
}

static int pac_refill_shadow_super_by(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_pack_blob *pb,
                                      struct silofs_sb_info *sbi)
{
	return pac_refill_shadow_unode_by(pa_ctx, pb, &sbi->sb_ui);
}

static int pac_refill_shadow_spnode_by(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_pack_blob *pb,
                                       struct silofs_spnode_info *sni)
{
	return pac_refill_shadow_unode_by(pa_ctx, pb, &sni->sn_ui);
}

static int pac_refill_shadow_spleaf_by(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_pack_blob *pb,
                                       struct silofs_spleaf_info *sli)
{
	return pac_refill_shadow_unode_by(pa_ctx, pb, &sli->sl_ui);
}

int silofs_repo_require_blob(struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobref_info **out_bri)
{
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(repo, blobid, out_bri);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(repo, blobid, out_bri);
	}
	return err;
}

static int pac_require_blob_of(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_blobid *blobid,
                               struct silofs_blobref_info **out_bri)
{
	struct silofs_repo *repo = pac_dst_repo(pa_ctx);

	return silofs_repo_require_blob(repo, blobid, out_bri);
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

static int
pac_exec_restore_vdata_blob(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit, loff_t voff)
{
	struct silofs_blobid warm;
	struct silofs_blobid cold;
	struct silofs_pack_blob *pb_cold = NULL;
	struct silofs_pack_blob *pb_warm = NULL;
	int err;

	err = sli_resolve_warm_at(spit->sli, voff, &warm);
	if (err) {
		return err;
	}
	if (pqs_has_pblob(&pa_ctx->pqs, &warm, spit->height - 1)) {
		/* already restored */
		return 0;
	}
	err = sli_resolve_cold_at(spit->sli, voff, &cold);
	if (err) {
		return err;
	}
	err = pac_put_new_pblob2(pa_ctx, &cold, spit->height - 1, &pb_cold);
	if (err) {
		return err;
	}
	err = pac_put_new_pblob2(pa_ctx, &warm, spit->height - 1, &pb_warm);
	if (err) {
		return err;
	}
	err = pac_load_cold_blob(pa_ctx, pb_cold);
	if (err) {
		return err;
	}
	err = pac_decode_blob_from(pa_ctx, pb_cold, pb_warm);
	if (err) {
		return err;
	}
	err = pac_save_warm_blob(pa_ctx, pb_warm);
	if (err) {
		return err;
	}
	pac_fixup_used_blobs(pa_ctx, pb_warm, pb_cold);
	return 0;
}

static int pac_exec_restore_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	int err;

	sli_vrange(spit->sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_exec_restore_vdata_blob(pa_ctx, spit, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = silofs_vrange_next(&vrange, voff);
	}
	return 0;
}

static int
pac_exec_restore_by_spnode2(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid cold;
	struct silofs_vrange vrange;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_spleaf_info *sli = NULL;
	loff_t voff;
	int err;

	err = silofs_sni_pack_blob(spit->sni2, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_pblob(pa_ctx, spit->height - 1, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	sni_vrange(spit->sni2, &vrange);
	for (size_t slot = 0; slot < SILOFS_SPNODE_NCHILDS; ++slot) {
		voff = silofs_vrange_voff_at(&vrange, slot);
		if (voff >= vrange.end) {
			break;
		}
		err = silofs_sni_subref_of(spit->sni2, voff, &uaddr);
		if (err == -ENOENT) {
			err = 0;
			break;
		}
		err = pac_shadow_spleaf_at(pa_ctx, &uaddr, &sli);
		if (err) {
			break;
		}
		err = pac_refill_shadow_spleaf_by(pa_ctx, pb_shadow, sli);
		if (err) {
			break;
		}
		sli = NULL;
	}
out:
	pblob_del(pb_shadow);
	return err;
}

static int
pac_exec_restore_by_spnode3(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid cold;
	struct silofs_vrange vrange;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_spnode_info *sni = NULL;
	loff_t voff;
	int err;

	err = silofs_sni_pack_blob(spit->sni3, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_pblob(pa_ctx, spit->height - 1, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	sni_vrange(spit->sni3, &vrange);
	for (size_t slot = 0; slot < SILOFS_SPNODE_NCHILDS; ++slot) {
		voff = silofs_vrange_voff_at(&vrange, slot);
		if (voff >= vrange.end) {
			break;
		}
		err = silofs_sni_subref_of(spit->sni3, voff, &uaddr);
		if (err == -ENOENT) {
			err = 0;
			break;
		}
		err = pac_shadow_spnode_at(pa_ctx, &uaddr, &sni);
		if (err) {
			break;
		}
		err = pac_refill_shadow_spnode_by(pa_ctx, pb_shadow, sni);
		if (err) {
			break;
		}
		sni = NULL;
	}
out:
	pblob_del(pb_shadow);
	return err;
}

static int
pac_exec_restore_by_spnode4(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid cold;
	struct silofs_vrange vrange;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_spnode_info *sni = NULL;
	loff_t voff;
	int err;

	err = silofs_sni_pack_blob(spit->sni4, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_pblob(pa_ctx, spit->height - 1, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	sni_vrange(spit->sni4, &vrange);
	for (size_t slot = 0; slot < SILOFS_SPNODE_NCHILDS; ++slot) {
		voff = silofs_vrange_voff_at(&vrange, slot);
		if (voff >= vrange.end) {
			break;
		}
		err = silofs_sni_subref_of(spit->sni4, voff, &uaddr);
		if (err == -ENOENT) {
			err = 0;
			break;
		}
		err = pac_shadow_spnode_at(pa_ctx, &uaddr, &sni);
		if (err) {
			break;
		}
		err = pac_refill_shadow_spnode_by(pa_ctx, pb_shadow, sni);
		if (err) {
			break;
		}
		sni = NULL;
	}
out:
	pblob_del(pb_shadow);
	return err;
}

static int
pac_exec_restore_by_super(struct silofs_pack_ctx *pa_ctx,
                          const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid cold;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = silofs_sbi_pack_blob(spit->sbi, spit->vspace, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_pblob(pa_ctx, spit->height - 1, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	err = silofs_sbi_sproot_of(spit->sbi, spit->vspace, &uaddr);
	if (err) {
		goto out;
	}
	err = pac_shadow_spnode_at(pa_ctx, &uaddr, &sni);
	if (err) {
		goto out;
	}
	err = pac_refill_shadow_spnode_by(pa_ctx, pb_shadow, sni);
	if (err) {
		goto out;
	}
out:
	pblob_del(pb_shadow);
	return err;
}

static int pac_exec_restore_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_blobid cold;
	struct silofs_uaddr sb_uaddr;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_sb_info *sbi = NULL;
	int err;

	silofs_bootsec_sb_uaddr(pa_ctx->src_bsec, &sb_uaddr);
	silofs_bootsec_cold_blobid(pa_ctx->src_bsec, &cold);

	err = pac_new_pblob(pa_ctx, SILOFS_HEIGHT_SUPER, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_shadow_super_at(pa_ctx, &sb_uaddr, &sbi);
	if (err) {
		goto out;
	}
	err = pac_refill_shadow_super_by(pa_ctx, pb_shadow, sbi);
	if (err) {
		goto out;
	}
	silofs_sbi_bind_uber(sbi, pa_ctx->uber);
	pac_bind_to(pa_ctx, sbi);
	pqs_insert_super(&pa_ctx->pqs, sbi);
out:
	pblob_del(pb_shadow);
	return err;
}

static int pac_exec_restore_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SUPER:
		err = pac_exec_restore_by_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_exec_restore_by_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_exec_restore_by_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_exec_restore_by_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_exec_restore_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}

static int pac_post_restore_at_unode(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_unode_info *ui)
{
	struct silofs_blobref_info *bri = NULL;
	const struct silofs_bkaddr *bkaddr = ui_bkaddr(ui);
	int err;

	err = pac_require_blob_of(pa_ctx, &bkaddr->blobid, &bri);
	if (err) {
		return err;
	}
	err = pac_restore_ubk_of(pa_ctx, ui->u_ubki, bkaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_post_restore_at_spleaf(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sli->sl_ui);
}

static int pac_post_restore_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sni2->sn_ui);
}

static int pac_post_restore_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sni3->sn_ui);
}

static int pac_post_restore_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sni4->sn_ui);
}

static int pac_post_restore_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sbi->sb_ui);
}

static int pac_post_restore_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_post_restore_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = pac_post_restore_at_spnode2(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = pac_post_restore_at_spnode3(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = pac_post_restore_at_spnode4(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_post_restore_at_super(pa_ctx, spit);
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

static int pac_post_restore_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	return pac_post_restore_at_unode(pa_ctx, &pa_ctx->sbi->sb_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unpack_exec(struct silofs_visitor *vis,
                       const struct silofs_space_iter *spit)
{
	return pac_exec_restore_at(pack_ctx_of(vis), spit);
}

static int unpack_post(struct silofs_visitor *vis,
                       const struct silofs_space_iter *spit)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_post_restore_at(pa_ctx, spit);
}

static int pac_walk_space_unpack(struct silofs_pack_ctx *pa_ctx)
{
	int ret;

	pa_ctx->vis.exec_hook = unpack_exec;
	pa_ctx->vis.post_hook = unpack_post;
	ret = silofs_walk_space_tree(pa_ctx->sbi, &pa_ctx->vis);
	pa_ctx->vis.exec_hook = NULL;
	pa_ctx->vis.post_hook = NULL;
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
	err = pac_exec_restore_at_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_walk_space_unpack(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_post_restore_at_uber(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_update_dst_bootsec(&pa_ctx);
out:
	pac_cleanup(&pa_ctx);
	return err;
}


