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
#include <silofs/fs-private.h>

/*
 * TODO-0052: Store "hint" objects within attic upon pack process.
 *
 * Keep track of already packed sub-trees by using local hint objects (1K).
 * Using those hint objects, there is no need to re-traverse large sub-tree
 * which is already archived in attic.
 */

struct silofs_pack_blob {
	struct silofs_list_head         pb_lh;
	struct silofs_blobid            pb_blobid;
	struct silofs_alloc            *pb_alloc;
	struct silofs_block            *pb_blob;
	struct silofs_pack_blob        *pb_cold;
	size_t                          pb_size_max;
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
	struct silofs_crypto            crypto;
	struct silofs_zcmpr             zcmpr;
	struct silofs_blobid            cold_blobid;
	struct silofs_pack_queues       pqs;
	const struct silofs_bootsec    *warm_bsec;
	const struct silofs_bootsec    *cold_bsec;
	const struct silofs_ivkey      *ivkey;
	struct silofs_task             *task;
	struct silofs_uber             *uber;
	struct silofs_repos            *repos;
	const struct silofs_cipher     *cipher;
	const struct silofs_mdigest    *mdigest;
	struct silofs_sb_info          *sbi;
	enum silofs_stype               vspace;
	bool                            forced;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void blobid_anon(struct silofs_blobid *blobid,
                        enum silofs_stype vspace, enum silofs_height height)
{
	struct silofs_hash256 hash;
	const size_t size = SILOFS_BLOB_SIZE_MAX;
	const enum silofs_pack pmode = SILOFS_PACK_SIMPLE;

	silofs_getentropy(&hash, sizeof(hash));
	silofs_blobid_make_ca(blobid, &hash, size, vspace, height, pmode);
}

static enum silofs_height ui_height(const struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	return uaddr->height;
}

static void ui_resolve_pos(const struct silofs_unode_info *ui,
                           loff_t *out_off_in_bk, size_t *out_len)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	*out_off_in_bk = uaddr->oaddr.pos % SILOFS_BK_SIZE;
	*out_len = uaddr->oaddr.len;
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
	const ssize_t span = silofs_height_to_space_span(uaddr->height + 1);
	const loff_t roff = uaddr->voff % span;
	const ssize_t nchilds = SILOFS_SPMAP_NCHILDS;

	return (size_t)((roff * nchilds) / span);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_pack_blob *
pblob_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_pack_blob *pb;

	pb = container_of2(lh, struct silofs_pack_blob, pb_lh);
	return unconst(pb);
}

static void pblob_blobid(const struct silofs_pack_blob *pb,
                         struct silofs_blobid *out_blobid)
{
	blobid_assign(out_blobid, &pb->pb_blobid);
}

static void pblob_init(struct silofs_pack_blob *pb,
                       struct silofs_alloc *alloc,
                       const struct silofs_blobid *blobid,
                       void *blob, size_t bsz)
{
	blobid_assign(&pb->pb_blobid, blobid);
	list_head_init(&pb->pb_lh);
	pb->pb_alloc = alloc;
	pb->pb_blob = blob;
	pb->pb_cold = NULL;
	pb->pb_size_max = bsz;
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
pblob_new(struct silofs_alloc *alloc, const struct silofs_blobid *blobid)
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
	pblob_init(pb, alloc, blobid, blob, bsz);
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
	pb->pb_blobid.size = size;
}

static void pblob_calc_blobid(const struct silofs_pack_blob *pb,
                              const struct silofs_mdigest *md,
                              enum silofs_pack pmode,
                              struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;
	const size_t size = pblob_length(pb);
	const enum silofs_stype vspace = pb->pb_blobid.vspace;
	const enum silofs_height height = pb->pb_blobid.height;

	silofs_sha3_256_of(md, pb->pb_blob, size, &hash);
	silofs_blobid_make_ca(out_blobid, &hash, size, vspace, height, pmode);
}

static void pblob_recalc_self(struct silofs_pack_blob *pb,
                              const struct silofs_mdigest *md,
                              enum silofs_pack pmode)
{
	pblob_calc_blobid(pb, md, pmode, &pb->pb_blobid);
}

static int pblob_check_blobid(const struct silofs_pack_blob *pb,
                              const struct silofs_mdigest *md)
{
	struct silofs_blobid blobid;
	bool eq;

	pblob_calc_blobid(pb, md, pb->pb_blobid.pmode, &blobid);
	eq = blobid_isequal(&blobid, &pb->pb_blobid);
	return eq ? 0 : -SILOFS_ECSUM;
}

static bool pblob_has_blobid(const struct silofs_pack_blob *pb,
                             const struct silofs_blobid *blobid)
{
	return !blobid_isnull(&pb->pb_blobid) &&
	       blobid_isequal(&pb->pb_blobid, blobid);
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
	struct silofs_alloc *alloc;

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
	struct silofs_listq *lq = pqs_pbq_of(pqs, pb->pb_blobid.height);

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

static void copy_unode(const struct silofs_block *ubk_src,
                       struct silofs_block *ubk_dst,
                       loff_t off_in_bk, size_t len)
{
	const void *src = &ubk_src->u.bk[off_in_bk];
	void *dst = &ubk_dst->u.bk[off_in_bk];

	memcpy(dst, src, len);
}

static int pe_assign_to_blob(const struct silofs_pack_elem *pe,
                             struct silofs_pack_blob *pb)
{
	const struct silofs_block *ubk_src = NULL;
	struct silofs_block *ubk_dst = NULL;
	const size_t blen = pblob_length(pb);
	const size_t slot = pe_slot(pe);
	loff_t off_in_bk;
	size_t len;
	size_t pb_size;

	ui_resolve_pos(pe->pe_ui, &off_in_bk, &len);
	ubk_src = pe->pe_ui->u_ubki->ubk_base.bk;
	ubk_dst = pblob_ubk_at(pb, slot);
	copy_unode(ubk_src, ubk_dst, off_in_bk, len);

	pb_size = (slot + 1) * sizeof(*ubk_dst);
	pblob_set_length(pb, max(pb_size, blen));
	return 0;
}

static int pqs_assign_pblob_by_pe(struct silofs_pack_queues *pqs,
                                  struct silofs_pack_blob *pb)
{
	const struct silofs_list_head *lh;
	const struct silofs_pack_elem *pe;
	const struct silofs_listq *lq = pqs_peq_of(pqs, pb->pb_blobid.height);
	int err;

	pblob_set_length(pb, SILOFS_BK_SIZE);
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
                 const struct silofs_blobid *blobid)
{
	struct silofs_pack_blob *pb;
	const struct silofs_list_head *lh;
	const struct silofs_listq *pbq = pqs_pbq_of(pqs, blobid->height);

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
                          const struct silofs_blobid *blobid)
{
	struct silofs_pack_blob *pb;

	pb = pqs_lookup_pblob(pqs, blobid);
	return (pb != NULL);
}

static bool pqs_resolve_cold_of(const struct silofs_pack_queues *pqs,
                                const struct silofs_blobid *warm,
                                struct silofs_blobid *out_cold)
{
	struct silofs_pack_blob *pb = pqs_lookup_pblob(pqs, warm);
	bool ret = false;

	if (pb && pb->pb_cold) {
		blobid_assign(out_cold, &pb->pb_cold->pb_blobid);
		ret = true;
	}
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_encrypt(const struct silofs_pack_ctx *pa_ctx,
                       void *out_dat, const void *in_dat, size_t dat_len)
{
	return silofs_encrypt_buf(pa_ctx->cipher, pa_ctx->ivkey,
	                          in_dat, out_dat, dat_len);
}

static int pac_decrypt(const struct silofs_pack_ctx *pa_ctx,
                       void *out_dat, const void *in_dat, size_t dat_len)
{
	return silofs_decrypt_buf(pa_ctx->cipher, pa_ctx->ivkey,
	                          in_dat, out_dat, dat_len);
}

static int
pac_compress(const struct silofs_pack_ctx *pa_ctx, void *dst, size_t dst_cap,
             const void *src, size_t src_size, size_t *out_len)
{
	return silofs_zcmpr_compress(&pa_ctx->zcmpr, dst, dst_cap, src,
	                             src_size, 0, out_len);
}

static int
pac_decompress(const struct silofs_pack_ctx *pa_ctx, void *dst, size_t dst_cap,
               const void *src, size_t src_size, size_t *out_len)
{
	int err;

	err = silofs_zcmpr_decompress(&pa_ctx->zcmpr, dst, dst_cap,
	                              src, src_size, out_len);
	return err ? -SILOFS_EFSCORRUPTED : 0;
}

static int pac_compress_encrypt(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_pack_blob *pb_warm,
                                struct silofs_pack_blob *pb_cold)
{
	const size_t inlen = pblob_length(pb_warm);
	size_t size = 0;
	int err;

	/* compress warm --> cold */
	err = pac_compress(pa_ctx, pb_cold->pb_blob, pb_cold->pb_size_max,
	                   pb_warm->pb_blob, inlen, &size);
	if (err) {
		return err;
	}
	/* encrypt cold in-place */
	pac_encrypt(pa_ctx, pb_cold->pb_blob, pb_cold->pb_blob, size);

	/* set cold id by content */
	pblob_set_length(pb_cold, size);
	pblob_recalc_self(pb_cold, pa_ctx->mdigest, SILOFS_PACK_ZSTD);
	return 0;
}

static int
pac_encrypt_only(struct silofs_pack_ctx *pa_ctx,
                 const struct silofs_pack_blob *pb_warm,
                 struct silofs_pack_blob *pb_cold)
{
	const size_t size = pblob_length(pb_warm);

	/* non compressed mode: encrypt-copy warm --> cold*/
	pac_encrypt(pa_ctx, pb_cold->pb_blob, pb_warm->pb_blob, size);

	/* set cold id by content */
	pblob_set_length(pb_cold, size);
	pblob_recalc_self(pb_cold, pa_ctx->mdigest, SILOFS_PACK_SIMPLE);
	return 0;
}

static int pac_encode_blob_into(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_pack_blob *pb_warm,
                                struct silofs_pack_blob *pb_cold)
{
	int err;

	/* try compress (zstd) mode */
	err = pac_compress_encrypt(pa_ctx, pb_warm, pb_cold);
	if (err) {
		/* can not compress; fall-back to simple mode */
		err = pac_encrypt_only(pa_ctx, pb_warm, pb_cold);
	}
	return err;
}

static int pac_decrypt_decompress(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_pack_blob *pb_cold,
                                  struct silofs_pack_blob *pb_dest)
{
	const size_t inlen = pblob_length(pb_cold);
	size_t size = inlen;
	int err = 0;

	/* decrypt cold in-place */
	pac_decrypt(pa_ctx, pb_cold->pb_blob, pb_cold->pb_blob, inlen);

	/* decompress cold --> dest */
	err = pac_decompress(pa_ctx, pb_dest->pb_blob, pb_dest->pb_size_max,
	                     pb_cold->pb_blob, inlen, &size);
	if (err) {
		return err;
	}
	pblob_set_length(pb_dest, size);
	return err;
}

static int pac_decrypt_only(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_pack_blob *pb_cold,
                            struct silofs_pack_blob *pb_dest)
{
	const size_t size = pblob_length(pb_cold);

	pac_decrypt(pa_ctx, pb_dest->pb_blob, pb_cold->pb_blob, size);
	pblob_set_length(pb_dest, size);
	return 0;
}

static int pac_decode_blob_from(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_pack_blob *pb_cold,
                                struct silofs_pack_blob *pb_dest)
{
	const enum silofs_pack pmode = pb_cold->pb_blobid.pmode;
	int err;

	if (pmode == SILOFS_PACK_ZSTD) {
		err = pac_decrypt_decompress(pa_ctx, pb_cold, pb_dest);
	} else if (pmode == SILOFS_PACK_SIMPLE) {
		err = pac_decrypt_only(pa_ctx, pb_cold, pb_dest);
	} else {
		err = -SILOFS_EFSCORRUPTED;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_alloc *pac_alloc(const struct silofs_pack_ctx *pa_ctx)
{
	return pa_ctx->uber->ub.alloc;
}

static int pac_init_crypto(struct silofs_pack_ctx *pa_ctx)
{
	int err;

	err = silofs_crypto_init(&pa_ctx->crypto);
	if (err) {
		return err;
	}
	pa_ctx->cipher = &pa_ctx->crypto.ci;
	pa_ctx->mdigest = &pa_ctx->crypto.md;
	return 0;
}

static void pac_fini_crypto(struct silofs_pack_ctx *pa_ctx)
{
	silofs_crypto_fini(&pa_ctx->crypto);
}

static int pac_init_zcmpr(struct silofs_pack_ctx *pa_ctx, bool de)
{
	return silofs_zcmpr_init(&pa_ctx->zcmpr, de);
}

static void pac_fini_zcmpr(struct silofs_pack_ctx *pa_ctx)
{
	silofs_zcmpr_fini(&pa_ctx->zcmpr);
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

static int pac_init_repos(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_repos *repos = pa_ctx->uber->ub.repos;
	struct silofs_repo *repo = NULL;

	repo = silofs_repos_get(repos, SILOFS_REPO_ATTIC);
	if (repo == NULL) {
		return -SILOFS_ENOREPO;
	}
	repo = silofs_repos_get(repos, SILOFS_REPO_LOCAL);
	if (repo == NULL) {
		return -SILOFS_ENOREPO;
	}
	pa_ctx->repos = repos;
	return 0;
}

static int
pac_init(struct silofs_pack_ctx *pa_ctx, bool de,
         struct silofs_task *task, const struct silofs_ivkey *ivkey)
{
	int err;

	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
	pa_ctx->task = task;
	pa_ctx->uber = task->t_uber;
	pa_ctx->ivkey = ivkey;

	pac_bind_to(pa_ctx, NULL);
	err = pac_init_repos(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_init_crypto(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_init_zcmpr(pa_ctx, de);
	if (err) {
		pac_fini_crypto(pa_ctx);
		return err;
	}
	pqs_init(&pa_ctx->pqs, pac_alloc(pa_ctx));
	blobid_reset(&pa_ctx->cold_blobid);
	return 0;
}

static void pac_fini(struct silofs_pack_ctx *pa_ctx)
{
	pqs_clear_all(&pa_ctx->pqs);
	pqs_fini(&pa_ctx->pqs);
	pac_fini_zcmpr(pa_ctx);
	pac_fini_crypto(pa_ctx);
	pac_bind_to(pa_ctx, NULL);
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
                         const struct silofs_blobid *blobid,
                         struct silofs_pack_blob **out_pb)
{
	*out_pb = pblob_new(pac_alloc(pa_ctx), blobid);
	return (*out_pb == NULL) ? -ENOMEM : 0;
}

static int
pac_new_anon_pblob(struct silofs_pack_ctx *pa_ctx,
                   enum silofs_stype vspace, enum silofs_height height,
                   struct silofs_pack_blob **out_pb)
{
	struct silofs_blobid anon;

	blobid_anon(&anon, vspace, height);
	return pac_new_pblob(pa_ctx, &anon, out_pb);
}

static int
pac_new_shadow_pblob(struct silofs_pack_ctx *pa_ctx,
                     const struct silofs_blobid *cold,
                     struct silofs_pack_blob **out_pb)
{
	return pac_new_anon_pblob(pa_ctx, cold->vspace, cold->height, out_pb);
}

static int pac_put_new_pblob(struct silofs_pack_ctx *pa_ctx,
                             const struct silofs_blobid *blobid,
                             struct silofs_pack_blob **out_pb)
{
	int err;

	err = pac_new_pblob(pa_ctx, blobid, out_pb);
	if (err) {
		return err;
	}
	pqs_insert_pblob(&pa_ctx->pqs, *out_pb);
	return 0;
}

static int
pac_put_new_anon_pblob(struct silofs_pack_ctx *pa_ctx,
                       enum silofs_stype vspace, enum silofs_height height,
                       struct silofs_pack_blob **out_pb)
{
	int err;

	err = pac_new_anon_pblob(pa_ctx, vspace, height, out_pb);
	if (err) {
		return err;
	}
	pqs_insert_pblob(&pa_ctx->pqs, *out_pb);
	return 0;
}

static int pac_verify_meta_of(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	int err;

	err = silofs_verify_view_by(ui->u_si.s_view, uaddr->stype);
	silofs_unused(pa_ctx);
	return err;
}

static int pac_require_restored_ubk(const struct silofs_pack_ctx *pa_ctx,
                                    const struct silofs_bkaddr *bkaddr,
                                    struct silofs_ubk_info **out_ubki)
{
	const struct silofs_blobid *blobid = &bkaddr->blobid;
	struct silofs_blobref_info *bri = NULL;
	const enum silofs_repo_mode repo_mode = SILOFS_REPO_LOCAL;
	int err;

	err = silofs_repos_lookup_blob(pa_ctx->repos, repo_mode, blobid);
	if (!err) {
		err = silofs_repos_stage_blob(pa_ctx->repos, true,
		                              repo_mode, blobid, &bri);
		if (err) {
			return err;
		}
		bri_incref(bri);
		err = silofs_repos_stage_ubk(pa_ctx->repos, true,
		                             repo_mode, bkaddr, out_ubki);
	} else if (err == -ENOENT) {
		err = silofs_repos_spawn_blob(pa_ctx->repos, repo_mode,
		                              blobid, &bri);
		if (err) {
			return err;
		}
		bri_incref(bri);
		err = silofs_repos_spawn_ubk(pa_ctx->repos, true,
		                             repo_mode, bkaddr, out_ubki);
	}
	bri_decref(bri);
	return err;
}

static int store_obj_at(struct silofs_blobref_info *bri,
                        const struct silofs_oaddr *oaddr, const void *dat)
{
	return silofs_bri_pwriten(bri, oaddr->pos, dat, oaddr->len, false);
}

static int store_obj_of(struct silofs_blobref_info *bri,
                        const struct silofs_uaddr *uaddr, const void *dat)
{
	return store_obj_at(bri, &uaddr->oaddr, dat);
}

static int pac_restore_unode_into(const struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_unode_info *ui,
                                  const struct silofs_bkaddr *bkaddr_dst)
{
	struct silofs_uaddr uaddr_dst = { .voff = -1 };
	struct silofs_ubk_info *ubki_dst = NULL;
	const struct silofs_uaddr *uaddr_src = ui_uaddr(ui);
	int err;

	err = pac_require_restored_ubk(pa_ctx, bkaddr_dst, &ubki_dst);
	if (err) {
		return err;
	}
	uaddr_setup(&uaddr_dst, &bkaddr_dst->blobid, uaddr_src->oaddr.pos,
	            uaddr_src->stype, uaddr_src->height, uaddr_src->voff);
	err = store_obj_of(ubki_dst->ubk_bri, &uaddr_dst, ui->u_si.s_view);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_load_warm_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	const enum silofs_repo_mode repo_mode = SILOFS_REPO_LOCAL;
	int err;

	err = silofs_repos_stage_blob(pa_ctx->repos, true,
	                              repo_mode, &pb->pb_blobid, &bri);
	if (err) {
		return err;
	}
	err = silofs_bri_read_blob(bri, pb->pb_blob, pb->pb_blobid.size);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_cold_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	const enum silofs_repo_mode repo_mode = SILOFS_REPO_ATTIC;
	int err;

	err = silofs_repos_lookup_blob(pa_ctx->repos, repo_mode,
	                               &pb->pb_blobid);
	if (!err) {
		if (!pa_ctx->forced) {
			return 0; /* ok -- already exists */
		}
		err = silofs_repos_stage_blob(pa_ctx->repos, true,
		                              repo_mode, &pb->pb_blobid, &bri);
	} else {
		err = silofs_repos_spawn_blob(pa_ctx->repos, repo_mode,
		                              &pb->pb_blobid, &bri);
	}
	if (err) {
		return err;
	}
	err = silofs_bri_pwriten(bri, 0, pb->pb_blob,
	                         pb->pb_blobid.size, false);
	if (err) {
		return err;
	}
	return 0;
}

static void pac_fixup_used_blobs(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_pack_blob *pb_warm,
                                 struct silofs_pack_blob *pb_cold)
{
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

static int pac_exec_archive_at_spnode1(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni1);
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

static int pac_exec_archive_at_spnode5(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pqs_insert_spnode(&pa_ctx->pqs, spit->sni5);
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
	case SILOFS_HEIGHT_SPNODE5:
		err = pac_exec_archive_at_spnode5(pa_ctx, spit);
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
	case SILOFS_HEIGHT_SPNODE1:
		err = pac_exec_archive_at_spnode1(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_exec_archive_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}

static int pac_archive_vdata_blob(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_blobid *warm,
                                  struct silofs_blobid *out_cold)
{
	struct silofs_pack_blob *pb_warm = NULL;
	struct silofs_pack_blob *pb_cold = NULL;
	int err;

	err = pac_put_new_pblob(pa_ctx, warm, &pb_warm);
	if (err) {
		return err;
	}
	err = pac_load_warm_blob(pa_ctx, pb_warm);
	if (err) {
		return err;
	}
	err = pac_put_new_anon_pblob(pa_ctx, warm->vspace,
	                             warm->height, &pb_cold);
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
	known = pqs_resolve_cold_of(pqs, &warm, &cold);
	if (known) {
		goto out_ok;
	}
	err = pac_archive_vdata_blob(pa_ctx, &warm, &cold);
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
	voff = off_max(vrange.beg, spit->voff);
	while (voff < vrange.end) {
		err = pac_post_archive_at_blob_of(pa_ctx, spit, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = vrange_next(&vrange, voff);
	}
	silofs_sli_seal_meta(spit->sli);
	return 0;
}

static int pac_assign_unodes_blob(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_pack_blob *pb)
{
	return pqs_assign_pblob_by_pe(&pa_ctx->pqs, pb);
}

static int
pac_archive_unodes_blob(struct silofs_pack_ctx *pa_ctx,
                        const struct silofs_blobid *anon,
                        struct silofs_blobid *out_cold)
{
	struct silofs_pack_blob *pb_warm = NULL;
	struct silofs_pack_blob *pb_cold = NULL;
	int err;

	err = pac_new_pblob(pa_ctx, anon, &pb_warm);
	if (err) {
		goto out;
	}
	err = pac_new_pblob(pa_ctx, anon, &pb_cold);
	if (err) {
		goto out;
	}
	err = pac_assign_unodes_blob(pa_ctx, pb_warm);
	if (err) {
		goto out;
	}
	err = pac_encode_blob_into(pa_ctx, pb_warm, pb_cold);
	if (err) {
		goto out;
	}
	err = pac_save_cold_blob(pa_ctx, pb_cold);
	if (err) {
		goto out;
	}
	pblob_blobid(pb_cold, out_cold);
out:
	pblob_del(pb_warm);
	pblob_del(pb_cold);
	return err;
}

static int pac_post_archive_at_spnode(struct silofs_pack_ctx *pa_ctx,
                                      const struct silofs_space_iter *spit,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid anon;
	struct silofs_blobid cold;
	int err;

	blobid_anon(&anon, spit->vspace, spit->height - 1);
	err = pac_archive_unodes_blob(pa_ctx, &anon, &cold);
	if (err) {
		return err;
	}
	silofs_sni_bind_cold_blob(sni, &cold);
	return 0;
}

static int pac_post_archive_at_spnode1(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_archive_at_spnode(pa_ctx, spit, spit->sni1);
}

static int pac_post_archive_at_spnode2(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_archive_at_spnode(pa_ctx, spit, spit->sni2);
}

static int pac_post_archive_at_spnode3(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_archive_at_spnode(pa_ctx, spit, spit->sni3);
}

static int pac_post_archive_at_spnode4(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_archive_at_spnode(pa_ctx, spit, spit->sni4);
}

static int pac_post_archive_at_spnode5(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_archive_at_spnode(pa_ctx, spit, spit->sni5);
}

static int pac_post_archive_at_super(struct silofs_pack_ctx *pa_ctx,
                                     const struct silofs_space_iter *spit)
{
	struct silofs_blobid anon;
	struct silofs_blobid cold;
	int err;

	blobid_anon(&anon, spit->vspace, spit->height - 1);
	err = pac_archive_unodes_blob(pa_ctx, &anon, &cold);
	if (err) {
		return err;
	}
	silofs_sbi_bind_cold_blob(spit->sbi, spit->vspace, &cold);
	return 0;
}

static void pac_post_cleanups_at(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_space_iter *spit)
{
	switch (spit->height) {
	case SILOFS_HEIGHT_SPNODE1:
		pac_clear_at(pa_ctx, spit->height - 2);
		pac_clear_at(pa_ctx, spit->height - 1);
		break;
	case SILOFS_HEIGHT_SPNODE2:
	case SILOFS_HEIGHT_SPNODE3:
	case SILOFS_HEIGHT_SPNODE4:
	case SILOFS_HEIGHT_SPNODE5:
	case SILOFS_HEIGHT_SUPER:
		pac_clear_at(pa_ctx, spit->height - 1);
		break;
	case SILOFS_HEIGHT_SPLEAF:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		break;
	}
}

static int pac_post_archive_at(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_post_archive_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE1:
		err = pac_post_archive_at_spnode1(pa_ctx, spit);
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
	case SILOFS_HEIGHT_SPNODE5:
		err = pac_post_archive_at_spnode5(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_post_archive_at_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		err = -SILOFS_EFSCORRUPTED;
		break;
	}
	pac_post_cleanups_at(pa_ctx, spit);
	return err;
}

static int pac_post_archive_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_blobid anon;

	blobid_anon(&anon, SILOFS_STYPE_SUPER, SILOFS_HEIGHT_SUPER);
	return pac_archive_unodes_blob(pa_ctx, &anon, &pa_ctx->cold_blobid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_exec_archive_at_uber(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = NULL;
	const struct silofs_uaddr *uaddr = &pa_ctx->warm_bsec->sb_uaddr;
	int err;

	err = silofs_stage_super_at(pa_ctx->uber, true, uaddr, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(sbi, pa_ctx->uber);
	pac_bind_to(pa_ctx, sbi);
	return 0;
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
	pa_ctx->vis.exec_hook = pack_exec;
	pa_ctx->vis.post_hook = pack_post;
	return silofs_walk_space_tree(pa_ctx->task, pa_ctx->sbi,
	                              &pa_ctx->vis, true);
}

static void pac_assign_cold_bootsec(struct silofs_pack_ctx *pa_ctx,
                                    struct silofs_bootsec *bsec)
{
	struct silofs_hash256 hash;

	silofs_bootsec_init(bsec);
	silofs_bootsec_set_sb_uaddr(bsec, sbi_uaddr(pa_ctx->sbi));
	silofs_bootsec_set_sb_cold(bsec, &pa_ctx->cold_blobid);
	silofs_calc_key_hash(&pa_ctx->ivkey->key, pa_ctx->mdigest, &hash);
	silofs_bootsec_set_keyhash(bsec, &hash);
}

int silofs_pack_fs(struct silofs_task *task,
                   const struct silofs_ivkey *ivkey,
                   const struct silofs_bootsec *warm_bsec,
                   struct silofs_bootsec *out_cold_bsec)
{
	struct silofs_pack_ctx pa_ctx;
	int err;

	err = pac_init(&pa_ctx, false, task, ivkey);
	if (err) {
		return err;
	}
	pa_ctx.warm_bsec = warm_bsec;
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
	pac_assign_cold_bootsec(&pa_ctx, out_cold_bsec);
out:
	pac_fini(&pa_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_check_cold_blob(const struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_pack_blob *pb)
{
	return pblob_check_blobid(pb, pa_ctx->mdigest);
}

static int pac_load_cold_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	const enum silofs_repo_mode repo_mode = SILOFS_REPO_ATTIC;
	int err;

	err = silofs_repos_stage_blob(pa_ctx->repos, true,
	                              repo_mode, &pb->pb_blobid, &bri);
	if (err) {
		return err;
	}
	err = silofs_bri_read_blob(bri, pb->pb_blob, pb->pb_blobid.size);
	if (err) {
		return err;
	}
	err = pac_check_cold_blob(pa_ctx, pb);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_save_warm_blob(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_pack_blob *pb)
{
	struct silofs_blobref_info *bri = NULL;
	const enum silofs_repo_mode repo_mode = SILOFS_REPO_LOCAL;
	int err;

	err = silofs_repos_lookup_blob(pa_ctx->repos, repo_mode,
	                               &pb->pb_blobid);
	if (!err) {
		if (!pa_ctx->forced) {
			return 0; /* ok -- already exists */
		}
		err = silofs_repos_stage_blob(pa_ctx->repos, true,
		                              repo_mode, &pb->pb_blobid, &bri);
	} else {
		err = silofs_repos_spawn_blob(pa_ctx->repos, repo_mode,
		                              &pb->pb_blobid, &bri);
	}
	if (err) {
		return err;
	}
	silofs_assert_ge(pb->pb_blobid.size, SILOFS_BK_SIZE);
	err = silofs_bri_pwriten(bri, 0, pb->pb_blob,
	                         pb->pb_blobid.size, false);
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

	err = pac_new_pblob(pa_ctx, cold, &pb_cold);
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
                              const struct silofs_block *ubk_src,
                              struct silofs_unode_info *ui)
{
	struct silofs_block *ubk_dst = ui->u_ubki->ubk_base.bk;
	loff_t off_in_bk;
	size_t len;
	int err;

	ui_resolve_pos(ui, &off_in_bk, &len);
	copy_unode(ubk_src, ubk_dst, off_in_bk, len);
	err = pac_verify_meta_of(pa_ctx, ui);
	if (err) {
		return err;
	}
	return 0;
}

static int
pac_do_refill_shadow_unode(struct silofs_pack_ctx *pa_ctx,
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

static int pac_refill_shadow_unode(struct silofs_pack_ctx *pa_ctx,
                                   const struct silofs_pack_blob *pb,
                                   struct silofs_unode_info *ui)
{
	int err;

	ui_incref(ui);
	err = pac_do_refill_shadow_unode(pa_ctx, pb, ui);
	ui_decref(ui);
	return err;
}

static int pac_refill_shadow_super(struct silofs_pack_ctx *pa_ctx,
                                   const struct silofs_pack_blob *pb,
                                   struct silofs_sb_info *sbi)
{
	return pac_refill_shadow_unode(pa_ctx, pb, &sbi->sb_ui);
}

static int pac_refill_shadow_spnode(struct silofs_pack_ctx *pa_ctx,
                                    const struct silofs_pack_blob *pb,
                                    struct silofs_spnode_info *sni)
{
	return pac_refill_shadow_unode(pa_ctx, pb, &sni->sn_ui);
}

static int pac_refill_shadow_spleaf(struct silofs_pack_ctx *pa_ctx,
                                    const struct silofs_pack_blob *pb,
                                    struct silofs_spleaf_info *sli)
{
	return pac_refill_shadow_unode(pa_ctx, pb, &sli->sl_ui);
}

static int pac_require_blob_of(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_blobid *blobid,
                               struct silofs_blobref_info **out_bri)
{
	return silofs_repos_require_blob(pa_ctx->repos,
	                                 SILOFS_REPO_LOCAL, blobid, out_bri);
}

static int pac_make_shadow_super(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_uaddr *uaddr,
                                 struct silofs_sb_info **out_sbi)
{
	return silofs_shadow_super_at(pa_ctx->uber, false, uaddr, out_sbi);
}

static int pac_make_shadow_spnode(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spnode_info **out_sni)
{
	return silofs_shadow_spnode_at(pa_ctx->uber, false, uaddr, out_sni);
}

static int pac_make_shadow_spleaf(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spleaf_info **out_sli)
{
	return silofs_shadow_spleaf_at(pa_ctx->uber, false, uaddr, out_sli);
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
	if (pqs_has_pblob(&pa_ctx->pqs, &warm)) {
		/* already restored */
		return 0;
	}
	err = sli_resolve_cold_at(spit->sli, voff, &cold);
	if (err) {
		return err;
	}
	err = pac_put_new_pblob(pa_ctx, &cold, &pb_cold);
	if (err) {
		return err;
	}
	err = pac_put_new_pblob(pa_ctx, &warm, &pb_warm);
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
	voff = off_max(vrange.beg, spit->voff);
	while (voff < vrange.end) {
		err = pac_exec_restore_vdata_blob(pa_ctx, spit, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = vrange_next(&vrange, voff);
	}
	return 0;
}

static int
pac_exec_restore_by_spnode1(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid cold;
	struct silofs_vrange vrange;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_spleaf_info *sli = NULL;
	loff_t voff;
	int err;

	err = silofs_sni_cold_blob(spit->sni1, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_shadow_pblob(pa_ctx, &cold, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	sni_vrange(spit->sni1, &vrange);
	voff = off_max(vrange.beg, spit->voff);
	while (voff < vrange.end) {
		err = silofs_sni_subref_of(spit->sni1, voff, &uaddr);
		if (err == -ENOENT) {
			err = 0;
			break;
		}
		err = pac_make_shadow_spleaf(pa_ctx, &uaddr, &sli);
		if (err) {
			break;
		}
		err = pac_refill_shadow_spleaf(pa_ctx, pb_shadow, sli);
		if (err) {
			break;
		}
		sli = NULL;
		voff = vrange_next(&vrange, voff);
	}
out:
	pblob_del(pb_shadow);
	return err;
}

static int
pac_exec_restore_by_spnode(struct silofs_pack_ctx *pa_ctx,
                           struct silofs_spnode_info *sni, loff_t sp_voff)
{
	struct silofs_uaddr uaddr;
	struct silofs_blobid cold;
	struct silofs_vrange vrange;
	struct silofs_pack_blob *pb_shadow = NULL;
	struct silofs_spnode_info *sni_shadow = NULL;
	loff_t voff;
	int err;

	err = silofs_sni_cold_blob(sni, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_shadow_pblob(pa_ctx, &cold, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	sni_vrange(sni, &vrange);
	voff = off_max(vrange.beg, sp_voff);
	while (voff < vrange.end) {
		err = silofs_sni_subref_of(sni, voff, &uaddr);
		if (err == -ENOENT) {
			err = 0;
			break;
		}
		err = pac_make_shadow_spnode(pa_ctx, &uaddr, &sni_shadow);
		if (err) {
			break;
		}
		err = pac_refill_shadow_spnode(pa_ctx, pb_shadow, sni_shadow);
		if (err) {
			break;
		}
		sni_shadow = NULL;
		voff = vrange_next(&vrange, voff);
	}
out:
	pblob_del(pb_shadow);
	return err;
}

static int
pac_exec_restore_by_spnode2(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	return pac_exec_restore_by_spnode(pa_ctx, spit->sni2, spit->voff);
}

static int
pac_exec_restore_by_spnode3(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	return pac_exec_restore_by_spnode(pa_ctx, spit->sni3, spit->voff);
}

static int
pac_exec_restore_by_spnode4(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	return pac_exec_restore_by_spnode(pa_ctx, spit->sni4, spit->voff);
}

static int
pac_exec_restore_by_spnode5(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_space_iter *spit)
{
	return pac_exec_restore_by_spnode(pa_ctx, spit->sni5, spit->voff);
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

	err = silofs_sbi_cold_blob(spit->sbi, spit->vspace, &cold);
	if (err) {
		goto out;
	}
	err = pac_new_shadow_pblob(pa_ctx, &cold, &pb_shadow);
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
	err = pac_make_shadow_spnode(pa_ctx, &uaddr, &sni);
	if (err) {
		goto out;
	}
	err = pac_refill_shadow_spnode(pa_ctx, pb_shadow, sni);
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

	silofs_bootsec_sb_uaddr(pa_ctx->cold_bsec, &sb_uaddr);
	silofs_bootsec_sb_cold(pa_ctx->cold_bsec, &cold);

	err = pac_new_shadow_pblob(pa_ctx, &cold, &pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_restore_shadow_blob(pa_ctx, &cold, pb_shadow);
	if (err) {
		goto out;
	}
	err = pac_make_shadow_super(pa_ctx, &sb_uaddr, &sbi);
	if (err) {
		goto out;
	}
	err = pac_refill_shadow_super(pa_ctx, pb_shadow, sbi);
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
	case SILOFS_HEIGHT_SPNODE5:
		err = pac_exec_restore_by_spnode5(pa_ctx, spit);
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
	case SILOFS_HEIGHT_SPNODE1:
		err = pac_exec_restore_by_spnode1(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = pac_exec_restore_at_spleaf(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
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
	err = pac_restore_unode_into(pa_ctx, ui, bkaddr);
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

static int pac_post_restore_at_spnode1(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sni1->sn_ui);
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

static int pac_post_restore_at_spnode5(struct silofs_pack_ctx *pa_ctx,
                                       const struct silofs_space_iter *spit)
{
	return pac_post_restore_at_unode(pa_ctx, &spit->sni5->sn_ui);
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
	case SILOFS_HEIGHT_SPNODE1:
		err = pac_post_restore_at_spnode1(pa_ctx, spit);
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
	case SILOFS_HEIGHT_SPNODE5:
		err = pac_post_restore_at_spnode5(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_SUPER:
		err = pac_post_restore_at_super(pa_ctx, spit);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	pac_post_cleanups_at(pa_ctx, spit);
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
	pa_ctx->vis.exec_hook = unpack_exec;
	pa_ctx->vis.post_hook = unpack_post;
	return silofs_walk_space_tree(pa_ctx->task, pa_ctx->sbi,
	                              &pa_ctx->vis, false);
}

static void pac_reassign_warm_bootsec(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_bootsec *bsec)
{
	silofs_bootsec_init(bsec);
	silofs_bootsec_set_sb_uaddr(bsec, sbi_uaddr(pa_ctx->sbi));
	silofs_bootsec_clear_keyhash(bsec);
}

int silofs_unpack_fs(struct silofs_task *task,
                     const struct silofs_ivkey *ivkey,
                     const struct silofs_bootsec *cold_bsec,
                     struct silofs_bootsec *out_warm_bsec)
{
	struct silofs_pack_ctx pa_ctx;
	int err;

	err = pac_init(&pa_ctx, true, task, ivkey);
	if (err) {
		return err;
	}
	pa_ctx.cold_bsec = cold_bsec;
	pa_ctx.forced = task->t_uber->ub.fs_args->restore_forced;

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
	pac_reassign_warm_bootsec(&pa_ctx, out_warm_bsec);
out:
	pac_fini(&pa_ctx);
	return err;
}
