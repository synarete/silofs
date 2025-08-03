/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include "infra.h"
#include "bs.h"
#include "fs.h"
#include "env.h"
#include "walk.h"
#include "arre.h"

struct silofs_ar_desc {
	struct silofs_caddr caddr;
	struct silofs_laddr laddr;
	size_t len;
};

struct silofs_ar_desc_info {
	struct silofs_list_head lh;
	struct silofs_ar_desc ard;
};

struct silofs_ar_index_view {
	struct silofs_ar_hdr1k *hdr;
	struct silofs_ar_desc256b *descs;
	size_t ndescs_max;
	size_t ndescs;
};

struct silofs_ar_index {
	struct silofs_mdigest mdigest;
	struct silofs_listq descq;
	struct silofs_alloc *alloc;
};

struct silofs_ar_ctx {
	struct silofs_ar_index aridx;
	struct silofs_task_ctx *task;
	struct silofs_env *env;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t arhdr1k_magic(const struct silofs_ar_hdr1k *ah1k)
{
	return silofs_le64_to_cpu(ah1k->ph_magic);
}

static void arhdr1k_set_magic(struct silofs_ar_hdr1k *ah1k, uint64_t magic)
{
	ah1k->ph_magic = silofs_cpu_to_le64(magic);
}

static uint32_t arhdr1k_version(const struct silofs_ar_hdr1k *ah1k)
{
	return silofs_le32_to_cpu(ah1k->ph_version);
}

static void arhdr1k_set_version(struct silofs_ar_hdr1k *ah1k, uint32_t vers)
{
	ah1k->ph_version = silofs_cpu_to_le32(vers);
}

static void arhdr1k_set_flags(struct silofs_ar_hdr1k *ah1k, uint32_t flags)
{
	ah1k->ph_flags = silofs_cpu_to_le32(flags);
}

static size_t arhdr1k_ndescs(const struct silofs_ar_hdr1k *ah1k)
{
	return silofs_le64_to_cpu(ah1k->ph_ndescs);
}

static void arhdr1k_set_ndescs(struct silofs_ar_hdr1k *ah1k, size_t ndescs)
{
	ah1k->ph_ndescs = silofs_cpu_to_le64(ndescs);
}

static uint64_t arhdr1k_descs_csum(const struct silofs_ar_hdr1k *ah1k)
{
	return silofs_le64_to_cpu(ah1k->ph_descs_csum);
}

static void arhdr1k_set_descs_csum(struct silofs_ar_hdr1k *ah1k, uint64_t csum)
{
	ah1k->ph_descs_csum = silofs_cpu_to_le64(csum);
}

static uint64_t arhdr1k_hdr_csum(const struct silofs_ar_hdr1k *ah1k)
{
	return silofs_le64_to_cpu(ah1k->ph_hdr_csum);
}

static void arhdr1k_set_hdr_csum(struct silofs_ar_hdr1k *ah1k, uint64_t csum)
{
	ah1k->ph_hdr_csum = silofs_cpu_to_le64(csum);
}

static void arhdr1k_init(struct silofs_ar_hdr1k *ah1k)
{
	silofs_memzero(ah1k, sizeof(*ah1k));
	arhdr1k_set_magic(ah1k, SILOFS_AR_INDEX_MAGIC);
	arhdr1k_set_version(ah1k, SILOFS_PACK_VERSION);
	arhdr1k_set_flags(ah1k, 0);
	arhdr1k_set_ndescs(ah1k, 0);
	arhdr1k_set_descs_csum(ah1k, 0);
	arhdr1k_set_hdr_csum(ah1k, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ard_init(struct silofs_ar_desc *ard,
                     const struct silofs_laddr *laddr, size_t len)
{
	silofs_memzero(ard, sizeof(*ard));
	silofs_laddr_assign(&ard->laddr, laddr);
	ard->len = len;
}

static void ard_fini(struct silofs_ar_desc *ard)
{
	silofs_caddr_reset(&ard->caddr);
	silofs_laddr_reset(&ard->laddr);
	ard->len = 0;
}

static void
ard_caddr(const struct silofs_ar_desc *ard, struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &ard->caddr);
}

static void
ard_update_caddr(struct silofs_ar_desc *ard, const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&ard->caddr, caddr);
}

static void ard_update_caddr_by(struct silofs_ar_desc *ard,
                                const struct silofs_mdigest *md,
                                const struct silofs_rovec *rov)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_caddr_of(md, &iov, 1, SILOFS_CTYPE_ENCSEG, &caddr);
	ard_update_caddr(ard, &caddr);
}

static void ardsc256b_reset(struct silofs_ar_desc256b *ard256)
{
	memset(ard256, 0, sizeof(*ard256));
}

static void ardsc256b_htox(struct silofs_ar_desc256b *ard256,
                           const struct silofs_ar_desc *ard)
{
	ardsc256b_reset(ard256);
	silofs_caddr64b_htox(&ard256->pd_caddr, &ard->caddr);
	silofs_laddr64b_htox(&ard256->pd_laddr, &ard->laddr);
	ard256->pd_len = silofs_cpu_to_le64(ard->len);
}

static void ardsc256b_xtoh(const struct silofs_ar_desc256b *ard256,
                           struct silofs_ar_desc *ard)
{
	silofs_caddr64b_xtoh(&ard256->pd_caddr, &ard->caddr);
	silofs_laddr64b_xtoh(&ard256->pd_laddr, &ard->laddr);
	ard->len = silofs_le64_to_cpu(ard256->pd_len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ar_desc_info *
adi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_ar_desc_info *adi = NULL;

	if (lh != NULL) {
		adi = container_of2(lh, struct silofs_ar_desc_info, lh);
	}
	return unconst(adi);
}

static struct silofs_ar_desc_info *adi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ar_desc_info *adi = NULL;

	adi = silofs_memalloc(alloc, sizeof(*adi), 0);
	return adi;
}

static void
adi_free(struct silofs_ar_desc_info *adi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, adi, sizeof(*adi), 0);
}

static void adi_init(struct silofs_ar_desc_info *adi,
                     const struct silofs_laddr *laddr, size_t len)
{
	silofs_list_head_init(&adi->lh);
	ard_init(&adi->ard, laddr, len);
}

static void adi_fini(struct silofs_ar_desc_info *adi)
{
	silofs_list_head_fini(&adi->lh);
	ard_fini(&adi->ard);
}

static struct silofs_ar_desc_info *
adi_new(const struct silofs_laddr *laddr, size_t len,
        struct silofs_alloc *alloc)
{
	struct silofs_ar_desc_info *adi;

	adi = adi_malloc(alloc);
	if (adi != NULL) {
		adi_init(adi, laddr, len);
	}
	return adi;
}

static void
adi_del(struct silofs_ar_desc_info *adi, struct silofs_alloc *alloc)
{
	if (adi != NULL) {
		adi_fini(adi);
		adi_free(adi, alloc);
	}
}

static void adi_caddr(const struct silofs_ar_desc_info *adi,
                      struct silofs_caddr *out_caddr)
{
	ard_caddr(&adi->ard, out_caddr);
}

static void adi_update_caddr(struct silofs_ar_desc_info *adi,
                             const struct silofs_caddr *caddr)
{
	ard_update_caddr(&adi->ard, caddr);
}

static bool adi_ismbr(const struct silofs_ar_desc_info *adi)
{
	const enum silofs_mtype mtype = silofs_laddr_mtype(&adi->ard.laddr);

	return (mtype == SILOFS_MTYPE_MBR);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int check_ar_index_size(size_t sz)
{
	const size_t sz_min = SILOFS_AR_INDEX_SIZE_MIN;
	const size_t sz_max = SILOFS_AR_INDEX_SIZE_MAX;

	return ((sz_min <= sz) && (sz <= sz_max)) ? 0 : -SILOFS_EINVAL;
}

static void *data_at(void *base, size_t pos)
{
	uint8_t *dat = base;

	return &dat[pos];
}

static int aiview_setup(struct silofs_ar_index_view *aiv, void *dat, size_t sz)
{
	const size_t hdr_size = sizeof(struct silofs_ar_hdr1k);
	const size_t dsc_size = sizeof(struct silofs_ar_desc256b);
	int err;

	err = check_ar_index_size(sz);
	if (err) {
		return err;
	}
	aiv->hdr = dat;
	aiv->descs = data_at(dat, hdr_size);
	aiv->ndescs_max = (sz - hdr_size) / dsc_size;
	aiv->ndescs = 0;
	return 0;
}

static int
aiview_setup2(struct silofs_ar_index_view *aiv, const void *dat, size_t sz)
{
	return aiview_setup(aiv, unconst(dat), sz);
}

static uint64_t aiview_calc_descs_csum(const struct silofs_ar_index_view *aiv)
{
	const uint64_t seed = SILOFS_AR_INDEX_MAGIC;
	const struct silofs_ar_desc256b *descs = aiv->descs;
	const size_t len = aiv->ndescs_max * sizeof(*descs);

	return silofs_hash_xxh64(descs, len, seed);
}

static uint64_t aiview_calc_hdr_csum(const struct silofs_ar_index_view *aiv)
{
	const uint64_t seed = SILOFS_AR_INDEX_MAGIC;
	const struct silofs_ar_hdr1k *ah1k = aiv->hdr;
	const size_t len = sizeof(*ah1k) - sizeof(ah1k->ph_hdr_csum);

	return silofs_hash_xxh64(ah1k, len, seed);
}

static void aiview_encode_hdr(struct silofs_ar_index_view *aiv)
{
	struct silofs_ar_hdr1k *ah1k = aiv->hdr;

	arhdr1k_init(ah1k);
	arhdr1k_set_ndescs(ah1k, aiv->ndescs);
	arhdr1k_set_descs_csum(ah1k, aiview_calc_descs_csum(aiv));
	arhdr1k_set_hdr_csum(ah1k, aiview_calc_hdr_csum(aiv));
}

static void aiview_decode_hdr(struct silofs_ar_index_view *aiv)
{
	aiv->ndescs = arhdr1k_ndescs(aiv->hdr);
}

static int aiview_check_hdr(const struct silofs_ar_index_view *aiv)
{
	const struct silofs_ar_hdr1k *ah1k = aiv->hdr;
	uint64_t csum_set, csum_exp;

	if (arhdr1k_magic(ah1k) != SILOFS_AR_INDEX_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (arhdr1k_version(ah1k) != SILOFS_PACK_VERSION) {
		return -SILOFS_EPROTO;
	}
	csum_set = arhdr1k_hdr_csum(ah1k);
	csum_exp = aiview_calc_hdr_csum(aiv);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	csum_set = arhdr1k_descs_csum(ah1k);
	csum_exp = aiview_calc_descs_csum(aiv);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	return 0;
}

static void aiview_calc_caddr(const struct silofs_ar_index_view *aiv,
                              const struct silofs_mdigest *md,
                              struct silofs_caddr *out_caddr)
{
	const struct silofs_ar_desc256b *descs = aiv->descs;
	const struct silofs_ar_hdr1k *ah1k = aiv->hdr;
	struct iovec iov[2];

	iov[0].iov_base = unconst(ah1k);
	iov[0].iov_len = sizeof(*ah1k);
	iov[1].iov_base = unconst(descs);
	iov[1].iov_len = aiv->ndescs_max * sizeof(*descs);

	silofs_calc_caddr_of(md, iov, 2, SILOFS_CTYPE_PACKIDX, out_caddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void aridx_link_desc(struct silofs_ar_index *aridx,
                            struct silofs_ar_desc_info *adi, bool front)
{
	if (front) {
		silofs_listq_push_front(&aridx->descq, &adi->lh);
	} else {
		silofs_listq_push_back(&aridx->descq, &adi->lh);
	}
}

static void aridx_unlink_desc(struct silofs_ar_index *aridx,
                              struct silofs_ar_desc_info *adi)
{
	silofs_listq_remove(&aridx->descq, &adi->lh);
}

static struct silofs_ar_desc_info *
aridx_add_desc(struct silofs_ar_index *aridx, const struct silofs_laddr *laddr,
               size_t len, bool front)
{
	struct silofs_ar_desc_info *adi;

	adi = adi_new(laddr, len, aridx->alloc);
	if (adi != NULL) {
		aridx_link_desc(aridx, adi, front);
	}
	return adi;
}

static void
aridx_rm_desc(struct silofs_ar_index *aridx, struct silofs_ar_desc_info *adi)
{
	aridx_unlink_desc(aridx, adi);
	adi_del(adi, aridx->alloc);
}

static struct silofs_ar_desc_info *
aridx_pop_desc(struct silofs_ar_index *aridx)
{
	struct silofs_list_head *lh;
	struct silofs_ar_desc_info *adi = NULL;

	lh = silofs_listq_pop_front(&aridx->descq);
	if (lh != NULL) {
		adi = adi_from_lh(lh);
	}
	return adi;
}

static const struct silofs_ar_desc_info *
aridx_next_desc(const struct silofs_ar_index *aridx,
                const struct silofs_ar_desc_info *curr)
{
	const struct silofs_list_head *lh;

	if (curr == NULL) {
		lh = silofs_listq_front(&aridx->descq);
	} else {
		lh = silofs_listq_next(&aridx->descq, &curr->lh);
	}
	return adi_from_lh(lh);
}

static void aridx_clear_descq(struct silofs_ar_index *aridx)
{
	struct silofs_ar_desc_info *adi;

	adi = aridx_pop_desc(aridx);
	while (adi != NULL) {
		adi_del(adi, aridx->alloc);
		adi = aridx_pop_desc(aridx);
	}
}

static size_t aridx_ndescs_inq(const struct silofs_ar_index *aridx)
{
	return aridx->descq.sz;
}

static size_t aridx_size_of(size_t ndesc)
{
	const size_t align = SILOFS_LBK_SIZE;
	const size_t hdr_size = sizeof(struct silofs_ar_hdr1k);
	const size_t dsc_size = sizeof(struct silofs_ar_desc256b);
	const size_t descs_total_size = ndesc * dsc_size;
	const size_t enc_total_size = hdr_size + descs_total_size;

	return silofs_div_round_up(enc_total_size, align) * align;
}

static int
aridx_init(struct silofs_ar_index *aridx, struct silofs_alloc *alloc)
{
	silofs_listq_init(&aridx->descq);
	aridx->alloc = alloc;
	return silofs_mdigest_init(&aridx->mdigest);
}

static void aridx_fini(struct silofs_ar_index *aridx)
{
	aridx_clear_descq(aridx);
	silofs_listq_fini(&aridx->descq);
	silofs_mdigest_fini(&aridx->mdigest);
	aridx->alloc = NULL;
}

static size_t aridx_encsize(const struct silofs_ar_index *aridx)
{
	return aridx_size_of(aridx_ndescs_inq(aridx));
}

static int aridx_encode_descs(const struct silofs_ar_index *aridx,
                              struct silofs_ar_index_view *aiview)
{
	const struct silofs_list_head *itr = NULL;
	const struct silofs_ar_desc_info *adi = NULL;
	const struct silofs_listq *descq = &aridx->descq;
	struct silofs_ar_desc256b *pdx = NULL;

	aiview->ndescs = 0;
	itr = silofs_listq_front(descq);
	while (itr != NULL) {
		if (aiview->ndescs >= aiview->ndescs_max) {
			return -SILOFS_EINVAL;
		}
		adi = adi_from_lh(itr);
		pdx = &aiview->descs[aiview->ndescs++];
		ardsc256b_htox(pdx, &adi->ard);
		itr = silofs_listq_next(descq, itr);
	}
	return 0;
}

static int aridx_decode_descs(struct silofs_ar_index *aridx,
                              const struct silofs_ar_index_view *aiview)
{
	struct silofs_ar_desc_info *adi = NULL;
	const struct silofs_ar_desc256b *pd256 = NULL;

	for (size_t i = 0; i < aiview->ndescs; ++i) {
		pd256 = &aiview->descs[i];
		adi = aridx_add_desc(aridx, silofs_laddr_none(), 0, false);
		if (adi == NULL) {
			return -SILOFS_ENOMEM;
		}
		ardsc256b_xtoh(pd256, &adi->ard);
	}
	return 0;
}

static void aridx_encode_meta(const struct silofs_ar_index *aridx,
                              struct silofs_ar_index_view *aiview)
{
	silofs_unused(aridx);
	aiview_encode_hdr(aiview);
}

static int aridx_decode_meta(struct silofs_ar_index *aridx,
                             struct silofs_ar_index_view *aiview)
{
	int err;

	silofs_unused(aridx);
	err = aiview_check_hdr(aiview);
	if (err) {
		return err;
	}
	aiview_decode_hdr(aiview);
	return 0;
}

static void aridx_calc_caddr_of(const struct silofs_ar_index *aridx,
                                const struct silofs_ar_index_view *aiview,
                                struct silofs_caddr *out_caddr)
{
	aiview_calc_caddr(aiview, &aridx->mdigest, out_caddr);
}

static int
aridx_encode(struct silofs_ar_index *aridx, struct silofs_rwvec *rwv,
             struct silofs_caddr *out_caddr)
{
	struct silofs_ar_index_view aiview = { .hdr = NULL, .descs = NULL };
	const size_t esz = aridx_encsize(aridx);
	int err;

	if (esz < rwv->rwv_len) {
		return -SILOFS_EINVAL;
	}
	err = aiview_setup(&aiview, rwv->rwv_base, rwv->rwv_len);
	if (err) {
		return err;
	}
	err = aridx_encode_descs(aridx, &aiview);
	if (err) {
		return err;
	}
	aridx_encode_meta(aridx, &aiview);
	aridx_calc_caddr_of(aridx, &aiview, out_caddr);
	return 0;
}

static int aridx_check_caddr(const struct silofs_ar_index *aridx,
                             const struct silofs_caddr *caddr,
                             const struct silofs_ar_index_view *aiview)
{
	struct silofs_caddr caddr_calc;

	aiview_calc_caddr(aiview, &aridx->mdigest, &caddr_calc);
	return silofs_caddr_isequal(caddr, &caddr_calc) ? 0 : -SILOFS_ECSUM;
}

static int
aridx_decode(struct silofs_ar_index *aridx, const struct silofs_caddr *caddr,
             const struct silofs_rovec *rov)
{
	struct silofs_ar_index_view aiview = { .hdr = NULL, .descs = NULL };
	int err;

	err = check_ar_index_size(rov->rov_len);
	if (err) {
		return err;
	}
	err = aiview_setup2(&aiview, rov->rov_base, rov->rov_len);
	if (err) {
		return err;
	}
	err = aridx_check_caddr(aridx, caddr, &aiview);
	if (err) {
		return err;
	}
	err = aridx_decode_meta(aridx, &aiview);
	if (err) {
		return err;
	}
	err = aridx_decode_descs(aridx, &aiview);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_alloc *arc_alloc(const struct silofs_ar_ctx *ar_ctx)
{
	return ar_ctx->env->base.alloc;
}

static struct silofs_repo *arc_repo(const struct silofs_ar_ctx *ar_ctx)
{
	return ar_ctx->env->base.repo;
}

static int arc_acquire_buf(const struct silofs_ar_ctx *ar_ctx, size_t len,
                           struct silofs_bytebuf *out_bbuf)
{
	void *dat;

	dat = silofs_memalloc(arc_alloc(ar_ctx), len, SILOFS_ALLOCF_BZERO);
	if (dat == NULL) {
		return -SILOFS_ENOMEM;
	}
	silofs_bytebuf_init2(out_bbuf, dat, len);
	return 0;
}

static void arc_release_buf(const struct silofs_ar_ctx *ar_ctx,
                            struct silofs_bytebuf *bbuf)
{
	if (bbuf && bbuf->cap) {
		silofs_memfree(arc_alloc(ar_ctx), bbuf->ptr, bbuf->cap, 0);
		silofs_bytebuf_fini(bbuf);
	}
}

static int arc_init(struct silofs_ar_ctx *ar_ctx, struct silofs_task_ctx *task)
{
	struct silofs_env *env = task->t_env;

	silofs_memzero(ar_ctx, sizeof(*ar_ctx));
	ar_ctx->task = task;
	ar_ctx->env = env;
	return aridx_init(&ar_ctx->aridx, arc_alloc(ar_ctx));
}

static void arc_fini(struct silofs_ar_ctx *ar_ctx)
{
	aridx_fini(&ar_ctx->aridx);
	ar_ctx->task = NULL;
	ar_ctx->env = NULL;
}

static int arc_stat_pack(const struct silofs_ar_ctx *ar_ctx,
                         const struct silofs_caddr *caddr, size_t *out_sz)
{
	ssize_t sz = -1;
	int err;

	err = silofs_repo_stat_pack(arc_repo(ar_ctx), caddr, &sz);
	if (err) {
		return err;
	}
	*out_sz = (size_t)sz;
	return 0;
}

static int arc_send_to_repo(const struct silofs_ar_ctx *ar_ctx,
                            const struct silofs_caddr *caddr,
                            const struct silofs_rovec *rov)
{
	return silofs_repo_save_pack(arc_repo(ar_ctx), caddr, rov);
}

static int arc_recv_from_repo(const struct silofs_ar_ctx *ar_ctx,
                              const struct silofs_caddr *caddr,
                              const struct silofs_rwvec *rwv)
{
	return silofs_repo_load_pack(arc_repo(ar_ctx), caddr, rwv);
}

static int
arc_send_pack(const struct silofs_ar_ctx *ar_ctx,
              const struct silofs_caddr *caddr, const void *dat, size_t len)
{
	const struct silofs_rovec rov = { .rov_base = dat, .rov_len = len };
	size_t sz = 0;
	int err;

	err = arc_stat_pack(ar_ctx, caddr, &sz);
	if ((err == -ENOENT) || (!err && (sz != len))) {
		err = arc_send_to_repo(ar_ctx, caddr, &rov);
	}
	return err;
}

static int
arc_recv_pack(const struct silofs_ar_ctx *ar_ctx,
              const struct silofs_caddr *caddr, void *dat, size_t len)
{
	const struct silofs_rwvec rwv = { .rwv_base = dat, .rwv_len = len };

	return arc_recv_from_repo(ar_ctx, caddr, &rwv);
}

static int
arc_load_seg(const struct silofs_ar_ctx *ar_ctx,
             const struct silofs_laddr *laddr, void *seg, size_t len)
{
	int err;

	err = silofs_repo_read_at(arc_repo(ar_ctx), laddr, seg, len);
	if (err) {
		log_err("failed to read: mtype=%d pos=%ld len=%zu err=%d",
		        silofs_laddr_mtype(laddr), laddr->pos, len, err);
	}
	return err;
}

static int
arc_save_seg(const struct silofs_ar_ctx *ar_ctx,
             const struct silofs_laddr *laddr, void *seg, size_t len)
{
	const enum silofs_mtype mtype = silofs_laddr_mtype(laddr);
	int err;

	err = silofs_repo_require_lseg(arc_repo(ar_ctx), &laddr->lsid);
	if (err) {
		log_err("failed to require lseg: mtype=%d", (int)mtype);
		return err;
	}
	err = silofs_repo_require_laddr(arc_repo(ar_ctx), laddr);
	if (err) {
		log_err("failed to require laddr: mtype=%d err=%d", (int)mtype,
		        err);
		return err;
	}
	err = silofs_repo_write_at(arc_repo(ar_ctx), laddr, seg, len);
	if (err) {
		log_err("failed to write: mtype=%d err=%d", (int)mtype, err);
		return err;
	}
	return 0;
}

static int
arc_load_mbr(const struct silofs_ar_ctx *ar_ctx,
             const struct silofs_caddr *caddr, struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_mbr mbr = { .flags = SILOFS_MBRF_NONE };
	int err;

	err = silofs_load_mbr(ar_ctx->env, caddr, &mbr);
	if (err) {
		log_err("failed to load mbr: err=%d", err);
		return err;
	}
	err = silofs_encode_mbr(ar_ctx->env, &mbr, out_mbr1k);
	if (err) {
		log_err("failed to encode mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
arc_save_mbr(const struct silofs_ar_ctx *ar_ctx,
             const struct silofs_caddr *caddr, struct silofs_mbr1k *mbr1k)
{
	struct silofs_mbr mbr = { .flags = SILOFS_MBRF_NONE };
	struct silofs_caddr caddr2;
	int err;

	err = silofs_decode_mbr(ar_ctx->env, mbr1k, &mbr);
	if (err) {
		return err;
	}
	/* TODO: check proper caddr before save */
	err = silofs_save_mbr(ar_ctx->env, &mbr, &caddr2);
	if (err) {
		return err;
	}
	if (!silofs_caddr_isequal(caddr, &caddr2)) {
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int arc_update_hash_of(const struct silofs_ar_ctx *ar_ctx,
                              struct silofs_ar_desc_info *adi, const void *dat)
{
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = adi->ard.len,
	};
	const struct silofs_mdigest *md = &ar_ctx->aridx.mdigest;

	ard_update_caddr_by(&adi->ard, md, &rov);
	return 0;
}

static int arc_export_segdata(const struct silofs_ar_ctx *ar_ctx,
                              struct silofs_ar_desc_info *adi)
{
	const struct silofs_laddr *laddr = &adi->ard.laddr;
	const size_t len = adi->ard.len;
	void *seg = NULL;
	int err;

	seg = silofs_memalloc(arc_alloc(ar_ctx), len, 0);
	if (seg == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = arc_load_seg(ar_ctx, laddr, seg, len);
	if (err) {
		goto out;
	}
	err = arc_update_hash_of(ar_ctx, adi, seg);
	if (err) {
		goto out;
	}
	err = arc_send_pack(ar_ctx, &adi->ard.caddr, seg, len);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(arc_alloc(ar_ctx), seg, len, 0);
	return err;
}

static int arc_import_segdata(const struct silofs_ar_ctx *ar_ctx,
                              const struct silofs_ar_desc_info *adi)
{
	const struct silofs_laddr *laddr = &adi->ard.laddr;
	const size_t len = adi->ard.len;
	void *seg = NULL;
	int err;

	seg = silofs_memalloc(arc_alloc(ar_ctx), len, 0);
	if (seg == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = arc_recv_pack(ar_ctx, &adi->ard.caddr, seg, len);
	if (err) {
		goto out;
	}
	/* TODO: recheck caddr by content */
	err = arc_save_seg(ar_ctx, laddr, seg, len);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(arc_alloc(ar_ctx), seg, len, 0);
	return err;
}

static int arc_fs_mbr_caddr(const struct silofs_ar_ctx *ar_ctx,
                            struct silofs_caddr *out_caddr)
{
	return silofs_env_mbr_main_addr(ar_ctx->env, out_caddr);
}

static int arc_export_mbr(const struct silofs_ar_ctx *ar_ctx,
                          struct silofs_ar_desc_info *adi)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 0xff };
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = arc_fs_mbr_caddr(ar_ctx, &caddr);
	if (err) {
		return err;
	}
	err = arc_load_mbr(ar_ctx, &caddr, &mbr1k);
	if (err) {
		return err;
	}
	adi_update_caddr(adi, &caddr);

	err = arc_send_pack(ar_ctx, &adi->ard.caddr, &mbr1k, sizeof(mbr1k));
	if (err) {
		return err;
	}
	return 0;
}

static int arc_import_mbr(const struct silofs_ar_ctx *ar_ctx,
                          const struct silofs_ar_desc_info *adi)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 0xff };
	const struct silofs_caddr *caddr = &adi->ard.caddr;
	int err;

	err = arc_recv_pack(ar_ctx, caddr, &mbr1k, sizeof(mbr1k));
	if (err) {
		return err;
	}
	err = arc_save_mbr(ar_ctx, caddr, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_export_by_desc(struct silofs_ar_ctx *ar_ctx,
                              struct silofs_ar_desc_info *adi)
{
	int err;

	if (adi_ismbr(adi)) {
		err = arc_export_mbr(ar_ctx, adi);
	} else {
		err = arc_export_segdata(ar_ctx, adi);
	}
	return err;
}

static int arc_export_by_laddr(struct silofs_ar_ctx *ar_ctx,
                               const struct silofs_laddr *laddr, size_t len)
{
	struct silofs_ar_desc_info *adi = NULL;
	int err;

	adi = aridx_add_desc(&ar_ctx->aridx, laddr, len, true);
	if (adi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = arc_export_by_desc(ar_ctx, adi);
	if (err) {
		aridx_rm_desc(&ar_ctx->aridx, adi);
		return err;
	}
	return 0;
}

static int
arc_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr, size_t len)
{
	struct silofs_ar_ctx *ar_ctx = ctx;

	return arc_export_by_laddr(ar_ctx, laddr, len);
}

static int arc_export_fs(struct silofs_ar_ctx *ar_ctx)
{
	const struct silofs_laddr_visitor lvis = {
		.hook = arc_visit_laddr_cb,
		.userp = ar_ctx,
	};
	struct silofs_task_ctx *task = ar_ctx->task;

	return silofs_walkfs_at(task, silofs_get_sbi(task), &lvis);
}

static int
arc_encode_save_aridx(struct silofs_ar_ctx *ar_ctx, struct silofs_bytebuf *bb,
                      struct silofs_caddr *out_caddr)
{
	struct silofs_rwvec rwv = { .rwv_base = bb->ptr, .rwv_len = bb->len };
	struct silofs_rovec rov = { .rov_base = bb->ptr, .rov_len = bb->len };
	int err;

	err = aridx_encode(&ar_ctx->aridx, &rwv, out_caddr);
	if (err) {
		return err;
	}
	err = arc_send_to_repo(ar_ctx, out_caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_acquire_enc_buf(const struct silofs_ar_ctx *ar_ctx,
                               struct silofs_bytebuf *out_bbuf)
{
	const size_t bsz = aridx_encsize(&ar_ctx->aridx);
	int err;

	err = check_ar_index_size(bsz);
	if (!err) {
		err = arc_acquire_buf(ar_ctx, bsz, out_bbuf);
	}
	return err;
}

static int
arc_export_aridx(struct silofs_ar_ctx *ar_ctx, struct silofs_caddr *out_caddr)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	int err;

	err = arc_acquire_enc_buf(ar_ctx, &bb);
	if (err) {
		goto out;
	}
	err = arc_encode_save_aridx(ar_ctx, &bb, out_caddr);
	if (err) {
		goto out;
	}
out:
	arc_release_buf(ar_ctx, &bb);
	return err;
}

static int
arc_export_post(struct silofs_ar_ctx *ar_ctx, const struct silofs_caddr *caddr)
{
	silofs_env_set_pack_caddr(ar_ctx->env, caddr);
	return 0;
}

static int arc_do_export(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = arc_export_fs(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_export_aridx(ar_ctx, &caddr);
	if (err) {
		return err;
	}
	err = arc_export_post(ar_ctx, &caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_archive_fs(struct silofs_task_ctx *task)
{
	struct silofs_ar_ctx ar_ctx;
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = arc_init(&ar_ctx, task);
	if (err) {
		goto out;
	}
	err = arc_do_export(&ar_ctx);
	if (err) {
		goto out;
	}
out:
	arc_fini(&ar_ctx);
	return err;
}

static int arc_acquire_dec_buf(const struct silofs_ar_ctx *ar_ctx, size_t sz,
                               struct silofs_bytebuf *out_bbuf)
{
	return arc_acquire_buf(ar_ctx, sz, out_bbuf);
}

static int arc_load_decode_aridx(struct silofs_ar_ctx *ar_ctx,
                                 const struct silofs_caddr *caddr,
                                 struct silofs_bytebuf *bb)
{
	struct silofs_rwvec rwv = { .rwv_base = bb->ptr, .rwv_len = bb->len };
	struct silofs_rovec rov = { .rov_base = bb->ptr, .rov_len = bb->len };
	int err;

	err = arc_recv_from_repo(ar_ctx, caddr, &rwv);
	if (err) {
		return err;
	}
	err = aridx_decode(&ar_ctx->aridx, caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_stat_aridx(const struct silofs_ar_ctx *ar_ctx,
                          const struct silofs_caddr *caddr, size_t *out_sz)
{
	int err;

	err = arc_stat_pack(ar_ctx, caddr, out_sz);
	if (err) {
		return err;
	}
	err = check_ar_index_size(*out_sz);
	if (err) {
		log_warn("illegal archive aridx: size=%zu", *out_sz);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static const struct silofs_caddr *
arc_ar_packidx_caddr(const struct silofs_ar_ctx *ar_ctx)
{
	const struct silofs_env *env = ar_ctx->env;
	const struct silofs_caddr *caddr = &env->pack_caddr;

	silofs_assert_eq(caddr->ctype, SILOFS_CTYPE_PACKIDX);
	return caddr;
}

static int arc_import_aridx(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	const struct silofs_caddr *caddr = NULL;
	size_t sz = 0;
	int err;

	caddr = arc_ar_packidx_caddr(ar_ctx);
	err = arc_stat_aridx(ar_ctx, caddr, &sz);
	if (err) {
		goto out;
	}
	err = arc_acquire_dec_buf(ar_ctx, sz, &bb);
	if (err) {
		goto out;
	}
	err = arc_load_decode_aridx(ar_ctx, caddr, &bb);
	if (err) {
		goto out;
	}
out:
	arc_release_buf(ar_ctx, &bb);
	return err;
}

static int arc_import_by_desc(const struct silofs_ar_ctx *ar_ctx,
                              const struct silofs_ar_desc_info *adi)
{
	int err;

	if (adi_ismbr(adi)) {
		err = arc_import_mbr(ar_ctx, adi);
	} else {
		err = arc_import_segdata(ar_ctx, adi);
	}
	return err;
}

static int arc_import_fs(struct silofs_ar_ctx *ar_ctx)
{
	const struct silofs_ar_desc_info *adi = NULL;
	int err;

	adi = aridx_next_desc(&ar_ctx->aridx, adi);
	while (adi != NULL) {
		err = arc_import_by_desc(ar_ctx, adi);
		if (err) {
			return err;
		}
		adi = aridx_next_desc(&ar_ctx->aridx, adi);
	}
	return 0;
}

static int arc_import_post(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	const struct silofs_ar_desc_info *adi = NULL;
	size_t nmbrs = 0;

	adi = aridx_next_desc(&ar_ctx->aridx, adi);
	while (adi != NULL) {
		if (adi_ismbr(adi)) {
			adi_caddr(adi, &caddr);
			nmbrs++;
		}
		adi = aridx_next_desc(&ar_ctx->aridx, adi);
	}
	if (nmbrs != 1) {
		return -SILOFS_EBADPACK;
	}
	silofs_env_set_mbr_main_addr(ar_ctx->env, &caddr);
	return 0;
}

static int arc_do_import(struct silofs_ar_ctx *ar_ctx)
{
	int err;

	err = arc_import_aridx(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_import_fs(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_import_post(ar_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_restore_fs(struct silofs_task_ctx *task)
{
	struct silofs_ar_ctx ar_ctx;
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = arc_init(&ar_ctx, task);
	if (err) {
		goto out;
	}
	err = arc_do_import(&ar_ctx);
	if (err) {
		goto out;
	}
out:
	arc_fini(&ar_ctx);
	return err;
}
