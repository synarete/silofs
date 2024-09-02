/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/ps.h>
#include <silofs/fs.h>


struct silofs_par_desc {
	struct silofs_caddr             caddr;
	struct silofs_laddr             laddr;
};

struct silofs_par_desc_info {
	struct silofs_list_head         lh;
	struct silofs_par_desc          pd;
};

struct silofs_par_index_view {
	struct silofs_par_hdr1k        *hdr;
	struct silofs_par_desc256b     *descs;
	size_t ndescs_max;
	size_t ndescs;
};

struct silofs_par_index {
	struct silofs_mdigest           mdigest;
	struct silofs_listq             descq;
	struct silofs_alloc            *alloc;
};

struct silofs_par_ctx {
	struct silofs_par_index         pac_pindex;
	struct silofs_task             *pac_task;
	struct silofs_fsenv            *pac_fsenv;
	struct silofs_alloc            *pac_alloc;
	struct silofs_repo             *pac_repo;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static uint64_t parhdr1k_magic(const struct silofs_par_hdr1k *ph1k)
{
	return silofs_le64_to_cpu(ph1k->ph_magic);
}

static void parhdr1k_set_magic(struct silofs_par_hdr1k *ph1k, uint64_t magic)
{
	ph1k->ph_magic = silofs_cpu_to_le64(magic);
}

static uint32_t parhdr1k_version(const struct silofs_par_hdr1k *ph1k)
{
	return silofs_le32_to_cpu(ph1k->ph_version);
}

static void parhdr1k_set_version(struct silofs_par_hdr1k *ph1k,
                                 uint32_t vers)
{
	ph1k->ph_version = silofs_cpu_to_le32(vers);
}

static void parhdr1k_set_flags(struct silofs_par_hdr1k *ph1k,
                               uint32_t flags)
{
	ph1k->ph_flags = silofs_cpu_to_le32(flags);
}

static size_t parhdr1k_ndescs(const struct silofs_par_hdr1k *ph1k)
{
	return silofs_le64_to_cpu(ph1k->ph_ndescs);
}

static void parhdr1k_set_ndescs(struct silofs_par_hdr1k *ph1k,
                                size_t ndescs)
{
	ph1k->ph_ndescs = silofs_cpu_to_le64(ndescs);
}

static uint64_t parhdr1k_descs_csum(const struct silofs_par_hdr1k *ph1k)
{
	return silofs_le64_to_cpu(ph1k->ph_descs_csum);
}

static void
parhdr1k_set_descs_csum(struct silofs_par_hdr1k *ph1k, uint64_t csum)
{
	ph1k->ph_descs_csum = silofs_cpu_to_le64(csum);
}

static uint64_t parhdr1k_hdr_csum(const struct silofs_par_hdr1k *ph1k)
{
	return silofs_le64_to_cpu(ph1k->ph_hdr_csum);
}

static void parhdr1k_set_hdr_csum(struct silofs_par_hdr1k *ph1k, uint64_t csum)
{
	ph1k->ph_hdr_csum = silofs_cpu_to_le64(csum);
}

static void parhdr1k_init(struct silofs_par_hdr1k *ph1k)
{
	silofs_memzero(ph1k, sizeof(*ph1k));
	parhdr1k_set_magic(ph1k, SILOFS_PAR_INDEX_MAGIC);
	parhdr1k_set_version(ph1k, SILOFS_PACK_VERSION);
	parhdr1k_set_flags(ph1k, 0);
	parhdr1k_set_ndescs(ph1k, 0);
	parhdr1k_set_descs_csum(ph1k, 0);
	parhdr1k_set_hdr_csum(ph1k, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pd_init(struct silofs_par_desc *pd,
                    const struct silofs_laddr *laddr)
{
	silofs_memzero(pd, sizeof(*pd));
	silofs_laddr_assign(&pd->laddr, laddr);
}

static void pd_fini(struct silofs_par_desc *pd)
{
	silofs_laddr_reset(&pd->laddr);
}

static void pd_caddr(const struct silofs_par_desc *pd,
                     struct silofs_caddr *out_caddr)
{
	caddr_assign(out_caddr, &pd->caddr);
}

static void pd_update_caddr(struct silofs_par_desc *pd,
                            const struct silofs_caddr *caddr)
{
	caddr_assign(&pd->caddr, caddr);
}

static void pd_update_caddr_by(struct silofs_par_desc *pd,
                               const struct silofs_mdigest *md,
                               const struct silofs_rovec *rov)
{
	struct silofs_caddr caddr;
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_caddr_of(&iov, 1, SILOFS_CTYPE_ENCSEG, md, &caddr);
	pd_update_caddr(pd, &caddr);
}

static void pardsc256b_reset(struct silofs_par_desc256b *pd256)
{
	memset(pd256, 0, sizeof(*pd256));
}

static void pardsc256b_htox(struct silofs_par_desc256b *pd256,
                            const struct silofs_par_desc *ard)
{
	pardsc256b_reset(pd256);
	silofs_caddr64b_htox(&pd256->pd_caddr, &ard->caddr);
	silofs_laddr48b_htox(&pd256->pd_laddr, &ard->laddr);
}

static void pardsc256b_xtoh(const struct silofs_par_desc256b *pd256,
                            struct silofs_par_desc *ard)
{
	silofs_caddr64b_xtoh(&pd256->pd_caddr, &ard->caddr);
	silofs_laddr48b_xtoh(&pd256->pd_laddr, &ard->laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_par_desc_info *
pdi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_par_desc_info *pdi = NULL;

	if (lh != NULL) {
		pdi = container_of2(lh, struct silofs_par_desc_info, lh);
	}
	return unconst(pdi);
}

static struct silofs_par_desc_info *pdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_par_desc_info *pdi = NULL;

	pdi = silofs_memalloc(alloc, sizeof(*pdi), 0);
	return pdi;
}

static void pdi_free(struct silofs_par_desc_info *pdi,
                     struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, pdi, sizeof(*pdi), 0);
}

static void pdi_init(struct silofs_par_desc_info *pdi,
                     const struct silofs_laddr *laddr)
{
	silofs_list_head_init(&pdi->lh);
	pd_init(&pdi->pd, laddr);
}

static void pdi_fini(struct silofs_par_desc_info *pdi)
{
	silofs_list_head_fini(&pdi->lh);
	pd_fini(&pdi->pd);
}

static struct silofs_par_desc_info *
pdi_new(const struct silofs_laddr *laddr, struct silofs_alloc *alloc)
{
	struct silofs_par_desc_info *pdi;

	pdi = pdi_malloc(alloc);
	if (pdi != NULL) {
		pdi_init(pdi, laddr);
	}
	return pdi;
}

static void pdi_del(struct silofs_par_desc_info *pdi,
                    struct silofs_alloc *alloc)
{
	if (pdi != NULL) {
		pdi_fini(pdi);
		pdi_free(pdi, alloc);
	}
}

static void pdi_caddr(const struct silofs_par_desc_info *pdi,
                      struct silofs_caddr *out_caddr)
{
	pd_caddr(&pdi->pd, out_caddr);
}

static void pdi_update_caddr(struct silofs_par_desc_info *pdi,
                             const struct silofs_caddr *caddr)
{
	pd_update_caddr(&pdi->pd, caddr);
}

static bool pdi_isbootrec(const struct silofs_par_desc_info *pdi)
{
	return ltype_isbootrec(laddr_ltype(&pdi->pd.laddr));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int check_archive_pindex_size(size_t sz)
{
	return ((sz >= SILOFS_PAR_INDEX_SIZE_MIN) &&
	        (sz <= SILOFS_PAR_INDEX_SIZE_MAX)) ? 0 : -SILOFS_EINVAL;
}

static void *data_at(void *base, size_t pos)
{
	uint8_t *dat = base;

	return &dat[pos];
}

static int piview_setup(struct silofs_par_index_view *piv,
                        void *dat, size_t sz)
{
	const size_t hdr_size = sizeof(struct silofs_par_hdr1k);
	const size_t dsc_size = sizeof(struct silofs_par_desc256b);
	int err;

	err = check_archive_pindex_size(sz);
	if (err) {
		return err;
	}
	piv->hdr = dat;
	piv->descs = data_at(dat, hdr_size);
	piv->ndescs_max = (sz - hdr_size) / dsc_size;
	piv->ndescs = 0;
	return 0;
}

static int piview_setup2(struct silofs_par_index_view *piv,
                         const void *dat, size_t sz)
{
	return piview_setup(piv, unconst(dat), sz);
}

static uint64_t
piview_calc_descs_csum(const struct silofs_par_index_view *piv)
{
	const uint64_t seed = SILOFS_PAR_INDEX_MAGIC;
	const struct silofs_par_desc256b *descs = piv->descs;
	const size_t len = piv->ndescs_max * sizeof(*descs);

	return silofs_hash_xxh64(descs, len, seed);
}

static uint64_t
piview_calc_hdr_csum(const struct silofs_par_index_view *piv)
{
	const uint64_t seed = SILOFS_PAR_INDEX_MAGIC;
	const struct silofs_par_hdr1k *ph1k = piv->hdr;
	const size_t len = sizeof(*ph1k) - sizeof(ph1k->ph_hdr_csum);

	return silofs_hash_xxh64(ph1k, len, seed);
}

static void piview_encode_hdr(struct silofs_par_index_view *piv)
{
	struct silofs_par_hdr1k *ph1k = piv->hdr;

	parhdr1k_init(ph1k);
	parhdr1k_set_ndescs(ph1k, piv->ndescs);
	parhdr1k_set_descs_csum(ph1k, piview_calc_descs_csum(piv));
	parhdr1k_set_hdr_csum(ph1k, piview_calc_hdr_csum(piv));
}

static void piview_decode_hdr(struct silofs_par_index_view *piv)
{
	piv->ndescs = parhdr1k_ndescs(piv->hdr);
}

static int piview_check_hdr(const struct silofs_par_index_view *piv)
{
	const struct silofs_par_hdr1k *ph1k = piv->hdr;
	uint64_t csum_set, csum_exp;

	if (parhdr1k_magic(ph1k) != SILOFS_PAR_INDEX_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (parhdr1k_version(ph1k) != SILOFS_PACK_VERSION) {
		return -SILOFS_EPROTO;
	}
	csum_set = parhdr1k_hdr_csum(ph1k);
	csum_exp = piview_calc_hdr_csum(piv);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	csum_set = parhdr1k_descs_csum(ph1k);
	csum_exp = piview_calc_descs_csum(piv);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	return 0;
}

static void piview_calc_caddr(const struct silofs_par_index_view *piv,
                              const struct silofs_mdigest *md,
                              struct silofs_caddr *out_caddr)
{
	const struct silofs_par_desc256b *descs = piv->descs;
	const struct silofs_par_hdr1k *ph1k = piv->hdr;
	struct iovec iov[2];

	iov[0].iov_base = unconst(ph1k);
	iov[0].iov_len = sizeof(*ph1k);
	iov[1].iov_base = unconst(descs);
	iov[1].iov_len = piv->ndescs_max * sizeof(*descs);

	silofs_calc_caddr_of(iov, 2, SILOFS_CTYPE_PACKIDX, md, out_caddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void paridx_link_desc(struct silofs_par_index *paridx,
                             struct silofs_par_desc_info *pdi, bool front)
{
	if (front) {
		silofs_listq_push_front(&paridx->descq, &pdi->lh);
	} else {
		silofs_listq_push_back(&paridx->descq, &pdi->lh);
	}
}

static void paridx_unlink_desc(struct silofs_par_index *paridx,
                               struct silofs_par_desc_info *pdi)
{
	silofs_listq_remove(&paridx->descq, &pdi->lh);
}

static struct silofs_par_desc_info *
paridx_add_desc(struct silofs_par_index *paridx,
                const struct silofs_laddr *laddr, bool front)
{
	struct silofs_par_desc_info *pdi;

	pdi = pdi_new(laddr, paridx->alloc);
	if (pdi != NULL) {
		paridx_link_desc(paridx, pdi, front);
	}
	return pdi;
}

static void paridx_rm_desc(struct silofs_par_index *paridx,
                           struct silofs_par_desc_info *pdi)
{
	paridx_unlink_desc(paridx, pdi);
	pdi_del(pdi, paridx->alloc);
}

static struct silofs_par_desc_info *
pindex_pop_desc(struct silofs_par_index *pindex)
{
	struct silofs_list_head *lh;
	struct silofs_par_desc_info *pdi = NULL;

	lh = silofs_listq_pop_front(&pindex->descq);
	if (lh != NULL) {
		pdi = pdi_from_lh(lh);
	}
	return pdi;
}

static const struct silofs_par_desc_info *
pindex_next_desc(const struct silofs_par_index *pindex,
                 const struct silofs_par_desc_info *curr)
{
	const struct silofs_list_head *lh;

	if (curr == NULL) {
		lh = silofs_listq_front(&pindex->descq);
	} else {
		lh = silofs_listq_next(&pindex->descq, &curr->lh);
	}
	return pdi_from_lh(lh);
}

static void pindex_clear_descq(struct silofs_par_index *pindex)
{
	struct silofs_par_desc_info *pdi;

	pdi = pindex_pop_desc(pindex);
	while (pdi != NULL) {
		pdi_del(pdi, pindex->alloc);
		pdi = pindex_pop_desc(pindex);
	}
}

static size_t pindex_ndescs_inq(const struct silofs_par_index *pindex)
{
	return pindex->descq.sz;
}

static size_t pindex_size_of(size_t ndesc)
{
	const size_t align = SILOFS_LBK_SIZE;
	const size_t hdr_size = sizeof(struct silofs_par_hdr1k);
	const size_t dsc_size = sizeof(struct silofs_par_desc256b);
	const size_t descs_total_size = ndesc * dsc_size;
	const size_t enc_total_size = hdr_size + descs_total_size;

	return silofs_div_round_up(enc_total_size, align) * align;
}

static int pindex_init(struct silofs_par_index *pindex,
                       struct silofs_alloc *alloc)
{
	silofs_listq_init(&pindex->descq);
	pindex->alloc = alloc;
	return silofs_mdigest_init(&pindex->mdigest);
}

static void pindex_fini(struct silofs_par_index *pindex)
{
	pindex_clear_descq(pindex);
	silofs_listq_fini(&pindex->descq);
	silofs_mdigest_fini(&pindex->mdigest);
	pindex->alloc = NULL;
}

static size_t pindex_encsize(const struct silofs_par_index *pindex)
{
	return pindex_size_of(pindex_ndescs_inq(pindex));
}

static int pindex_encode_descs(const struct silofs_par_index *pindex,
                               struct silofs_par_index_view *piview)
{
	const struct silofs_list_head *itr = NULL;
	const struct silofs_par_desc_info *pdi = NULL;
	const struct silofs_listq *descq = &pindex->descq;
	struct silofs_par_desc256b *pdx = NULL;

	piview->ndescs = 0;
	itr = silofs_listq_front(descq);
	while (itr != NULL) {
		if (piview->ndescs >= piview->ndescs_max) {
			return -SILOFS_EINVAL;
		}
		pdi = pdi_from_lh(itr);
		pdx = &piview->descs[piview->ndescs++];
		pardsc256b_htox(pdx, &pdi->pd);
		itr = silofs_listq_next(descq, itr);
	}
	return 0;
}

static int pindex_decode_descs(struct silofs_par_index *pindex,
                               const struct silofs_par_index_view *piview)
{
	struct silofs_par_desc_info *pdi = NULL;
	const struct silofs_par_desc256b *pd256 = NULL;

	for (size_t i = 0; i < piview->ndescs; ++i) {
		pd256 = &piview->descs[i];
		pdi = paridx_add_desc(pindex, laddr_none(), false);
		if (pdi == NULL) {
			return -SILOFS_ENOMEM;
		}
		pardsc256b_xtoh(pd256, &pdi->pd);
	}
	return 0;
}


static void pindex_encode_meta(const struct silofs_par_index *pindex,
                               struct silofs_par_index_view *piview)
{
	silofs_unused(pindex);
	piview_encode_hdr(piview);
}

static int pindex_decode_meta(struct silofs_par_index *pindex,
                              struct silofs_par_index_view *piview)
{
	int err;

	silofs_unused(pindex);
	err = piview_check_hdr(piview);
	if (err) {
		return err;
	}
	piview_decode_hdr(piview);
	return 0;
}

static void pindex_calc_caddr_of(const struct silofs_par_index *pindex,
                                 const struct silofs_par_index_view *piview,
                                 struct silofs_caddr *out_caddr)
{
	piview_calc_caddr(piview, &pindex->mdigest, out_caddr);
}

static int pindex_encode(struct silofs_par_index *pindex,
                         struct silofs_rwvec *rwv,
                         struct silofs_caddr *out_caddr)
{
	struct silofs_par_index_view piview = { .hdr = NULL, .descs = NULL };
	const size_t esz = pindex_encsize(pindex);
	int err;

	if (esz < rwv->rwv_len) {
		return -SILOFS_EINVAL;
	}
	err = piview_setup(&piview, rwv->rwv_base, rwv->rwv_len);
	if (err) {
		return err;
	}
	err = pindex_encode_descs(pindex, &piview);
	if (err) {
		return err;
	}
	pindex_encode_meta(pindex, &piview);
	pindex_calc_caddr_of(pindex, &piview, out_caddr);
	return 0;
}

static int pindex_check_caddr(const struct silofs_par_index *pindex,
                              const struct silofs_caddr *caddr,
                              const struct silofs_par_index_view *piview)
{
	struct silofs_caddr caddr_calc;

	piview_calc_caddr(piview, &pindex->mdigest, &caddr_calc);
	return caddr_isequal(caddr, &caddr_calc) ? 0 : -SILOFS_ECSUM;
}

static int pindex_decode(struct silofs_par_index *pindex,
                         const struct silofs_caddr *caddr,
                         const struct silofs_rovec *rov)
{
	struct silofs_par_index_view piview = { .hdr = NULL, .descs = NULL };
	int err;

	err = check_archive_pindex_size(rov->rov_len);
	if (err) {
		return err;
	}
	err = piview_setup2(&piview, rov->rov_base, rov->rov_len);
	if (err) {
		return err;
	}
	err = pindex_check_caddr(pindex, caddr, &piview);
	if (err) {
		return err;
	}
	err = pindex_decode_meta(pindex, &piview);
	if (err) {
		return err;
	}
	err = pindex_decode_descs(pindex, &piview);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pac_acquire_buf(const struct silofs_par_ctx *pa_ctx, size_t len,
                           struct silofs_bytebuf *out_bbuf)
{
	void *dat;

	dat = silofs_memalloc(pa_ctx->pac_alloc, len, SILOFS_ALLOCF_BZERO);
	if (dat == NULL) {
		return -SILOFS_ENOMEM;
	}
	silofs_bytebuf_init2(out_bbuf, dat, len);
	return 0;
}

static void pac_release_buf(const struct silofs_par_ctx *pa_ctx,
                            struct silofs_bytebuf *bbuf)
{
	if (bbuf && bbuf->cap) {
		silofs_memfree(pa_ctx->pac_alloc, bbuf->ptr, bbuf->cap, 0);
		silofs_bytebuf_fini(bbuf);
	}
}

static int pac_init(struct silofs_par_ctx *pa_ctx,
                    struct silofs_task *task)
{
	struct silofs_fsenv *fsenv = task->t_fsenv;

	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
	pa_ctx->pac_task = task;
	pa_ctx->pac_fsenv = fsenv;
	pa_ctx->pac_alloc = fsenv->fse.alloc;
	pa_ctx->pac_repo = fsenv->fse.repo;
	return pindex_init(&pa_ctx->pac_pindex, pa_ctx->pac_alloc);
}

static void pac_fini(struct silofs_par_ctx *pa_ctx)
{
	pindex_fini(&pa_ctx->pac_pindex);
	pa_ctx->pac_task = NULL;
	pa_ctx->pac_fsenv = NULL;
	pa_ctx->pac_alloc = NULL;
	pa_ctx->pac_repo = NULL;
}

static int
pac_stat_pack(const struct silofs_par_ctx *pa_ctx,
              const struct silofs_caddr *caddr, size_t *out_sz)
{
	ssize_t sz = -1;
	int err;

	err = silofs_repo_stat_pack(pa_ctx->pac_repo, caddr, &sz);
	if (err) {
		return err;
	}
	*out_sz = (size_t)sz;
	return 0;
}

static int pac_send_to_repo(const struct silofs_par_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            const struct silofs_rovec *rov)
{
	return silofs_repo_save_pack(pa_ctx->pac_repo, caddr, rov);
}

static int pac_recv_from_repo(const struct silofs_par_ctx *pa_ctx,
                              const struct silofs_caddr *caddr,
                              const struct silofs_rwvec *rwv)
{
	return silofs_repo_load_pack(pa_ctx->pac_repo, caddr, rwv);
}

static int pac_send_pack(const struct silofs_par_ctx *pa_ctx,
                         const struct silofs_caddr *caddr,
                         const void *dat, size_t len)
{
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = len
	};
	size_t sz = 0;
	int err;

	err = pac_stat_pack(pa_ctx, caddr, &sz);
	if ((err == -ENOENT) || (!err && (sz != len))) {
		err = pac_send_to_repo(pa_ctx, caddr, &rov);
	}
	return err;
}

static int pac_recv_pack(const struct silofs_par_ctx *pa_ctx,
                         const struct silofs_caddr *caddr,
                         void *dat, size_t len)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = dat,
		.rwv_len = len
	};

	return pac_recv_from_repo(pa_ctx, caddr, &rwv);
}

static int pac_load_seg(const struct silofs_par_ctx *pa_ctx,
                        const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(pa_ctx->pac_repo, laddr, seg);
	if (err) {
		log_err("failed to read: ltype=%d len=%zu err=%d",
		        laddr_ltype(laddr), laddr->len, err);
	}
	return err;
}

static int pac_save_seg(const struct silofs_par_ctx *pa_ctx,
                        const struct silofs_laddr *laddr, void *seg)
{
	const enum silofs_ltype ltype = laddr_ltype(laddr);
	int err;

	err = silofs_repo_require_lseg(pa_ctx->pac_repo, &laddr->lsid);
	if (err) {
		log_err("failed to require lseg: ltype=%d", (int)ltype);
		return err;
	}
	err = silofs_repo_require_laddr(pa_ctx->pac_repo, laddr);
	if (err) {
		log_err("failed to require laddr: ltype=%d len=%zu err=%d",
		        (int)ltype, laddr->len, err);
		return err;
	}
	err = silofs_repo_write_at(pa_ctx->pac_repo, laddr, seg);
	if (err) {
		log_err("failed to write: ltype=%d len=%zu err=%d",
		        (int)ltype, laddr->len, err);
		return err;
	}
	return 0;
}

static int pac_load_bootrec(const struct silofs_par_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            struct silofs_bootrec1k *out_brec1k)
{
	struct silofs_bootrec brec = { .flags = 0 };
	int err;

	err = silofs_load_bootrec(pa_ctx->pac_fsenv, caddr, &brec);
	if (err) {
		log_err("failed to load bootrec: err=%d", err);
		return err;
	}
	err = silofs_encode_bootrec(pa_ctx->pac_fsenv, &brec, out_brec1k);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	return 0;
}

static int pac_save_bootrec(const struct silofs_par_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            struct silofs_bootrec1k *brec1k)
{
	struct silofs_bootrec brec = { .flags = 0 };
	struct silofs_caddr caddr2;
	int err;

	err = silofs_decode_bootrec(pa_ctx->pac_fsenv, brec1k, &brec);
	if (err) {
		return err;
	}
	/* TODO: check proper caddr before save */
	err = silofs_save_bootrec(pa_ctx->pac_fsenv, &brec, &caddr2);
	if (err) {
		return err;
	}
	if (!caddr_isequal(caddr, &caddr2)) {
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static int
pac_update_hash_of(const struct silofs_par_ctx *pa_ctx,
                   struct silofs_par_desc_info *pdi, const void *dat)
{
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = pdi->pd.laddr.len
	};
	const struct silofs_mdigest *md = &pa_ctx->pac_pindex.mdigest;

	pd_update_caddr_by(&pdi->pd, md, &rov);
	return 0;
}

static int pac_export_segdata(const struct silofs_par_ctx *pa_ctx,
                              struct silofs_par_desc_info *pdi)
{
	const struct silofs_laddr *laddr = &pdi->pd.laddr;
	const size_t len = laddr->len;
	void *seg = NULL;
	int err;

	seg = silofs_memalloc(pa_ctx->pac_alloc, len, 0);
	if (seg == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_load_seg(pa_ctx, laddr, seg);
	if (err) {
		goto out;
	}
	err = pac_update_hash_of(pa_ctx, pdi, seg);
	if (err) {
		goto out;
	}
	err = pac_send_pack(pa_ctx, &pdi->pd.caddr, seg, len);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(pa_ctx->pac_alloc, seg, len, 0);
	return err;
}

static int pac_import_segdata(const struct silofs_par_ctx *pa_ctx,
                              const struct silofs_par_desc_info *pdi)
{
	const struct silofs_laddr *laddr = &pdi->pd.laddr;
	const size_t len = laddr->len;
	void *seg = NULL;
	int err;

	seg = silofs_memalloc(pa_ctx->pac_alloc, len, 0);
	if (seg == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_recv_pack(pa_ctx, &pdi->pd.caddr, seg, len);
	if (err) {
		goto out;
	}
	/* TODO: recheck caddr by content */
	err = pac_save_seg(pa_ctx, laddr, seg);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(pa_ctx->pac_alloc, seg, len, 0);
	return err;
}

static const struct silofs_caddr *
pac_fs_bootrec_caddr(const struct silofs_par_ctx *pa_ctx)
{
	const struct silofs_fsenv *fsenv = pa_ctx->pac_fsenv;
	const struct silofs_caddr *caddr = &fsenv->fse_boot.caddr;

	silofs_assert_eq(caddr->ctype, SILOFS_CTYPE_BOOTREC);
	return caddr;
}

static int pac_export_bootrec(const struct silofs_par_ctx *pa_ctx,
                              struct silofs_par_desc_info *pdi)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 0xff };
	const struct silofs_caddr *boot_caddr = NULL;
	int err;

	boot_caddr = pac_fs_bootrec_caddr(pa_ctx);
	err = pac_load_bootrec(pa_ctx, boot_caddr, &brec1k);
	if (err) {
		return err;
	}
	pdi_update_caddr(pdi, boot_caddr);

	err = pac_send_pack(pa_ctx, &pdi->pd.caddr, &brec1k, sizeof(brec1k));
	if (err) {
		return err;
	}
	return 0;
}

static int pac_import_bootrec(const struct silofs_par_ctx *pa_ctx,
                              const struct silofs_par_desc_info *pdi)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 0xff };
	const struct silofs_caddr *caddr = &pdi->pd.caddr;
	int err;

	err = pac_recv_pack(pa_ctx, caddr, &brec1k, sizeof(brec1k));
	if (err) {
		return err;
	}
	err = pac_save_bootrec(pa_ctx, caddr, &brec1k);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_export_by_desc(struct silofs_par_ctx *pa_ctx,
                              struct silofs_par_desc_info *pdi)
{
	int err;

	if (pdi_isbootrec(pdi)) {
		err = pac_export_bootrec(pa_ctx, pdi);
	} else {
		err = pac_export_segdata(pa_ctx, pdi);
	}
	return err;
}

static int pac_export_by_laddr(struct silofs_par_ctx *pa_ctx,
                               const struct silofs_laddr *laddr)
{
	struct silofs_par_desc_info *pdi = NULL;
	int err;

	pdi = paridx_add_desc(&pa_ctx->pac_pindex, laddr, true);
	if (pdi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_export_by_desc(pa_ctx, pdi);
	if (err) {
		paridx_rm_desc(&pa_ctx->pac_pindex, pdi);
		return err;
	}
	return 0;
}

static int pac_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr)
{
	struct silofs_par_ctx *pa_ctx = ctx;

	return pac_export_by_laddr(pa_ctx, laddr);
}

static int pac_export_fs(struct silofs_par_ctx *pa_ctx)
{
	return silofs_fs_inspect(pa_ctx->pac_task, pac_visit_laddr_cb, pa_ctx);
}

static int pac_encode_save_pindex(struct silofs_par_ctx *pa_ctx,
                                  struct silofs_bytebuf *bb,
                                  struct silofs_caddr *out_caddr)
{
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = pindex_encode(&pa_ctx->pac_pindex, &rwv, out_caddr);
	if (err) {
		return err;
	}
	err = pac_send_to_repo(pa_ctx, out_caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_acquire_enc_buf(const struct silofs_par_ctx *pa_ctx,
                               struct silofs_bytebuf *out_bbuf)
{
	const size_t bsz = pindex_encsize(&pa_ctx->pac_pindex);
	int err;

	err = check_archive_pindex_size(bsz);
	if (!err) {
		err = pac_acquire_buf(pa_ctx, bsz, out_bbuf);
	}
	return err;
}

static int pac_export_pindex(struct silofs_par_ctx *pa_ctx,
                             struct silofs_caddr *out_caddr)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	int err;

	err = pac_acquire_enc_buf(pa_ctx, &bb);
	if (err) {
		goto out;
	}
	err = pac_encode_save_pindex(pa_ctx, &bb, out_caddr);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static int pac_export_post(struct silofs_par_ctx *pa_ctx,
                           const struct silofs_caddr *caddr)
{
	silofs_assert_eq(caddr->ctype, SILOFS_CTYPE_PACKIDX);

	return silofs_fsenv_set_base_caddr(pa_ctx->pac_fsenv, caddr);
}

static int pac_do_export(struct silofs_par_ctx *pa_ctx,
                         struct silofs_caddr *out_caddr)
{
	int err;

	err = pac_export_fs(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_export_pindex(pa_ctx, out_caddr);
	if (err) {
		return err;
	}
	err = pac_export_post(pa_ctx, out_caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fs_pack(struct silofs_task *task,
                   struct silofs_caddr *out_caddr)
{
	struct silofs_par_ctx pa_ctx;
	int err;

	err = pac_init(&pa_ctx, task);
	if (err) {
		goto out;
	}
	err = pac_do_export(&pa_ctx, out_caddr);
	if (err) {
		goto out;
	}
out:
	pac_fini(&pa_ctx);
	return err;
}

static int pac_acquire_dec_buf(const struct silofs_par_ctx *pa_ctx, size_t sz,
                               struct silofs_bytebuf *out_bbuf)
{
	return pac_acquire_buf(pa_ctx, sz, out_bbuf);
}

static int pac_load_decode_pindex(struct silofs_par_ctx *pa_ctx,
                                  const struct silofs_caddr *caddr,
                                  struct silofs_bytebuf *bb)
{
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = pac_recv_from_repo(pa_ctx, caddr, &rwv);
	if (err) {
		return err;
	}
	err = pindex_decode(&pa_ctx->pac_pindex, caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_stat_pindex(const struct silofs_par_ctx *pa_ctx,
                           const struct silofs_caddr *caddr, size_t *out_sz)
{
	int err;

	err = pac_stat_pack(pa_ctx, caddr, out_sz);
	if (err) {
		return err;
	}
	err = check_archive_pindex_size(*out_sz);
	if (err) {
		log_warn("illegal archive pindex: size=%zu", *out_sz);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static const struct silofs_caddr *
pac_ar_packidx_caddr(const struct silofs_par_ctx *pa_ctx)
{
	const struct silofs_fsenv *fsenv = pa_ctx->pac_fsenv;
	const struct silofs_caddr *caddr = &fsenv->fse_pack_caddr;

	silofs_assert_eq(caddr->ctype, SILOFS_CTYPE_PACKIDX);
	return caddr;
}

static int pac_import_pindex(struct silofs_par_ctx *pa_ctx)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	const struct silofs_caddr *caddr = NULL;
	size_t sz = 0;
	int err;

	caddr = pac_ar_packidx_caddr(pa_ctx);
	err = pac_stat_pindex(pa_ctx, caddr, &sz);
	if (err) {
		goto out;
	}
	err = pac_acquire_dec_buf(pa_ctx, sz, &bb);
	if (err) {
		goto out;
	}
	err = pac_load_decode_pindex(pa_ctx, caddr, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static int pac_import_by_desc(const struct silofs_par_ctx *pa_ctx,
                              const struct silofs_par_desc_info *pdi)
{
	int err;

	if (pdi_isbootrec(pdi)) {
		err = pac_import_bootrec(pa_ctx, pdi);
	} else {
		err = pac_import_segdata(pa_ctx, pdi);
	}
	return err;
}

static int pac_import_fs(struct silofs_par_ctx *pa_ctx)
{
	const struct silofs_par_desc_info *pdi = NULL;
	int err;

	pdi = pindex_next_desc(&pa_ctx->pac_pindex, pdi);
	while (pdi != NULL) {
		err = pac_import_by_desc(pa_ctx, pdi);
		if (err) {
			return err;
		}
		pdi = pindex_next_desc(&pa_ctx->pac_pindex, pdi);
	}
	return 0;
}

static int pac_import_post(struct silofs_par_ctx *pa_ctx,
                           struct silofs_caddr *out_caddr)
{
	const struct silofs_par_desc_info *pdi = NULL;
	size_t nbootrecs = 0;

	pdi = pindex_next_desc(&pa_ctx->pac_pindex, pdi);
	while (pdi != NULL) {
		if (pdi_isbootrec(pdi)) {
			pdi_caddr(pdi, out_caddr);
			nbootrecs++;
		}
		pdi = pindex_next_desc(&pa_ctx->pac_pindex, pdi);
	}
	if (nbootrecs != 1) {
		return -SILOFS_EBADPACK;
	}
	return silofs_fsenv_set_base_caddr(pa_ctx->pac_fsenv, out_caddr);
}

static int pac_do_import(struct silofs_par_ctx *pa_ctx,
                         struct silofs_caddr *out_caddr)
{
	int err;

	err = pac_import_pindex(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_import_fs(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_import_post(pa_ctx, out_caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fs_unpack(struct silofs_task *task,
                     struct silofs_caddr *out_caddr)
{
	struct silofs_par_ctx pa_ctx;
	int err;

	err = pac_init(&pa_ctx, task);
	if (err) {
		goto out;
	}
	err = pac_do_import(&pa_ctx, out_caddr);
	if (err) {
		goto out;
	}
out:
	pac_fini(&pa_ctx);
	return err;
}
