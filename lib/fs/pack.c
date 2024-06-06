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
#include <silofs/vol.h>
#include <silofs/fs.h>


struct silofs_archive_desc {
	struct silofs_caddr             caddr;
	struct silofs_laddr             laddr;
};

struct silofs_archive_desc_info {
	struct silofs_list_head         lh;
	struct silofs_archive_desc      ad;
};

struct silofs_archive_view {
	struct silofs_archive_meta1k   *meta;
	struct silofs_archive_desc256b *descs;
	size_t capacity;
	size_t ndescs_max;
	size_t ndescs;
};

struct silofs_archive_index {
	struct silofs_mdigest           mdigest;
	struct silofs_listq             descq;
	struct silofs_alloc            *alloc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static uint64_t armeta1k_magic(const struct silofs_archive_meta1k *arm1k)
{
	return silofs_le64_to_cpu(arm1k->am_magic);
}

static void armeta1k_set_magic(struct silofs_archive_meta1k *arm1k,
                               uint64_t magic)
{
	arm1k->am_magic = silofs_cpu_to_le64(magic);
}

static uint32_t armeta1k_version(const struct silofs_archive_meta1k *arm1k)
{
	return silofs_le32_to_cpu(arm1k->am_version);
}

static void armeta1k_set_version(struct silofs_archive_meta1k *arm1k,
                                 uint32_t vers)
{
	arm1k->am_version = silofs_cpu_to_le32(vers);
}

static void armeta1k_set_flags(struct silofs_archive_meta1k *arm1k,
                               uint32_t flags)
{
	arm1k->am_flags = silofs_cpu_to_le32(flags);
}

static size_t armeta1k_ndescs(const struct silofs_archive_meta1k *arm1k)
{
	return silofs_le64_to_cpu(arm1k->am_ndescs);
}

static void armeta1k_set_ndescs(struct silofs_archive_meta1k *arm1k,
                                size_t ndescs)
{
	arm1k->am_ndescs = silofs_cpu_to_le64(ndescs);
}

static uint64_t armeta1k_descs_csum(const struct silofs_archive_meta1k *arm1k)
{
	return silofs_le64_to_cpu(arm1k->am_descs_csum);
}

static void armeta1k_set_descs_csum(struct silofs_archive_meta1k *arm1k,
                                    uint64_t descs_csum)
{
	arm1k->am_descs_csum = silofs_cpu_to_le64(descs_csum);
}

static uint64_t armeta1k_meta_csum(const struct silofs_archive_meta1k *arm1k)
{
	return silofs_le64_to_cpu(arm1k->am_meta_csum);
}

static void armeta1k_set_meta_csum(struct silofs_archive_meta1k *arm1k,
                                   uint64_t meta_csum)
{
	arm1k->am_meta_csum = silofs_cpu_to_le64(meta_csum);
}

static void armeta1k_init(struct silofs_archive_meta1k *arm1k)
{
	silofs_memzero(arm1k, sizeof(*arm1k));
	armeta1k_set_magic(arm1k, SILOFS_PACK_META_MAGIC);
	armeta1k_set_version(arm1k, SILOFS_PACK_VERSION);
	armeta1k_set_flags(arm1k, 0);
	armeta1k_set_ndescs(arm1k, 0);
	armeta1k_set_descs_csum(arm1k, 0);
	armeta1k_set_meta_csum(arm1k, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ard_init(struct silofs_archive_desc *ard,
                     const struct silofs_laddr *laddr)
{
	silofs_memzero(ard, sizeof(*ard));
	silofs_laddr_assign(&ard->laddr, laddr);
}

static void ard_fini(struct silofs_archive_desc *ard)
{
	silofs_laddr_reset(&ard->laddr);
}

static void ard_update_caddr_by(struct silofs_archive_desc *ard,
                                const struct silofs_mdigest *md,
                                const struct silofs_rovec *rov)
{
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_caddr_of(&iov, 1, md, &ard->caddr);
}

static void ardesc256b_reset(struct silofs_archive_desc256b *ard256)
{
	memset(ard256, 0, sizeof(*ard256));
}

static void ardesc256b_htox(struct silofs_archive_desc256b *ard256,
                            const struct silofs_archive_desc *ard)
{
	ardesc256b_reset(ard256);
	silofs_caddr64b_htox(&ard256->ad_caddr, &ard->caddr);
	silofs_laddr48b_htox(&ard256->ad_laddr, &ard->laddr);
}

static void ardesc256b_xtoh(const struct silofs_archive_desc256b *ard256,
                            struct silofs_archive_desc *ard)
{
	silofs_caddr64b_xtoh(&ard256->ad_caddr, &ard->caddr);
	silofs_laddr48b_xtoh(&ard256->ad_laddr, &ard->laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_archive_desc_info *
ardi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_archive_desc_info *ardi = NULL;

	if (lh != NULL) {
		ardi = container_of2(lh, struct silofs_archive_desc_info, lh);
	}
	return unconst(ardi);
}

static struct silofs_archive_desc_info *ardi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_archive_desc_info *ardi = NULL;

	ardi = silofs_memalloc(alloc, sizeof(*ardi), 0);
	return ardi;
}

static void ardi_free(struct silofs_archive_desc_info *ardi,
                      struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ardi, sizeof(*ardi), 0);
}

static void ardi_init(struct silofs_archive_desc_info *ardi,
                      const struct silofs_laddr *laddr)
{
	silofs_list_head_init(&ardi->lh);
	ard_init(&ardi->ad, laddr);
}

static void ardi_fini(struct silofs_archive_desc_info *ardi)
{
	silofs_list_head_fini(&ardi->lh);
	ard_fini(&ardi->ad);
}

static struct silofs_archive_desc_info *
ardi_new(const struct silofs_laddr *laddr, struct silofs_alloc *alloc)
{
	struct silofs_archive_desc_info *ardi;

	ardi = ardi_malloc(alloc);
	if (ardi != NULL) {
		ardi_init(ardi, laddr);
	}
	return ardi;
}

static void ardi_del(struct silofs_archive_desc_info *ardi,
                     struct silofs_alloc *alloc)
{
	if (ardi != NULL) {
		ardi_fini(ardi);
		ardi_free(ardi, alloc);
	}
}

static bool ardi_isbootrec(const struct silofs_archive_desc_info *ardi)
{
	return (ardi->ad.laddr.ltype == SILOFS_LTYPE_BOOTREC);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int check_archive_index_size(size_t sz)
{
	return ((sz >= SILOFS_ARCHIVE_INDEX_SIZE_MIN) &&
	        (sz <= SILOFS_ARCHIVE_INDEX_SIZE_MAX)) ? 0 : -SILOFS_EINVAL;
}

static void *data_at(void *base, size_t pos)
{
	uint8_t *dat = base;

	return &dat[pos];
}

static int arview_setup(struct silofs_archive_view *arview, void *dat,
                        size_t sz)
{
	const size_t meta_size = sizeof(struct silofs_archive_meta1k);
	const size_t desc_size = sizeof(struct silofs_archive_desc256b);
	int err;

	err = check_archive_index_size(sz);
	if (err) {
		return err;
	}
	arview->meta = dat;
	arview->descs = data_at(dat, meta_size);
	arview->ndescs_max = (sz - meta_size) / desc_size;
	arview->ndescs = 0;
	return 0;
}

static int arview_setup2(struct silofs_archive_view *arview,
                         const void *dat, size_t sz)
{
	return arview_setup(arview, unconst(dat), sz);
}

static uint64_t arview_calc_descs_csum(const struct silofs_archive_view
                                       *arview)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const struct silofs_archive_desc256b *descs = arview->descs;

	return silofs_hash_xxh64(descs, arview->ndescs * sizeof(*descs), seed);
}

static uint64_t arview_calc_meta_csum(const struct silofs_archive_view *arview)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const struct silofs_archive_meta1k *arm1k = arview->meta;
	const size_t len = sizeof(*arm1k) - sizeof(arm1k->am_meta_csum);

	return silofs_hash_xxh64(arm1k, len, seed);
}

static void arview_encode_meta(struct silofs_archive_view *arview)
{
	struct silofs_archive_meta1k *arm1k = arview->meta;

	armeta1k_init(arm1k);
	armeta1k_set_ndescs(arm1k, arview->ndescs);
	armeta1k_set_descs_csum(arm1k, arview_calc_descs_csum(arview));
	armeta1k_set_meta_csum(arm1k, arview_calc_meta_csum(arview));
}

static void arview_decode_meta(struct silofs_archive_view *arview)
{
	arview->ndescs = armeta1k_ndescs(arview->meta);
}

static int arview_check_meta(const struct silofs_archive_view *arview)
{
	const struct silofs_archive_meta1k *arm1k = arview->meta;
	uint64_t csum_set, csum_exp;

	if (armeta1k_magic(arm1k) != SILOFS_PACK_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (armeta1k_version(arm1k) != SILOFS_PACK_VERSION) {
		return -SILOFS_EPROTO;
	}
	csum_set = armeta1k_meta_csum(arm1k);
	csum_exp = arview_calc_meta_csum(arview);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	csum_set = armeta1k_descs_csum(arm1k);
	csum_exp = arview_calc_descs_csum(arview);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	return 0;
}

static void arview_calc_caddr(const struct silofs_archive_view *arview,
                              const struct silofs_mdigest *md,
                              struct silofs_caddr *out_caddr)
{
	const struct silofs_archive_desc256b *descs = arview->descs;
	const struct silofs_archive_meta1k *arm1k = arview->meta;
	struct iovec iov[2];

	iov[0].iov_base = unconst(arm1k);
	iov[0].iov_len = sizeof(*arm1k);
	iov[1].iov_base = unconst(descs);
	iov[1].iov_len = arview->ndescs * sizeof(*descs);

	silofs_calc_caddr_of(iov, 2, md, out_caddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void index_link_desc(struct silofs_archive_index *index,
                            struct silofs_archive_desc_info *ardi)
{
	silofs_listq_push_front(&index->descq, &ardi->lh);
}

static void index_unlink_desc(struct silofs_archive_index *index,
                              struct silofs_archive_desc_info *ardi)
{
	silofs_listq_remove(&index->descq, &ardi->lh);
}

static struct silofs_archive_desc_info *
index_add_desc(struct silofs_archive_index *index,
               const struct silofs_laddr *laddr)
{
	struct silofs_archive_desc_info *ardi;

	ardi = ardi_new(laddr, index->alloc);
	if (ardi != NULL) {
		index_link_desc(index, ardi);
	}
	return ardi;
}

static void index_rm_desc(struct silofs_archive_index *index,
                          struct silofs_archive_desc_info *ardi)
{
	index_unlink_desc(index, ardi);
	ardi_del(ardi, index->alloc);
}

static struct silofs_archive_desc_info *
index_pop_desc(struct silofs_archive_index *index)
{
	struct silofs_list_head *lh;
	struct silofs_archive_desc_info *ardi = NULL;

	lh = silofs_listq_pop_front(&index->descq);
	if (lh != NULL) {
		ardi = ardi_from_lh(lh);
	}
	return ardi;
}

static void index_clear_descq(struct silofs_archive_index *index)
{
	struct silofs_archive_desc_info *ardi;

	ardi = index_pop_desc(index);
	while (ardi != NULL) {
		ardi_del(ardi, index->alloc);
		ardi = index_pop_desc(index);
	}
}

static size_t index_ndescs_inq(const struct silofs_archive_index *index)
{
	return index->descq.sz;
}

static size_t encode_sizeof(size_t ndesc)
{
	const size_t align = SILOFS_LBK_SIZE;
	const size_t meta_size = sizeof(struct silofs_archive_meta1k);
	const size_t desc_size = sizeof(struct silofs_archive_desc256b);
	const size_t descs_total_size = ndesc * desc_size;
	const size_t enc_total_size = meta_size + descs_total_size;

	return silofs_div_round_up(enc_total_size, align) * align;
}

static int index_init(struct silofs_archive_index *index,
                      struct silofs_alloc *alloc)
{
	silofs_listq_init(&index->descq);
	index->alloc = alloc;
	return silofs_mdigest_init(&index->mdigest);
}

static void index_fini(struct silofs_archive_index *index)
{
	index_clear_descq(index);
	silofs_listq_fini(&index->descq);
	silofs_mdigest_fini(&index->mdigest);
	index->alloc = NULL;
}

static size_t index_encsize(const struct silofs_archive_index *index)
{
	return encode_sizeof(index_ndescs_inq(index));
}

static int index_encode_descs(const struct silofs_archive_index *index,
                              struct silofs_archive_view *arview)
{
	const struct silofs_list_head *itr = NULL;
	const struct silofs_archive_desc_info *ardi = NULL;
	const struct silofs_listq *descq = &index->descq;
	struct silofs_archive_desc256b *pdx = NULL;

	arview->ndescs = 0;
	itr = silofs_listq_front(descq);
	while (itr != NULL) {
		if (arview->ndescs >= arview->ndescs_max) {
			return -SILOFS_EINVAL;
		}
		ardi = ardi_from_lh(itr);
		pdx = &arview->descs[arview->ndescs++];
		ardesc256b_htox(pdx, &ardi->ad);
		itr = silofs_listq_next(descq, itr);
	}
	return 0;
}

static int index_decode_descs(struct silofs_archive_index *index,
                              const struct silofs_archive_view *arview)
{
	struct silofs_archive_desc_info *ardi = NULL;
	const struct silofs_archive_desc256b *ard256 = NULL;

	for (size_t i = 0; i < arview->ndescs; ++i) {
		ard256 = &arview->descs[i];
		ardi = index_add_desc(index, laddr_none());
		if (ardi == NULL) {
			return -SILOFS_ENOMEM;
		}
		ardesc256b_xtoh(ard256, &ardi->ad);
	}
	return 0;
}


static void index_encode_meta(const struct silofs_archive_index *index,
                              struct silofs_archive_view *arview)
{
	silofs_unused(index);
	arview_encode_meta(arview);
}

static int index_decode_meta(struct silofs_archive_index *index,
                             struct silofs_archive_view *arview)
{
	int err;

	silofs_unused(index);
	err = arview_check_meta(arview);
	if (err) {
		return err;
	}
	arview_decode_meta(arview);
	return 0;
}

static void index_calc_caddr_of(const struct silofs_archive_index *index,
                                const struct silofs_archive_view *arview,
                                struct silofs_caddr *out_caddr)
{
	arview_calc_caddr(arview, &index->mdigest, out_caddr);
}


static int index_encode(struct silofs_archive_index *index,
                        struct silofs_rwvec *rwv,
                        struct silofs_caddr *out_caddr)
{
	struct silofs_archive_view arview = { .meta = NULL, .descs = NULL };
	const size_t esz = index_encsize(index);
	int err;

	if (esz < rwv->rwv_len) {
		return -SILOFS_EINVAL;
	}
	err = arview_setup(&arview, rwv->rwv_base, rwv->rwv_len);
	if (err) {
		return err;
	}
	err = index_encode_descs(index, &arview);
	if (err) {
		return err;
	}
	index_encode_meta(index, &arview);
	index_calc_caddr_of(index, &arview, out_caddr);
	return 0;
}

static int index_check_caddr(const struct silofs_archive_index *index,
                             const struct silofs_caddr *caddr,
                             const struct silofs_archive_view *arview)
{
	struct silofs_caddr caddr_calc;

	arview_calc_caddr(arview, &index->mdigest, &caddr_calc);
	return silofs_caddr_isequal(caddr, &caddr_calc) ? 0 : -SILOFS_ECSUM;
}

static int index_decode(struct silofs_archive_index *index,
                        const struct silofs_caddr *caddr,
                        const struct silofs_rovec *rov)
{
	struct silofs_archive_view arview = { .meta = NULL, .descs = NULL };
	int err;

	err = check_archive_index_size(rov->rov_len);
	if (err) {
		return err;
	}
	err = arview_setup2(&arview, rov->rov_base, rov->rov_len);
	if (err) {
		return err;
	}
	err = index_check_caddr(index, caddr, &arview);
	if (err) {
		return err;
	}
	err = index_decode_meta(index, &arview);
	if (err) {
		return err;
	}
	err = index_decode_descs(index, &arview);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_pack_ctx {
	struct silofs_archive_index   pac_index;
	struct silofs_task           *pac_task;
	struct silofs_alloc          *pac_alloc;
	struct silofs_repo           *pac_repo;
	long pad;
};

static int pac_acquire_buf(const struct silofs_pack_ctx *pa_ctx, size_t len,
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

static void pac_release_buf(const struct silofs_pack_ctx *pa_ctx,
                            struct silofs_bytebuf *bbuf)
{
	if (bbuf && bbuf->cap) {
		silofs_memfree(pa_ctx->pac_alloc, bbuf->ptr, bbuf->cap, 0);
		silofs_bytebuf_fini(bbuf);
	}
}

static int pac_init(struct silofs_pack_ctx *pa_ctx,
                    struct silofs_task *task)
{
	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
	pa_ctx->pac_task = task;
	pa_ctx->pac_alloc = task->t_fsenv->fse.alloc;
	pa_ctx->pac_repo = task->t_fsenv->fse.repo;
	return index_init(&pa_ctx->pac_index, pa_ctx->pac_alloc);
}

static void pac_fini(struct silofs_pack_ctx *pa_ctx)
{
	index_fini(&pa_ctx->pac_index);
	pa_ctx->pac_task = NULL;
	pa_ctx->pac_alloc = NULL;
	pa_ctx->pac_repo = NULL;
}

static int
pac_stat_pack(const struct silofs_pack_ctx *pa_ctx,
              const struct silofs_caddr *caddr, size_t *out_sz)
{
	ssize_t sz = -1;
	int err;

	err = silofs_repo_stat_pack(pa_ctx->pac_repo, caddr, &sz);
	if (err) {
		return err;
	}
	err = check_archive_index_size((size_t)sz);
	if (err) {
		log_warn("illegal archive index: size=%zd", sz);
		return -SILOFS_EINVAL;
	}
	*out_sz = (size_t)sz;
	return 0;
}

static int pac_send_to_repo(const struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            const struct silofs_rovec *rov)
{
	return silofs_repo_save_pack(pa_ctx->pac_repo, caddr, rov);
}

static int pac_recv_from_repo(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_caddr *caddr,
                              const struct silofs_rwvec *rwv)
{
	return silofs_repo_load_pack(pa_ctx->pac_repo, caddr, rwv);
}

static int pac_send_pack(const struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_archive_desc_info *ardi,
                         const void *dat)
{
	const struct silofs_caddr *caddr = &ardi->ad.caddr;
	const struct silofs_laddr *laddr = &ardi->ad.laddr;
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = laddr->len
	};
	size_t sz = 0;
	int err;

	err = pac_stat_pack(pa_ctx, caddr, &sz);
	if ((err == -ENOENT) || (!err && (sz != laddr->len))) {
		err = pac_send_to_repo(pa_ctx, caddr, &rov);
	}
	return err;
}

static int pac_load_seg(const struct silofs_pack_ctx *pa_ctx,
                        const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(pa_ctx->pac_repo, laddr, seg);
	if (err) {
		log_err("failed to read: ltype=%d len=%zu err=%d",
		        laddr->ltype, laddr->len, err);
	}
	return err;
}

static int pac_load_bootrec(const struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            struct silofs_bootrec1k *out_brec1k)
{
	struct silofs_bootrec brec = { .flags = 0 };
	const struct silofs_fsenv *fsenv = pa_ctx->pac_task->t_fsenv;
	int err;

	err = silofs_load_bootrec(fsenv, caddr, &brec);
	if (err) {
		log_err("failed to load bootrec: err=%d", err);
		return err;
	}
	err = silofs_encode_bootrec(fsenv, &brec, out_brec1k);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	return 0;
}

static int
pac_update_hash_of(const struct silofs_pack_ctx *pa_ctx,
                   struct silofs_archive_desc_info *ardi, const void *dat)
{
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = ardi->ad.laddr.len
	};
	const struct silofs_mdigest *md = &pa_ctx->pac_index.mdigest;

	ard_update_caddr_by(&ardi->ad, md, &rov);
	return 0;
}

static int pac_export_segdata(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_archive_desc_info *ardi)
{
	const size_t seg_len = ardi->ad.laddr.len;
	void *seg = NULL;
	int err = -SILOFS_ENOMEM;

	seg = silofs_memalloc(pa_ctx->pac_alloc, seg_len, 0);
	if (seg == NULL) {
		goto out;
	}
	err = pac_load_seg(pa_ctx, &ardi->ad.laddr, seg);
	if (err) {
		goto out;
	}
	err = pac_update_hash_of(pa_ctx, ardi, seg);
	if (err) {
		goto out;
	}
	err = pac_send_pack(pa_ctx, ardi, seg);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(pa_ctx->pac_alloc, seg, seg_len, 0);
	return err;
}

static const struct silofs_caddr *
pac_bootrec_caddr(const struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_fsenv *fsenv = pa_ctx->pac_task->t_fsenv;

	return &fsenv->fse_boot_ref;
}

static int pac_export_bootrec(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_archive_desc_info *ardi)
{
	struct silofs_bootrec1k brec = { .br_magic = 0xFFFFFFFF };
	const struct silofs_caddr *boot_caddr = NULL;
	int err;

	boot_caddr = pac_bootrec_caddr(pa_ctx);
	err = pac_load_bootrec(pa_ctx, boot_caddr, &brec);
	if (err) {
		return err;
	}
	err = pac_update_hash_of(pa_ctx, ardi, &brec);
	if (err) {
		return err;
	}
	err = pac_send_pack(pa_ctx, ardi, &brec);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_process_pdi(struct silofs_pack_ctx *pa_ctx,
                           struct silofs_archive_desc_info *ardi)
{
	int err;

	if (ardi_isbootrec(ardi)) {
		err = pac_export_bootrec(pa_ctx, ardi);
	} else {
		err = pac_export_segdata(pa_ctx, ardi);
	}
	return err;
}

static int pac_process_by_laddr(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_laddr *laddr)
{
	struct silofs_archive_desc_info *ardi = NULL;
	int err;

	ardi = index_add_desc(&pa_ctx->pac_index, laddr);
	if (ardi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_process_pdi(pa_ctx, ardi);
	if (err) {
		index_rm_desc(&pa_ctx->pac_index, ardi);
		return err;
	}
	return 0;
}

static int pac_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr)
{
	struct silofs_pack_ctx *pa_ctx = ctx;

	return pac_process_by_laddr(pa_ctx, laddr);
}

static int pac_export_fs(struct silofs_pack_ctx *pa_ctx)
{
	return silofs_fs_inspect(pa_ctx->pac_task, pac_visit_laddr_cb, pa_ctx);
}

static int pac_encode_save_index(struct silofs_pack_ctx *pa_ctx,
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

	err = index_encode(&pa_ctx->pac_index, &rwv, out_caddr);
	if (err) {
		return err;
	}
	err = pac_send_to_repo(pa_ctx, out_caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_acquire_enc_buf(const struct silofs_pack_ctx *pa_ctx,
                               struct silofs_bytebuf *out_bbuf)
{
	const size_t bsz = index_encsize(&pa_ctx->pac_index);
	int err;

	err = check_archive_index_size(bsz);
	if (!err) {
		err = pac_acquire_buf(pa_ctx, bsz, out_bbuf);
	}
	return err;
}

static int pac_export_index(struct silofs_pack_ctx *pa_ctx,
                            struct silofs_caddr *out_caddr)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	int err;

	err = pac_acquire_enc_buf(pa_ctx, &bb);
	if (err) {
		goto out;
	}
	err = pac_encode_save_index(pa_ctx, &bb, out_caddr);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static int pac_do_export(struct silofs_pack_ctx *pa_ctx,
                         struct silofs_caddr *out_caddr)
{
	int err;

	err = pac_export_fs(pa_ctx);
	if (err) {
		return err;
	}
	err = pac_export_index(pa_ctx, out_caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fs_pack(struct silofs_task *task,
                   struct silofs_caddr *out_caddr)
{
	struct silofs_pack_ctx pa_ctx = {
		.pad = -1,
	};
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

static int pac_acquire_dec_buf(const struct silofs_pack_ctx *pa_ctx, size_t sz,
                               struct silofs_bytebuf *out_bbuf)
{
	return pac_acquire_buf(pa_ctx, sz, out_bbuf);
}

static int pac_load_decode_index(struct silofs_pack_ctx *pa_ctx,
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
	err = index_decode(&pa_ctx->pac_index, caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_import_index(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_caddr *caddr)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	size_t sz;
	int err;

	err = pac_stat_pack(pa_ctx, caddr, &sz);
	if (err) {
		goto out;
	}
	err = pac_acquire_dec_buf(pa_ctx, sz, &bb);
	if (err) {
		goto out;
	}
	err = pac_load_decode_index(pa_ctx, caddr, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static int pac_do_import(struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_caddr *caddr)
{
	int err;

	err = pac_import_index(pa_ctx, caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fs_unpack(struct silofs_task *task,
                     const struct silofs_caddr *caddr)
{
	struct silofs_pack_ctx pa_ctx = {
		.pad = -1,
	};
	int err;

	err = pac_init(&pa_ctx, task);
	if (err) {
		goto out;
	}
	err = pac_do_import(&pa_ctx, caddr);
	if (err) {
		goto out;
	}
out:
	pac_fini(&pa_ctx);
	return err;
}
