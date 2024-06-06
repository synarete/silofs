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
	struct silofs_caddr             ard_caddr;
	struct silofs_laddr             ard_laddr;
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
	struct silofs_caddr             caddr;
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
	silofs_laddr_assign(&ard->ard_laddr, laddr);
}

static void ard_fini(struct silofs_archive_desc *ard)
{
	silofs_laddr_reset(&ard->ard_laddr);
}

static void ard_update_caddr_by(struct silofs_archive_desc *ard,
                                const struct silofs_mdigest *md,
                                const struct silofs_rovec *rov)
{
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_caddr_of(&iov, 1, md, &ard->ard_caddr);
}

static void ardesc256b_reset(struct silofs_archive_desc256b *ard256)
{
	memset(ard256, 0, sizeof(*ard256));
}

static void ardesc256b_htox(struct silofs_archive_desc256b *ard256,
                            const struct silofs_archive_desc *ard)
{
	ardesc256b_reset(ard256);
	silofs_caddr64b_htox(&ard256->ad_caddr, &ard->ard_caddr);
	silofs_laddr48b_htox(&ard256->ad_laddr, &ard->ard_laddr);
}

static void ardesc256b_xtoh(const struct silofs_archive_desc256b *ard256,
                            struct silofs_archive_desc *ard)
{
	silofs_caddr64b_xtoh(&ard256->ad_caddr, &ard->ard_caddr);
	silofs_laddr48b_xtoh(&ard256->ad_laddr, &ard->ard_laddr);
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
	return (ardi->ad.ard_laddr.ltype == SILOFS_LTYPE_BOOTREC);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void *data_at(void *base, size_t pos)
{
	uint8_t *dat = base;

	return &dat[pos];
}

static int arv_check_size(size_t sz)
{
	return ((sz >= SILOFS_CATALOG_SIZE_MIN) &&
	        (sz <= SILOFS_CATALOG_SIZE_MAX)) ? 0 : -SILOFS_EINVAL;
}

static int arv_setup(struct silofs_archive_view *arv, void *dat,
                     size_t sz)
{
	const size_t meta_size = sizeof(struct silofs_archive_meta1k);
	const size_t desc_size = sizeof(struct silofs_archive_desc256b);
	int err;

	err = arv_check_size(sz);
	if (err) {
		return err;
	}
	arv->meta = dat;
	arv->descs = data_at(dat, meta_size);
	arv->ndescs_max = (sz - meta_size) / desc_size;
	arv->ndescs = 0;
	return 0;
}

static int arv_setup2(struct silofs_archive_view *arv,
                      const void *dat, size_t sz)
{
	return arv_setup(arv, unconst(dat), sz);
}

static uint64_t arv_calc_descs_csum(const struct silofs_archive_view
                                    *arv)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const struct silofs_archive_desc256b *descs = arv->descs;

	return silofs_hash_xxh64(descs, arv->ndescs * sizeof(*descs), seed);
}

static uint64_t arv_calc_meta_csum(const struct silofs_archive_view *arv)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const struct silofs_archive_meta1k *arm1k = arv->meta;
	const size_t len = sizeof(*arm1k) - sizeof(arm1k->am_meta_csum);

	return silofs_hash_xxh64(arm1k, len, seed);
}

static void arv_encode_meta(struct silofs_archive_view *arv)
{
	struct silofs_archive_meta1k *arm1k = arv->meta;

	armeta1k_init(arm1k);
	armeta1k_set_ndescs(arm1k, arv->ndescs);
	armeta1k_set_descs_csum(arm1k, arv_calc_descs_csum(arv));
	armeta1k_set_meta_csum(arm1k, arv_calc_meta_csum(arv));
}

static void arv_decode_meta(struct silofs_archive_view *arv)
{
	arv->ndescs = armeta1k_ndescs(arv->meta);
}

static int arv_check_meta(const struct silofs_archive_view *arv)
{
	const struct silofs_archive_meta1k *arm1k = arv->meta;
	uint64_t csum_set, csum_exp;

	if (armeta1k_magic(arm1k) != SILOFS_PACK_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (armeta1k_version(arm1k) != SILOFS_PACK_VERSION) {
		return -SILOFS_EPROTO;
	}
	csum_set = armeta1k_meta_csum(arm1k);
	csum_exp = arv_calc_meta_csum(arv);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	csum_set = armeta1k_descs_csum(arm1k);
	csum_exp = arv_calc_descs_csum(arv);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	return 0;
}

static void arv_calc_caddr(const struct silofs_archive_view *arv,
                           const struct silofs_mdigest *md,
                           struct silofs_caddr *out_caddr)
{
	const struct silofs_archive_desc256b *descs = arv->descs;
	const struct silofs_archive_meta1k *arm1k = arv->meta;
	struct iovec iov[2];

	iov[0].iov_base = unconst(arm1k);
	iov[0].iov_len = sizeof(*arm1k);
	iov[1].iov_base = unconst(descs);
	iov[1].iov_len = arv->ndescs * sizeof(*descs);

	silofs_calc_caddr_of(iov, 2, md, out_caddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ari_link_desc(struct silofs_archive_index *ari,
                          struct silofs_archive_desc_info *ardi)
{
	silofs_listq_push_front(&ari->descq, &ardi->lh);
}

static void ari_unlink_desc(struct silofs_archive_index *ari,
                            struct silofs_archive_desc_info *ardi)
{
	silofs_listq_remove(&ari->descq, &ardi->lh);
}

static struct silofs_archive_desc_info *
ari_add_desc(struct silofs_archive_index *ari,
             const struct silofs_laddr *laddr)
{
	struct silofs_archive_desc_info *ardi;

	ardi = ardi_new(laddr, ari->alloc);
	if (ardi != NULL) {
		ari_link_desc(ari, ardi);
	}
	return ardi;
}

static void ari_rm_desc(struct silofs_archive_index *ari,
                        struct silofs_archive_desc_info *ardi)
{
	ari_unlink_desc(ari, ardi);
	ardi_del(ardi, ari->alloc);
}

static struct silofs_archive_desc_info *
ari_pop_desc(struct silofs_archive_index *ari)
{
	struct silofs_list_head *lh;
	struct silofs_archive_desc_info *ardi = NULL;

	lh = silofs_listq_pop_front(&ari->descq);
	if (lh != NULL) {
		ardi = ardi_from_lh(lh);
	}
	return ardi;
}

static void ari_clear_descq(struct silofs_archive_index *ari)
{
	struct silofs_archive_desc_info *ardi;

	ardi = ari_pop_desc(ari);
	while (ardi != NULL) {
		ardi_del(ardi, ari->alloc);
		ardi = ari_pop_desc(ari);
	}
}

static size_t ari_ndescs_inq(const struct silofs_archive_index *ari)
{
	return ari->descq.sz;
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

static int ari_init(struct silofs_archive_index *ari,
                    struct silofs_alloc *alloc)
{
	silofs_listq_init(&ari->descq);
	ari->alloc = alloc;
	return silofs_mdigest_init(&ari->mdigest);
}

static void ari_fini(struct silofs_archive_index *ari)
{
	ari_clear_descq(ari);
	silofs_listq_fini(&ari->descq);
	silofs_mdigest_fini(&ari->mdigest);
	ari->alloc = NULL;
}

static size_t ari_encsize(const struct silofs_archive_index *ari)
{
	return encode_sizeof(ari_ndescs_inq(ari));
}

static int check_ari_encsize(size_t sz)
{
	return ((sz >= SILOFS_CATALOG_SIZE_MIN) &&
	        (sz <= SILOFS_CATALOG_SIZE_MAX)) ? -SILOFS_EINVAL : 0;
}

static int silofs_ari_encsize(const struct silofs_archive_index *ari,
                              size_t *out_encodebuf_size)
{
	*out_encodebuf_size = ari_encsize(ari);
	return check_ari_encsize(*out_encodebuf_size);
}

static int ari_encode_descs(const struct silofs_archive_index *ari,
                            struct silofs_archive_view *arv)
{
	const struct silofs_list_head *itr = NULL;
	const struct silofs_archive_desc_info *ardi = NULL;
	const struct silofs_listq *descq = &ari->descq;
	struct silofs_archive_desc256b *pdx = NULL;

	arv->ndescs = 0;
	itr = silofs_listq_front(descq);
	while (itr != NULL) {
		if (arv->ndescs >= arv->ndescs_max) {
			return -SILOFS_EINVAL;
		}
		ardi = ardi_from_lh(itr);
		pdx = &arv->descs[arv->ndescs++];
		ardesc256b_htox(pdx, &ardi->ad);
		itr = silofs_listq_next(descq, itr);
	}
	return 0;
}

static int ari_decode_descs(struct silofs_archive_index *ari,
                            const struct silofs_archive_view *arv)
{
	struct silofs_archive_desc_info *ardi = NULL;
	const struct silofs_archive_desc256b *ard256 = NULL;

	for (size_t i = 0; i < arv->ndescs; ++i) {
		ard256 = &arv->descs[i];
		ardi = ari_add_desc(ari, laddr_none());
		if (ardi == NULL) {
			return -SILOFS_ENOMEM;
		}
		ardesc256b_xtoh(ard256, &ardi->ad);
	}
	return 0;
}


static void ari_encode_meta(const struct silofs_archive_index *ari,
                            struct silofs_archive_view *arv)
{
	silofs_unused(ari);
	arv_encode_meta(arv);
}

static int ari_decode_meta(struct silofs_archive_index *ari,
                           struct silofs_archive_view *arv)
{
	int err;

	silofs_unused(ari);
	err = arv_check_meta(arv);
	if (err) {
		return err;
	}
	arv_decode_meta(arv);
	return 0;
}

static void ari_update_caddr(struct silofs_archive_index *ari,
                             struct silofs_archive_view *arv)
{
	arv_calc_caddr(arv, &ari->mdigest, &ari->caddr);
}


static int ari_encode(struct silofs_archive_index *ari,
                      struct silofs_rwvec *rwv)
{
	struct silofs_archive_view arv = { .meta = NULL, .descs = NULL };
	const size_t esz = ari_encsize(ari);
	int err;

	if (esz < rwv->rwv_len) {
		return -SILOFS_EINVAL;
	}
	err = arv_setup(&arv, rwv->rwv_base, rwv->rwv_len);
	if (err) {
		return err;
	}
	err = ari_encode_descs(ari, &arv);
	if (err) {
		return err;
	}
	ari_encode_meta(ari, &arv);
	ari_update_caddr(ari, &arv);
	return 0;
}

static int ari_check_caddr(const struct silofs_archive_index *ari,
                           const struct silofs_archive_view *arv)
{
	const struct silofs_caddr *caddr_exp = &ari->caddr;
	struct silofs_caddr caddr;

	arv_calc_caddr(arv, &ari->mdigest, &caddr);
	return silofs_caddr_isequal(&caddr, caddr_exp) ? 0 : -SILOFS_ECSUM;
}

static int ari_decode(struct silofs_archive_index *ari,
                      const struct silofs_rovec *rov)
{
	struct silofs_archive_view arv = { .meta = NULL, .descs = NULL };
	int err;

	err = check_ari_encsize(rov->rov_len);
	if (err) {
		return err;
	}
	err = arv_setup2(&arv, rov->rov_base, rov->rov_len);
	if (err) {
		return err;
	}
	err = ari_check_caddr(ari, &arv);
	if (err) {
		return err;
	}
	err = ari_decode_meta(ari, &arv);
	if (err) {
		return err;
	}
	err = ari_decode_descs(ari, &arv);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_pack_ctx {
	struct silofs_archive_index   pac_ari;
	struct silofs_task     *pac_task;
	struct silofs_alloc    *pac_alloc;
	struct silofs_repo     *pac_repo;
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
	return ari_init(&pa_ctx->pac_ari, pa_ctx->pac_alloc);
}

static void pac_fini(struct silofs_pack_ctx *pa_ctx)
{
	ari_fini(&pa_ctx->pac_ari);
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
	if ((sz < SILOFS_CATALOG_SIZE_MIN) ||
	    (sz > SILOFS_CATALOG_SIZE_MAX)) {
		log_warn("illegal pack-ari: size=%zu", sz);
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
	const struct silofs_caddr *caddr = &ardi->ad.ard_caddr;
	const struct silofs_laddr *laddr = &ardi->ad.ard_laddr;
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
		.rov_len = ardi->ad.ard_laddr.len
	};
	const struct silofs_mdigest *md = &pa_ctx->pac_ari.mdigest;

	ard_update_caddr_by(&ardi->ad, md, &rov);
	return 0;
}

static int pac_export_segdata(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_archive_desc_info *ardi)
{
	const size_t seg_len = ardi->ad.ard_laddr.len;
	void *seg = NULL;
	int err = -SILOFS_ENOMEM;

	seg = silofs_memalloc(pa_ctx->pac_alloc, seg_len, 0);
	if (seg == NULL) {
		goto out;
	}
	err = pac_load_seg(pa_ctx, &ardi->ad.ard_laddr, seg);
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

	ardi = ari_add_desc(&pa_ctx->pac_ari, laddr);
	if (ardi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_process_pdi(pa_ctx, ardi);
	if (err) {
		ari_rm_desc(&pa_ctx->pac_ari, ardi);
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

static int pac_encode_save_ari(struct silofs_pack_ctx *pa_ctx,
                               struct silofs_bytebuf *bb)
{
	struct silofs_archive_index *cat = &pa_ctx->pac_ari;
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = ari_encode(cat, &rwv);
	if (err) {
		return err;
	}
	err = pac_send_to_repo(pa_ctx, &cat->caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_acquire_enc_buf(const struct silofs_pack_ctx *pa_ctx,
                               struct silofs_bytebuf *out_bbuf)
{
	size_t bsz = 0;
	int err;

	err = silofs_ari_encsize(&pa_ctx->pac_ari, &bsz);
	if (!err) {
		err = pac_acquire_buf(pa_ctx, bsz, out_bbuf);
	}
	return err;
}

static int pac_export_ari(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	int err;

	err = pac_acquire_enc_buf(pa_ctx, &bb);
	if (err) {
		goto out;
	}
	err = pac_encode_save_ari(pa_ctx, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static void pac_ari_id(const struct silofs_pack_ctx *pa_ctx,
                       struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &pa_ctx->pac_ari.caddr);
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
		return err;
	}
	err = pac_export_fs(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_export_ari(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_ari_id(&pa_ctx, out_caddr);
out:
	pac_fini(&pa_ctx);
	return err;
}

static void pac_set_ari_id(struct silofs_pack_ctx *pa_ctx,
                           const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&pa_ctx->pac_ari.caddr, caddr);
}

static int pac_acquire_dec_buf(const struct silofs_pack_ctx *pa_ctx, size_t sz,
                               struct silofs_bytebuf *out_bbuf)
{
	return pac_acquire_buf(pa_ctx, sz, out_bbuf);
}

static int pac_load_decode_ari(struct silofs_pack_ctx *pa_ctx,
                               struct silofs_bytebuf *bb)
{
	struct silofs_archive_index *cat = &pa_ctx->pac_ari;
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = pac_recv_from_repo(pa_ctx, &cat->caddr, &rwv);
	if (err) {
		return err;
	}
	err = ari_decode(cat, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_import_ari(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_archive_index *cat = &pa_ctx->pac_ari;
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	size_t sz;
	int err;

	err = pac_stat_pack(pa_ctx, &cat->caddr, &sz);
	if (err) {
		goto out;
	}
	err = pac_acquire_dec_buf(pa_ctx, sz, &bb);
	if (err) {
		goto out;
	}
	err = pac_load_decode_ari(pa_ctx, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
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
		return err;
	}
	pac_set_ari_id(&pa_ctx, caddr);
	if (err) {
		goto out;
	}
	err = pac_import_ari(&pa_ctx);
	if (err) {
		goto out;
	}
out:
	pac_fini(&pa_ctx);
	return err;
}
