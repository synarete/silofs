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

struct silofs_pack_ref {
	struct silofs_pack_meta1k   *meta;
	struct silofs_pack_desc256b *descs;
	size_t capacity;
	size_t ndescs_max;
	size_t ndescs;
};

struct silofs_catalog {
	struct silofs_mdigest   cat_mdigest;
	struct silofs_caddr     cat_caddr;
	struct silofs_listq     cat_descq;
	struct silofs_alloc    *cat_alloc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static uint64_t pkmeta1k_magic(const struct silofs_pack_meta1k *pkm)
{
	return silofs_le64_to_cpu(pkm->pm_magic);
}

static void pkmeta1k_set_magic(struct silofs_pack_meta1k *pkm, uint64_t magic)
{
	pkm->pm_magic = silofs_cpu_to_le64(magic);
}

static uint32_t pkmeta1k_version(const struct silofs_pack_meta1k *pkm)
{
	return silofs_le32_to_cpu(pkm->pm_version);
}

static void pkmeta1k_set_version(struct silofs_pack_meta1k *pkm, uint32_t vers)
{
	pkm->pm_version = silofs_cpu_to_le32(vers);
}

static void pkmeta1k_set_flags(struct silofs_pack_meta1k *pkm, uint32_t flags)
{
	pkm->pm_flags = silofs_cpu_to_le32(flags);
}

static size_t pkmeta1k_capacity(const struct silofs_pack_meta1k *pkm)
{
	return silofs_le64_to_cpu(pkm->pm_capacity);
}

static void pkmeta1k_set_capacity(struct silofs_pack_meta1k *pkm, size_t cap)
{
	pkm->pm_capacity = silofs_cpu_to_le64(cap);
}

static size_t pkmeta1k_ndescs(const struct silofs_pack_meta1k *pkm)
{
	return silofs_le64_to_cpu(pkm->pm_ndescs);
}

static void pkmeta1k_set_ndescs(struct silofs_pack_meta1k *pkm, size_t ndescs)
{
	pkm->pm_ndescs = silofs_cpu_to_le64(ndescs);
}

static uint64_t pkmeta1k_descs_csum(const struct silofs_pack_meta1k *pkm)
{
	return silofs_le64_to_cpu(pkm->pm_descs_csum);
}

static void pkmeta1k_set_descs_csum(struct silofs_pack_meta1k *pkm,
                                    uint64_t descs_csum)
{
	pkm->pm_descs_csum = silofs_cpu_to_le64(descs_csum);
}

static uint64_t pkmeta1k_meta_csum(const struct silofs_pack_meta1k *pkm)
{
	return silofs_le64_to_cpu(pkm->pm_meta_csum);
}

static void pkmeta1k_set_meta_csum(struct silofs_pack_meta1k *pkm,
                                   uint64_t meta_csum)
{
	pkm->pm_meta_csum = silofs_cpu_to_le64(meta_csum);
}

static void pkmeta1k_init(struct silofs_pack_meta1k *pkm)
{
	silofs_memzero(pkm, sizeof(*pkm));
	pkmeta1k_set_magic(pkm, SILOFS_PACK_META_MAGIC);
	pkmeta1k_set_version(pkm, SILOFS_PACK_VERSION);
	pkmeta1k_set_flags(pkm, 0);
	pkmeta1k_set_capacity(pkm, 0);
	pkmeta1k_set_ndescs(pkm, 0);
	pkmeta1k_set_descs_csum(pkm, 0);
	pkmeta1k_set_meta_csum(pkm, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pkdesc_init(struct silofs_pack_desc *pd,
                        const struct silofs_laddr *laddr)
{
	silofs_memzero(pd, sizeof(*pd));
	silofs_laddr_assign(&pd->pd_laddr, laddr);
}

static void pkdesc_fini(struct silofs_pack_desc *pd)
{
	silofs_laddr_reset(&pd->pd_laddr);
}

static void pkdesc_update_caddr_by(struct silofs_pack_desc *pd,
                                   const struct silofs_mdigest *md,
                                   const struct silofs_rovec *rov)
{
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_caddr_of(&iov, 1, md, &pd->pd_caddr);
}

static void silofs_pack_desc256b_reset(struct silofs_pack_desc256b *pdx)
{
	memset(pdx, 0, sizeof(*pdx));
}

static void pkdesc128b_htox(struct silofs_pack_desc256b *pdx,
                            const struct silofs_pack_desc *pd)
{
	silofs_pack_desc256b_reset(pdx);
	silofs_caddr64b_htox(&pdx->pd_caddr, &pd->pd_caddr);
	silofs_laddr48b_htox(&pdx->pd_laddr, &pd->pd_laddr);
}

static void pkdesc128b_xtoh(const struct silofs_pack_desc256b *pdx,
                            struct silofs_pack_desc *pd)
{
	silofs_caddr64b_xtoh(&pdx->pd_caddr, &pd->pd_caddr);
	silofs_laddr48b_xtoh(&pdx->pd_laddr, &pd->pd_laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pack_desc_info *
pdi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_pack_desc_info *pdi = NULL;

	if (lh != NULL) {
		pdi = container_of2(lh, struct silofs_pack_desc_info, pdi_lh);
	}
	return unconst(pdi);
}

static struct silofs_pack_desc_info *pdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_pack_desc_info *pdi = NULL;

	pdi = silofs_memalloc(alloc, sizeof(*pdi), 0);
	return pdi;
}

static void pdi_free(struct silofs_pack_desc_info *pdi,
                     struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, pdi, sizeof(*pdi), 0);
}

static void pdi_init(struct silofs_pack_desc_info *pdi,
                     const struct silofs_laddr *laddr)
{
	silofs_list_head_init(&pdi->pdi_lh);
	pkdesc_init(&pdi->pd, laddr);
}

static void pdi_fini(struct silofs_pack_desc_info *pdi)
{
	silofs_list_head_fini(&pdi->pdi_lh);
	pkdesc_fini(&pdi->pd);
}

static struct silofs_pack_desc_info *
pdi_new(const struct silofs_laddr *laddr, struct silofs_alloc *alloc)
{
	struct silofs_pack_desc_info *pdi;

	pdi = pdi_malloc(alloc);
	if (pdi != NULL) {
		pdi_init(pdi, laddr);
	}
	return pdi;
}

static void pdi_del(struct silofs_pack_desc_info *pdi,
                    struct silofs_alloc *alloc)
{
	if (pdi != NULL) {
		pdi_fini(pdi);
		pdi_free(pdi, alloc);
	}
}

static bool pdi_isbootrec(const struct silofs_pack_desc_info *pdi)
{
	return (pdi->pd.pd_laddr.ltype == SILOFS_LTYPE_BOOTREC);
}

static size_t pdi_capacity(const struct silofs_pack_desc_info *pdi)
{
	return pdi->pd.pd_laddr.len;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void *data_at(void *base, size_t pos)
{
	uint8_t *dat = base;

	return &dat[pos];
}

static int pref_check_size(size_t sz)
{
	return ((sz >= SILOFS_CATALOG_SIZE_MIN) &&
	        (sz <= SILOFS_CATALOG_SIZE_MAX)) ? 0 : -SILOFS_EINVAL;
}

static int pref_setup(struct silofs_pack_ref *pref, void *dat, size_t sz)
{
	const size_t meta_size = sizeof(struct silofs_pack_meta1k);
	const size_t desc_size = sizeof(struct silofs_pack_desc256b);
	int err;

	err = pref_check_size(sz);
	if (err) {
		return err;
	}
	pref->meta = dat;
	pref->descs = data_at(dat, meta_size);
	pref->ndescs_max = (sz - meta_size) / desc_size;
	pref->ndescs = 0;
	pref->capacity = 0;
	return 0;
}

static int pref_setup2(struct silofs_pack_ref *pref,
                       const void *dat, size_t sz)
{
	return pref_setup(pref, unconst(dat), sz);
}

static uint64_t pref_calc_descs_csum(const struct silofs_pack_ref *pref)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const struct silofs_pack_desc256b *descs = pref->descs;

	return silofs_hash_xxh64(descs, pref->ndescs * sizeof(*descs), seed);
}

static uint64_t pref_calc_meta_csum(const struct silofs_pack_ref *pref)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const struct silofs_pack_meta1k *pkm = pref->meta;
	const size_t len = sizeof(*pkm) - sizeof(pkm->pm_meta_csum);

	return silofs_hash_xxh64(pkm, len, seed);
}

static void pref_encode_meta(struct silofs_pack_ref *pref)
{
	struct silofs_pack_meta1k *pkm = pref->meta;

	pkmeta1k_init(pkm);
	pkmeta1k_set_capacity(pkm, pref->capacity);
	pkmeta1k_set_ndescs(pkm, pref->ndescs);
	pkmeta1k_set_descs_csum(pkm, pref_calc_descs_csum(pref));
	pkmeta1k_set_meta_csum(pkm, pref_calc_meta_csum(pref));
}

static void pref_decode_meta(struct silofs_pack_ref *pref)
{
	const struct silofs_pack_meta1k *pkm = pref->meta;

	pref->capacity = pkmeta1k_capacity(pkm);
	pref->ndescs = pkmeta1k_ndescs(pkm);
}

static int pref_check_meta(const struct silofs_pack_ref *pref)
{
	const struct silofs_pack_meta1k *pkm = pref->meta;
	uint64_t csum_set, csum_exp;

	if (pkmeta1k_magic(pkm) != SILOFS_PACK_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (pkmeta1k_version(pkm) != SILOFS_PACK_VERSION) {
		return -SILOFS_EPROTO;
	}
	csum_set = pkmeta1k_meta_csum(pkm);
	csum_exp = pref_calc_meta_csum(pref);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	csum_set = pkmeta1k_descs_csum(pkm);
	csum_exp = pref_calc_descs_csum(pref);
	if (csum_set != csum_exp) {
		return -SILOFS_ECSUM;
	}
	return 0;
}

static void pref_calc_caddr(const struct silofs_pack_ref *pref,
                            const struct silofs_mdigest *md,
                            struct silofs_caddr *out_caddr)
{
	const struct silofs_pack_desc256b *descs = pref->descs;
	const struct silofs_pack_meta1k *pkm = pref->meta;
	struct iovec iov[2];

	iov[0].iov_base = unconst(pkm);
	iov[0].iov_len = sizeof(*pkm);
	iov[1].iov_base = unconst(descs);
	iov[1].iov_len = pref->ndescs * sizeof(*descs);

	silofs_calc_caddr_of(iov, 2, md, out_caddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void catalog_link_desc(struct silofs_catalog *catalog,
                              struct silofs_pack_desc_info *pdi)
{
	silofs_listq_push_front(&catalog->cat_descq, &pdi->pdi_lh);
}

static void catalog_unlink_desc(struct silofs_catalog *catalog,
                                struct silofs_pack_desc_info *pdi)
{
	silofs_listq_remove(&catalog->cat_descq, &pdi->pdi_lh);
}

static struct silofs_pack_desc_info *
catalog_add_desc(struct silofs_catalog *catalog,
                 const struct silofs_laddr *laddr)
{
	struct silofs_pack_desc_info *pdi;

	pdi = pdi_new(laddr, catalog->cat_alloc);
	if (pdi != NULL) {
		catalog_link_desc(catalog, pdi);
	}
	return pdi;
}

static void catalog_rm_desc(struct silofs_catalog *catalog,
                            struct silofs_pack_desc_info *pdi)
{
	catalog_unlink_desc(catalog, pdi);
	pdi_del(pdi, catalog->cat_alloc);
}

static struct silofs_pack_desc_info *
catalog_pop_desc(struct silofs_catalog *catalog)
{
	struct silofs_list_head *lh;
	struct silofs_pack_desc_info *pdi = NULL;

	lh = silofs_listq_pop_front(&catalog->cat_descq);
	if (lh != NULL) {
		pdi = pdi_from_lh(lh);
	}
	return pdi;
}

static void catalog_clear_descq(struct silofs_catalog *catalog)
{
	struct silofs_pack_desc_info *pdi;

	pdi = catalog_pop_desc(catalog);
	while (pdi != NULL) {
		pdi_del(pdi, catalog->cat_alloc);
		pdi = catalog_pop_desc(catalog);
	}
}

static size_t catalog_ndescs_inq(const struct silofs_catalog *catalog)
{
	return catalog->cat_descq.sz;
}

static size_t encode_sizeof(size_t ndesc)
{
	const size_t align = SILOFS_LBK_SIZE;
	const size_t meta_size = sizeof(struct silofs_pack_meta1k);
	const size_t desc_size = sizeof(struct silofs_pack_desc256b);
	const size_t descs_total_size = ndesc * desc_size;
	const size_t enc_total_size = meta_size + descs_total_size;

	return silofs_div_round_up(enc_total_size, align) * align;
}

static int catalog_init(struct silofs_catalog *catalog,
                        struct silofs_alloc *alloc)
{
	silofs_listq_init(&catalog->cat_descq);
	catalog->cat_alloc = alloc;
	return silofs_mdigest_init(&catalog->cat_mdigest);
}

static void catalog_fini(struct silofs_catalog *catalog)
{
	catalog_clear_descq(catalog);
	silofs_listq_fini(&catalog->cat_descq);
	silofs_mdigest_fini(&catalog->cat_mdigest);
	catalog->cat_alloc = NULL;
}

static size_t catalog_encsize(const struct silofs_catalog *catalog)
{
	return encode_sizeof(catalog_ndescs_inq(catalog));
}

static int check_catalog_encsize(size_t sz)
{
	return ((sz >= SILOFS_CATALOG_SIZE_MIN) &&
	        (sz <= SILOFS_CATALOG_SIZE_MAX)) ? -SILOFS_EINVAL : 0;
}

static int silofs_catalog_encsize(const struct silofs_catalog *catalog,
                                  size_t *out_encodebuf_size)
{
	*out_encodebuf_size = catalog_encsize(catalog);
	return check_catalog_encsize(*out_encodebuf_size);
}

static int catalog_encode_descs(const struct silofs_catalog *catalog,
                                struct silofs_pack_ref *pref)
{
	const struct silofs_list_head *itr = NULL;
	const struct silofs_pack_desc_info *pdi = NULL;
	const struct silofs_listq *descq = &catalog->cat_descq;
	struct silofs_pack_desc256b *pdx = NULL;

	pref->capacity = 0;
	pref->ndescs = 0;
	itr = silofs_listq_front(descq);
	while (itr != NULL) {
		if (pref->ndescs >= pref->ndescs_max) {
			return -SILOFS_EINVAL;
		}
		pdi = pdi_from_lh(itr);
		pdx = &pref->descs[pref->ndescs++];
		pkdesc128b_htox(pdx, &pdi->pd);

		pref->capacity += pdi_capacity(pdi);
		itr = silofs_listq_next(descq, itr);
	}
	return 0;
}

static int catalog_decode_descs(struct silofs_catalog *catalog,
                                const struct silofs_pack_ref *pref)
{
	struct silofs_pack_desc_info *pdi = NULL;
	const struct silofs_pack_desc256b *pdx = NULL;

	for (size_t i = 0; i < pref->ndescs; ++i) {
		pdx = &pref->descs[i];
		pdi = catalog_add_desc(catalog, laddr_none());
		if (pdi == NULL) {
			return -SILOFS_ENOMEM;
		}
		pkdesc128b_xtoh(pdx, &pdi->pd);
	}
	return 0;
}


static void catalog_encode_meta(const struct silofs_catalog *catalog,
                                struct silofs_pack_ref *pref)
{
	silofs_unused(catalog);
	pref_encode_meta(pref);
}

static int catalog_decode_meta(struct silofs_catalog *catalog,
                               struct silofs_pack_ref *pref)
{
	int err;

	silofs_unused(catalog);
	err = pref_check_meta(pref);
	if (err) {
		return err;
	}
	pref_decode_meta(pref);
	return 0;
}

static void catalog_update_caddr(struct silofs_catalog *catalog,
                                 struct silofs_pack_ref *pref)
{
	pref_calc_caddr(pref, &catalog->cat_mdigest, &catalog->cat_caddr);
}


static int catalog_encode(struct silofs_catalog *catalog,
                          struct silofs_rwvec *rwv)
{
	struct silofs_pack_ref pref = { .meta = NULL, .descs = NULL };
	const size_t esz = catalog_encsize(catalog);
	int err;

	if (esz < rwv->rwv_len) {
		return -SILOFS_EINVAL;
	}
	err = pref_setup(&pref, rwv->rwv_base, rwv->rwv_len);
	if (err) {
		return err;
	}
	err = catalog_encode_descs(catalog, &pref);
	if (err) {
		return err;
	}
	catalog_encode_meta(catalog, &pref);
	catalog_update_caddr(catalog, &pref);
	return 0;
}

static int catalog_check_caddr(const struct silofs_catalog *catalog,
                               const struct silofs_pack_ref *pref)
{
	const struct silofs_caddr *caddr_exp = &catalog->cat_caddr;
	struct silofs_caddr caddr;

	pref_calc_caddr(pref, &catalog->cat_mdigest, &caddr);
	return silofs_caddr_isequal(&caddr, caddr_exp) ? 0 : -SILOFS_ECSUM;
}

static int catalog_decode(struct silofs_catalog *catalog,
                          const struct silofs_rovec *rov)
{
	struct silofs_pack_ref pref = { .meta = NULL, .descs = NULL };
	int err;

	err = check_catalog_encsize(rov->rov_len);
	if (err) {
		return err;
	}
	err = pref_setup2(&pref, rov->rov_base, rov->rov_len);
	if (err) {
		return err;
	}
	err = catalog_check_caddr(catalog, &pref);
	if (err) {
		return err;
	}
	err = catalog_decode_meta(catalog, &pref);
	if (err) {
		return err;
	}
	err = catalog_decode_descs(catalog, &pref);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_pack_ctx {
	struct silofs_catalog   pac_catalog;
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
	return catalog_init(&pa_ctx->pac_catalog, pa_ctx->pac_alloc);
}

static void pac_fini(struct silofs_pack_ctx *pa_ctx)
{
	catalog_fini(&pa_ctx->pac_catalog);
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
		log_warn("illegal pack-catalog: size=%zu", sz);
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
                         const struct silofs_pack_desc_info *pdi,
                         const void *dat)
{
	const struct silofs_caddr *caddr = &pdi->pd.pd_caddr;
	const struct silofs_laddr *laddr = &pdi->pd.pd_laddr;
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
                   struct silofs_pack_desc_info *pdi, const void *dat)
{
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = pdi->pd.pd_laddr.len
	};
	const struct silofs_mdigest *md = &pa_ctx->pac_catalog.cat_mdigest;

	pkdesc_update_caddr_by(&pdi->pd, md, &rov);
	return 0;
}

static int pac_export_segdata(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_pack_desc_info *pdi)
{
	const size_t seg_len = pdi->pd.pd_laddr.len;
	void *seg = NULL;
	int err = -SILOFS_ENOMEM;

	seg = silofs_memalloc(pa_ctx->pac_alloc, seg_len, 0);
	if (seg == NULL) {
		goto out;
	}
	err = pac_load_seg(pa_ctx, &pdi->pd.pd_laddr, seg);
	if (err) {
		goto out;
	}
	err = pac_update_hash_of(pa_ctx, pdi, seg);
	if (err) {
		goto out;
	}
	err = pac_send_pack(pa_ctx, pdi, seg);
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
                              struct silofs_pack_desc_info *pdi)
{
	struct silofs_bootrec1k brec = { .br_magic = 0xFFFFFFFF };
	const struct silofs_caddr *boot_caddr = NULL;
	int err;

	boot_caddr = pac_bootrec_caddr(pa_ctx);
	err = pac_load_bootrec(pa_ctx, boot_caddr, &brec);
	if (err) {
		return err;
	}
	err = pac_update_hash_of(pa_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	err = pac_send_pack(pa_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_process_pdi(struct silofs_pack_ctx *pa_ctx,
                           struct silofs_pack_desc_info *pdi)
{
	int err;

	if (pdi_isbootrec(pdi)) {
		err = pac_export_bootrec(pa_ctx, pdi);
	} else {
		err = pac_export_segdata(pa_ctx, pdi);
	}
	return err;
}

static int pac_process_by_laddr(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_laddr *laddr)
{
	struct silofs_pack_desc_info *pdi = NULL;
	int err;

	pdi = catalog_add_desc(&pa_ctx->pac_catalog, laddr);
	if (pdi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_process_pdi(pa_ctx, pdi);
	if (err) {
		catalog_rm_desc(&pa_ctx->pac_catalog, pdi);
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

static int pac_encode_save_catalog(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_bytebuf *bb)
{
	struct silofs_catalog *cat = &pa_ctx->pac_catalog;
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = catalog_encode(cat, &rwv);
	if (err) {
		return err;
	}
	err = pac_send_to_repo(pa_ctx, &cat->cat_caddr, &rov);
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

	err = silofs_catalog_encsize(&pa_ctx->pac_catalog, &bsz);
	if (!err) {
		err = pac_acquire_buf(pa_ctx, bsz, out_bbuf);
	}
	return err;
}

static int pac_export_catalog(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	int err;

	err = pac_acquire_enc_buf(pa_ctx, &bb);
	if (err) {
		goto out;
	}
	err = pac_encode_save_catalog(pa_ctx, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static void pac_catalog_id(const struct silofs_pack_ctx *pa_ctx,
                           struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &pa_ctx->pac_catalog.cat_caddr);
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
	err = pac_export_catalog(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_catalog_id(&pa_ctx, out_caddr);
out:
	pac_fini(&pa_ctx);
	return err;
}

static void pac_set_catalog_id(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&pa_ctx->pac_catalog.cat_caddr, caddr);
}

static int pac_acquire_dec_buf(const struct silofs_pack_ctx *pa_ctx, size_t sz,
                               struct silofs_bytebuf *out_bbuf)
{
	return pac_acquire_buf(pa_ctx, sz, out_bbuf);
}

static int pac_load_decode_catalog(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_bytebuf *bb)
{
	struct silofs_catalog *cat = &pa_ctx->pac_catalog;
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = pac_recv_from_repo(pa_ctx, &cat->cat_caddr, &rwv);
	if (err) {
		return err;
	}
	err = catalog_decode(cat, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_import_catalog(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_catalog *cat = &pa_ctx->pac_catalog;
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	size_t sz;
	int err;

	err = pac_stat_pack(pa_ctx, &cat->cat_caddr, &sz);
	if (err) {
		goto out;
	}
	err = pac_acquire_dec_buf(pa_ctx, sz, &bb);
	if (err) {
		goto out;
	}
	err = pac_load_decode_catalog(pa_ctx, &bb);
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
	pac_set_catalog_id(&pa_ctx, caddr);
	if (err) {
		goto out;
	}
	err = pac_import_catalog(&pa_ctx);
	if (err) {
		goto out;
	}
out:
	pac_fini(&pa_ctx);
	return err;
}
