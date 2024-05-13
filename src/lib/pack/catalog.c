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
#include <silofs/pack.h>


static void pkmeta1k_set_magic(struct silofs_pack_meta1k *pkm, uint64_t magic)
{
	pkm->pm_magic = silofs_cpu_to_le64(magic);
}

static void pkmeta1k_set_version(struct silofs_pack_meta1k *pkm, uint32_t vers)
{
	pkm->pm_version = silofs_cpu_to_le32(vers);
}

static void pkmeta1k_set_flags(struct silofs_pack_meta1k *pkm, uint32_t flags)
{
	pkm->pm_flags = silofs_cpu_to_le32(flags);
}

static void pkmeta1k_set_capacity(struct silofs_pack_meta1k *pkm, size_t cap)
{
	pkm->pm_capacity = silofs_cpu_to_le64(cap);
}

static void pkmeta1k_set_ndescs(struct silofs_pack_meta1k *pkm, size_t ndescs)
{
	pkm->pm_ndescs = silofs_cpu_to_le64(ndescs);
}

static void pkmeta1k_set_descs_csum(struct silofs_pack_meta1k *pkm,
                                    uint64_t descs_csum)
{
	pkm->pm_descs_csum = silofs_cpu_to_le64(descs_csum);
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

void silofs_pkdesc_init(struct silofs_pack_desc *pd,
                        const struct silofs_laddr *laddr)
{
	silofs_memzero(pd, sizeof(*pd));
	silofs_laddr_assign(&pd->pd_laddr, laddr);
}

void silofs_pkdesc_fini(struct silofs_pack_desc *pd)
{
	silofs_laddr_reset(&pd->pd_laddr);
}

void silofs_pkdesc_update_caddr(struct silofs_pack_desc *pd,
                                const struct silofs_mdigest *md,
                                const void *buf, size_t bsz)
{
	silofs_calc_caddr_of(buf, bsz, md, &pd->pd_caddr);
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

void silofs_pkdesc128b_xtoh(const struct silofs_pack_desc256b *pdx,
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
	silofs_pkdesc_init(&pdi->pd, laddr);
}

static void pdi_fini(struct silofs_pack_desc_info *pdi)
{
	silofs_list_head_fini(&pdi->pdi_lh);
	silofs_pkdesc_fini(&pdi->pd);
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

bool silofs_pdi_isbootrec(const struct silofs_pack_desc_info *pdi)
{
	return (pdi->pd.pd_laddr.ltype == SILOFS_LTYPE_BOOTREC);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void catalog_add_capacity(struct silofs_catalog *catalog,
                                 const struct silofs_laddr *laddr)
{
	catalog->cat_capacity += laddr->len;
}

static void catalog_sub_capacity(struct silofs_catalog *catalog,
                                 const struct silofs_laddr *laddr)
{
	silofs_assert_ge(catalog->cat_capacity, laddr->len);
	catalog->cat_capacity -= laddr->len;
}

static void catalog_link_desc(struct silofs_catalog *catalog,
                              struct silofs_pack_desc_info *pdi)
{
	silofs_listq_push_front(&catalog->cat_descq, &pdi->pdi_lh);
	catalog_add_capacity(catalog, &pdi->pd.pd_laddr);
}

static void catalog_unlink_desc(struct silofs_catalog *catalog,
                                struct silofs_pack_desc_info *pdi)
{
	catalog_sub_capacity(catalog, &pdi->pd.pd_laddr);
	silofs_listq_remove(&catalog->cat_descq, &pdi->pdi_lh);
}

struct silofs_pack_desc_info *
silofs_catalog_add_desc(struct silofs_catalog *catalog,
                        const struct silofs_laddr *laddr)
{
	struct silofs_pack_desc_info *pdi;

	pdi = pdi_new(laddr, catalog->cat_alloc);
	if (pdi != NULL) {
		catalog_link_desc(catalog, pdi);
	}
	return pdi;
}

void silofs_catalog_rm_desc(struct silofs_catalog *catalog,
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
	catalog->cat_capacity = 0;
}

static size_t catalog_ndescs(const struct silofs_catalog *catalog)
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

static int catalog_acquire_buf(struct silofs_catalog *catalog, size_t len)
{
	struct silofs_bytebuf *bb = &catalog->cat_bbuf;
	void *dat;

	dat = silofs_memalloc(catalog->cat_alloc, len, SILOFS_ALLOCF_BZERO);
	if (dat == NULL) {
		return -SILOFS_ENOMEM;
	}
	silofs_bytebuf_init2(bb, dat, len);
	return 0;
}

static void catalog_release_buf(struct silofs_catalog *catalog)
{
	struct silofs_bytebuf *bb = &catalog->cat_bbuf;

	if (bb->cap > 0) {
		silofs_memfree(catalog->cat_alloc, bb->ptr, bb->cap, 0);
		silofs_bytebuf_fini(bb);
	}
}

int silofs_catalog_init(struct silofs_catalog *catalog,
                        struct silofs_alloc *alloc)
{
	silofs_listq_init(&catalog->cat_descq);
	silofs_bytebuf_init(&catalog->cat_bbuf, NULL, 0);
	catalog->cat_alloc = alloc;
	catalog->cat_capacity = 0;
	return silofs_mdigest_init(&catalog->cat_mdigest);
}

void silofs_catalog_fini(struct silofs_catalog *catalog)
{
	catalog_release_buf(catalog);
	catalog_clear_descq(catalog);
	silofs_listq_fini(&catalog->cat_descq);
	silofs_mdigest_fini(&catalog->cat_mdigest);
	catalog->cat_alloc = NULL;
}

static int catalog_pre_encode(struct silofs_catalog *catalog)
{
	const size_t ndescs = catalog_ndescs(catalog);
	const size_t enc_size = encode_sizeof(ndescs);

	catalog_release_buf(catalog);
	return catalog_acquire_buf(catalog, enc_size);
}

static void *data_at(void *base, size_t pos)
{
	uint8_t *dat = base;

	return &dat[pos];
}

static struct silofs_pack_desc256b *
catalog_pkdesc(const struct silofs_catalog *catalog)
{
	struct silofs_pack_desc256b *descs = NULL;
	const size_t meta_size = sizeof(struct silofs_pack_meta1k);

	descs = data_at(catalog->cat_bbuf.ptr, meta_size);
	return descs;
}

static struct silofs_pack_meta1k *
catalog_pkmeta(const struct silofs_catalog *catalog)
{
	struct silofs_pack_meta1k *pkm = NULL;

	pkm = data_at(catalog->cat_bbuf.ptr, 0);
	return pkm;
}

static void catalog_encode_descs(struct silofs_catalog *catalog)
{
	const struct silofs_list_head *itr = NULL;
	const struct silofs_pack_desc_info *pdi = NULL;
	const struct silofs_listq *descq = &catalog->cat_descq;
	struct silofs_pack_desc256b *pdx = catalog_pkdesc(catalog);
	size_t slot = 0;

	itr = silofs_listq_front(descq);
	while (itr != NULL) {
		pdi = pdi_from_lh(itr);
		pkdesc128b_htox(&pdx[slot++], &pdi->pd);
		itr = silofs_listq_next(descq, itr);
	}
}

static uint64_t catalog_calc_descs_csum(const struct silofs_catalog *catalog)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	const size_t ndescs = catalog_ndescs(catalog);
	const struct silofs_pack_desc256b *descs = catalog_pkdesc(catalog);

	return silofs_hash_xxh64(descs, ndescs * sizeof(*descs), seed);
}

static uint64_t catalog_calc_meta_csum(const struct silofs_catalog *catalog)
{
	const uint64_t seed = SILOFS_PACK_META_MAGIC;
	struct silofs_pack_meta1k *pkm = catalog_pkmeta(catalog);
	const size_t len = sizeof(*pkm) - sizeof(pkm->pm_meta_csum);

	return silofs_hash_xxh64(pkm, len, seed);
}

static void catalog_encode_meta(struct silofs_catalog *catalog)
{
	struct silofs_pack_meta1k *pkm = catalog_pkmeta(catalog);

	pkmeta1k_init(pkm);
	pkmeta1k_set_capacity(pkm, catalog->cat_capacity);
	pkmeta1k_set_ndescs(pkm, catalog_ndescs(catalog));
	pkmeta1k_set_descs_csum(pkm, catalog_calc_descs_csum(catalog));
	pkmeta1k_set_meta_csum(pkm, catalog_calc_meta_csum(catalog));
}

static void catalog_update_caddr(struct silofs_catalog *catalog)
{
	silofs_calc_caddr_of(catalog->cat_bbuf.ptr,
	                     catalog->cat_bbuf.len,
	                     &catalog->cat_mdigest,
	                     &catalog->cat_caddr);
}

int silofs_catalog_encode(struct silofs_catalog *catalog)
{
	int err;

	err = catalog_pre_encode(catalog);
	if (err) {
		return err;
	}
	catalog_encode_descs(catalog);
	catalog_encode_meta(catalog);
	catalog_update_caddr(catalog);
	return 0;
}
