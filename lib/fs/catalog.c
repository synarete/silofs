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

void silofs_pkdesc_update_caddr_by(struct silofs_pack_desc *pd,
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

size_t silofs_pdi_capacity(const struct silofs_pack_desc_info *pdi)
{
	return pdi->pd.pd_laddr.len;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_pack_ref {
	struct silofs_pack_meta1k   *meta;
	struct silofs_pack_desc256b *descs;
	size_t capacity;
	size_t ndescs_max;
	size_t ndescs;
};

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

int silofs_catalog_init(struct silofs_catalog *catalog,
                        struct silofs_alloc *alloc)
{
	silofs_listq_init(&catalog->cat_descq);
	catalog->cat_alloc = alloc;
	return silofs_mdigest_init(&catalog->cat_mdigest);
}

void silofs_catalog_fini(struct silofs_catalog *catalog)
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

int silofs_catalog_encsize(const struct silofs_catalog *catalog,
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

		pref->capacity += silofs_pdi_capacity(pdi);
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
		pdi = silofs_catalog_add_desc(catalog, laddr_none());
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


int silofs_catalog_encode(struct silofs_catalog *catalog,
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

int silofs_catalog_decode(struct silofs_catalog *catalog,
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
