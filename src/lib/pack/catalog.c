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

void silofs_pkdesc_to_name(const struct silofs_pack_desc *pd,
                           struct silofs_strbuf *out_name)
{
	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(pd->pd_hash.hash, sizeof(pd->pd_hash.hash),
	                    out_name->str, sizeof(out_name->str) - 1);
}

static void calc_hash_of(const struct silofs_mdigest *md,
                         const void *buf, size_t bsz,
                         struct silofs_hash256 *out_hash)
{
	silofs_sha256_of(md, buf, bsz, out_hash);
}

void silofs_pkdesc_update_hash(struct silofs_pack_desc *pd,
                               const struct silofs_mdigest *md,
                               const void *buf, size_t bsz)
{
	calc_hash_of(md, buf, bsz, &pd->pd_hash);
}


static void silofs_pack_desc128b_reset(struct silofs_pack_desc128b *pdx)
{
	memset(pdx, 0, sizeof(*pdx));
}

void silofs_pkdesc128b_htox(struct silofs_pack_desc128b *pdx,
                            const struct silofs_pack_desc *pd)
{
	silofs_pack_desc128b_reset(pdx);
	silofs_hash256_assign(&pdx->pd_hash, &pd->pd_hash);
	silofs_laddr48b_htox(&pdx->pd_laddr, &pd->pd_laddr);
}

void silofs_pkdesc128b_xtoh(const struct silofs_pack_desc128b *pdx,
                            struct silofs_pack_desc *pd)
{
	silofs_hash256_assign(&pd->pd_hash, &pdx->pd_hash);
	silofs_laddr48b_xtoh(&pdx->pd_laddr, &pd->pd_laddr);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pack_desc_info *pdi_from_lh(struct silofs_list_head *lh)
{
	struct silofs_pack_desc_info *pdi = NULL;

	if (lh != NULL) {
		pdi = container_of(lh, struct silofs_pack_desc_info, pdi_lh);
	}
	return pdi;
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

void silofs_pdi_to_name(const struct silofs_pack_desc_info *pdi,
                        struct silofs_strbuf *out_name)
{
	silofs_pkdesc_to_name(&pdi->pd, out_name);
}

bool silofs_pdi_isbootrec(const struct silofs_pack_desc_info *pdi)
{
	return (pdi->pd.pd_laddr.ltype == SILOFS_LTYPE_BOOTREC);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_catalog_init(struct silofs_catalog *catalog,
                        struct silofs_alloc *alloc)
{
	silofs_listq_init(&catalog->cat_descq);
	catalog->cat_alloc = alloc;
	catalog->cat_capacity = 0;
	return silofs_mdigest_init(&catalog->cat_mdigest);
}

void silofs_catalog_fini(struct silofs_catalog *catalog)
{
	silofs_catalog_clear_descq(catalog);
	silofs_listq_fini(&catalog->cat_descq);
	silofs_mdigest_fini(&catalog->cat_mdigest);
	catalog->cat_alloc = NULL;
}

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
	silofs_listq_push_back(&catalog->cat_descq, &pdi->pdi_lh);
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

void silofs_catalog_clear_descq(struct silofs_catalog *catalog)
{
	struct silofs_pack_desc_info *pdi;

	pdi = catalog_pop_desc(catalog);
	while (pdi != NULL) {
		pdi_del(pdi, catalog->cat_alloc);
		pdi = catalog_pop_desc(catalog);
	}
}
