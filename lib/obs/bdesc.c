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
#include "addr.h"
#include "pnodes.h"
#include "bdesc.h"

static void bd_setup_hdr(struct silofs_blob_desc *bd)
{
	silofs_hdr_setup(&bd->bd_hdr, SILOFS_PTYPE_BDESC, sizeof(*bd),
	                 SILOFS_HDRF_PTYPE);
}

static void
bd_set_prev(struct silofs_blob_desc *bd, const struct silofs_blobid *blobid)
{
	silofs_blobid_assign(&bd->bd_prev, blobid);
}

static void bd_reset_prev(struct silofs_blob_desc *bd)
{
	bd_set_prev(bd, silofs_blobid_none());
}

static void
bd_set_refblob(struct silofs_blob_desc *bd, const struct silofs_blobid *blobid)
{
	silofs_blobid_assign(&bd->bd_refblob, blobid);
}

static void bd_reset_refblob(struct silofs_blob_desc *bd)
{
	bd_set_refblob(bd, silofs_blobid_none());
}

static void bd_set_blobsize(struct silofs_blob_desc *bd, size_t sz)
{
	bd->bd_blobsize = silofs_cpu_to_le64(sz);
}

static void bd_set_objsize(struct silofs_blob_desc *bd, size_t sz)
{
	bd->bd_objsize = silofs_cpu_to_le32((uint32_t)sz);
}

static void bd_set_nobjs_max(struct silofs_blob_desc *bd, size_t n)
{
	bd->bd_nobjs_max = silofs_cpu_to_le32((uint32_t)n);
}

static void bd_set_nobjs(struct silofs_blob_desc *bd, size_t n)
{
	bd->bd_nobjs = silofs_cpu_to_le32((uint32_t)n);
}

static void bd_set_reftype(struct silofs_blob_desc *bd, uint16_t t)
{
	bd->bd_reftype = silofs_cpu_to_le16((uint16_t)t);
}

static void bd_reset_state(struct silofs_blob_desc *bd)
{
	memset(bd->bd_alloc_state, 0, sizeof(bd->bd_alloc_state));
}

static void bd_init(struct silofs_blob_desc *bd)
{
	bd_setup_hdr(bd);
	bd_reset_prev(bd);
	bd_reset_refblob(bd);
	bd_set_blobsize(bd, 0);
	bd_set_objsize(bd, 0);
	bd_set_nobjs_max(bd, 0);
	bd_set_nobjs(bd, 0);
	bd_set_reftype(bd, 0);
	bd_reset_state(bd);
}

static void bd_fini(struct silofs_blob_desc *bd)
{
	bd_reset_prev(bd);
	bd_reset_refblob(bd);
	bd_set_nobjs(bd, 0);
	bd_reset_state(bd);
}

static struct silofs_blob_desc *bd_malloc(struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd;

	bd = silofs_memalloc(alloc, sizeof(*bd), SILOFS_ALLOCF_BZERO);
	return bd;
}

static void bd_free(struct silofs_blob_desc *bd, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bd, sizeof(*bd), SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_blob_desc *bd_new(struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd;

	bd = bd_malloc(alloc);
	if (bd != NULL) {
		bd_init(bd);
	}
	return bd;
}

static void bd_del(struct silofs_blob_desc *bd, struct silofs_alloc *alloc)
{
	bd_fini(bd);
	bd_free(bd, alloc);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_bdesc_info *bdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_bdesc_info *bdi = NULL;

	bdi = silofs_memalloc(alloc, sizeof(*bdi), 0);
	return bdi;
}

static void bdi_free(struct silofs_bdesc_info *bdi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, bdi, sizeof(*bdi), 0);
}

static void
bdi_init(struct silofs_bdesc_info *bdi, const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));
	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BDESC);

	silofs_pni_init(&bdi->bd_pni, paddr);
	bdi->bd = NULL;
}

static void bdi_fini(struct silofs_bdesc_info *bdi)
{
	silofs_pni_fini(&bdi->bd_pni);
	bdi->bd = NULL;
}

struct silofs_bdesc_info *
silofs_bdi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd = NULL;
	struct silofs_bdesc_info *bdi = NULL;

	bd = bd_new(alloc);
	if (bd == NULL) {
		return NULL;
	}
	bdi = bdi_malloc(alloc);
	if (bdi == NULL) {
		bd_del(bd, alloc);
		return NULL;
	}
	bdi_init(bdi, paddr);
	bdi->bd = bd;
	return bdi;
}

void silofs_bdi_del(struct silofs_bdesc_info *bdi, struct silofs_alloc *alloc)
{
	struct silofs_blob_desc *bd = bdi->bd;

	bdi_fini(bdi);
	bdi_free(bdi, alloc);
	bd_del(bd, alloc);
}

void silofs_bdi_dirtify(struct silofs_bdesc_info *bdi)
{
	silofs_pni_dirtify(&bdi->bd_pni);
}

void silofs_bdi_undirtify(struct silofs_bdesc_info *bdi)
{
	silofs_pni_undirtify(&bdi->bd_pni);
}

static struct silofs_bdesc_info *bdi_unconst(const struct silofs_bdesc_info *p)
{
	union {
		const struct silofs_bdesc_info *p;
		struct silofs_bdesc_info *q;
	} u = { .p = p };

	return u.q;
}

struct silofs_bdesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni)
{
	const struct silofs_bdesc_info *bdi = NULL;

	if (pni != NULL) {
		silofs_assert_eq(pni->pn_paddr.ptype, SILOFS_PTYPE_BDESC);
		bdi = container_of2(pni, struct silofs_bdesc_info, bd_pni);
	}
	return bdi_unconst(bdi);
}

void silofs_bdi_set_dq(struct silofs_bdesc_info *bdi, struct silofs_dirtyq *dq)
{
	silofs_pni_set_dq(&bdi->bd_pni, dq);
}
