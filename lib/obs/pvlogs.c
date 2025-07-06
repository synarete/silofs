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
#include "pvlogs.h"

void silofs_pvsegr_init(struct silofs_pvsegr *pvsegr)
{
	silofs_blobid_generate(&pvsegr->blobid);
	pvsegr->base_index = 1;
	pvsegr->curr_index = 1;
	pvsegr->curr_pos = 0;
}

void silofs_pvsegr_fini(struct silofs_pvsegr *pvsegr)
{
	pvsegr->base_index = 0;
	pvsegr->curr_index = 0;
	pvsegr->curr_pos = -1;
}

void silofs_pvsegr_assign(struct silofs_pvsegr *pvsegr,
                          const struct silofs_pvsegr *other)
{
	silofs_blobid_assign(&pvsegr->blobid, &other->blobid);
	pvsegr->base_index = other->base_index;
	pvsegr->curr_index = other->curr_index;
	pvsegr->curr_pos = other->curr_pos;
}

static void pvsegr_curr_pvsid(const struct silofs_pvsegr *pvsegr,
                              struct silofs_pvsid *out_pvsid)
{
	silofs_pvsid_init(out_pvsid, &pvsegr->blobid, pvsegr->curr_index);
}

static void
pvsegr_curr_paddr_at(const struct silofs_pvsegr *pvsegr, loff_t pos,
                     enum silofs_ptype ptype, struct silofs_paddr *out_paddr)
{
	struct silofs_pvsid pvsid;
	const size_t len = silofs_ptype_size(ptype);

	pvsegr_curr_pvsid(pvsegr, &pvsid);
	silofs_paddr_init(out_paddr, &pvsid, ptype, pos, len);
}

static void
pvsegr_curr_paddr(const struct silofs_pvsegr *pvsegr, enum silofs_ptype ptype,
                  struct silofs_paddr *out_paddr)
{
	pvsegr_curr_paddr_at(pvsegr, pvsegr->curr_pos, ptype, out_paddr);
}

static void
pvsegr_last_paddr(const struct silofs_pvsegr *pvsegr, enum silofs_ptype ptype,
                  struct silofs_paddr *out_paddr)
{
	const loff_t off = pvsegr->curr_pos;
	const ssize_t len = (ssize_t)silofs_ptype_size(ptype);
	const loff_t pos = (off > len) ? (off - len) : 0;

	pvsegr_curr_paddr_at(pvsegr, pos, ptype, out_paddr);
}

static void pvsegr_advance_by(struct silofs_pvsegr *pvsegr,
                              const struct silofs_paddr *paddr)
{
	pvsegr->curr_pos = silofs_off_end(paddr->off, paddr->len);
}

static void pvsegr_carve(struct silofs_pvsegr *pvsegr, enum silofs_ptype ptype,
                         struct silofs_paddr *out_paddr)
{
	pvsegr_curr_paddr(pvsegr, ptype, out_paddr);
	pvsegr_advance_by(pvsegr, out_paddr);
}

static bool pvsegr_has_blobid(const struct silofs_pvsegr *pvsegr,
                              const struct silofs_blobid *blobid)
{
	return silofs_blobid_isequal(&pvsegr->blobid, blobid);
}

static bool pvsegr_has_index(const struct silofs_pvsegr *pvsegr, uint32_t idx)
{
	return (idx >= pvsegr->base_index) && (idx <= pvsegr->curr_index);
}

bool silofs_pvsegr_has_paddr(const struct silofs_pvsegr *pvsegr,
                             const struct silofs_paddr *paddr)
{
	if (silofs_paddr_isnull(paddr)) {
		return false;
	}
	if (!pvsegr_has_blobid(pvsegr, &paddr->pvsid.blobid)) {
		return false;
	}
	if (!pvsegr_has_index(pvsegr, paddr->pvsid.index)) {
		return false;
	}
	return true;
}

int silofs_pvsegr_validate(const struct silofs_pvsegr *pvsegr)
{
	if (pvsegr->base_index > pvsegr->curr_index) {
		return -SILOFS_EINVAL;
	}
	if (pvsegr->base_index > (UINT32_MAX / 2)) {
		return -SILOFS_EINVAL;
	}
	if (silofs_off_isnull(pvsegr->curr_pos)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

void silofs_pvsegr_next_chkpt(struct silofs_pvsegr *pvsegr,
                              struct silofs_paddr *out_paddr)
{
	pvsegr_carve(pvsegr, SILOFS_PTYPE_CHKPT, out_paddr);
}

void silofs_pvsegr_last_chkpt(const struct silofs_pvsegr *pvsegr,
                              struct silofs_paddr *out_paddr)
{
	pvsegr_last_paddr(pvsegr, SILOFS_PTYPE_CHKPT, out_paddr);
}

void silofs_pvsegr_next_btnode(struct silofs_pvsegr *pvsegr,
                               struct silofs_paddr *out_paddr)
{
	silofs_assert_gt(pvsegr->curr_pos, 0);

	pvsegr_carve(pvsegr, SILOFS_PTYPE_BTNODE, out_paddr);
}

void silofs_pvsegr64b_htox(struct silofs_pvsegr64b *pvsegr64,
                           const struct silofs_pvsegr *pvsegr)
{
	memset(pvsegr64, 0, sizeof(*pvsegr64));
	silofs_blobid_assign(&pvsegr64->blobid, &pvsegr->blobid);
	pvsegr64->base_index = silofs_cpu_to_le32(pvsegr->base_index);
	pvsegr64->curr_index = silofs_cpu_to_le32(pvsegr->curr_index);
	pvsegr64->curr_pos = silofs_cpu_to_off(pvsegr->curr_pos);
}

void silofs_pvsegr64b_xtoh(const struct silofs_pvsegr64b *pvsegr64,
                           struct silofs_pvsegr *pvsegr)
{
	silofs_blobid_assign(&pvsegr->blobid, &pvsegr64->blobid);
	pvsegr->base_index = silofs_le32_to_cpu(pvsegr64->base_index);
	pvsegr->curr_index = silofs_le32_to_cpu(pvsegr64->curr_index);
	pvsegr->curr_pos = silofs_off_to_cpu(pvsegr64->curr_pos);
}
