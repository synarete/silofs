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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pvlogs.h>

void silofs_pvasd_init(struct silofs_pvasd *pvasd)
{
	silofs_pvid_generate(&pvasd->pvid);
	pvasd->base_index = 1;
	pvasd->curr_index = 1;
	pvasd->curr_pos = 0;
}

void silofs_pvasd_fini(struct silofs_pvasd *pvasd)
{
	pvasd->base_index = 0;
	pvasd->curr_index = 0;
	pvasd->curr_pos = -1;
}

void silofs_pvasd_assign(struct silofs_pvasd *pvasd,
                         const struct silofs_pvasd *other)
{
	silofs_pvid_assign(&pvasd->pvid, &other->pvid);
	pvasd->base_index = other->base_index;
	pvasd->curr_index = other->curr_index;
	pvasd->curr_pos = other->curr_pos;
}

static void
pvasd_curr_psid(const struct silofs_pvasd *pvasd, struct silofs_psid *out_psid)
{
	silofs_psid_init(out_psid, &pvasd->pvid, pvasd->curr_index);
}

static void
pvasd_curr_paddr_at(const struct silofs_pvasd *pvasd, loff_t pos,
                    enum silofs_ptype ptype, struct silofs_paddr *out_paddr)
{
	struct silofs_psid psid;
	const size_t len = silofs_ptype_size(ptype);

	pvasd_curr_psid(pvasd, &psid);
	silofs_paddr_init(out_paddr, &psid, ptype, pos, len);
}

static void
pvasd_curr_paddr(const struct silofs_pvasd *pvasd, enum silofs_ptype ptype,
                 struct silofs_paddr *out_paddr)
{
	pvasd_curr_paddr_at(pvasd, pvasd->curr_pos, ptype, out_paddr);
}

static void
pvasd_last_paddr(const struct silofs_pvasd *pvasd, enum silofs_ptype ptype,
                 struct silofs_paddr *out_paddr)
{
	const loff_t off = pvasd->curr_pos;
	const ssize_t len = (ssize_t)silofs_ptype_size(ptype);
	const loff_t pos = (off > len) ? (off - len) : 0;

	pvasd_curr_paddr_at(pvasd, pos, ptype, out_paddr);
}

static void
pvasd_advance_by(struct silofs_pvasd *pvasd, const struct silofs_paddr *paddr)
{
	pvasd->curr_pos = off_end(paddr->off, paddr->len);
}

static void pvasd_carve(struct silofs_pvasd *pvasd, enum silofs_ptype ptype,
                        struct silofs_paddr *out_paddr)
{
	pvasd_curr_paddr(pvasd, ptype, out_paddr);
	pvasd_advance_by(pvasd, out_paddr);
}

static bool pvasd_has_pvid(const struct silofs_pvasd *pvasd,
                           const struct silofs_pvid *pvid)
{
	return silofs_pvid_isequal(&pvasd->pvid, pvid);
}

static bool pvasd_has_index(const struct silofs_pvasd *pvasd, uint32_t idx)
{
	return (idx >= pvasd->base_index) && (idx <= pvasd->curr_index);
}

bool silofs_pvasd_has_paddr(const struct silofs_pvasd *pvasd,
                            const struct silofs_paddr *paddr)
{
	if (paddr_isnull(paddr)) {
		return false;
	}
	if (!pvasd_has_pvid(pvasd, &paddr->psid.pvid)) {
		return false;
	}
	if (!pvasd_has_index(pvasd, paddr->psid.index)) {
		return false;
	}
	return true;
}

int silofs_pvasd_validate(const struct silofs_pvasd *pvasd)
{
	if (pvasd->base_index > pvasd->curr_index) {
		return -SILOFS_EINVAL;
	}
	if (pvasd->base_index > (UINT32_MAX / 2)) {
		return -SILOFS_EINVAL;
	}
	if (off_isnull(pvasd->curr_pos)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

void silofs_pvasd_next_chkpt(struct silofs_pvasd *pvasd,
                             struct silofs_paddr *out_paddr)
{
	pvasd_carve(pvasd, SILOFS_PTYPE_CHKPT, out_paddr);
}

void silofs_pvasd_last_chkpt(const struct silofs_pvasd *pvasd,
                             struct silofs_paddr *out_paddr)
{
	pvasd_last_paddr(pvasd, SILOFS_PTYPE_CHKPT, out_paddr);
}

void silofs_pvasd_next_btnode(struct silofs_pvasd *pvasd,
                              struct silofs_paddr *out_paddr)
{
	silofs_assert_gt(pvasd->curr_pos, 0);

	pvasd_carve(pvasd, SILOFS_PTYPE_BTNODE, out_paddr);
}

void silofs_pvasd64b_htox(struct silofs_pvasd64b *pvasd64,
                          const struct silofs_pvasd *pvasd)
{
	memset(pvasd64, 0, sizeof(*pvasd64));
	silofs_pvid_assign(&pvasd64->pvid, &pvasd->pvid);
	pvasd64->base_index = silofs_cpu_to_le32(pvasd->base_index);
	pvasd64->curr_index = silofs_cpu_to_le32(pvasd->curr_index);
	pvasd64->curr_pos = silofs_cpu_to_off(pvasd->curr_pos);
}

void silofs_pvasd64b_xtoh(const struct silofs_pvasd64b *pvasd64,
                          struct silofs_pvasd *pvasd)
{
	silofs_pvid_assign(&pvasd->pvid, &pvasd64->pvid);
	pvasd->base_index = silofs_le32_to_cpu(pvasd64->base_index);
	pvasd->curr_index = silofs_le32_to_cpu(pvasd64->curr_index);
	pvasd->curr_pos = silofs_off_to_cpu(pvasd64->curr_pos);
}
