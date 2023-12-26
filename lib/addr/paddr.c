/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvid_generate(struct silofs_pvid *pvid)
{
	silofs_uuid_generate(&pvid->uuid);
}

void silofs_pvid_assign(struct silofs_pvid *pvid,
                        const struct silofs_pvid *other)
{
	silofs_uuid_assign(&pvid->uuid, &other->uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr s_paddr_none = {
	.index = 0,
	.off = SILOFS_OFF_NULL,
	.len = 0
};

const struct silofs_paddr *silofs_paddr_none(void)
{
	return &s_paddr_none;
}

bool silofs_paddr_isnull(const struct silofs_paddr *paddr)
{
	return !paddr->index || !paddr->len || off_isnull(paddr->off);
}

void silofs_paddr_reset(struct silofs_paddr *paddr)
{
	silofs_memzero(paddr, sizeof(*paddr));
	paddr->off = SILOFS_OFF_NULL;
}

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other)
{
	silofs_pvid_assign(&paddr->pvid, &other->pvid);
	paddr->index = other->index;
	paddr->off = other->off;
	paddr->len = other->len;
}


void silofs_paddr32b_reset(struct silofs_paddr32b *paddr32)
{
	memset(paddr32, 0, sizeof(*paddr32));
	paddr32->index = 0;
	paddr32->len = 0;
	paddr32->off = SILOFS_OFF_NULL;
}

void silofs_paddr32b_htox(struct silofs_paddr32b *paddr32,
                          const struct silofs_paddr *paddr)
{
	silofs_pvid_assign(&paddr32->pvid, &paddr->pvid);
	paddr32->index = silofs_cpu_to_le32((uint32_t)(paddr->index));
	paddr32->len = silofs_cpu_to_le32((uint32_t)(paddr->len));
	paddr32->off = silofs_cpu_to_off(paddr->off);
}

void silofs_paddr32b_xtoh(const struct silofs_paddr32b *paddr32,
                          struct silofs_paddr *paddr)
{
	silofs_pvid_assign(&paddr->pvid, &paddr32->pvid);
	paddr->index = silofs_le32_to_cpu(paddr32->index);
	paddr->len = silofs_le32_to_cpu(paddr32->len);
	paddr->off = silofs_off_to_cpu(paddr32->off);
}
