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
#include "str.h"
#include "htox.h"
#include "baddr.h"

void silofs_baddr_reset(struct silofs_baddr *baddr)
{
	silofs_memffff(baddr, sizeof(*baddr));
	baddr->adt = SILOFS_ADT_NONE;
}

void silofs_baddr_setup(struct silofs_baddr *baddr,
                        const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&baddr->ad.paddr, paddr);
	baddr->adt = SILOFS_ADT_PADDR;
}

void silofs_baddr_setup2(struct silofs_baddr *baddr,
                         const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&baddr->ad.caddr, caddr);
	baddr->adt = SILOFS_ADT_CADDR;
}

static enum silofs_adt baddr64_adt(const union silofs_baddr64b *baddr64)
{
	return baddr64->b.adt;
}

static void
baddr64_set_type(union silofs_baddr64b *baddr64, enum silofs_adt adt)
{
	baddr64->b.adt = (uint8_t)adt;
}

void silofs_baddr64b_reset(union silofs_baddr64b *baddr64)
{
	silofs_memzero(baddr64, sizeof(*baddr64));
	baddr64_set_type(baddr64, SILOFS_ADT_NONE);
}

void silofs_baddr64b_htox(union silofs_baddr64b *baddr64,
                          const struct silofs_baddr *baddr)
{
	switch (baddr->adt) {
	case SILOFS_ADT_PADDR:
		silofs_paddr64b_htox(&baddr64->paddr, &baddr->ad.paddr);
		baddr64_set_type(baddr64, SILOFS_ADT_PADDR);
		break;
	case SILOFS_ADT_CADDR:
		silofs_caddr64b_htox(&baddr64->caddr, &baddr->ad.caddr);
		baddr64_set_type(baddr64, SILOFS_ADT_CADDR);
		break;
	case SILOFS_ADT_NONE:
	default:
		silofs_baddr64b_reset(baddr64);
		break;
	}
}

void silofs_baddr64b_xtoh(const union silofs_baddr64b *baddr64,
                          struct silofs_baddr *baddr)
{
	enum silofs_adt adt = baddr64_adt(baddr64);

	switch (adt) {
	case SILOFS_ADT_PADDR:
		silofs_paddr64b_xtoh(&baddr64->paddr, &baddr->ad.paddr);
		baddr->adt = SILOFS_ADT_PADDR;
		break;
	case SILOFS_ADT_CADDR:
		silofs_caddr64b_xtoh(&baddr64->caddr, &baddr->ad.caddr);
		baddr->adt = SILOFS_ADT_CADDR;
		break;
	case SILOFS_ADT_NONE:
	default:
		silofs_baddr_reset(baddr);
		break;
	}
}
