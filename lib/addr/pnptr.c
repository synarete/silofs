/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/addr.h>

static const struct silofs_pnptr s_pnptr_none = {
	.nmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.nmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
	.paddr.pos         = SILOFS_OFF_NULL,
	.paddr.ptype       = SILOFS_PTYPE_NONE,
};

const struct silofs_pnptr *silofs_pnptr_none(void)
{
	return &s_pnptr_none;
}

void silofs_pnptr_setup(struct silofs_pnptr *pnptr,
                        const struct silofs_paddr *paddr,
                        const struct silofs_civkey *civkey)
{
	silofs_paddr_assign(&pnptr->paddr, paddr);
	silofs_nmeta_setup(&pnptr->nmeta, civkey);
}

void silofs_pnptr_setup2(struct silofs_pnptr *pnptr,
                         const struct silofs_paddr *paddr,
                         const struct silofs_nmeta *nmeta)
{
	silofs_paddr_assign(&pnptr->paddr, paddr);
	silofs_nmeta_assign(&pnptr->nmeta, nmeta);
}

void silofs_pnptr_reset(struct silofs_pnptr *pnptr)
{
	silofs_paddr_reset(&pnptr->paddr);
	silofs_nmeta_reset(&pnptr->nmeta);
}

void silofs_pnptr_assign(struct silofs_pnptr *pnptr,
                         const struct silofs_pnptr *other)
{
	silofs_paddr_assign(&pnptr->paddr, &other->paddr);
	silofs_nmeta_assign(&pnptr->nmeta, &other->nmeta);
}

bool silofs_pnptr_isequal(const struct silofs_pnptr *pnptr,
                          const struct silofs_pnptr *other)
{
	return silofs_paddr_isequal(&pnptr->paddr, &other->paddr) &&
	       silofs_nmeta_isequal(&pnptr->nmeta, &other->nmeta);
}

bool silofs_pnptr_isnull(const struct silofs_pnptr *pnptr)
{
	return silofs_paddr_isnull(&pnptr->paddr) ||
	       !pnptr->nmeta.ciargs.algo || !pnptr->nmeta.ciargs.mode;
}

void silofs_pnptr256b_htox(struct silofs_pnptr256b *pnptr256,
                           const struct silofs_pnptr *pnptr)
{
	memset(pnptr256, 0, sizeof(*pnptr256));
	silofs_paddr64b_htox(&pnptr256->pp_paddr, &pnptr->paddr);
	silofs_nmeta128b_htox(&pnptr256->pp_nmeta, &pnptr->nmeta);
}

void silofs_pnptr256b_xtoh(const struct silofs_pnptr256b *pnptr256,
                           struct silofs_pnptr *pnptr)
{
	silofs_paddr64b_xtoh(&pnptr256->pp_paddr, &pnptr->paddr);
	silofs_nmeta128b_xtoh(&pnptr256->pp_nmeta, &pnptr->nmeta);
}
