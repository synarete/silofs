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
#include "htox.h"
#include "pndptr.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_pndptr s_pndptr_none = {
	.nmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.nmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
	.paddr.pos         = SILOFS_OFF_NULL,
	.paddr.mtype       = SILOFS_MTYPE_NONE,
};

const struct silofs_pndptr *silofs_pndptr_none(void)
{
	return &s_pndptr_none;
}

void silofs_pndptr_setup(struct silofs_pndptr *pndptr,
                         const struct silofs_paddr *paddr,
                         const struct silofs_civkey *civkey)
{
	silofs_paddr_assign(&pndptr->paddr, paddr);
	silofs_nmeta_setup(&pndptr->nmeta, civkey);
}

void silofs_pndptr_setup2(struct silofs_pndptr *pndptr,
                          const struct silofs_paddr *paddr,
                          const struct silofs_nmeta *nmeta)
{
	silofs_paddr_assign(&pndptr->paddr, paddr);
	silofs_nmeta_assign(&pndptr->nmeta, nmeta);
}

void silofs_pndptr_reset(struct silofs_pndptr *pndptr)
{
	silofs_paddr_reset(&pndptr->paddr);
	silofs_nmeta_reset(&pndptr->nmeta);
}

void silofs_pndptr_assign(struct silofs_pndptr *pndptr,
                          const struct silofs_pndptr *other)
{
	silofs_paddr_assign(&pndptr->paddr, &other->paddr);
	silofs_nmeta_assign(&pndptr->nmeta, &other->nmeta);
}

bool silofs_pndptr_isnull(const struct silofs_pndptr *pndptr)
{
	return silofs_paddr_isnull(&pndptr->paddr) ||
	       !pndptr->nmeta.ciargs.algo || !pndptr->nmeta.ciargs.mode;
}

void silofs_pndptr192b_htox(struct silofs_pndptr192b *pndptr192,
                            const struct silofs_pndptr *pndptr)
{
	memset(pndptr192, 0, sizeof(*pndptr192));
	silofs_paddr64b_htox(&pndptr192->np_paddr, &pndptr->paddr);
	silofs_nmeta128b_htox(&pndptr192->np_nmeta, &pndptr->nmeta);
}

void silofs_pndptr192b_xtoh(const struct silofs_pndptr192b *pndptr192,
                            struct silofs_pndptr *pndptr)
{
	silofs_paddr64b_xtoh(&pndptr192->np_paddr, &pndptr->paddr);
	silofs_nmeta128b_xtoh(&pndptr192->np_nmeta, &pndptr->nmeta);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_btnptr s_btnptr_none = {
	.base.nmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.base.nmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
	.base.paddr.pos         = SILOFS_OFF_NULL,
	.base.paddr.mtype       = SILOFS_MTYPE_NONE,
	.nsub_vobjs             = 0,
	.nsub_btnodes           = 0,

};

const struct silofs_btnptr *silofs_btnptr_none(void)
{
	return &s_btnptr_none;
}

void silofs_btnptr_setup(struct silofs_btnptr *btnptr,
                         const struct silofs_pndptr *pndptr)
{
	silofs_pndptr_assign(&btnptr->base, pndptr);
	btnptr->nsub_vobjs   = 0;
	btnptr->nsub_btnodes = 0;
}

void silofs_btnptr_reset(struct silofs_btnptr *btnptr)
{
	silofs_pndptr_reset(&btnptr->base);
	btnptr->nsub_vobjs   = 0;
	btnptr->nsub_btnodes = 0;
}

void silofs_btnptr_assign(struct silofs_btnptr *btnptr,
                          const struct silofs_btnptr *other)
{
	silofs_pndptr_assign(&btnptr->base, &other->base);
	btnptr->nsub_vobjs   = other->nsub_vobjs;
	btnptr->nsub_btnodes = other->nsub_btnodes;
}

bool silofs_btnptr_isnull(const struct silofs_btnptr *btnptr)
{
	return silofs_pndptr_isnull(&btnptr->base);
}

void silofs_btnptr256b_htox(struct silofs_btnptr256b *btnptr256,
                            const struct silofs_btnptr *btnptr)
{
	memset(btnptr256, 0, sizeof(*btnptr256));
	silofs_pndptr192b_htox(&btnptr256->btp_base, &btnptr->base);
	btnptr256->btp_nsub_vobjs = silofs_cpu_to_le64(btnptr->nsub_vobjs);
	btnptr256->btp_nsub_btnodes =
		silofs_cpu_to_le32((uint32_t)btnptr->nsub_btnodes);
}

void silofs_btnptr256b_xtoh(const struct silofs_btnptr256b *btnptr256,
                            struct silofs_btnptr *btnptr)
{
	silofs_pndptr192b_xtoh(&btnptr256->btp_base, &btnptr->base);
	btnptr->nsub_vobjs   = silofs_le64_to_cpu(btnptr256->btp_nsub_vobjs);
	btnptr->nsub_btnodes = silofs_le32_to_cpu(btnptr256->btp_nsub_btnodes);
}
