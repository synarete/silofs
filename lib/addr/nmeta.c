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
#include "paddr.h"
#include "nmeta.h"

static const struct silofs_nmeta s_nmeta_none = {
	.ciargs.algo = SILOFS_CIPHER_NONE,
	.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
};

const struct silofs_nmeta *silofs_nmeta_none(void)
{
	return &s_nmeta_none;
}

void silofs_nmeta_setup(struct silofs_nmeta *nmeta,
                        const struct silofs_civkey *civkey)
{
	silofs_civkey_assign(&nmeta->civkey, civkey);
	silofs_ciargs_assign(&nmeta->ciargs, silofs_ciargs_default());
}

void silofs_nmeta_reset(struct silofs_nmeta *nmeta)
{
	silofs_civkey_reset(&nmeta->civkey);
	silofs_ciargs_reset(&nmeta->ciargs);
}

void silofs_nmeta_assign(struct silofs_nmeta *nmeta,
                         const struct silofs_nmeta *other)
{
	silofs_civkey_assign(&nmeta->civkey, &other->civkey);
	silofs_ciargs_assign(&nmeta->ciargs, &other->ciargs);
}

void silofs_nmeta128b_htox(struct silofs_nmeta128b *nmeta128,
                           const struct silofs_nmeta *nmeta)
{
	const uint16_t algo = (uint16_t)(nmeta->ciargs.algo);
	const uint16_t mode = (uint16_t)(nmeta->ciargs.mode);

	memset(nmeta128, 0, sizeof(*nmeta128));
	silofs_ckey_assign(&nmeta128->nm_cipher_key, &nmeta->civkey.key);
	silofs_civ_assign(&nmeta128->nm_cipher_iv, &nmeta->civkey.iv);
	nmeta128->nm_cipher_algo = silofs_cpu_to_le16(algo);
	nmeta128->nm_cipher_mode = silofs_cpu_to_le16(mode);
}

void silofs_nmeta128b_xtoh(const struct silofs_nmeta128b *nmeta128,
                           struct silofs_nmeta *nmeta)
{
	const uint16_t algo = silofs_le16_to_cpu(nmeta128->nm_cipher_algo);
	const uint16_t mode = silofs_le16_to_cpu(nmeta128->nm_cipher_mode);

	silofs_ckey_assign(&nmeta->civkey.key, &nmeta128->nm_cipher_key);
	silofs_civ_assign(&nmeta->civkey.iv, &nmeta128->nm_cipher_iv);
	nmeta->ciargs.algo = (enum silofs_cipher_algo)algo;
	nmeta->ciargs.mode = (enum silofs_cipher_mode)mode;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_pnodeptr s_pnodeptr_none = {
	.nmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.nmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
	.paddr.pos         = SILOFS_OFF_NULL,
	.paddr.mtype       = SILOFS_MTYPE_NONE,
	.paddr.btype       = SILOFS_BTYPE_NONE,
	.nsub_vobjs        = 0,
	.nsub_btnodes      = 0,

};

const struct silofs_pnodeptr *silofs_pnodeptr_none(void)
{
	return &s_pnodeptr_none;
}

void silofs_pnodeptr_setup(struct silofs_pnodeptr *pnodeptr,
                           const struct silofs_paddr *paddr,
                           const struct silofs_civkey *civkey)
{
	silofs_paddr_assign(&pnodeptr->paddr, paddr);
	silofs_nmeta_setup(&pnodeptr->nmeta, civkey);
	pnodeptr->nsub_vobjs   = 0;
	pnodeptr->nsub_btnodes = 0;
}

void silofs_pnodeptr_setup2(struct silofs_pnodeptr *pnodeptr,
                            const struct silofs_paddr *paddr,
                            const struct silofs_nmeta *nmeta)
{
	silofs_paddr_assign(&pnodeptr->paddr, paddr);
	silofs_nmeta_assign(&pnodeptr->nmeta, nmeta);
	pnodeptr->nsub_vobjs   = 0;
	pnodeptr->nsub_btnodes = 0;
}

void silofs_pnodeptr_reset(struct silofs_pnodeptr *pnodeptr)
{
	silofs_paddr_reset(&pnodeptr->paddr);
	silofs_nmeta_reset(&pnodeptr->nmeta);
	pnodeptr->nsub_vobjs   = 0;
	pnodeptr->nsub_btnodes = 0;
}

void silofs_pnodeptr_assign(struct silofs_pnodeptr *pnodeptr,
                            const struct silofs_pnodeptr *other)
{
	silofs_paddr_assign(&pnodeptr->paddr, &other->paddr);
	silofs_nmeta_assign(&pnodeptr->nmeta, &other->nmeta);
	pnodeptr->nsub_vobjs   = other->nsub_vobjs;
	pnodeptr->nsub_btnodes = other->nsub_btnodes;
}

bool silofs_pnodeptr_isnull(const struct silofs_pnodeptr *pnodeptr)
{
	return silofs_paddr_isnull(&pnodeptr->paddr);
}

void silofs_pnodeptr256b_htox(struct silofs_pnodeptr256b *pnodeptr256,
                              const struct silofs_pnodeptr *pnodeptr)
{
	memset(pnodeptr256, 0, sizeof(*pnodeptr256));
	silofs_paddr64b_htox(&pnodeptr256->pn_paddr, &pnodeptr->paddr);
	silofs_nmeta128b_htox(&pnodeptr256->pn_nmeta, &pnodeptr->nmeta);
	pnodeptr256->pn_nsub_vobjs = silofs_cpu_to_le64(pnodeptr->nsub_vobjs);
	pnodeptr256->pn_nsub_btnodes =
		silofs_cpu_to_le32((uint32_t)pnodeptr->nsub_btnodes);
}

void silofs_pnodeptr256b_xtoh(const struct silofs_pnodeptr256b *pnodeptr256,
                              struct silofs_pnodeptr *pnodeptr)
{
	silofs_paddr64b_xtoh(&pnodeptr256->pn_paddr, &pnodeptr->paddr);
	silofs_nmeta128b_xtoh(&pnodeptr256->pn_nmeta, &pnodeptr->nmeta);
	pnodeptr->nsub_vobjs = silofs_le64_to_cpu(pnodeptr256->pn_nsub_vobjs);
	pnodeptr->nsub_btnodes =
		silofs_le32_to_cpu(pnodeptr256->pn_nsub_btnodes);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pstate384b_htox(struct silofs_pstate384b *pstate384,
                            const struct silofs_pstate *pstate)
{
	memset(pstate384, 0, sizeof(*pstate384));
	silofs_pnodeptr256b_htox(&pstate384->bts_apex, &pstate->apex);
	silofs_paddr64b_htox(&pstate384->bts_edge, &pstate->edge);
}

void silofs_pstate384b_xtoh(const struct silofs_pstate384b *pstate384,
                            struct silofs_pstate *pstate)
{
	silofs_pnodeptr256b_xtoh(&pstate384->bts_apex, &pstate->apex);
	silofs_paddr64b_xtoh(&pstate384->bts_edge, &pstate->edge);
	pstate->vspace = SILOFS_MTYPE_NONE;
}
