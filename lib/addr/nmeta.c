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

static const struct silofs_nodeptr s_nodeptr_none = {
	.nmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.nmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
	.paddr.pos         = SILOFS_OFF_NULL,
	.paddr.mtype       = SILOFS_MTYPE_NONE,
	.paddr.btype       = SILOFS_BTYPE_NONE,
};

const struct silofs_nodeptr *silofs_nodeptr_none(void)
{
	return &s_nodeptr_none;
}

void silofs_nodeptr_setup(struct silofs_nodeptr *nodeptr,
                          const struct silofs_paddr *paddr,
                          const struct silofs_civkey *civkey)
{
	silofs_paddr_assign(&nodeptr->paddr, paddr);
	silofs_nmeta_setup(&nodeptr->nmeta, civkey);
}

void silofs_nodeptr_setup2(struct silofs_nodeptr *nodeptr,
                           const struct silofs_paddr *paddr,
                           const struct silofs_nmeta *nmeta)
{
	silofs_paddr_assign(&nodeptr->paddr, paddr);
	silofs_nmeta_assign(&nodeptr->nmeta, nmeta);
}

void silofs_nodeptr_reset(struct silofs_nodeptr *nodeptr)
{
	silofs_paddr_reset(&nodeptr->paddr);
	silofs_nmeta_reset(&nodeptr->nmeta);
}

void silofs_nodeptr_assign(struct silofs_nodeptr *nodeptr,
                           const struct silofs_nodeptr *other)
{
	silofs_paddr_assign(&nodeptr->paddr, &other->paddr);
	silofs_nmeta_assign(&nodeptr->nmeta, &other->nmeta);
}

bool silofs_nodeptr_isnull(const struct silofs_nodeptr *nodeptr)
{
	return silofs_paddr_isnull(&nodeptr->paddr);
}

void silofs_nodeptr256b_htox(struct silofs_nodeptr256b *nodeptr256,
                             const struct silofs_nodeptr *nodeptr)
{
	memset(nodeptr256, 0, sizeof(*nodeptr256));
	silofs_paddr64b_htox(&nodeptr256->pn_paddr, &nodeptr->paddr);
	silofs_nmeta128b_htox(&nodeptr256->pn_nmeta, &nodeptr->nmeta);
}

void silofs_nodeptr256b_xtoh(const struct silofs_nodeptr256b *nodeptr256,
                             struct silofs_nodeptr *nodeptr)
{
	silofs_paddr64b_xtoh(&nodeptr256->pn_paddr, &nodeptr->paddr);
	silofs_nmeta128b_xtoh(&nodeptr256->pn_nmeta, &nodeptr->nmeta);
}
