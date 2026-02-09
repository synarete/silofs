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
#include "nodeptr.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_nodeptr s_nodeptr_none = {
	.nmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.nmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
	.paddr.pos         = SILOFS_OFF_NULL,
	.paddr.mtype       = SILOFS_MTYPE_NONE,
	.paddr.btype       = SILOFS_BTYPE_NONE,
	.nsub_vobjs        = 0,
	.nsub_btnodes      = 0,

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
	nodeptr->nsub_vobjs   = 0;
	nodeptr->nsub_btnodes = 0;
}

void silofs_nodeptr_setup2(struct silofs_nodeptr *nodeptr,
                           const struct silofs_paddr *paddr,
                           const struct silofs_nmeta *nmeta)
{
	silofs_paddr_assign(&nodeptr->paddr, paddr);
	silofs_nmeta_assign(&nodeptr->nmeta, nmeta);
	nodeptr->nsub_vobjs   = 0;
	nodeptr->nsub_btnodes = 0;
}

void silofs_nodeptr_reset(struct silofs_nodeptr *nodeptr)
{
	silofs_paddr_reset(&nodeptr->paddr);
	silofs_nmeta_reset(&nodeptr->nmeta);
	nodeptr->nsub_vobjs   = 0;
	nodeptr->nsub_btnodes = 0;
}

void silofs_nodeptr_assign(struct silofs_nodeptr *nodeptr,
                           const struct silofs_nodeptr *other)
{
	silofs_paddr_assign(&nodeptr->paddr, &other->paddr);
	silofs_nmeta_assign(&nodeptr->nmeta, &other->nmeta);
	nodeptr->nsub_vobjs   = other->nsub_vobjs;
	nodeptr->nsub_btnodes = other->nsub_btnodes;
}

bool silofs_nodeptr_isnull(const struct silofs_nodeptr *nodeptr)
{
	return silofs_paddr_isnull(&nodeptr->paddr) ||
	       !nodeptr->nmeta.ciargs.algo || !nodeptr->nmeta.ciargs.mode;
}

void silofs_nodeptr256b_htox(struct silofs_nodeptr256b *nodeptr256,
                             const struct silofs_nodeptr *nodeptr)
{
	memset(nodeptr256, 0, sizeof(*nodeptr256));
	silofs_paddr64b_htox(&nodeptr256->np_paddr, &nodeptr->paddr);
	silofs_nmeta128b_htox(&nodeptr256->np_nmeta, &nodeptr->nmeta);
	nodeptr256->np_nsub_vobjs = silofs_cpu_to_le64(nodeptr->nsub_vobjs);
	nodeptr256->np_nsub_btnodes =
		silofs_cpu_to_le32((uint32_t)nodeptr->nsub_btnodes);
}

void silofs_nodeptr256b_xtoh(const struct silofs_nodeptr256b *nodeptr256,
                             struct silofs_nodeptr *nodeptr)
{
	silofs_paddr64b_xtoh(&nodeptr256->np_paddr, &nodeptr->paddr);
	silofs_nmeta128b_xtoh(&nodeptr256->np_nmeta, &nodeptr->nmeta);
	nodeptr->nsub_vobjs = silofs_le64_to_cpu(nodeptr256->np_nsub_vobjs);
	nodeptr->nsub_btnodes =
		silofs_le32_to_cpu(nodeptr256->np_nsub_btnodes);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_plogdesc s_plogdesc_none = {
	.head.pos = SILOFS_OFF_NULL,
	.tail.pos = SILOFS_OFF_NULL,
};

const struct silofs_plogdesc *silofs_plogdesc_none(void)
{
	return &s_plogdesc_none;
}

void silofs_plogdesc_setup(struct silofs_plogdesc *pldesc,
                           const struct silofs_paddr *head,
                           const struct silofs_paddr *tail)
{
	silofs_paddr_assign(&pldesc->head, head);
	silofs_paddr_assign(&pldesc->tail, tail);
}

void silofs_plogdesc_ignite(struct silofs_plogdesc *pldesc,
                            const struct silofs_paddr *paddr)
{
	silofs_plogdesc_setup(pldesc, paddr, paddr);
}

void silofs_plogdesc_htox(struct silofs_plogdesc128b *plogdesc128,
                          const struct silofs_plogdesc *plogdesc)
{
	silofs_paddr64b_htox(&plogdesc128->pl_head, &plogdesc->head);
	silofs_paddr64b_htox(&plogdesc128->pl_tail, &plogdesc->tail);
}

void silofs_plogdesc_xtoh(const struct silofs_plogdesc128b *plogdesc128,
                          struct silofs_plogdesc *plogdesc)
{
	silofs_paddr64b_xtoh(&plogdesc128->pl_head, &plogdesc->head);
	silofs_paddr64b_xtoh(&plogdesc128->pl_tail, &plogdesc->tail);
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
                         const struct silofs_nodeptr *nodeptr)
{
	silofs_nodeptr_assign(&btnptr->base, nodeptr);
	btnptr->nsub_vobjs   = 0;
	btnptr->nsub_btnodes = 0;
}

void silofs_btnptr_reset(struct silofs_btnptr *btnptr)
{
	silofs_nodeptr_reset(&btnptr->base);
	btnptr->nsub_vobjs   = 0;
	btnptr->nsub_btnodes = 0;
}

void silofs_btnptr_assign(struct silofs_btnptr *btnptr,
                          const struct silofs_btnptr *other)
{
	silofs_nodeptr_assign(&btnptr->base, &other->base);
	btnptr->nsub_vobjs   = other->nsub_vobjs;
	btnptr->nsub_btnodes = other->nsub_btnodes;
}

bool silofs_btnptr_isnull(const struct silofs_btnptr *btnptr)
{
	return silofs_nodeptr_isnull(&btnptr->base);
}

void silofs_btnptr256b_htox(struct silofs_btnptr256b *btnptr256,
                            const struct silofs_btnptr *btnptr)
{
	memset(btnptr256, 0, sizeof(*btnptr256));
	silofs_nodeptr256b_htox(&btnptr256->btp_base, &btnptr->base);
	btnptr256->btp_nsub_vobjs = silofs_cpu_to_le64(btnptr->nsub_vobjs);
	btnptr256->btp_nsub_btnodes =
		silofs_cpu_to_le32((uint32_t)btnptr->nsub_btnodes);
}

void silofs_btnptr256b_xtoh(const struct silofs_btnptr256b *btnptr256,
                            struct silofs_btnptr *btnptr)
{
	silofs_nodeptr256b_xtoh(&btnptr256->btp_base, &btnptr->base);
	btnptr->nsub_vobjs   = silofs_le64_to_cpu(btnptr256->btp_nsub_vobjs);
	btnptr->nsub_btnodes = silofs_le32_to_cpu(btnptr256->btp_nsub_btnodes);
}
