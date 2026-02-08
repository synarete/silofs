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
#ifndef SILOFS_NMETA_H_
#define SILOFS_NMETA_H_

#include "crypto.h"
#include "paddr.h"

/* nodes meta settings */
struct silofs_nmeta {
	struct silofs_civkey civkey;
	struct silofs_ciargs ciargs;
};

/* pnode meta pointer */
struct silofs_pnodeptr {
	struct silofs_nmeta nmeta;
	struct silofs_paddr paddr;
	size_t              nsub_vobjs;
	size_t              nsub_btnodes;
};

/* persistent state: pointer to root-node and next free space */
struct silofs_plogref {
	struct silofs_pnodeptr apex;
	struct silofs_paddr    edge;
	enum silofs_mtype      vspace;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_nmeta *silofs_nmeta_none(void);

void silofs_nmeta_setup(struct silofs_nmeta        *nmeta,
                        const struct silofs_civkey *civkey);

void silofs_nmeta_reset(struct silofs_nmeta *nmeta);

void silofs_nmeta_assign(struct silofs_nmeta       *nmeta,
                         const struct silofs_nmeta *other);

void silofs_nmeta128b_htox(struct silofs_nmeta128b   *nmeta128,
                           const struct silofs_nmeta *nmeta);

void silofs_nmeta128b_xtoh(const struct silofs_nmeta128b *nmeta128,
                           struct silofs_nmeta           *nmeta);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_pnodeptr *silofs_pnodeptr_none(void);

void silofs_pnodeptr_setup(struct silofs_pnodeptr     *pnodeptr,
                           const struct silofs_paddr  *paddr,
                           const struct silofs_civkey *civkey);

void silofs_pnodeptr_setup2(struct silofs_pnodeptr    *pnodeptr,
                            const struct silofs_paddr *paddr,
                            const struct silofs_nmeta *nmeta);

void silofs_pnodeptr_reset(struct silofs_pnodeptr *pnodeptr);

void silofs_pnodeptr_assign(struct silofs_pnodeptr       *pnodeptr,
                            const struct silofs_pnodeptr *other);

bool silofs_pnodeptr_isnull(const struct silofs_pnodeptr *pnodeptr);

void silofs_pnodeptr256b_htox(struct silofs_pnodeptr256b   *pnodeptr256,
                              const struct silofs_pnodeptr *pnodeptr);

void silofs_pnodeptr256b_xtoh(const struct silofs_pnodeptr256b *pnodeptr256,
                              struct silofs_pnodeptr           *pnodeptr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_plogref *silofs_plogref_none(void);

void silofs_plogref384b_htox(struct silofs_plogref384b   *plogref384,
                             const struct silofs_plogref *plogref);

void silofs_plogref384b_xtoh(const struct silofs_plogref384b *plogref384,
                             struct silofs_plogref           *plogref);

#endif /* SILOFS_NMETA_H_ */
