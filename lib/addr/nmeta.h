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

/* p-nodes meta settings */
struct silofs_pnodeptr {
	struct silofs_nmeta nmeta;
	struct silofs_paddr paddr;
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

#endif /* SILOFS_NMETA_H_ */
