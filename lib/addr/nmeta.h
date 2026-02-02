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
struct silofs_nodeptr {
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

const struct silofs_nodeptr *silofs_nodeptr_none(void);

void silofs_nodeptr_setup(struct silofs_nodeptr      *nodeptr,
                          const struct silofs_paddr  *paddr,
                          const struct silofs_civkey *civkey);

void silofs_nodeptr_setup2(struct silofs_nodeptr     *nodeptr,
                           const struct silofs_paddr *paddr,
                           const struct silofs_nmeta *nmeta);

void silofs_nodeptr_reset(struct silofs_nodeptr *nodeptr);

void silofs_nodeptr_assign(struct silofs_nodeptr       *nodeptr,
                           const struct silofs_nodeptr *other);

bool silofs_nodeptr_isnull(const struct silofs_nodeptr *nodeptr);

void silofs_nodeptr256b_htox(struct silofs_nodeptr256b   *nodeptr256,
                             const struct silofs_nodeptr *nodeptr);

void silofs_nodeptr256b_xtoh(const struct silofs_nodeptr256b *nodeptr256,
                             struct silofs_nodeptr           *nodeptr);

#endif /* SILOFS_NMETA_H_ */
