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
#ifndef SILOFS_NODEPTR_H_
#define SILOFS_NODEPTR_H_

#include "nmeta.h"

/* pnode meta pointer */
struct silofs_nodeptr {
	struct silofs_nmeta nmeta;
	struct silofs_paddr paddr;
	size_t              nsub_vobjs;
	size_t              nsub_btnodes;
};

/* plog descriptor */
struct silofs_plogdesc {
	struct silofs_paddr head;
	struct silofs_paddr tail;
};

/* btnode meta pointer */
struct silofs_btnptr {
	struct silofs_nodeptr base;
	size_t                nsub_vobjs;
	size_t                nsub_btnodes;
};

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_plogdesc *silofs_plogdesc_none(void);

void silofs_plogdesc_setup(struct silofs_plogdesc    *pldesc,
                           const struct silofs_paddr *head,
                           const struct silofs_paddr *tail);

void silofs_plogdesc_ignite(struct silofs_plogdesc    *pldesc,
                            const struct silofs_paddr *paddr);

void silofs_plogdesc_htox(struct silofs_plogdesc128b   *plogdesc128,
                          const struct silofs_plogdesc *plogdesc);

void silofs_plogdesc_xtoh(const struct silofs_plogdesc128b *plogdesc128,
                          struct silofs_plogdesc           *plogdesc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_btnptr *silofs_btnptr_none(void);

void silofs_btnptr_setup(struct silofs_btnptr        *btnptr,
                         const struct silofs_nodeptr *nodeptr);

void silofs_btnptr_reset(struct silofs_btnptr *btnptr);

void silofs_btnptr_assign(struct silofs_btnptr       *btnptr,
                          const struct silofs_btnptr *other);

bool silofs_btnptr_isnull(const struct silofs_btnptr *btnptr);

void silofs_btnptr256b_htox(struct silofs_btnptr256b   *btnptr256,
                            const struct silofs_btnptr *btnptr);

void silofs_btnptr256b_xtoh(const struct silofs_btnptr256b *btnptr256,
                            struct silofs_btnptr           *btnptr);

#endif /* SILOFS_NODEPTR_H_ */
