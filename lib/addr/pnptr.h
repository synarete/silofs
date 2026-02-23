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
#ifndef SILOFS_PNPTR_H_
#define SILOFS_PNPTR_H_

#include "nmeta.h"

/* pnode meta pointer */
struct silofs_pnptr {
	struct silofs_nmeta nmeta;
	struct silofs_paddr paddr;
};

/* btnode meta pointer */
struct silofs_btnptr {
	struct silofs_pnptr base;
	size_t              nsub_vobjs;
	size_t              nsub_btnodes;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_pnptr *silofs_pnptr_none(void);

void silofs_pnptr_setup(struct silofs_pnptr        *pnptr,
                        const struct silofs_paddr  *paddr,
                        const struct silofs_civkey *civkey);

void silofs_pnptr_setup2(struct silofs_pnptr       *pnptr,
                         const struct silofs_paddr *paddr,
                         const struct silofs_nmeta *nmeta);

void silofs_pnptr_reset(struct silofs_pnptr *pnptr);

void silofs_pnptr_assign(struct silofs_pnptr       *pnptr,
                         const struct silofs_pnptr *other);

bool silofs_pnptr_isequal(const struct silofs_pnptr *pnptr,
                          const struct silofs_pnptr *other);

bool silofs_pnptr_isnull(const struct silofs_pnptr *pnptr);

void silofs_pnptr192b_htox(struct silofs_pnptr192b   *pnptr192,
                           const struct silofs_pnptr *pnptr);

void silofs_pnptr192b_xtoh(const struct silofs_pnptr192b *pnptr192,
                           struct silofs_pnptr           *pnptr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_btnptr *silofs_btnptr_none(void);

void silofs_btnptr_setup(struct silofs_btnptr      *btnptr,
                         const struct silofs_pnptr *pnptr);

void silofs_btnptr_reset(struct silofs_btnptr *btnptr);

void silofs_btnptr_assign(struct silofs_btnptr       *btnptr,
                          const struct silofs_btnptr *other);

bool silofs_btnptr_isnull(const struct silofs_btnptr *btnptr);

void silofs_btnptr256b_htox(struct silofs_btnptr256b   *btnptr256,
                            const struct silofs_btnptr *btnptr);

void silofs_btnptr256b_xtoh(const struct silofs_btnptr256b *btnptr256,
                            struct silofs_btnptr           *btnptr);

#endif /* SILOFS_PNPTR_H_ */
