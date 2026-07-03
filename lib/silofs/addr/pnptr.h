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

/* nodes meta crypto settings */
struct silofs_nmeta {
	struct silofs_civkey civkey;
	struct silofs_ciargs ciargs;
	struct silofs_ctag   ctag;
};

const struct silofs_nmeta *silofs_nmeta_none(void);

void silofs_nmeta_setup(struct silofs_nmeta        *nmeta,
                        const struct silofs_civkey *civkey);

void silofs_nmeta_reset(struct silofs_nmeta *nmeta);

void silofs_nmeta_assign(struct silofs_nmeta       *nmeta,
                         const struct silofs_nmeta *other);

void silofs_nmeta_update(struct silofs_nmeta      *nmeta,
                         const struct silofs_ctag *ctag);

bool silofs_nmeta_isequal(const struct silofs_nmeta *nmeta,
                          const struct silofs_nmeta *other);

void silofs_nmeta128b_htox(struct silofs_nmeta128b   *nmeta128,
                           const struct silofs_nmeta *nmeta);

void silofs_nmeta128b_xtoh(const struct silofs_nmeta128b *nmeta128,
                           struct silofs_nmeta           *nmeta);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* pnode meta pointer */
struct silofs_pnptr {
	struct silofs_nmeta nmeta;
	struct silofs_paddr paddr;
};

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

void silofs_pnptr256b_htox(struct silofs_pnptr256b   *pnptr256,
                           const struct silofs_pnptr *pnptr);

void silofs_pnptr256b_xtoh(const struct silofs_pnptr256b *pnptr256,
                           struct silofs_pnptr           *pnptr);

#endif /* SILOFS_PNPTR_H_ */
