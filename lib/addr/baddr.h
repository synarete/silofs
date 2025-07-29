/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_BADDR_H_
#define SILOFS_BADDR_H_

#include "paddr.h"
#include "caddr.h"

/* blob address */
struct silofs_baddr {
	union {
		struct silofs_paddr paddr;
		struct silofs_caddr caddr;
	} ad;
	enum silofs_adt adt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_baddr_reset(struct silofs_baddr *baddr);

void silofs_baddr_setup(struct silofs_baddr       *baddr,
                        const struct silofs_paddr *paddr);

void silofs_baddr_setup2(struct silofs_baddr       *baddr,
                         const struct silofs_caddr *caddr);

void silofs_baddr64b_reset(union silofs_baddr64b *baddr64);

void silofs_baddr64b_htox(union silofs_baddr64b     *baddr64,
                          const struct silofs_baddr *baddr);

void silofs_baddr64b_xtoh(const union silofs_baddr64b *baddr64,
                          struct silofs_baddr         *baddr);

#endif /* SILOFS_BADDR_H_ */
