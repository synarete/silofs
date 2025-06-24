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
#ifndef SILOFS_UADDR_H_
#define SILOFS_UADDR_H_

#include <silofs/ondisk.h>
#include "laddr.h"

/* logical addressing of space-mapping nodes */
struct silofs_uaddr {
	struct silofs_laddr laddr;
	loff_t              voff;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_uaddr_none(void);

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr);

void silofs_uaddr_reset(struct silofs_uaddr *uaddr);

void silofs_uaddr_assign(struct silofs_uaddr       *uaddr,
                         const struct silofs_uaddr *other);

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

bool silofs_uaddr_isequal(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

const struct silofs_volumeid *
silofs_uaddr_volumeid(const struct silofs_uaddr *uaddr);

const struct silofs_lsid *silofs_uaddr_lsid(const struct silofs_uaddr *uaddr);

enum silofs_ltype silofs_uaddr_ltype(const struct silofs_uaddr *uaddr);

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr);

void silofs_uaddr_setup(struct silofs_uaddr      *uaddr,
                        const struct silofs_lsid *lsid, loff_t bpos,
                        loff_t voff);

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uaddr64);

void silofs_uaddr64b_htox(struct silofs_uaddr64b    *uaddr64,
                          const struct silofs_uaddr *uaddr);

void silofs_uaddr64b_xtoh(const struct silofs_uaddr64b *uaddr64,
                          struct silofs_uaddr          *uaddr);

#endif /* SILOFS_UADDR_H_ */
