/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_BKADDR_H_
#define SILOFS_BKADDR_H_

#include <silofs/defs.h>

/* block address as extension of logical address */
struct silofs_bkaddr {
	struct silofs_laddr     laddr;
	silofs_lba_t            lba;
};

/* a pair of block-address and its associate (random) IV */
struct silofs_blink {
	struct silofs_bkaddr    bka;
	struct silofs_iv        riv;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_bkaddr *silofs_bkaddr_none(void);

void silofs_bkaddr_reset(struct silofs_bkaddr *bkaddr);

void silofs_bkaddr_setup(struct silofs_bkaddr *bkaddr,
                         const struct silofs_lsegid *lsegid, silofs_lba_t lba);

void  silofs_bkaddr_by_off(struct silofs_bkaddr *bkaddr,
                           const struct silofs_lsegid *lsegid, loff_t off);

void silofs_bkaddr_by_laddr(struct silofs_bkaddr *bkaddr,
                            const struct silofs_laddr *laddr);

bool silofs_bkaddr_isequal(const struct silofs_bkaddr *bkaddr,
                           const struct silofs_bkaddr *other);

long silofs_bkaddr_compare(const struct silofs_bkaddr *bkaddr1,
                           const struct silofs_bkaddr *bkaddr2);

void silofs_bkaddr_assign(struct silofs_bkaddr *bkaddr,
                          const struct silofs_bkaddr *other);

bool silofs_bkaddr_isnull(const struct silofs_bkaddr *bkaddr);

#endif /* SILOFS_BKADDR_H_ */
