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
#ifndef SILOFS_PADDR_H_
#define SILOFS_PADDR_H_

#include <silofs/ondisk.h>

/* persistent object address within specific blob */
struct silofs_paddr {
	struct silofs_blobid blobid;
	loff_t               off;
	enum silofs_ptype    ptype;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_ptype_size(enum silofs_ptype ptype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_paddr *silofs_paddr_none(void);

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

void silofs_paddr_init(struct silofs_paddr        *paddr,
                       const struct silofs_blobid *blobid,
                       enum silofs_ptype ptype, loff_t off);

void silofs_paddr_fini(struct silofs_paddr *paddr);

void silofs_paddr_reset(struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr       *paddr,
                         const struct silofs_paddr *other);

bool silofs_paddr_isdata(const struct silofs_paddr *paddr);

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);

bool silofs_paddr_isequal(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);

void silofs_paddr64b_reset(struct silofs_paddr64b *paddr64);

void silofs_paddr64b_htox(struct silofs_paddr64b    *paddr64,
                          const struct silofs_paddr *paddr);

void silofs_paddr64b_xtoh(const struct silofs_paddr64b *paddr64,
                          struct silofs_paddr          *paddr);

#endif /* SILOFS_PADDR_H_ */
