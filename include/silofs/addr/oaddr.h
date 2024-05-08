/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_OADDR_H_
#define SILOFS_OADDR_H_


/* object-address within specific volume mapping */
struct silofs_oaddr {
	struct silofs_ovid      ovid;
	uint32_t                index;
	enum silofs_otype       otype;
	loff_t                  off;
	size_t                  len;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ovid_generate(struct silofs_ovid *ovid);

void silofs_ovid_assign(struct silofs_ovid *ovid,
                        const struct silofs_ovid *other);

uint64_t silofs_ovid_hash64(const struct silofs_ovid *ovid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_oaddr *silofs_oaddr_none(void);

bool silofs_oaddr_isnull(const struct silofs_oaddr *oaddr);

void silofs_oaddr_reset(struct silofs_oaddr *oaddr);

void silofs_oaddr_assign(struct silofs_oaddr *oaddr,
                         const struct silofs_oaddr *other);

long silofs_oaddr_compare(const struct silofs_oaddr *oaddr1,
                          const struct silofs_oaddr *oaddr2);


void silofs_oaddr32b_reset(struct silofs_oaddr32b *oaddr32);

void silofs_oaddr32b_htox(struct silofs_oaddr32b *oaddr32,
                          const struct silofs_oaddr *oaddr);

void silofs_oaddr32b_xtoh(const struct silofs_oaddr32b *oaddr32,
                          struct silofs_oaddr *oaddr);

#endif /* SILOFS_OADDR_H_ */
