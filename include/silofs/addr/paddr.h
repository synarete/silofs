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
#ifndef SILOFS_PADDR_H_
#define SILOFS_PADDR_H_

#include <silofs/defs.h>
#include <silofs/str.h>


/* persistent volume segment */
struct silofs_psegid {
	struct silofs_pvid      pvid;
	uint32_t                index;
	enum silofs_ptype       ptype;
};

/* persistent object address within specific volume segment */
struct silofs_paddr {
	struct silofs_pvid      pvid;
	uint32_t                index;
	enum silofs_ptype       ptype;
	loff_t                  off;
	size_t                  len;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvid_generate(struct silofs_pvid *pvid);

void silofs_pvid_assign(struct silofs_pvid *pvid,
                        const struct silofs_pvid *other);

uint64_t silofs_pvid_hash64(const struct silofs_pvid *pvid);

void silofs_pvid_to_str(const struct silofs_pvid *pvid,
                        struct silofs_strbuf *sbuf);

int silofs_pvid_from_str(struct silofs_lvid *pvid,
                         const struct silofs_strview *sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_paddr *silofs_paddr_none(void);

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

void silofs_paddr_reset(struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other);

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);


void silofs_paddr32b_reset(struct silofs_paddr32b *paddr32);

void silofs_paddr32b_htox(struct silofs_paddr32b *paddr32,
                          const struct silofs_paddr *paddr);

void silofs_paddr32b_xtoh(const struct silofs_paddr32b *paddr32,
                          struct silofs_paddr *paddr);

#endif /* SILOFS_PADDR_H_ */