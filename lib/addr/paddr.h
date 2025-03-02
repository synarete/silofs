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

#include <silofs/defs.h>
#include <silofs/str.h>

/* persistent-volume segment id */
struct silofs_pvsid {
	struct silofs_volid volid;
	uint32_t            index;
};

/* persistent object address within specific volume segment */
struct silofs_paddr {
	struct silofs_pvsid pvsid;
	loff_t              off;
	size_t              len;
	enum silofs_ptype   ptype;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_ptype_size(enum silofs_ptype ptype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_pvsid *silofs_pvsid_none(void);

void silofs_pvsid_init(struct silofs_pvsid       *pvsid,
                       const struct silofs_volid *volid, uint32_t idx);

void silofs_pvsid_fini(struct silofs_pvsid *pvsid);

bool silofs_pvsid_isnull(const struct silofs_pvsid *pvsid);

bool silofs_pvsid_has_volid(const struct silofs_pvsid *pvsid,
                            const struct silofs_volid *volid);

void silofs_pvsid_generate(struct silofs_pvsid *pvsid);

void silofs_pvsid_reset(struct silofs_pvsid *pvsid);

void silofs_pvsid_assign(struct silofs_pvsid       *pvsid,
                         const struct silofs_pvsid *other);

bool silofs_pvsid_isequal(const struct silofs_pvsid *pvsid,
                          const struct silofs_pvsid *other);

uint64_t silofs_pvsid_hash64(const struct silofs_pvsid *pvsid);

void silofs_pvsid_to_str(const struct silofs_pvsid *pvsid,
                         struct silofs_strbuf      *sbuf);

void silofs_pvsid32b_htox(struct silofs_pvsid32b    *pvsid32,
                          const struct silofs_pvsid *pvsid);

void silofs_pvsid32b_xtoh(const struct silofs_pvsid32b *pvsid32,
                          struct silofs_pvsid          *pvsid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_paddr *silofs_paddr_none(void);

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

void silofs_paddr_init(struct silofs_paddr       *paddr,
                       const struct silofs_pvsid *pvsid,
                       enum silofs_ptype ptype, loff_t off, size_t len);

void silofs_paddr_fini(struct silofs_paddr *paddr);

void silofs_paddr_reset(struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr       *paddr,
                         const struct silofs_paddr *other);

bool silofs_paddr_isdata(const struct silofs_paddr *paddr);

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);

bool silofs_paddr_isequal(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);

void silofs_paddr48b_reset(struct silofs_paddr48b *paddr48);

void silofs_paddr48b_htox(struct silofs_paddr48b    *paddr48,
                          const struct silofs_paddr *paddr);

void silofs_paddr48b_xtoh(const struct silofs_paddr48b *paddr48,
                          struct silofs_paddr          *paddr);

#ifdef SILOFS_USE_PRIVATE
#define paddr_none()            silofs_paddr_none()
#define paddr_reset(pa)         silofs_paddr_reset(pa)
#define paddr_assign(pa, oth)   silofs_paddr_assign(pa, oth)
#define paddr_isequal(pa1, pa2) silofs_paddr_isequal(pa1, pa2)
#define paddr_isnull(pa)        silofs_paddr_isnull(pa)
#endif

#endif /* SILOFS_PADDR_H_ */
