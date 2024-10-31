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


/* persistent-volume segment id */
struct silofs_psid {
	struct silofs_pvid      pvid;
	uint32_t                index;
};

/* persistent object address within specific volume segment */
struct silofs_paddr {
	struct silofs_psid      psid;
	loff_t                  off;
	size_t                  len;
	enum silofs_ptype       ptype;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint32_t silofs_ptype_size(enum silofs_ptype ptype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvid_generate(struct silofs_pvid *pvid);

void silofs_pvid_assign(struct silofs_pvid *pvid,
                        const struct silofs_pvid *other);

bool silofs_pvid_isequal(const struct silofs_pvid *pvid1,
                         const struct silofs_pvid *pvid2);

uint64_t silofs_pvid_hash64(const struct silofs_pvid *pvid);

void silofs_pvid_to_str(const struct silofs_pvid *pvid,
                        struct silofs_strbuf *sbuf);

int silofs_pvid_from_str(struct silofs_lvid *pvid,
                         const struct silofs_strview *sv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_psid *silofs_psid_none(void);

void silofs_psid_init(struct silofs_psid *psid,
                      const struct silofs_pvid *pvid, uint32_t idx);

void silofs_psid_fini(struct silofs_psid *psid);

bool silofs_psid_isnull(const struct silofs_psid *psid);

bool silofs_psid_has_pvid(const struct silofs_psid *psid,
                          const struct silofs_pvid *pvid);

void silofs_psid_generate(struct silofs_psid *psid);

void silofs_psid_reset(struct silofs_psid *psid);

void silofs_psid_assign(struct silofs_psid *psid,
                        const struct silofs_psid *other);

bool silofs_psid_isequal(const struct silofs_psid *psid,
                         const struct silofs_psid *other);

uint64_t silofs_psid_hash64(const struct silofs_psid *psid);

void silofs_psid_to_str(const struct silofs_psid *psid,
                        struct silofs_strbuf *sbuf);

void silofs_psid32b_htox(struct silofs_psid32b *psid32,
                         const struct silofs_psid *psid);

void silofs_psid32b_xtoh(const struct silofs_psid32b *psid32,
                         struct silofs_psid *psid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_paddr *silofs_paddr_none(void);

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

void silofs_paddr_init(struct silofs_paddr *paddr,
                       const struct silofs_psid *psid,
                       enum silofs_ptype ptype, loff_t off, size_t len);

void silofs_paddr_fini(struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other);

long silofs_paddr_compare(const struct silofs_paddr *paddr1,
                          const struct silofs_paddr *paddr2);


void silofs_paddr48b_reset(struct silofs_paddr48b *paddr48);

void silofs_paddr48b_htox(struct silofs_paddr48b *paddr48,
                          const struct silofs_paddr *paddr);

void silofs_paddr48b_xtoh(const struct silofs_paddr48b *paddr48,
                          struct silofs_paddr *paddr);

#endif /* SILOFS_PADDR_H_ */
