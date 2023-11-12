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
#ifndef SILOFS_LADDR_H_
#define SILOFS_LADDR_H_

#include <sys/types.h>

typedef loff_t          silofs_lba_t;

/* logical-extend id within specific volume mapping */
struct silofs_lextid {
	struct silofs_lvid      lvid;
	loff_t                  voff;
	size_t                  size;
	enum silofs_stype       vspace;
	enum silofs_height      height;
};

/* logical-address within specific volume's mapping extend */
struct silofs_laddr {
	struct silofs_lextid    lextid;
	loff_t                  pos;
	size_t                  len;
};

/* physical-address within specific volume mapping */
struct silofs_paddr {
	struct silofs_pvid      pvid;
	size_t                  index;
	loff_t                  pos;
	size_t                  len;
};

/* logical-to-physical address mapping */
struct silofs_ltop {
	struct silofs_laddr     laddr;
	struct silofs_paddr     paddr;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_off_isnull(loff_t off);

loff_t silofs_off_min(loff_t off1, loff_t off2);

loff_t silofs_off_max(loff_t off1, loff_t off2);

loff_t silofs_off_end(loff_t off, size_t len);

loff_t silofs_off_align(loff_t off, ssize_t align);

loff_t silofs_off_align_to_lbk(loff_t off);

loff_t silofs_off_next(loff_t off, ssize_t len);

ssize_t silofs_off_diff(loff_t beg, loff_t end);

ssize_t silofs_off_len(loff_t beg, loff_t end);

size_t silofs_off_ulen(loff_t beg, loff_t end);

silofs_lba_t silofs_off_to_lba(loff_t off);

loff_t silofs_off_in_lbk(loff_t off);

loff_t silofs_off_remainder(loff_t off, size_t len);


bool silofs_lba_isnull(silofs_lba_t lba);

loff_t silofs_lba_to_off(silofs_lba_t lba);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uuid_generate(struct silofs_uuid *uu);

void silofs_uuid_assign(struct silofs_uuid *uu1,
                        const struct silofs_uuid *uu2);

void silofs_uuid_name(const struct silofs_uuid *uu, struct silofs_namebuf *nb);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvid_generate(struct silofs_pvid *pvid);

void silofs_pvid_assign(struct silofs_pvid *pvid,
                        const struct silofs_pvid *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_lvid_generate(struct silofs_lvid *lvid);

long silofs_lvid_compare(const struct silofs_lvid *lvid1,
                         const struct silofs_lvid *lvid2);

void silofs_lvid_assign(struct silofs_lvid *lvid,
                        const struct silofs_lvid *other);

bool silofs_lvid_isequal(const struct silofs_lvid *lvid1,
                         const struct silofs_lvid *lvid2);

void silofs_lvid_by_uuid(struct silofs_lvid *lvid,
                         const struct silofs_uuid *uuid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_lextid *silofs_lextid_none(void);

size_t silofs_lextid_size(const struct silofs_lextid *lextid);

bool silofs_lextid_isnull(const struct silofs_lextid *lextid);

bool silofs_lextid_has_lvid(const struct silofs_lextid *lextid,
                            const struct silofs_lvid *lvid);

void silofs_lextid_reset(struct silofs_lextid *lextid);

void silofs_lextid_setup(struct silofs_lextid *lextid,
                         const struct silofs_lvid *lvid,
                         loff_t voff, enum silofs_stype vspace,
                         enum silofs_height height);

void silofs_lextid_assign(struct silofs_lextid *lextid,
                          const struct silofs_lextid *other);

long silofs_lextid_compare(const struct silofs_lextid *lextid1,
                           const struct silofs_lextid *lextid2);

bool silofs_lextid_isequal(const struct silofs_lextid *lextid,
                           const struct silofs_lextid *other);

uint64_t silofs_lextid_hash64(const struct silofs_lextid *lextid);

loff_t silofs_lextid_pos(const struct silofs_lextid *lextid, loff_t off);

void silofs_lextid32b_reset(struct silofs_lextid32b *lextid32);

void silofs_lextid32b_htox(struct silofs_lextid32b *lextid32,
                           const struct silofs_lextid *lextid);

void silofs_lextid32b_xtoh(const struct silofs_lextid32b *lextid32,
                           struct silofs_lextid *lextid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_laddr *silofs_laddr_none(void);

void silofs_laddr_setup(struct silofs_laddr *laddr,
                        const struct silofs_lextid *lextid,
                        loff_t off, size_t len);

void silofs_laddr_reset(struct silofs_laddr *laddr);

void silofs_laddr_assign(struct silofs_laddr *laddr,
                         const struct silofs_laddr *other);

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2);

void silofs_laddr_as_iv(const struct silofs_laddr *laddr,
                        struct silofs_iv *out_iv);

bool silofs_laddr_isnull(const struct silofs_laddr *laddr);

bool silofs_laddr_isvalid(const struct silofs_laddr *laddr);

bool silofs_laddr_isequal(const struct silofs_laddr *laddr,
                          const struct silofs_laddr *other);

void silofs_laddr48b_htox(struct silofs_laddr48b *laddr48,
                          const struct silofs_laddr *laddr);

void silofs_laddr48b_xtoh(const struct silofs_laddr48b *laddr48,
                          struct silofs_laddr *laddr);

void silofs_laddr48b_reset(struct silofs_laddr48b *laddr48);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_paddr_isnull(const struct silofs_paddr *paddr);

void silofs_paddr_assign(struct silofs_paddr *paddr,
                         const struct silofs_paddr *other);


void silofs_paddr32b_reset(struct silofs_paddr32b *paddr32);

void silofs_paddr32b_htox(struct silofs_paddr32b *paddr32,
                          const struct silofs_paddr *paddr);

void silofs_paddr32b_xtoh(const struct silofs_paddr32b *paddr32,
                          struct silofs_paddr *paddr);

#endif /* SILOFS_LADDR_H_ */
