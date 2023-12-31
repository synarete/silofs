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


/* logical-extend id within specific volume mapping */
struct silofs_lsegid {
	struct silofs_lvid      lvid;
	loff_t                  voff;
	size_t                  size;
	enum silofs_ltype       vspace;
	enum silofs_height      height;
};

/* logical-address within specific volume's mapping extend */
struct silofs_laddr {
	struct silofs_lsegid    lsegid;
	loff_t                  pos;
	size_t                  len;
};

/* a pair of object logical-address and its associate (random) IV */
struct silofs_llink {
	struct silofs_laddr     laddr;
	struct silofs_iv        riv;
};

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

const struct silofs_lsegid *silofs_lsegid_none(void);

size_t silofs_lsegid_size(const struct silofs_lsegid *lsegid);

bool silofs_lsegid_isnull(const struct silofs_lsegid *lsegid);

bool silofs_lsegid_has_lvid(const struct silofs_lsegid *lsegid,
                            const struct silofs_lvid *lvid);

void silofs_lsegid_reset(struct silofs_lsegid *lsegid);

void silofs_lsegid_setup(struct silofs_lsegid *lsegid,
                         const struct silofs_lvid *lvid,
                         loff_t voff, enum silofs_ltype vspace,
                         enum silofs_height height);

void silofs_lsegid_assign(struct silofs_lsegid *lsegid,
                          const struct silofs_lsegid *other);

long silofs_lsegid_compare(const struct silofs_lsegid *lsegid1,
                           const struct silofs_lsegid *lsegid2);

bool silofs_lsegid_isequal(const struct silofs_lsegid *lsegid,
                           const struct silofs_lsegid *other);

uint64_t silofs_lsegid_hash64(const struct silofs_lsegid *lsegid);

loff_t silofs_lsegid_pos(const struct silofs_lsegid *lsegid, loff_t off);

void silofs_lsegid32b_reset(struct silofs_lsegid32b *lsegid32);

void silofs_lsegid32b_htox(struct silofs_lsegid32b *lsegid32,
                           const struct silofs_lsegid *lsegid);

void silofs_lsegid32b_xtoh(const struct silofs_lsegid32b *lsegid32,
                           struct silofs_lsegid *lsegid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_laddr *silofs_laddr_none(void);

void silofs_laddr_setup(struct silofs_laddr *laddr,
                        const struct silofs_lsegid *lsegid,
                        loff_t off, size_t len);

void silofs_laddr_setup_lbk(struct silofs_laddr *laddr,
                            const struct silofs_lsegid *lsegid, loff_t off);

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

void silofs_llink_setup(struct silofs_llink *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_iv *riv);

void silofs_llink_assign(struct silofs_llink *llink,
                         const struct silofs_llink *other);

void silofs_llink_reset(struct silofs_llink *llink);


#endif /* SILOFS_LADDR_H_ */
