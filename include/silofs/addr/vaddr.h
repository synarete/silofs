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
#ifndef SILOFS_VADDR_H_
#define SILOFS_VADDR_H_

#include <silofs/defs.h>


/* logical addressing of virtual nodes */
struct silofs_vaddr {
	loff_t                  off;
	enum silofs_ltype       ltype;
	unsigned int            len;
};

/* set of addresses within single vblock */
struct silofs_vaddrs {
	struct silofs_vaddr     vaddr[SILOFS_NKB_IN_LBK];
	size_t                  count;
};

/* vspace address range [beg, end) */
struct silofs_vrange {
	loff_t                  beg;
	loff_t                  end;
	size_t                  len;
	enum silofs_height      height;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_vaddr *silofs_vaddr_none(void);

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

bool silofs_vaddr_isequal(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

void silofs_vaddr_setup(struct silofs_vaddr *vaddr,
                        enum silofs_ltype ltype, loff_t off);

void silofs_vaddr_setup2(struct silofs_vaddr *vaddr,
                         enum silofs_ltype ltype, silofs_lba_t lba);

void silofs_vaddr_assign(struct silofs_vaddr *vaddr,
                         const struct silofs_vaddr *other);

void silofs_vaddr_reset(struct silofs_vaddr *vaddr);

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdatabk(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr);


void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_ltype ltype,
                            loff_t voff_base, size_t bn, size_t kbn);

void silofs_vaddr56_htox(struct silofs_vaddr56 *va, loff_t off);

void silofs_vaddr56_xtoh(const struct silofs_vaddr56 *va, loff_t *out_off);

void silofs_vaddr64_htox(struct silofs_vaddr64 *vadr,
                         const struct silofs_vaddr *vaddr);

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vadr,
                         struct silofs_vaddr *vaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ssize_t silofs_height_to_space_span(enum silofs_height height);

bool silofs_vrange_within(const struct silofs_vrange *vrange, loff_t off);

void silofs_vrange_setup(struct silofs_vrange *vrange,
                         enum silofs_height height, loff_t beg, loff_t end);

void silofs_vrange_setup_sub(struct silofs_vrange *vrange,
                             const struct silofs_vrange *other, loff_t beg);

void silofs_vrange_of_space(struct silofs_vrange *vrange,
                            enum silofs_height height, loff_t voff_base);

void silofs_vrange_of_spmap(struct silofs_vrange *vrange,
                            enum silofs_height height, loff_t voff_base);

loff_t silofs_vrange_voff_at(const struct silofs_vrange *vrange, size_t slot);

loff_t silofs_vrange_next(const struct silofs_vrange *vrange, loff_t voff);

void silofs_vrange128_reset(struct silofs_vrange128 *vrng);

void silofs_vrange128_htox(struct silofs_vrange128 *vrng,
                           const struct silofs_vrange *vrange);

void silofs_vrange128_xtoh(const struct silofs_vrange128 *vrng,
                           struct silofs_vrange *vrange);

#endif /* SILOFS_VADDR_H_ */
