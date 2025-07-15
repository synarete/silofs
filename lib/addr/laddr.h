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
#ifndef SILOFS_LADDR_H_
#define SILOFS_LADDR_H_

#include "crypt.h"

struct silofs_strbuf;

/* logical-segment id within specific volume mapping */
struct silofs_lsid {
	struct silofs_blobid blobid;
	size_t               lsize;
	uint32_t             vindex;
	enum silofs_mtype    vspace;
	enum silofs_height   height;
	enum silofs_mtype    mtype;
};

/* logical-address within specific volume's mapping extend */
struct silofs_laddr {
	struct silofs_lsid lsid;
	loff_t             pos;
};

/* logical-address and its associate IV-key */
struct silofs_llink {
	struct silofs_laddr laddr;
	struct silofs_ivkey ivkey;
};

/* logical-space address-range [beg, end) */
struct silofs_lrange {
	loff_t             beg;
	loff_t             end;
	enum silofs_height height;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_lsid *silofs_lsid_none(void);

size_t silofs_lsid_size(const struct silofs_lsid *lsid);

bool silofs_lsid_isnull(const struct silofs_lsid *lsid);

bool silofs_lsid_has_blobid(const struct silofs_lsid   *lsid,
                            const struct silofs_blobid *blobid);

void silofs_lsid_reset(struct silofs_lsid *lsid);

void silofs_lsid_setup(struct silofs_lsid         *lsid,
                       const struct silofs_blobid *blobid, loff_t voff,
                       enum silofs_mtype vspace, enum silofs_height height,
                       enum silofs_mtype mtype);

void silofs_lsid_assign(struct silofs_lsid       *lsid,
                        const struct silofs_lsid *other);

bool silofs_lsid_isequal(const struct silofs_lsid *lsid,
                         const struct silofs_lsid *other);

uint64_t silofs_lsid_hash64(const struct silofs_lsid *lsid);

loff_t silofs_lsid_pos(const struct silofs_lsid *lsid, loff_t off);

void silofs_lsid48b_reset(struct silofs_lsid48b *lsid48);

void silofs_lsid48b_htox(struct silofs_lsid48b    *lsid48,
                         const struct silofs_lsid *lsid);

void silofs_lsid48b_xtoh(const struct silofs_lsid48b *lsid48,
                         struct silofs_lsid          *lsid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_laddr *silofs_laddr_none(void);

void silofs_laddr_setpos(struct silofs_laddr *laddr, loff_t off);

void silofs_laddr_setup(struct silofs_laddr      *laddr,
                        const struct silofs_lsid *lsid, loff_t off);

void silofs_laddr_setup_lbk(struct silofs_laddr      *laddr,
                            const struct silofs_lsid *lsid, loff_t off);

void silofs_laddr_reset(struct silofs_laddr *laddr);

void silofs_laddr_assign(struct silofs_laddr       *laddr,
                         const struct silofs_laddr *other);

enum silofs_mtype silofs_laddr_mtype(const struct silofs_laddr *laddr);

size_t silofs_laddr_len(const struct silofs_laddr *laddr);

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2);

void silofs_laddr_as_iv(const struct silofs_laddr *laddr,
                        struct silofs_iv          *out_iv);

bool silofs_laddr_isnull(const struct silofs_laddr *laddr);

bool silofs_laddr_isvalid(const struct silofs_laddr *laddr);

bool silofs_laddr_isequal(const struct silofs_laddr *laddr,
                          const struct silofs_laddr *other);

void silofs_laddr64b_htox(struct silofs_laddr64b    *laddr64,
                          const struct silofs_laddr *laddr);

void silofs_laddr64b_xtoh(const struct silofs_laddr64b *laddr64,
                          struct silofs_laddr          *laddr);

void silofs_laddr64b_reset(struct silofs_laddr64b *laddr64);

void silofs_laddr_to_ascii(const struct silofs_laddr *laddr,
                           struct silofs_strbuf      *sbuf);

int silofs_laddr_from_ascii(struct silofs_laddr        *laddr,
                            const struct silofs_strbuf *sbuf);

void silofs_laddr_to_base64(const struct silofs_laddr *laddr,
                            struct silofs_strbuf      *sbuf);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_setup(struct silofs_llink       *llink,
                        const struct silofs_laddr *laddr,
                        const struct silofs_key   *key);

void silofs_llink_setup2(struct silofs_llink       *llink,
                         const struct silofs_laddr *laddr,
                         const struct silofs_key   *key,
                         const struct silofs_iv    *iv);

void silofs_llink_assign(struct silofs_llink       *llink,
                         const struct silofs_llink *other);

void silofs_llink_reset(struct silofs_llink *llink);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_lrange_isvalid(const struct silofs_lrange *lrange);

size_t silofs_lrange_len(const struct silofs_lrange *lrange);

bool silofs_lrange_within(const struct silofs_lrange *lrange, loff_t off);

void silofs_lrange_setup(struct silofs_lrange *lrange,
                         enum silofs_height height, loff_t beg, loff_t end);

void silofs_lrange_setup_sub(struct silofs_lrange       *lrange,
                             const struct silofs_lrange *other, loff_t beg);

void silofs_lrange_of_space(struct silofs_lrange *lrange,
                            enum silofs_height height, loff_t voff_base);

void silofs_lrange_of_spmap(struct silofs_lrange *lrange,
                            enum silofs_height height, loff_t voff_base);

loff_t silofs_lrange_voff_at(const struct silofs_lrange *lrange, size_t slot);

loff_t silofs_lrange_next(const struct silofs_lrange *lrange, loff_t voff);

void silofs_lrange128_reset(struct silofs_lrange128 *vrng);

void silofs_lrange128_htox(struct silofs_lrange128    *vrng,
                           const struct silofs_lrange *lrange);

void silofs_lrange128_xtoh(const struct silofs_lrange128 *vrng,
                           struct silofs_lrange          *lrange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ssize_t silofs_height_to_space_span(enum silofs_height height);

#endif /* SILOFS_LADDR_H_ */
