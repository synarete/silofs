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
#ifndef SILOFS_UADDR_H_
#define SILOFS_UADDR_H_

#include <silofs/defs.h>
#include <silofs/infra.h>
#include "laddr.h"

/* logical addressing of space-mapping nodes */
struct silofs_uaddr {
	struct silofs_laddr laddr;
	loff_t              voff;
};

/* a pair of unode-address and its associate (random) IV */
struct silofs_ulink {
	struct silofs_uaddr uaddr;
	struct silofs_iv    riv;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_uaddr_none(void);

bool silofs_uaddr_isnull(const struct silofs_uaddr *uaddr);

void silofs_uaddr_reset(struct silofs_uaddr *uaddr);

void silofs_uaddr_assign(struct silofs_uaddr       *uaddr,
                         const struct silofs_uaddr *other);

long silofs_uaddr_compare(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

bool silofs_uaddr_isequal(const struct silofs_uaddr *uaddr1,
                          const struct silofs_uaddr *uaddr2);

const struct silofs_volid *
silofs_uaddr_volid(const struct silofs_uaddr *uaddr);

const struct silofs_lsid *silofs_uaddr_lsid(const struct silofs_uaddr *uaddr);

enum silofs_ltype silofs_uaddr_ltype(const struct silofs_uaddr *uaddr);

enum silofs_height silofs_uaddr_height(const struct silofs_uaddr *uaddr);

void silofs_uaddr_setup(struct silofs_uaddr      *uaddr,
                        const struct silofs_lsid *lsid, loff_t bpos,
                        loff_t voff);

void silofs_uaddr64b_reset(struct silofs_uaddr64b *uaddr64);

void silofs_uaddr64b_htox(struct silofs_uaddr64b    *uaddr64,
                          const struct silofs_uaddr *uaddr);

void silofs_uaddr64b_xtoh(const struct silofs_uaddr64b *uaddr64,
                          struct silofs_uaddr          *uaddr);

#ifdef SILOFS_USE_PRIVATE
#define uaddr_none()                    silofs_uaddr_none()
#define uaddr_isnull(ua)                silofs_uaddr_isnull(ua)
#define uaddr_assign(ua, oth)           silofs_uaddr_assign(ua, oth)
#define uaddr_reset(ua)                 silofs_uaddr_reset(ua)
#define uaddr_isequal(ua1, ua2)         silofs_uaddr_isequal(ua1, ua2)
#define uaddr_setup(ua, ls, p, o)       silofs_uaddr_setup(ua, ls, p, o)
#define uaddr_volid(ua)                 silofs_uaddr_volid(ua)
#define uaddr_lsid(ua)                  silofs_uaddr_lsid(ua)
#define uaddr_ltype(ua)                 silofs_uaddr_ltype(ua)
#define uaddr_height(ua)                silofs_uaddr_height(ua)
#endif

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ulink_assign(struct silofs_ulink       *ulink,
                         const struct silofs_ulink *other);

void silofs_ulink_assign2(struct silofs_ulink       *ulink,
                          const struct silofs_uaddr *uaddr,
                          const struct silofs_iv    *iv);

void silofs_ulink_reset(struct silofs_ulink *ulink);

void silofs_ulink_as_llink(const struct silofs_ulink *ulink,
                           struct silofs_llink       *out_llink);

#ifdef SILOFS_USE_PRIVATE
#define ulink_assign(ul, oth)           silofs_ulink_assign(ul, oth)
#define ulink_assign2(ul, ua, iv)       silofs_ulink_assign2(ul, ua, iv)
#define ulink_reset(ul)                 silofs_ulink_reset(ul)
#endif

#endif /* SILOFS_UADDR_H_ */
