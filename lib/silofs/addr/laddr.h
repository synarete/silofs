/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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

#include <silofs/ondisk.h>

bool silofs_ltype_isnone(enum silofs_ltype ltype);

bool silofs_ltype_isinode(enum silofs_ltype ltype);

bool silofs_ltype_isdata(enum silofs_ltype ltype);

bool silofs_ltype_usespmap(enum silofs_ltype ltype);

size_t silofs_ltype_size(enum silofs_ltype ltype);

ssize_t silofs_ltype_ssize(enum silofs_ltype ltype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* logical addressing of meta nodes */
struct silofs_laddr {
	off_t             off;
	enum silofs_ltype ltype;
};

const struct silofs_laddr *silofs_laddr_none(void);

size_t silofs_laddr_len(const struct silofs_laddr *laddr);

long silofs_laddr_compare(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2);

bool silofs_laddr_isequal(const struct silofs_laddr *laddr1,
                          const struct silofs_laddr *laddr2);

void silofs_laddr_setup(struct silofs_laddr *laddr, //
                        enum silofs_ltype ltype, off_t off);

void silofs_laddr_advance(const struct silofs_laddr *laddr, size_t nsteps,
                          struct silofs_laddr *out_laddr);

void silofs_laddr_assign(struct silofs_laddr       *laddr,
                         const struct silofs_laddr *other);

void silofs_laddr_reset(struct silofs_laddr *laddr);

bool silofs_laddr_isnull(const struct silofs_laddr *laddr);

bool silofs_laddr_isdata(const struct silofs_laddr *laddr);

bool silofs_laddr_isinode(const struct silofs_laddr *laddr);

void silofs_laddr56_htox(struct silofs_laddr56 *laddr56, off_t off);

void silofs_laddr56_xtoh(const struct silofs_laddr56 *laddr56, off_t *out_off);

void silofs_laddr64_htox(struct silofs_laddr64     *laddr64,
                         const struct silofs_laddr *laddr);

void silofs_laddr64_xtoh(const struct silofs_laddr64 *laddr64,
                         struct silofs_laddr         *laddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ino_to_laddr(ino_t ino, struct silofs_laddr *out_laddr);

void silofs_laddr_to_ino(const struct silofs_laddr *laddr, ino_t *out_ino);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_resolve_spnode2_laddr(const struct silofs_laddr *ref_laddr,
                                  struct silofs_laddr       *out_laddr);

#endif /* SILOFS_LADDR_H_ */
