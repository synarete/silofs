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
#ifndef SILOFS_VADDR_H_
#define SILOFS_VADDR_H_

#include <silofs/ondisk.h>
#include "offlba.h"

/* logical addressing of virtual nodes */
struct silofs_vaddr {
	off_t             off;
	enum silofs_mtype mtype;
};

/* set of addresses within single vblock */
struct silofs_vaddrs {
	struct silofs_vaddr vaddr[SILOFS_NKB_IN_LBK];
	size_t              count;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_vaddr *silofs_vaddr_none(void);

size_t silofs_vaddr_len(const struct silofs_vaddr *vaddr);

long silofs_vaddr_compare(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

bool silofs_vaddr_isequal(const struct silofs_vaddr *vaddr1,
                          const struct silofs_vaddr *vaddr2);

void silofs_vaddr_setup(struct silofs_vaddr *vaddr, enum silofs_mtype mtype,
                        off_t off);

void silofs_vaddr_setup2(struct silofs_vaddr *vaddr, enum silofs_mtype mtype,
                         silofs_lba_t lba);

void silofs_vaddr_of_lsmap(struct silofs_vaddr *vaddr,
                           enum silofs_mtype refmtype, off_t off);

void silofs_vaddr_assign(struct silofs_vaddr       *vaddr,
                         const struct silofs_vaddr *other);

void silofs_vaddr_reset(struct silofs_vaddr *vaddr);

bool silofs_vaddr_isnull(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdata(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isdatabk(const struct silofs_vaddr *vaddr);

bool silofs_vaddr_isinode(const struct silofs_vaddr *vaddr);

void silofs_vaddr_by_spleaf(struct silofs_vaddr *vaddr,
                            enum silofs_mtype mtype, off_t voff_base,
                            size_t bn, size_t kbn);

void silofs_vaddr56_htox(struct silofs_vaddr56 *va, off_t off);

void silofs_vaddr56_xtoh(const struct silofs_vaddr56 *va, off_t *out_off);

void silofs_vaddr64_htox(struct silofs_vaddr64     *vadr,
                         const struct silofs_vaddr *vaddr);

void silofs_vaddr64_xtoh(const struct silofs_vaddr64 *vadr,
                         struct silofs_vaddr         *vaddr);

#endif /* SILOFS_VADDR_H_ */
