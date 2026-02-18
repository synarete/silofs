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
#ifndef SILOFS_BLOBID_H_
#define SILOFS_BLOBID_H_

#include <silofs/ondisk.h>
#include <stdlib.h>
#include "str.h"
#include "crypto.h"
#include "layerid.h"

union silofs_stype {
	enum silofs_ptype ptype;
	enum silofs_mtype mtype;
	unsigned          xtype;
};

struct silofs_blobid {
	struct silofs_layerid layerid;
	struct silofs_uniqid  uniqid;
	union silofs_stype    stype;
	enum silofs_bidf      flags;
	enum silofs_mtype     vspace;
	enum silofs_height    height;
	uint16_t              vers;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_blobid *silofs_blobid_none(void);

void silofs_blobid_initp(struct silofs_blobid *blobid, enum silofs_ptype ptype,
                         enum silofs_mtype vspace);

void silofs_blobid_initv(struct silofs_blobid *blobid,
                         enum silofs_mtype     mtype);

void silofs_blobid_fini(struct silofs_blobid *blobid);

void silofs_blobid_reset(struct silofs_blobid *blobid);

void silofs_blobid_assign(struct silofs_blobid       *blobid,
                          const struct silofs_blobid *other);

long silofs_blobid_compare(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other);

bool silofs_blobid_isequal(const struct silofs_blobid *blobid,
                           const struct silofs_blobid *other);

void silofs_blobid_update(struct silofs_blobid        *blobid,
                          const struct silofs_layerid *layerid,
                          const struct silofs_uniqid  *uniqid);

void silofs_blobid56b_htox(struct silofs_blobid56b    *blobid56,
                           const struct silofs_blobid *blobid);

void silofs_blobid56b_xtoh(const struct silofs_blobid56b *blobid56,
                           struct silofs_blobid          *blobid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobidx_setup(struct silofs_blobidx       *blobidx,
                          const struct silofs_hash256 *h);

void silofs_blobidx_assign(struct silofs_blobidx       *blobidx,
                           const struct silofs_blobidx *other);

void silofs_blobidx_derive(struct silofs_blobidx          *blobidx,
                           const struct silofs_mdigest_hd *md_hd,
                           const struct silofs_blobid     *blobid);

bool silofs_blobidx_isequal(const struct silofs_blobidx *blobidx,
                            const struct silofs_blobidx *other);

int silofs_blobidx_to_str(const struct silofs_blobidx *blobidx, char *str,
                          size_t len);

int silofs_blobidx_from_str(struct silofs_blobidx *blobidx, const char *str,
                            size_t len);

#endif /* SILOFS_BLOBID_H_ */
