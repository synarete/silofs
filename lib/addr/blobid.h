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

struct silofs_blobid56b_info {
	struct silofs_layerid layerid;
	struct silofs_uniqid  uniqid;
	enum silofs_bidf      flags;
	union {
		uint8_t           stype;
		enum silofs_ptype ptype;
		enum silofs_mtype mtype;
	} u;
	enum silofs_mtype  vspace;
	enum silofs_height height;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_blobid56b *silofs_blobid56b_none(void);

void silofs_blobid56b_setup_raw2(struct silofs_blobid56b     *blobid56b,
                                 const struct silofs_layerid *layerid,
                                 const struct silofs_uniqid  *uniq,
                                 enum silofs_mtype            mtype,
                                 enum silofs_mtype            vspace,
                                 enum silofs_height           height);

void silofs_blobid56b_setup_raw3(struct silofs_blobid56b     *blobid56b,
                                 const struct silofs_layerid *layerid,
                                 const struct silofs_uniqid  *uniq,
                                 enum silofs_mtype            mtype);

void silofs_blobid56b_setup_cas(struct silofs_blobid56b     *blobid56b,
                                const struct silofs_layerid *layerid,
                                const struct silofs_hash256 *hash,
                                enum silofs_mtype            mtype);

void silofs_blobid56b_get_layerid(const struct silofs_blobid56b *blobid56b,
                                  struct silofs_layerid         *out_layerid);

enum silofs_mtype
silofs_blobid56b_get_mtype(const struct silofs_blobid56b *blobid56b);

enum silofs_mtype
silofs_blobid56b_get_vspace(const struct silofs_blobid56b *blobid56b);

enum silofs_height
silofs_blobid56b_get_height(const struct silofs_blobid56b *blobid56b);

void silofs_blobid56b_reset(struct silofs_blobid56b *blobid56b);

void silofs_blobid56b_assign(struct silofs_blobid56b       *blobid56b,
                             const struct silofs_blobid56b *other);

void silofs_blobid56b_copyto(const struct silofs_blobid56b *blobid56b,
                             struct silofs_blobid56b       *other);

long silofs_blobid56b_compare(const struct silofs_blobid56b *blobid56b1,
                              const struct silofs_blobid56b *blobid56b2);

bool silofs_blobid56b_isequal(const struct silofs_blobid56b *blobid56b1,
                              const struct silofs_blobid56b *blobid56b2);

bool silofs_blobid56b_isnone(const struct silofs_blobid56b *blobid56b);

void silofs_blobid56b_to_sbuf(const struct silofs_blobid56b *blobid56b,
                              struct silofs_strbuf          *sbuf);

uint64_t silofs_blobid56b_hash64(const struct silofs_blobid56b *blobid56b,
                                 uint64_t                       seed);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_blobid56bx_setup(struct silofs_blobid56bx    *blobid56bx,
                             const struct silofs_hash256 *h);

void silofs_blobid56bx_assign(struct silofs_blobid56bx       *blobid56bx,
                              const struct silofs_blobid56bx *other);

void silofs_blobid56bx_derive(struct silofs_blobid56bx       *blobid56bx,
                              const struct silofs_mdigest_hd *md_hd,
                              const struct silofs_blobid56b  *blobid56b);

bool silofs_blobid56bx_isequal(const struct silofs_blobid56bx *blobid56bx,
                               const struct silofs_blobid56bx *other);

int silofs_blobid56bx_to_str(const struct silofs_blobid56bx *blobid56bx,
                             char *str, size_t len);

int silofs_blobid56bx_from_str(struct silofs_blobid56bx *blobid56bx,
                               const char *str, size_t len);

#endif /* SILOFS_BLOBID_H_ */
