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
#ifndef SILOFS_META_H_
#define SILOFS_META_H_

#include <stdlib.h>
#include <stdint.h>
#include <silofs/ondisk.h>

struct silofs_strview;
struct silofs_strbuf;

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other);

void silofs_hash256_assign(struct silofs_hash256       *hash,
                           const struct silofs_hash256 *other);

void silofs_hash256_to_u64s(const struct silofs_hash256 *hash, uint64_t u[4]);

void silofs_hash256_from_u64s(struct silofs_hash256 *hash,
                              const uint64_t         u[4]);

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf        *out_name);

int silofs_hash256_by_name(struct silofs_hash256      *hash,
                           const struct silofs_strbuf *name);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hdr_setup(struct silofs_header *hdr, uint16_t type, size_t size);

void silofs_hdr_setup2(struct silofs_header *hdr, uint16_t type, size_t size,
                       enum silofs_hdrf flags);

int silofs_hdr_verify(const struct silofs_header *hdr, uint16_t type,
                      size_t size, enum silofs_hdrf flags);

int silofs_hdr_verify2(const struct silofs_header *hdr,
                       enum silofs_mtype           mtype);

void silofs_hdr_seal(struct silofs_header *hdr);

#endif /* SILOFS_META_H_ */
