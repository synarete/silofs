/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/str.h>

struct silofs_uuid;
struct silofs_header;

uint32_t silofs_squash_to_u32(const void *ptr, size_t len);

uint64_t silofs_u8b_as_u64(const uint8_t p[8]);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uuid_generate(struct silofs_uuid *uu);

void silofs_uuid_assign(struct silofs_uuid       *uu,
			const struct silofs_uuid *other);

void silofs_uuid_assign2(struct silofs_uuid *uu, const uint8_t u[16]);

void silofs_uuid_copyto(const struct silofs_uuid *uu, uint8_t u[16]);

long silofs_uuid_compare(const struct silofs_uuid *uu1,
			 const struct silofs_uuid *uu2);

void silofs_uuid_unparse(const struct silofs_uuid *uu,
			 struct silofs_strbuf     *sbuf);

int silofs_uuid_parse(struct silofs_uuid          *uu,
		      const struct silofs_strview *sv);

void silofs_uuid_as_u64s(const struct silofs_uuid *uu, uint64_t u[2]);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hdr_setup(struct silofs_header *hdr, uint8_t type, size_t size,
		      enum silofs_hdrf flags);

int silofs_hdr_verify(const struct silofs_header *hdr, uint8_t type,
		      size_t size, enum silofs_hdrf flags);

void silofs_hdr_seal(struct silofs_header *hdr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_hash256_isnil(const struct silofs_hash256 *hash);

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

#endif /* SILOFS_META_H_ */
