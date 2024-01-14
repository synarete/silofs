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

uint64_t silofs_u8b_as_u64(const uint8_t p[8]);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uuid_generate(struct silofs_uuid *uu);

void silofs_uuid_assign(struct silofs_uuid *uu,
                        const struct silofs_uuid *other);

long silofs_uuid_compare(const struct silofs_uuid *uu1,
                         const struct silofs_uuid *uu2);

void silofs_uuid_name(const struct silofs_uuid *uu,
                      struct silofs_namebuf *nb);

uint64_t silofs_uuid_as_u64(const struct silofs_uuid *uu);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hdr_setup(struct silofs_header *hdr,
                      uint8_t type, size_t size, enum silofs_hdrf flags);

int silofs_hdr_verify(const struct silofs_header *hdr,
                      uint8_t type, size_t size, enum silofs_hdrf flags);

void silofs_hdr_seal(struct silofs_header *hdr);

#endif /* SILOFS_META_H_ */