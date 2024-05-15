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
#ifndef SILOFS_CADDR_H_
#define SILOFS_CADDR_H_

/* packed-object identifier */
struct silofs_caddr {
	struct silofs_hash256 hash;
	uint8_t pad[32]; /* padding for ioctl */
};


void silofs_caddr_reset(struct silofs_caddr *caddr);

void silofs_caddr_setup(struct silofs_caddr *caddr,
                        const struct silofs_hash256 *hash);

void silofs_caddr_assign(struct silofs_caddr *caddr,
                         const struct silofs_caddr *other);

bool silofs_caddr_isnone(const struct silofs_caddr *caddr);

bool silofs_caddr_isequal(const struct silofs_caddr *caddr,
                          const struct silofs_caddr *other);

void silofs_caddr_to_name(const struct silofs_caddr *caddr,
                          struct silofs_strbuf *out_name);

void silofs_caddr_to_name2(const struct silofs_caddr *caddr,
                           char s[SILOFS_NAME_MAX + 1]);

int silofs_caddr_by_name(struct silofs_caddr *caddr,
                         const struct silofs_strbuf *name);

uint32_t silofs_caddr_to_u32(const struct silofs_caddr *caddr);


void silofs_caddr64b_htox(struct silofs_caddr64b *caddr64b,
                          const struct silofs_caddr *caddr);

void silofs_caddr64b_xtoh(const struct silofs_caddr64b *caddr64b,
                          struct silofs_caddr *caddr);

#endif /* SILOFS_CADDR_H_ */
